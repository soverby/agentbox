#!/usr/bin/env python3
"""P7 smoke test (PLAN §5 P7) against real Docker and real launchd.

1. `schedule add` (claude, far-away cron) with no Claude token -> `run-now`
   records a preflight failure with the fix command, no box start.
2. A fake Claude token (env backend) -> `run-now` runs the real box
   headless: claude gets an auth error, rc != 0, transcript + last.json
   recorded; `schedule ls` shows it.
3. Overlap: run-now during a fire -> rc 75, "skipped: a run is active";
   two jobs of one profile at once -> both run, box stopped after both;
   a user-`up` (pinned) box stays up after a scheduled run; the in-box
   kill script kills only the run's processes; SIGTERM during a fire ->
   status terminated, rc 143, box stopped.
4. Live launchd fire: `add --force --every 1m` (StartInterval 60) with
   label prefix com.agentbox-test.<tag> and a temp LaunchAgents dir
   (launchctl bootstrap accepts plists outside ~/Library/LaunchAgents),
   wait <= 150 s for launchd to run the job, assert last.json/transcript,
   then `schedule rm`: launchctl no longer knows the label, plist gone.
   If launchctl is denied, this part is SKIP with the reason.

Env backend, AGENTBOX_* roots in a temp dir. Cleanup boots out every test
label and removes every test plist, container, network, volume, and dir,
also on failure.

Usage: python3 tests/integration/p7_smoke.py
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TAG = secrets.token_hex(3)
NAME = f"it7-{TAG}"
PROJECT = f"agentbox-{NAME}"
PREFIX = f"agentbox-test-{TAG}"
LPREFIX = f"com.agentbox-test.t{TAG}"
UID = os.getuid()
RESULTS: list[tuple[str, str, str]] = []

PROFILE = """
[box]
agents = ["claude"]

[[mount]]
host = "{proj}"
mode = "rw"
allow_dotpath = true

[network]
mode = "strict"
presets = ["anthropic"]
"""


def rec(ok: bool | None, name: str, detail: str = "") -> bool:
    st = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    RESULTS.append((st, name, detail))
    print(f"{st} {name}" + (f": {detail}" if detail else ""), flush=True)
    return bool(ok)


def sh(args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


class Env:
    def __init__(self) -> None:
        self.roots = Path(tempfile.mkdtemp(prefix="agentbox-p7-"))
        self.work = Path.home() / f".agentbox-it7-{TAG}"
        self.proj = self.work / "proj"
        self.proj.mkdir(parents=True)
        self.la = self.roots / "LaunchAgents"
        cfg = self.roots / "config"
        (cfg / "profiles").mkdir(parents=True)
        (cfg / "config.toml").write_text(f'secret_backend = "env"\nsecret_prefix = "{PREFIX}"\n')
        (cfg / "profiles" / f"{NAME}.toml").write_text(PROFILE.format(proj=self.proj))
        self.prompt = self.roots / "prompt.md"
        self.prompt.write_text("Say hello.\n")
        self.env = dict(
            os.environ,
            AGENTBOX_CONFIG_HOME=str(cfg),
            AGENTBOX_STATE_HOME=str(self.roots / "state"),
            AGENTBOX_TEST_SECRET_STORE=str(self.roots / "store.json"),
            AGENTBOX_LAUNCHAGENTS_DIR=str(self.la),
            AGENTBOX_LAUNCHD_PREFIX=LPREFIX,
            PYTHONPATH=str(ROOT / "cli"),
        )
        self.env.pop("AGENTBOX_REPO", None)
        self.env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)

    def ab(self, *args, input=None, timeout=1800) -> subprocess.CompletedProcess:
        return sh([sys.executable, "-m", "agentbox.cli", *args], env=self.env, cwd=str(self.proj),
                  timeout=timeout, input=input,
                  stdin=None if input is not None else subprocess.DEVNULL)  # fmt: skip

    def jd(self, job: str) -> Path:
        return self.roots / "state" / NAME / "schedules" / job

    def last(self, job: str) -> dict:
        try:
            return json.loads((self.jd(job) / "last.json").read_text())
        except (OSError, ValueError):
            return {}

    def fire_bg(self, job: str) -> subprocess.Popen:
        return subprocess.Popen([sys.executable, "-m", "agentbox.cli", "schedule", "_fire", NAME,
                                 job], env=self.env, cwd="/", stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # fmt: skip

    def wait_running(self, job: str, limit: float = 60) -> None:
        t0 = time.monotonic()
        while self.last(job).get("status") != "running" and time.monotonic() - t0 < limit:
            time.sleep(0.2)

    def box_up(self) -> bool:
        return sh(["docker", "ps", "-q", "--filter",
                   f"label=com.docker.compose.project={PROJECT}"]).stdout.strip() != ""  # fmt: skip

    def history(self, job: str) -> list[dict]:
        f = self.jd(job) / "history.jsonl"
        return [json.loads(x) for x in f.read_text().splitlines()] if f.is_file() else []


def label(job: str) -> str:
    return f"{LPREFIX}.{NAME}.{job}"


def known(lbl: str) -> bool:
    return sh(["launchctl", "print", f"gui/{UID}/{lbl}"]).returncode == 0


def main() -> int:
    e = Env()
    before_vols = set(sh(["docker", "volume", "ls", "-q"]).stdout.split())
    try:
        steps(e)
    except Exception as ex:  # noqa: BLE001
        rec(False, "harness", repr(ex))
    finally:
        cleanup(e, before_vols)
    fails = [r for r in RESULTS if r[0] == "FAIL"]
    print(f"\nSUMMARY: {sum(r[0] == 'PASS' for r in RESULTS)} pass, {len(fails)} fail, "
          f"{sum(r[0] == 'SKIP' for r in RESULTS)} skip")  # fmt: skip
    return 1 if fails else 0


def steps(e: Env) -> None:
    job = "nightly"
    add = ["schedule", "add", NAME, "--name", job, "--agent", "claude",
           "--prompt-file", str(e.prompt)]  # fmt: skip
    # 1. no token: preflight failure recorded, with the fix command
    r = e.ab(*add, "--cron", "0 3 1 1 *")
    rec(r.returncode == 0 and "run-now" in r.stdout and r.stdout.count("\n  20") == 3,
        "add: next 3 fire times + run-now hint", r.stdout.strip().replace("\n", " | "))  # fmt: skip
    rec("CLAUDE_CODE_OAUTH_TOKEN is missing" in r.stderr, "add warns: Claude token missing")
    plist = e.la / f"{label(job)}.plist"
    raw = plist.read_bytes() if plist.is_file() else b""
    rec(b"sk-ant" not in raw and b"<key>PATH</key>" in raw and b"<key>HOME</key>" in raw,
        "plist written: PATH, HOME, no secret")  # fmt: skip
    pm = (e.jd(job) / "prompt.md").stat().st_mode & 0o777
    rec(pm == 0o600, "prompt copied to state 0600", oct(pm))
    r = e.ab("schedule", "run-now", NAME, job, timeout=300)
    last = e.last(job)
    rec(r.returncode == 78 and last.get("status") == "failed"
        and "agentbox setup" in (last.get("message") or ""),
        "run-now, no token: failure + fix recorded", f"rc={r.returncode} {last}")  # fmt: skip

    # 2. fake token -> real headless run, auth error
    fake = "sk-ant-oat01-" + "A" * 40 + TAG
    r = e.ab("secret", "set", "--shared", "CLAUDE_CODE_OAUTH_TOKEN", "--stdin", input=fake + "\n")
    rec(r.returncode == 0, "store fake Claude token (env backend)", r.stderr.strip())
    r = e.ab("schedule", "run-now", NAME, job, timeout=900)
    last = e.last(job)
    tr = Path(last.get("transcript") or "/nonexistent")
    text = tr.read_text() if tr.is_file() else ""
    rec(r.returncode != 0 and last.get("exit_code") == r.returncode and text.strip() != ""
        and (Path(last["run_dir"]) / "exit_code").read_text().strip() == str(r.returncode),
        "run-now: real run, rc != 0 recorded, transcript",
        f"rc={r.returncode} transcript tail: {text.strip()[-200:]!r}")  # fmt: skip
    rec(fake not in text and fake not in json.dumps(last), "token not in transcript/last.json")
    r = e.ab("schedule", "ls")
    rec(r.returncode == 0 and f"{NAME}/{job}" in r.stdout and str(tr) in r.stdout
        and f"exit={last.get('exit_code')}" in r.stdout and "[loaded]" in r.stdout,
        "schedule ls shows last result", r.stdout.strip().replace("\n", " | "))  # fmt: skip
    rec(sh(["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}"])
        .stdout.strip() == "", "box stopped after the run (stop_if_idle)")  # fmt: skip

    # 3. overlap of one job: run-now while a fire runs -> rc 75, skip recorded
    n0 = len(e.history(job))
    a = e.fire_bg(job)
    e.wait_running(job)
    b = e.ab("schedule", "run-now", NAME, job, timeout=120)
    a.wait(timeout=900)
    hist = e.history(job)[n0:]
    st = [h["status"] for h in hist]
    rec(b.returncode == 75 and "skipped: a run is active" in b.stdout
        and st == ["skipped", "failed"] and hist[0]["exit_code"] == 75,
        "overlap (same job): one runs, one skipped rc 75",
        f"{st} rc={b.returncode} out={b.stdout.strip()[-120:]!r}")  # fmt: skip
    rec(not e.box_up(), "box stopped after the overlap")

    # 3b. two jobs of one profile at once: both run, box stopped after both
    r = e.ab("schedule", "add", NAME, "--name", "second", "--agent", "claude",
             "--prompt-file", str(e.prompt), "--cron", "0 3 1 1 *")  # fmt: skip
    rec(r.returncode == 0, "add a second job", r.stderr.strip()[-200:])
    n1, n2 = len(e.history(job)), len(e.history("second"))
    p1, p2 = e.fire_bg(job), e.fire_bg("second")
    p1.wait(timeout=900)
    p2.wait(timeout=900)
    h1, h2 = e.history(job)[n1:], e.history("second")[n2:]
    rec([h["status"] for h in h1] == ["failed"] and [h["status"] for h in h2] == ["failed"]
        and all(h[0].get("run_dir") and h[0].get("exit_code") not in (None, 125)
                for h in (h1, h2)) and h1[0]["run_dir"] != h2[0]["run_dir"]
        and not e.box_up(), "two jobs at once: both ran, box stopped after both",
        f"{h1} {h2} up={e.box_up()}")  # fmt: skip

    # 3c. a box the user started with `up` stays up after a scheduled run
    r = e.ab("up", NAME, timeout=900)
    ok_up = r.returncode == 0 and e.box_up()
    r2 = e.ab("schedule", "run-now", NAME, job, timeout=900)
    rec(ok_up and r2.returncode not in (0, 75) and e.box_up(),
        "pinned (user `up`) box stays up after a scheduled run",
        f"up={ok_up} rc={r2.returncode} still_up={e.box_up()}")  # fmt: skip

    # 3d. in-box kill of one run's processes (the timeout / SIGTERM path)
    sys.path.insert(0, str(ROOT / "cli"))
    from agentbox import runs as runsmod

    cf = str(e.roots / "state" / NAME / "compose.json")
    dc = ["docker", "compose", "-p", PROJECT, "-f", cf, "exec", "-T"]
    victim = subprocess.Popen([*dc, "-e", "AGENTBOX_RUN=smoke-kill", "agent",
                               "/usr/local/bin/with-secrets", "sleep", "317"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)  # fmt: skip
    bystander = subprocess.Popen([*dc, "agent", "/usr/local/bin/with-secrets", "sleep", "318"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)  # fmt: skip
    time.sleep(4)
    alive_before = victim.poll() is None and bystander.poll() is None
    k = sh([*dc, "agent", "sh", "-c", runsmod.kill_script("smoke-kill")])
    try:
        vrc = victim.wait(timeout=20)
    except subprocess.TimeoutExpired:
        vrc = None
    time.sleep(1)
    rec(alive_before and k.returncode == 0 and vrc == 137 and bystander.poll() is None,
        "kill_script kills only the run's processes in the box",
        f"before={alive_before} k={k.returncode} victim={vrc} o={bystander.poll()}")  # fmt: skip
    bystander.kill()
    sh([*dc, "agent", "sh", "-c", "pkill -f 'sleep 318' || true"])
    r = e.ab("down", NAME, timeout=300)
    rec(r.returncode == 0 and not e.box_up(), "down (clears the pin)")

    # 3e. SIGTERM during a fire: cleanup runs, terminated rc 143 recorded, box stopped
    n0 = len(e.history(job))
    p = e.fire_bg(job)
    e.wait_running(job)
    time.sleep(3)
    p.send_signal(signal.SIGTERM)
    prc = p.wait(timeout=300)
    last = e.last(job)
    rd = last.get("run_dir")
    ec = (
        (Path(rd) / "exit_code").read_text().strip()
        if rd and Path(rd, "exit_code").is_file()
        else None
    )
    rec(prc == 143 and last.get("status") == "terminated" and last.get("exit_code") == 143
        and len(e.history(job)) == n0 + 1 and not e.box_up() and ec in ("143", None),
        "SIGTERM: terminated rc 143 recorded, box stopped",
        f"rc={prc} last={last.get('status')}/{last.get('exit_code')} run_exit={ec}")  # fmt: skip
    r = e.ab("schedule", "rm", NAME, "second")
    rec(r.returncode == 0, "rm second job")

    # 4. live launchd fire
    probe = sh(["launchctl", "print", f"gui/{UID}"])
    if probe.returncode != 0:
        rec(None, "live launchd fire", f"launchctl denied: {probe.stderr.strip()[:200]}")
        return
    r = e.ab(*add, "--every", "1m", "--force")
    rec(r.returncode == 0 and known(label(job)), "add --every 1m: loaded in launchd",
        r.stderr.strip()[-200:])  # fmt: skip
    n0 = len(e.history(job))
    t0 = time.monotonic()
    while time.monotonic() - t0 < 150 and len(e.history(job)) == n0:
        time.sleep(2)
    # a fire may be in progress: wait for it to end
    while time.monotonic() - t0 < 600 and e.last(job).get("status") == "running":
        time.sleep(2)
    hist = e.history(job)[n0:]
    last = e.last(job)
    tr = Path(last.get("transcript") or "/nonexistent")
    err = e.jd(job) / "launchd.err"
    errtext = err.read_text() if err.is_file() else ""
    rec(bool(hist) and last.get("status") == "failed" and last.get("exit_code") not in (None, 0)
        and tr.is_file() and tr.read_text().strip() != "" and "exit" in errtext,
        "live launchd fire: last.json + transcript",
        f"{time.monotonic() - t0:.0f}s {last} err={errtext.strip()[-200:]!r}")  # fmt: skip
    r = e.ab("schedule", "rm", NAME, job)
    rec(r.returncode == 0 and not known(label(job)) and not plist.exists()
        and not e.jd(job).exists(), "rm: label booted out, plist + job dir gone",
        r.stderr.strip())  # fmt: skip


def cleanup(e: Env, before_vols: set[str]) -> None:
    for p in e.la.glob(f"{LPREFIX}.*.plist") if e.la.is_dir() else []:
        sh(["launchctl", "bootout", f"gui/{UID}/{p.stem}"])
        p.unlink(missing_ok=True)
    for j in ("nightly", "second"):
        sh(["launchctl", "bootout", f"gui/{UID}/{label(j)}"])
    f = e.roots / "state" / NAME / "compose.json"
    if f.exists():
        sh(["docker", "compose", "-p", PROJECT, "-f", str(f), "down", "-v", "--remove-orphans",
            "--timeout", "2"])  # fmt: skip
    sh(["docker", "volume", "rm", "-f", f"{PROJECT}-home"])
    shutil.rmtree(e.work, ignore_errors=True)
    shutil.rmtree(e.roots, ignore_errors=True)
    labels = [x for x in sh(["launchctl", "list"]).stdout.split() if x.startswith(LPREFIX)]
    left = sh(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split()
    nets = sh(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split()
    vols = sh(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split()
    ours = [x for x in left + nets + vols if NAME in x or TAG in x]
    new_vols = sorted(set(sh(["docker", "volume", "ls", "-q"]).stdout.split()) - before_vols)
    real_la = list((Path.home() / "Library/LaunchAgents").glob(f"{LPREFIX}*"))
    rec(not labels and not ours and not new_vols and not real_la
        and not e.work.exists() and not e.roots.exists(),
        "cleanup (launchd labels, plists, containers, networks, volumes, dirs)",
        f"leftovers {labels} {ours} {new_vols} {real_la}")  # fmt: skip


if __name__ == "__main__":
    sys.exit(main())
