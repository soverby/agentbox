#!/usr/bin/env python3
"""P3 smoke test (PLAN §5 P3) against real Docker.

Runs the real CLI (`python -m agentbox.cli`) with AGENTBOX_CONFIG_HOME and
AGENTBOX_STATE_HOME pointed at a temp dir, so the user's config and state are
never touched. Mounts a dir under $HOME/.agentbox-it-<rand> (host /tmp is
/private/tmp, which the mount denylist refuses). Removes every container,
network, volume, and derived image it created; keeps the base images
(agentbox/agent, agentbox/egress, agentbox/ollama-gate).

Usage: python3 tests/integration/p3_smoke.py
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TAG = secrets.token_hex(3)
MAIN, PKG = f"it-{TAG}", f"it-{TAG}-pkg"
BASE_REPOS = ("agentbox/agent", "agentbox/egress", "agentbox/ollama-gate")
RESULTS: list[tuple[str, str, str]] = []


def rec(ok: bool | None, name: str, detail: str = "") -> bool:
    st = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    RESULTS.append((st, name, detail))
    print(f"{st} {name}" + (f": {detail}" if detail else ""), flush=True)
    return bool(ok)


def sh(args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


class Env:
    def __init__(self) -> None:
        self.roots = Path(tempfile.mkdtemp(prefix="agentbox-p3-"))
        self.work = Path.home() / f".agentbox-it-{TAG}"
        self.proj = self.work / "proj"
        self.sub = self.proj / "sub" / "dir"
        self.pkg_dir = self.work / "pkg"
        self.sub.mkdir(parents=True)
        self.pkg_dir.mkdir()
        self.env = dict(
            os.environ,
            AGENTBOX_CONFIG_HOME=str(self.roots / "config"),
            AGENTBOX_STATE_HOME=str(self.roots / "state"),
            PYTHONPATH=str(ROOT / "cli"),
        )
        self.env.pop("AGENTBOX_REPO", None)
        # P4: never read the user's keychain. Test-only env backend + test prefix;
        # no values are set, so declared secrets are reported missing.
        (self.roots / "config").mkdir()
        (self.roots / "config" / "config.toml").write_text(
            f'secret_backend = "env"\nsecret_prefix = "agentbox-test-{TAG}"\n'
        )
        self.env["AGENTBOX_TEST_SECRET_STORE"] = str(self.roots / "secret-store.json")

    def ab(self, *args, cwd=None, timeout=1800) -> subprocess.CompletedProcess:
        return sh(
            [sys.executable, "-m", "agentbox.cli", *args],
            env=self.env,
            cwd=str(cwd or self.work),
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )

    def state(self, name: str) -> Path:
        return self.roots / "state" / name

    def profile(self, name: str) -> Path:
        return self.roots / "config" / "profiles" / f"{name}.toml"


def images() -> set[str]:
    out = sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]).stdout
    return {x for x in out.split() if x.startswith("agentbox/")}


def started(project: str) -> dict[str, str]:
    ids = sh(["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={project}"])
    ids = ids.stdout.split()
    if not ids:
        return {}
    out = sh(["docker", "inspect", *ids, "--format", "{{.Name}} {{.Id}} {{.State.StartedAt}}"])
    return dict(line.split(" ", 1) for line in out.stdout.splitlines())


def proxy_code(e: Env, name: str, host: str) -> str:
    r = e.ab(
        "shell",
        name,
        "--",
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-m",
        "15",
        "-w",
        "%{http_connect}",
        f"https://{host}/",
    )
    return r.stdout.strip()


def ck(c: str) -> tuple:
    return (int(c.split("-")[0].split()[0]), c)


# P6: the MCP gateway always runs (checks 13, 14, 20).
P6_PASS = ("13 (mcp-gateway)", "14 claude-mcp", "14 codex-config", "14 connectors-proxy",
           "20 auth", "20 policy", "20 upstream-direct", "20 gateway-fs",
           "20 upstreams")  # fmt: skip


def doctor_ok(e: Env, name: str, want_skip: set[str], want_pass: set[str]) -> None:
    r = e.ab("doctor", name, timeout=900)
    lines = [x for x in r.stdout.splitlines() if x.split(" ")[0] in ("PASS", "FAIL", "SKIP")]
    # check id = text between the status word and ": " ("17 env", "19-v6", ...)
    status = {x.split(" ", 1)[1].partition(": ")[0].strip(): x.split()[0] for x in lines}
    fails = [x for x in lines if x.startswith("FAIL")]
    skips = {c for c, s in status.items() if s == "SKIP"}
    passes = {c for c, s in status.items() if s == "PASS"}
    skip_reasons = all(": " in x for x in lines if x.startswith("SKIP"))
    ok = (
        r.returncode == 0
        and not fails
        and want_pass <= passes
        and skips <= want_skip
        and skip_reasons
    )
    rec(
        ok,
        f"doctor {name}",
        f"rc={r.returncode} pass={sorted(passes, key=ck)} skip={sorted(skips, key=ck)}"
        + (f" FAILS={fails}" if fails else "")
        + ("" if skip_reasons else " (SKIP without reason)"),
    )
    for x in lines:
        print(f"    {x}")


def volumes() -> set[str]:
    return set(sh(["docker", "volume", "ls", "-q"]).stdout.split())


def main() -> int:  # noqa: C901 (linear scenario)
    before_images = images()
    before_vols = volumes()
    e = Env()
    mounted = [MAIN, PKG]
    print(f"== roots {e.roots}, work {e.work}", flush=True)
    try:
        # -- init
        r = e.ab("init", MAIN, "--mount", str(e.proj))
        rec(r.returncode != 0 and "allow_dotpath" in r.stderr, "init refuses dot-path w/o opt-in")
        r = e.ab("init", MAIN, "--mount", "/tmp")
        rec(r.returncode != 0 and "/private" in r.stderr, "init refuses /tmp (-> /private/tmp)")
        r = e.ab("init", MAIN, "--mount", str(e.proj), "--allow-dotpath")
        rec(r.returncode == 0 and e.profile(MAIN).is_file(), "init", r.stderr.strip())
        r = e.ab("init", MAIN, "--mount", str(e.proj), "--allow-dotpath")
        rec(r.returncode != 0 and "not overwriting" in r.stderr, "init refuses overwrite")
        mode = oct(e.state(MAIN).stat().st_mode & 0o777) if e.state(MAIN).exists() else "-"

        # -- up (fast subset gates it)
        t0 = time.time()
        r = e.ab("up", MAIN)
        rec(
            r.returncode == 0,
            "up (fast subset 1,2,6,9 passed)",
            f"{time.time() - t0:.1f}s {r.stderr.strip()[-400:]}",
        )
        if r.returncode != 0:
            return finish()
        mode = oct(e.state(MAIN).stat().st_mode & 0o777)
        rec(mode == "0o700", "state dir 0700", mode)
        cj = json.loads((e.state(MAIN) / "compose.json").read_text())
        a = cj["services"]["agent"]
        rec(
            a["cap_drop"] == ["ALL"]
            and a["user"] == "1000:1000"
            and a["init"] is True
            and list(a["networks"]) == ["internal"]
            # P4: no values are stored in this smoke, so only the per-box token is
            # delivered; the file holds names and env var names only.
            and cj.get("secrets")
            == {"MCP_GATEWAY_TOKEN": {"environment": "AGENTBOX_SECRET_MCP_GATEWAY_TOKEN"}},
            "rendered compose: hardening, internal-only agent, secrets = box token (names only)",
        )

        # -- packages profile (open mode) second, so doctor 12 has a target
        r = e.ab(
            "init",
            PKG,
            "--mount",
            str(e.pkg_dir),
            "--allow-dotpath",
            "--open",
            "--agents",
            "claude",
        )
        txt = e.profile(PKG).read_text().replace('# packages = ["ffmpeg"]', 'packages = ["tree"]')
        (e.work / "a").mkdir()
        (e.work / "b").mkdir()
        os.symlink(e.work / "a", e.work / "alias")
        txt = txt.replace(
            "[network]",
            f'[[mount]]\nhost = "{e.work / "alias"}"\npath = "/alias"\nallow_dotpath = true\n\n'
            "[network]",
        )
        e.profile(PKG).write_text(txt)
        t0 = time.time()
        r = e.ab("up", PKG)
        built = "building agentbox/agent-pkgs:" in r.stderr
        rec(
            r.returncode == 0 and (built or any("agent-pkgs" in x for x in before_images)),
            "packages profile up (derived image)",
            f"{time.time() - t0:.1f}s built={built}",
        )
        r = e.ab("shell", PKG, "--", "sh", "-c", "tree --version && id -u")
        rec(
            r.returncode == 0 and "tree v" in r.stdout and r.stdout.split()[-1] == "1000",
            "derived image: package present, runtime user agent",
            r.stdout.strip()[-80:],
        )
        img1 = sh(
            [
                "docker",
                "compose",
                "-p",
                f"agentbox-{PKG}",
                "-f",
                str(e.state(PKG) / "compose.json"),
                "images",
                "--format",
                "json",
                "agent",
            ]
        )
        r = e.ab("up", PKG)
        img2 = sh(
            [
                "docker",
                "compose",
                "-p",
                f"agentbox-{PKG}",
                "-f",
                str(e.state(PKG) / "compose.json"),
                "images",
                "--format",
                "json",
                "agent",
            ]
        )
        rec(
            r.returncode == 0 and "building" not in r.stderr and img1.stdout == img2.stdout,
            "second up reuses cached derived image",
        )

        # -- doctor (both modes)
        doctor_ok(
            e,
            MAIN,
            {
                "13 (router)",
                "21 router",
                "14 codex-apps-live",
                "15",
                "17 live",
                "18",
                "19",
                "20 allowed-call",
            },
            {
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "8",
                "9",
                "10",
                "11",
                "12",
                "16",
                "17 env",
                *P6_PASS,
            },
        )
        doctor_ok(
            e,
            PKG,
            {
                "2",
                "13 (router)",
                "21 router",  # P5: no [models.remote.*] -> no router
                "14 codex-config",
                "15",
                "17 live",
                "18",
                "19-v6",
                "14 pi-mcp",
                "20 allowed-call",
            },
            {
                "1",
                "3",
                "4",
                "5",
                "6",
                "7",
                "8",
                "9",
                "10",
                "11",
                "12",
                "16",
                "17 env",
                "19",
                "13 (mcp-gateway)",
                "14 claude-mcp",
                "14 connectors-proxy",
                "20 upstreams",
                "20 auth",
                "20 policy",
                "20 upstream-direct",
                "20 gateway-fs",
            },
        )

        # -- sessions from inside the mounted dir
        want_dir = os.path.realpath(e.sub)
        r = e.ab("shell", "--", "pwd", cwd=e.sub)
        rec(
            r.returncode == 0 and r.stdout.strip() == want_dir,
            "shell -- pwd (profile from cwd) runs in the mapped dir",
            r.stdout.strip(),
        )
        r = e.ab("claude", "--", "--version", cwd=e.sub)
        rec(
            r.returncode == 0 and "Claude Code" in r.stdout,
            "claude -- --version from mounted dir",
            r.stdout.strip() or r.stderr.strip()[-200:],
        )
        r = e.ab(
            "shell",
            MAIN,
            "--",
            "bash",
            "-c",
            "shopt -q login_shell && echo LOGIN || echo NOLOGIN; echo $PATH",
        )
        out = r.stdout.split()
        rec(
            r.returncode == 0
            and out[:1] == ["NOLOGIN"]
            and out[1:2]
            == [
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
                "/home/agent/.npm-global/bin:/home/agent/.local/bin"
            ],
            "session is not a login shell; home PATH entries last",
            " | ".join(out),
        )
        r = e.ab(
            "shell",
            MAIN,
            "--",
            "git",
            "config",
            "--global",
            "--get",
            "url.https://github.com/.insteadof",
        )
        rec(r.stdout.strip() == "git@github.com:", "git insteadOf set in box", r.stdout.strip())
        host_name = sh(["git", "config", "--global", "--get", "user.name"]).stdout.strip()
        r = e.ab("shell", MAIN, "--", "git", "config", "--global", "--get", "user.name")
        rec(r.stdout.strip() == host_name, "git user.name copied from host", r.stdout.strip())
        r = e.ab("shell", "--", "pwd", cwd=e.roots)
        rec(
            r.returncode != 0 and "no profile mounts" in r.stderr and MAIN in r.stderr,
            "cwd outside every mount: error lists candidates",
        )

        # -- headless run (no auth: non-zero exit expected)
        pf = e.work / "prompt.txt"
        pf.write_text("Reply with the word ok.\n")
        r = e.ab("run", MAIN, "--agent", "claude", "--prompt-file", str(pf), timeout=600)
        runs = sorted((e.state(MAIN) / "runs").iterdir())
        ok = bool(runs)
        if ok:
            rd = runs[-1]
            code = (rd / "exit_code").read_text().strip()
            meta = json.loads((rd / "meta.json").read_text())
            tr = (rd / "transcript.log").read_text()
            ok = (
                r.returncode != 0
                and code == str(r.returncode)
                and meta["exit_code"] == r.returncode
                and tr.strip() != ""
                and meta["box_was_running"] is True
            )
            detail = f"rc={r.returncode} dir={rd.name} transcript={tr.strip()[:60]!r}"
        else:
            detail = "no run dir"
        rec(ok, "run --agent claude records transcript + exit code", detail)
        r = e.ab("down", MAIN)
        r = e.ab("run", MAIN, "--agent", "claude", "--prompt-file", str(pf), timeout=900)
        rd = sorted((e.state(MAIN) / "runs").iterdir())[-1]
        meta = json.loads((rd / "meta.json").read_text())
        rec(
            meta["box_was_running"] is False
            and not started(f"agentbox-{MAIN}")
            and meta["exit_code"] == r.returncode != 0,
            "run starts and stops a stopped box; exit code propagated",
            f"rc={r.returncode}",
        )
        r = e.ab("up", MAIN)
        rec(r.returncode == 0, "up again after run")

        # -- F6: prompt on stdin: starts with "---" and is 200 KB; no option parsing
        big = e.work / "big-prompt.txt"
        big.write_text("--- not an option\n" + ("x" * 99 + "\n") * 2000)
        for agent, auth_words in (
            ("claude", ("Not logged in · Please run /login",)),
            ("codex", ("401 Unauthorized: Missing bearer or basic authentication in header",)),
            ("pi", ("No API key found for the selected model.",)),
        ):
            r = e.ab("run", MAIN, "--agent", agent, "--prompt-file", str(big), timeout=600)
            rd = sorted((e.state(MAIN) / "runs").iterdir())[-1]
            tr = (rd / "transcript.log").read_text(errors="replace")
            bad = [
                w
                for w in (
                    "unexpected argument",
                    "unknown option",
                    "Unknown option",
                    "Argument list too long",
                    "error: unrecognized",
                )
                if w in tr
            ]
            rec(
                r.returncode != 0
                and not bad
                and any(w in tr for w in auth_words)
                and (rd / "exit_code").read_text().strip() == str(r.returncode),
                f"run --agent {agent}: 200 KB '---' prompt on stdin reaches the agent",
                f"rc={r.returncode} transcript={tr.strip()[-120:]!r}",
            )

        # -- F4: run must not stop a box another session joined
        e.ab("down", MAIN)
        small = e.work / "prompt.txt"
        runp = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "agentbox.cli",
                "run",
                MAIN,
                "--agent",
                "claude",
                "--prompt-file",
                str(small),
            ],
            env=e.env,
            cwd=str(e.work),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        time.sleep(1.0)
        t0 = time.time()
        shp = subprocess.Popen(
            [sys.executable, "-m", "agentbox.cli", "shell", MAIN, "--", "sleep", "40"],
            env=e.env,
            cwd=str(e.work),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        rout, rerr = runp.communicate(timeout=600)
        up_after_run = bool(started(f"agentbox-{MAIN}"))
        sout, serr = shp.communicate(timeout=600)
        rec(
            runp.returncode != 0
            and up_after_run
            and shp.returncode == 0
            and time.time() - t0 >= 40,
            "run leaves a joined box up; concurrent shell -- sleep 40 completes rc 0",
            f"run rc={runp.returncode} ({rerr.strip()[-100:]!r}) shell rc={shp.returncode} "
            f"({serr.strip()[-300:]!r})",
        )

        # -- allow: live reload, no restart
        dom = "www.wikipedia.org"
        before = proxy_code(e, MAIN, dom)
        st1 = started(f"agentbox-{MAIN}")
        r = e.ab("allow", MAIN, dom)
        after = ""
        for _ in range(20):
            after = proxy_code(e, MAIN, dom)
            if after == "200":
                break
            time.sleep(0.5)
        st2 = started(f"agentbox-{MAIN}")
        text = e.profile(MAIN).read_text()
        rec(
            before == "403"
            and r.returncode == 0
            and after == "200"
            and st1 == st2
            and f'allow = ["{dom}"]' in text
            and "# CLAUDE_CODE_OAUTH_TOKEN is implicit" in text,
            "allow: reachable without restart, profile edited in place",
            f"{before} -> {after}, restarted={st1 != st2}",
        )
        r = e.ab("allow", MAIN, "10.1.2.3")
        rec(r.returncode != 0 and e.profile(MAIN).read_text() == text, "allow rejects IP literal")

        # -- F1: a hand edit that tightens [network] applies at the next up
        e.profile(MAIN).write_text(text.replace(f'allow = ["{dom}"]', "allow = []"))
        r = e.ab("up", MAIN)
        code = proxy_code(e, MAIN, dom)
        rec(r.returncode == 0 and code == "403", "hand-removed domain -> up -> 403", code)
        ptxt = e.profile(PKG).read_text()
        c_open = proxy_code(e, PKG, "example.org")
        lab1 = sh(
            [
                "docker",
                "inspect",
                f"agentbox-{PKG}-egress-1",
                "--format",
                '{{index .Config.Labels "agentbox.egress-config"}}',
            ]
        ).stdout.strip()
        e.profile(PKG).write_text(ptxt.replace('mode = "open"  ', 'mode = "strict"'))
        r = e.ab("up", PKG)
        c_strict = proxy_code(e, PKG, "example.org")
        lab2 = sh(
            [
                "docker",
                "inspect",
                f"agentbox-{PKG}-egress-1",
                "--format",
                '{{index .Config.Labels "agentbox.egress-config"}}',
            ]
        ).stdout.strip()
        rec(
            r.returncode == 0 and c_open == "200" and c_strict == "403" and lab1 and lab1 != lab2,
            "mode open -> strict -> up -> strict behavior; egress-config label changed",
            f"{c_open} -> {c_strict}, label {lab1} -> {lab2}",
        )

        # -- F5 negative control: tamper with the live squid.conf -> doctor FAIL 5
        conf = e.state(MAIN) / "egress" / "squid.conf"
        orig = conf.read_text()
        bad_conf = orig.replace("dstdomain -n ", "dstdomain ").replace(
            "http_access deny ip_literal\n", ""
        )
        conf.write_text(bad_conf)
        sh(
            [
                "docker",
                "compose",
                "-p",
                f"agentbox-{MAIN}",
                "-f",
                str(e.state(MAIN) / "compose.json"),
                "exec",
                "-T",
                "egress",
                "squid",
                "-k",
                "reconfigure",
                "-f",
                "/etc/squid/agentbox/squid.conf",
            ]
        )
        r = e.ab("doctor", MAIN, timeout=900)
        l5 = [x for x in r.stdout.splitlines() if x.startswith(("PASS 5", "FAIL 5"))]
        rec(
            bad_conf != orig and r.returncode != 0 and l5[:1] and l5[0].startswith("FAIL 5"),
            "negative control: tampered live squid.conf -> doctor FAIL 5",
            l5[0] if l5 else r.stdout[-300:],
        )
        r = e.ab("up", MAIN)
        r2 = e.ab("doctor", MAIN, timeout=900)
        l5 = [x for x in r2.stdout.splitlines() if x.startswith(("PASS 5", "FAIL 5"))]
        rec(
            r.returncode == 0
            and conf.read_text() == orig
            and r2.returncode == 0
            and l5[:1]
            and l5[0].startswith("PASS 5"),
            "up restores the render; doctor PASS 5 again",
            l5[0] if l5 else "",
        )

        # -- F2: a real agent denial made during a fast-subset window stays
        # visible; the doctor's own (nonce User-Agent) probes do not show.
        real = "www.example.net"
        sh(
            [
                "docker",
                "compose",
                "-p",
                f"agentbox-{MAIN}",
                "-f",
                str(e.state(MAIN) / "compose.json"),
                "exec",
                "-d",
                "-T",
                "agent",
                "sh",
                "-c",
                f"for i in $(seq 1 60); do curl -s -o /dev/null -m 5 https://{real}/; "
                "sleep 0.15; done",
            ]
        )
        time.sleep(0.5)
        r = e.ab("up", MAIN)  # runs the fast subset (1, 2, 6, 9) while the loop runs
        time.sleep(12)
        wins = [
            json.loads(x) for x in (e.state(MAIN) / "doctor-windows.jsonl").read_text().splitlines()
        ]
        w = wins[-1]
        log = (e.state(MAIN) / "logs" / "egress" / "egress.log").read_text().splitlines()
        in_win = [
            x
            for x in log
            if f"CONNECT {real}:443" in x and w["start"] <= float(x.split()[0]) <= w["end"]
        ]
        doc_in_win = [x for x in log if w["ua"] in x]
        r = e.ab("denied", MAIN, "--json", "--since", "10m")
        items = {d["host"]: d for d in json.loads(r.stdout or "[]")}
        hosts = set(items)
        rec(
            r.returncode == 0
            and len(in_win) > 0
            and len(doc_in_win) > 0
            and real in hosts
            and dom in hosts
            and not hosts & {"example.org", "host.docker.internal", "1.1.1.1"},
            "denied: real denials inside a doctor window listed; doctor probes not",
            f"{len(in_win)} {real} denials inside window {w['ua']} "
            f"(+{len(doc_in_win)} doctor lines); listed={sorted(hosts)}",
        )

        # -- denied (a probe outside any agentbox command, like agent traffic)
        sh(
            [
                "docker",
                "compose",
                "-p",
                f"agentbox-{MAIN}",
                "-f",
                str(e.state(MAIN) / "compose.json"),
                "exec",
                "-T",
                "agent",
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-m",
                "15",
                "https://example.org/",
            ]
        )
        r = e.ab("denied", MAIN, "--json", "--since", "10m")
        items = {d["host"]: d for d in json.loads(r.stdout or "[]")}
        d = items.get("example.org")
        rec(
            r.returncode == 0 and d is not None and d["allowable"] and d["count"] >= 1,
            "denied lists example.org",
            json.dumps(d),
        )
        r = e.ab("denied", MAIN)
        rec(r.returncode == 0 and "example.org" in r.stdout, "denied (table)")

        # -- re-up of a running box
        st1 = started(f"agentbox-{MAIN}")
        r = e.ab("up", MAIN)
        rec(
            r.returncode == 0 and started(f"agentbox-{MAIN}") == st1,
            "re-up of running box succeeds, no restart",
        )

        # -- update --check
        r = e.ab("update", "--check", timeout=300)
        rec(
            r.returncode == 0
            and "CLAUDE_CODE_VERSION" in r.stdout
            and "PYTHON_VERSION" in r.stdout,
            "update --check lists pins",
            "\n" + r.stdout.rstrip(),
        )

        # -- F7: the reviewer's attack: a mount path through a symlink in a rw mount
        (e.work / "other").mkdir()
        os.symlink(e.work / "other", e.proj / "link")
        mtxt = e.profile(MAIN).read_text()
        e.profile(MAIN).write_text(
            mtxt.replace(
                "[network]",
                f'[[mount]]\nhost = "{e.proj / "link"}"\npath = "/other"\n'
                "allow_dotpath = true\n\n[network]",
            )
        )
        r = e.ab("up", MAIN)
        rec(
            r.returncode != 0 and "inside the rw mount" in r.stderr,
            "mount through a symlink inside a rw mount refused",
            r.stderr.strip()[-160:],
        )
        e.profile(MAIN).write_text(mtxt)
        os.unlink(e.work / "alias")
        os.symlink(e.work / "b", e.work / "alias")
        (e.work / "b" / "marker-b").write_text("b")
        r = e.ab("up", PKG)
        r2 = e.ab("up", PKG, "--accept-mount-change")
        r3 = e.ab("shell", PKG, "--", "ls", "/alias")
        rec(
            r.returncode != 0
            and "--accept-mount-change" in r.stderr
            and r2.returncode == 0
            and r3.stdout.split() == ["marker-b"],
            "changed mount realpath refused until --accept-mount-change",
            r.stderr.strip()[-160:],
        )

        # -- down, ls
        r1, r2 = e.ab("down", MAIN), e.ab("down", PKG)
        r = e.ab("ls")
        lines = {x.split()[0]: x.split()[1] for x in r.stdout.splitlines() if x.strip()}
        rec(
            r1.returncode == r2.returncode == 0
            and lines.get(MAIN) == "stopped"
            and lines.get(PKG) == "stopped"
            and not started(f"agentbox-{MAIN}"),
            "down; ls shows stopped",
            r.stdout.strip().replace("\n", " | "),
        )
        vol = sh(["docker", "volume", "ls", "-q", "--filter", f"name=agentbox-{MAIN}-home"])
        rec(vol.stdout.strip() == f"agentbox-{MAIN}-home", "down keeps the home volume")
    except Exception as ex:  # noqa: BLE001
        rec(False, "smoke harness", repr(ex))
    finally:
        cleanup(e, mounted, before_images, before_vols)
    return finish()


def cleanup(e: Env, names: list[str], before_images: set[str], before_vols: set[str]) -> None:
    for n in names:
        f = e.state(n) / "compose.json"
        if f.exists():
            sh(
                [
                    "docker",
                    "compose",
                    "-p",
                    f"agentbox-{n}",
                    "-f",
                    str(f),
                    "down",
                    "-v",
                    "--remove-orphans",
                    "--timeout",
                    "2",
                ]
            )
        sh(["docker", "volume", "rm", "-f", f"agentbox-{n}-home"])
    new = images() - before_images
    derived = sorted(
        i for i in new if not i.startswith(tuple(r + ":" for r in BASE_REPOS)) or ":base-" in i
    )
    if derived:
        sh(["docker", "rmi", *derived])
    shutil.rmtree(e.work, ignore_errors=True)
    shutil.rmtree(e.roots, ignore_errors=True)
    left = sh(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split()
    nets = sh(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split()
    vols = sh(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split()
    ours = [x for x in left + nets + vols if f"it-{TAG}" in x]
    new_vols = sorted(volumes() - before_vols)
    rec(not new_vols, "no new volumes (named or anonymous) left behind", str(new_vols))
    rec(
        not ours and not e.work.exists() and not e.roots.exists(),
        "cleanup",
        f"removed images {derived}; leftovers {ours}",
    )


def finish() -> int:
    fails = [r for r in RESULTS if r[0] == "FAIL"]
    print(
        f"\nSUMMARY: {sum(r[0] == 'PASS' for r in RESULTS)} pass, {len(fails)} fail, "
        f"{sum(r[0] == 'SKIP' for r in RESULTS)} skip"
    )
    for r in fails:
        print(f"  FAIL {r[1]}: {r[2]}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
