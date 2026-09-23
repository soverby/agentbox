#!/usr/bin/env python3
"""P4 smoke test (PLAN §5 P4) against real Docker: secrets delivery, doctor 11
and 17, leak audit, recreate on secret change, token rotation.

Backend: the test-only `env` backend with a JSON store file
(AGENTBOX_TEST_SECRET_STORE) and secret_prefix agentbox-test-<rand>. The real
macOS keychain is not used: this session's permission policy refuses
`security` writes, so keychain automation is not available here (the keychain
backend is unit-tested with a fake `security` that records argv + stdin).

Runs the real CLI with AGENTBOX_CONFIG_HOME / AGENTBOX_STATE_HOME in a temp
dir. Every value is a unique random marker; the leak audit greps for each one.
Removes every container, network, volume, and file it created.

Usage: python3 tests/integration/p4_smoke.py
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TAG = secrets.token_hex(3)
NAME = f"it4-{TAG}"
PROJECT = f"agentbox-{NAME}"
PREFIX = f"agentbox-test-{TAG}"
RESULTS: list[tuple[str, str, str]] = []


def marker(label: str) -> str:
    return f"MARK{TAG}{label}{secrets.token_hex(12)}"


def rec(ok: bool | None, name: str, detail: str = "") -> bool:
    st = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    RESULTS.append((st, name, detail))
    print(f"{st} {name}" + (f": {detail}" if detail else ""), flush=True)
    return bool(ok)


def sh(args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


def sha(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


PROFILE = """
[box]
agents = ["claude"]

[[mount]]
host = "{proj}"
mode = "rw"
allow_dotpath = true

[[mount]]
host = "{dollar}"
allow_dotpath = true

[network]
mode = "strict"
presets = ["anthropic", "github"]

[secrets]
GH_TOKEN = "shared"
AGENT_TOK = {{}}
BOTH_TOK = {{ shared = true, to = ["agent", "mcp-gateway"] }}

[models.remote.m]
api_base = "https://example-modal.example.com/v1"
key = "ROUTER_TOK"

[mcp.servers.docs]
url = "https://mcp.example.com/mcp"
bearer = "GW_TOK"
"""


class Env:
    def __init__(self) -> None:
        self.roots = Path(tempfile.mkdtemp(prefix="agentbox-p4-"))
        self.vault = Path(tempfile.mkdtemp(prefix="agentbox-p4-store-"))  # outside state
        self.work = Path.home() / f".agentbox-it4-{TAG}"
        self.proj = self.work / "proj"
        self.proj.mkdir(parents=True)
        # a literal `${...}` in a host path must not interpolate a secret
        self.dollar = self.work / "d${AGENTBOX_SECRET_GH_TOKEN}"
        self.dollar.mkdir()
        cfg = self.roots / "config"
        (cfg / "profiles").mkdir(parents=True)
        (cfg / "config.toml").write_text(f'secret_backend = "env"\nsecret_prefix = "{PREFIX}"\n')
        (cfg / "profiles" / f"{NAME}.toml").write_text(
            PROFILE.format(proj=self.proj, dollar=self.dollar)
        )
        self.env = dict(
            os.environ,
            AGENTBOX_CONFIG_HOME=str(cfg),
            AGENTBOX_STATE_HOME=str(self.roots / "state"),
            AGENTBOX_TEST_SECRET_STORE=str(self.vault / "store.json"),
            PYTHONPATH=str(ROOT / "cli"),
        )
        self.env.pop("AGENTBOX_REPO", None)

    def ab(self, *args, input=None, timeout=1800, extra_env=None) -> subprocess.CompletedProcess:
        return sh(
            [sys.executable, "-m", "agentbox.cli", *args],
            env={**self.env, **(extra_env or {})},
            cwd=str(self.proj),
            timeout=timeout,
            input=input,
            stdin=None if input is not None else subprocess.DEVNULL,
        )

    @property
    def state(self) -> Path:
        return self.roots / "state" / NAME

    def compose(self, *args, env=None) -> subprocess.CompletedProcess:
        return sh(
            ["docker", "compose", "-p", PROJECT, "-f", str(self.state / "compose.json"), *args],
            env=env,
        )

    def session(self, secs: int) -> subprocess.Popen:
        """Background CLI session: `sleep <secs>; echo SURVIVED` in the box."""
        return subprocess.Popen(
            [sys.executable, "-m", "agentbox.cli", "shell", NAME, "--", "sh", "-c",
             f"sleep {secs}; echo SURVIVED"],
            env=self.env, cwd=str(self.proj), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, text=True,
        )  # fmt: skip

    def box(self, script: str) -> subprocess.CompletedProcess:
        """sh -c in the agent through with-secrets (like every CLI session)."""
        return self.ab("shell", NAME, "--", "sh", "-c", script, timeout=300)


def container_ids() -> dict[str, str]:
    out = sh(
        ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={PROJECT}",
         "--format", '{{.Label "com.docker.compose.service"}} {{.ID}}']
    ).stdout  # fmt: skip
    return dict(line.split() for line in out.splitlines() if line.strip())


def label(cid: str) -> str:
    return sh(
        ["docker", "inspect", "--format", '{{index .Config.Labels "agentbox.secrets"}}', cid]
    ).stdout.strip()


def wait_in_box(cid: str, needle: str) -> bool:
    for _ in range(90):
        if needle in sh(["docker", "top", cid, "-eo", "pid,args"]).stdout:
            return True
        time.sleep(1)
    return False


def up_with_ps(e: Env) -> tuple[subprocess.CompletedProcess, str]:
    """`agentbox up` while sampling `ps -axww` (argv of every host process)."""
    snaps: list[str] = []
    done = threading.Event()

    def sample():
        while not done.is_set():
            snaps.append(sh(["ps", "-axww"]).stdout)
            time.sleep(0.1)

    t = threading.Thread(target=sample)
    t.start()
    try:
        r = e.ab("up", NAME)
    finally:
        done.set()
        t.join()
    return r, "\n".join(snaps)


def audit(e: Env, markers: dict[str, str], ps_text: str, tag: str) -> None:
    """Grep every marker in all places the plan names. Prints names only."""
    hits: list[str] = []

    def scan(where: str, text: str | bytes) -> None:
        b = text.encode() if isinstance(text, str) else text
        for n, v in markers.items():
            if v.encode() in b:
                hits.append(f"{n} in {where}")

    for f in sorted(e.state.rglob("*")):
        if not f.is_file():
            continue
        data = f.read_bytes()
        if f.name == "box-tokens.json":  # holds box tokens by design (PLAN §2.4)
            for n, v in markers.items():
                if not n.startswith("MCP_GATEWAY_TOKEN(box") and v.encode() in data:
                    hits.append(f"{n} in state:{f.name}")
            continue
        scan(f"state:{f.relative_to(e.state)}", data)
    scan("compose.json", (e.state / "compose.json").read_bytes())
    ids = container_ids()
    imgs = set()
    for svc, cid in ids.items():
        info = sh(["docker", "inspect", cid]).stdout
        scan(f"docker inspect {svc}", info)
        d = json.loads(info)[0]
        for part in ("Env", "Labels"):
            scan(f"{svc} Config.{part}", json.dumps(d["Config"].get(part)))
        scan(f"{svc} Mounts", json.dumps(d.get("Mounts")))
        imgs.add(d["Config"]["Image"])
    scan("docker compose config", e.compose("config").stdout)
    # worst case: the same env the CLI gives `compose up`
    up_env = dict(os.environ, **{f"AGENTBOX_SECRET_{n}": v for n, v in markers.items()})
    scan("docker compose config (secret env set)", e.compose("config", env=up_env).stdout)
    scan("docker compose logs", e.compose("logs", "--no-color").stdout)
    for img in sorted(imgs):
        scan(f"docker history {img}", sh(["docker", "history", "--no-trunc", img]).stdout)
    scan("ps -axww during up", ps_text)
    rec(
        not hits,
        f"leak audit ({tag}): {len(markers)} markers; state, compose file, inspect x{len(ids)}, "
        f"compose config, logs, history x{len(imgs)}, ps",
        "; ".join(hits),
    )


def doctor(e: Env) -> dict[str, tuple[str, str]]:
    r = e.ab("doctor", NAME, timeout=1800)
    res = {}
    for line in r.stdout.splitlines():
        for st in ("PASS", "FAIL", "SKIP"):
            if line.startswith(st + " "):
                check, _, detail = line[len(st) + 1 :].partition(": ")
                res[check.strip()] = (st, detail)
    return res


def main() -> int:  # noqa: C901 (linear scenario)
    before_vols = set(sh(["docker", "volume", "ls", "-q"]).stdout.split())
    e = Env()
    print(f"== roots {e.roots}, store {e.vault}, work {e.work}", flush=True)
    vals = {
        "GH_TOKEN": marker("gh"),
        "AGENT_TOK": marker("agent"),
        "BOTH_TOK": marker("both"),
        "ROUTER_TOK": marker("router"),
        "GW_TOK": marker("gw"),
    }
    markers = dict(vals)
    try:
        # -- secret set: shared + profile scopes, values on stdin
        for n, scope in (("GH_TOKEN", "--shared"), ("BOTH_TOK", "--shared"),
                         ("AGENT_TOK", NAME), ("ROUTER_TOK", NAME), ("GW_TOK", NAME)):  # fmt: skip
            r = e.ab("secret", "set", scope, n, "--stdin", input=vals[n] + "\n")
            if r.returncode != 0:
                rec(False, f"secret set {n}", r.stderr.strip())
        store = json.loads((e.vault / "store.json").read_text())
        rec(
            set(store)
            == {
                f"{PREFIX}/_shared/GH_TOKEN".replace("/", "_").replace("-", "_").upper(),
                f"{PREFIX}/_shared/BOTH_TOK".replace("/", "_").replace("-", "_").upper(),
                *(
                    f"{PREFIX}/{NAME}/{n}".replace("/", "_").replace("-", "_").upper()
                    for n in ("AGENT_TOK", "ROUTER_TOK", "GW_TOK")
                ),
            },  # fmt: skip
            "secret set: shared and profile scopes stored under the test prefix",
            ", ".join(sorted(store)),
        )
        r = e.ab("secret", "set", NAME, "MCP_GATEWAY_TOKEN", "--stdin", input="x\n")
        rec(r.returncode == 1 and "reserved" in r.stderr, "secret set refuses a reserved name")

        # -- up
        t0 = time.time()
        r, ps_text = up_with_ps(e)
        rec(r.returncode == 0, "up", f"{time.time() - t0:.1f}s {r.stderr.strip()[-300:]}")
        rec(
            "CLAUDE_CODE_OAUTH_TOKEN is not set" in r.stderr and "agentbox setup" in r.stderr,
            "up without the Claude token works and prints the setup hint",
        )

        # -- what the agent sees (hashes only; values never on a command line)
        r = e.box("ls -A /run/secrets")
        names = sorted(r.stdout.split())
        rec(
            names == ["AGENT_TOK", "BOTH_TOK", "GH_TOKEN", "MCP_GATEWAY_TOKEN"],
            "agent /run/secrets = agent-targeted names only",
            " ".join(names),
        )
        r = e.box(
            "for n in GH_TOKEN AGENT_TOK BOTH_TOK MCP_GATEWAY_TOKEN; do "
            'printf "%s %s\\n" "$n" "$(printenv "$n" | tr -d "\\n" | sha256sum | cut -d" " -f1)"; '
            "done"
        )
        got = dict(line.split() for line in r.stdout.splitlines() if line.strip())
        tokens = json.loads((e.state / "box-tokens.json").read_text())
        want = {n: sha(vals[n]) for n in ("GH_TOKEN", "AGENT_TOK", "BOTH_TOK")}
        want["MCP_GATEWAY_TOKEN"] = sha(tokens["MCP_GATEWAY_TOKEN"])
        rec(got == want, "with-secrets exports the delivered values (sha256 compare)")
        r = e.box("env; cat /run/secrets/* 2>/dev/null")
        leaked = [n for n in ("ROUTER_TOK", "GW_TOK") if vals[n] in r.stdout or n in r.stdout]
        rec(not leaked, "router / mcp-gateway secrets absent from the agent", ",".join(leaked))
        r = e.box("git config --global --get-regexp '^credential\\.'")
        rec("gh auth git-credential" in r.stdout, "gh auth setup-git ran (GH_TOKEN targets agent)",
            r.stdout.strip()[-200:])  # fmt: skip
        mode = oct((e.state / "box-tokens.json").stat().st_mode & 0o777)
        kmode = oct((e.state / "secrets-hmac.key").stat().st_mode & 0o777)
        rec(mode == kmode == "0o600", "box tokens and HMAC key are 0600", f"{mode} {kmode}")
        markers["MCP_GATEWAY_TOKEN(box)"] = tokens["MCP_GATEWAY_TOKEN"]

        # -- doctor 11 (+ 17 env)
        res = doctor(e)
        rec(res.get("11", ("-",))[0] == "PASS", "doctor 11", res.get("11", ("-", "missing"))[1])
        others = {k: v for k, v in res.items() if v[0] == "FAIL"}
        rec(not others, "full doctor: no FAIL", json.dumps(others)[:400])
        rec(res.get("17 live", ("-",))[0] == "SKIP", "doctor 17 live SKIP without a token")

        # -- leak audit 1 (tokens are in state by design: audit test markers only)
        audit(e, markers, ps_text, "after up")

        # -- `$` in a mount path: literal in the container, no secret interpolated
        ids = container_ids()
        info = json.loads(sh(["docker", "inspect", ids["agent"]]).stdout)[0]
        srcs = [m.get("Source", "") for m in info["Mounts"]]
        rec(
            any(x.endswith("d${AGENTBOX_SECRET_GH_TOKEN}") for x in srcs)
            and vals["GH_TOKEN"] not in json.dumps(info),
            "`${AGENTBOX_SECRET_GH_TOKEN}` in a mount path stays literal (no value in inspect)",
            ", ".join(x for x in srcs if "agentbox-it4" in x),
        )

        # -- the agent cannot rewrite /run/secrets (root:agent 0440)
        r = e.box("stat -c '%n %u %g %a' /run/secrets/*")
        owners = {tuple(x.split()[1:]) for x in r.stdout.splitlines() if x.strip()}
        rec(owners == {("0", "0", "444")}, "/run/secrets files are root:root 0444",
            r.stdout.strip().replace("\n", " | "))  # fmt: skip
        r = e.box("chmod 600 /run/secrets/GH_TOKEN && echo x > /run/secrets/GH_TOKEN")
        r2 = e.box('printf %s "$GH_TOKEN" | sha256sum')
        rec(
            r.returncode != 0 and sha(vals["GH_TOKEN"]) in r2.stdout,
            "attack `chmod 600 && echo x >` /run/secrets/GH_TOKEN fails; next session has "
            "the real value",
            " ".join(r.stderr.split())[-160:],
        )

        # -- a secret change during a running session: no recreate, session survives
        ids0 = container_ids()
        bg = e.session(240)  # long enough for a full doctor during the deferral
        rec(wait_in_box(ids0["agent"], "sleep 240"), "background session started")
        vals["AGENT_TOK"] = markers["AGENT_TOK2"] = marker("agent2")
        e.ab("secret", "set", NAME, "AGENT_TOK", "--stdin", input=vals["AGENT_TOK"] + "\n")
        r, ps_d = up_with_ps(e)
        rec(
            r.returncode == 0
            and container_ids()["agent"] == ids0["agent"]
            and "secret change applies after sessions end" in r.stderr
            and bg.poll() is None,  # the session still runs
            "secret change while a session runs: agent kept, message printed",
            " ".join(r.stderr.split())[-200:],
        )
        res = doctor(e)
        d11 = res.get("11", ("-", "missing"))
        rec(
            d11[0] == "PASS" and "secret change deferred: sessions active" in d11[1]
            and bg.poll() is None,
            "doctor 11 during the deferral: PASS (deferred), ownership still checked",
            d11[1][:200],
        )  # fmt: skip
        out, _ = bg.communicate(timeout=400)
        rec("SURVIVED" in out, "the running session survived the secret change")
        ps_text += ps_d

        # -- after the session ended: the next up recreates only the agent
        ids1 = container_ids()
        lab1 = label(ids1["agent"])
        r, ps2 = up_with_ps(e)
        ids2 = container_ids()
        lab2 = label(ids2["agent"])
        rec(
            r.returncode == 0
            and ids1["agent"] != ids2["agent"]
            and ids1["egress"] == ids2["egress"]
            and ids1["ollama-gate"] == ids2["ollama-gate"]
            and lab1 != lab2
            and lab1
            and lab2,
            "secret change recreates only the agent container (label changed)",
            f"agent {ids1['agent']}->{ids2['agent']} egress {ids1['egress']}->{ids2['egress']}",
        )
        r = e.box('printf %s "$AGENT_TOK" | sha256sum')
        rec(sha(vals["AGENT_TOK"]) in r.stdout, "new value delivered after the change")
        r, _ = up_with_ps(e)
        rec(container_ids() == ids2, "re-up without a change recreates nothing")

        # -- secret ls: names, scope, status, targets; no values
        r = e.ab("secret", "ls", NAME)
        bad = [n for n, v in markers.items() if v in r.stdout + r.stderr]
        rows = {x.split()[0]: x.split() for x in r.stdout.splitlines()[1:] if x.strip()}
        rec(
            r.returncode == 0
            and not bad
            and rows.get("GW_TOK", [])[1:4] == ["profile", "present", "mcp-gateway"]
            and rows.get("GH_TOKEN", [])[1:4] == ["shared", "present", "agent"]
            and rows.get("CLAUDE_CODE_OAUTH_TOKEN", [])[2:3] == ["missing"],
            "secret ls: names/scope/status/targets, no values",
            r.stdout.strip().replace("\n", " | ")[:300],
        )
        r = e.ab("secret", "ls", "--shared")
        rec(r.returncode == 0 and not any(v in r.stdout for v in markers.values())
            and "BOTH_TOK" in r.stdout, "secret ls --shared, no values")  # fmt: skip

        # -- check 17 with an invalid Claude token, delivered through the backend
        bad_tok = f"sk-ant-oat01-invalid{TAG}{secrets.token_hex(20)}"
        markers["CLAUDE_INVALID"] = bad_tok
        r = e.ab("secret", "set", "--shared", "CLAUDE_CODE_OAUTH_TOKEN", "--stdin",
                 input=bad_tok + "\n")  # fmt: skip
        r, ps3 = up_with_ps(e)
        res = doctor(e)
        rec(res.get("17 env", ("-",))[0] == "PASS", "doctor 17 env: invalid env token -> API 401",
            res.get("17 env", ("-", "missing"))[1])  # fmt: skip
        live = res.get("17 live", ("-", ""))
        rec(
            live[0] == "FAIL" and "rejected" in live[1] and bad_tok not in live[1],
            "doctor 17 live: delivered invalid token reaches the API (rejected, not "
            "'Not logged in')",
            live[1][:200],
        )
        pf = e.work / "prompt.txt"
        pf.write_text("Reply with OK.\n")
        r = e.ab("run", NAME, "--agent", "claude", "--prompt-file", str(pf), timeout=600)
        runs = sorted((e.state / "runs").glob("*/transcript*"))
        tr = runs[-1].read_text(errors="replace") if runs else ""
        low = tr.lower()
        rec(
            r.returncode != 0
            and ("401" in low or "authentication" in low or "invalid" in low)
            and "not logged in" not in low,
            "headless `agentbox run` uses the delivered token (invalid -> auth error)",
            " ".join(tr.split())[-200:],
        )
        rec(bad_tok not in tr, "transcript does not hold the token")

        # -- leak audit 2 (after change, token, run)
        tok_now = json.loads((e.state / "box-tokens.json").read_text())["MCP_GATEWAY_TOKEN"]
        markers["MCP_GATEWAY_TOKEN(box)"] = tok_now
        audit(e, markers, ps_text + ps2 + ps3, "after change + run")

        # -- running session + removed secret + memory change: Compose must
        # recreate, so no deferral (a restored name would have no value); a
        # shell AGENTBOX_SECRET_* never fills the gap.
        ids_a = container_ids()
        bg = e.session(120)
        rec(wait_in_box(ids_a["agent"], "sleep 120"), "background session 2 started")
        e.ab("secret", "rm", NAME, "AGENT_TOK")
        pf_ = e.roots / "config" / "profiles" / f"{NAME}.toml"
        res_line = 'agents = ["claude"]\nresources = { cpus = 2, memory = "3g" }'
        pf_.write_text(pf_.read_text().replace('agents = ["claude"]', res_line))
        shell_val = marker("shell")
        markers["SHELL_INHERITED"] = shell_val
        r = e.ab("up", NAME, extra_env={"AGENTBOX_SECRET_AGENT_TOK": shell_val})
        ids_b = container_ids()
        rs = e.box("ls -A /run/secrets; env")
        rec(
            r.returncode == 0
            and ids_a["agent"] != ids_b["agent"]
            and "AGENT_TOK" not in rs.stdout.split()
            and shell_val not in rs.stdout,
            "removed secret + memory change during a session: recreated, no unset-variable "
            "error, shell AGENTBOX_SECRET_* ignored",
            " ".join((r.stderr + rs.stderr).split())[-240:],
        )
        bg.kill()
        bg.communicate(timeout=30)
        audit(e, markers, "", "after remove + recreate")

        # -- down rotates MCP_GATEWAY_TOKEN
        before = json.loads((e.state / "box-tokens.json").read_text())["MCP_GATEWAY_TOKEN"]
        r = e.ab("down", NAME)
        after = json.loads((e.state / "box-tokens.json").read_text())["MCP_GATEWAY_TOKEN"]
        rec(r.returncode == 0 and before != after, "down rotates MCP_GATEWAY_TOKEN")
        markers["MCP_GATEWAY_TOKEN(box, rotated)"] = after
        audit(e, markers, "", "after down (all tokens, incl. rotated)")
        r = e.ab("secret", "rm", "--shared", "GH_TOKEN")
        r2 = e.ab("secret", "rm", "--shared", "GH_TOKEN")
        rec(r.returncode == 0 and r2.returncode == 1, "secret rm (then: not found)")
    except Exception as ex:  # noqa: BLE001
        rec(False, "smoke harness", repr(ex))
    finally:
        cleanup(e, before_vols)
    return finish()


def cleanup(e: Env, before_vols: set[str]) -> None:
    f = e.state / "compose.json"
    if f.exists():
        sh(["docker", "compose", "-p", PROJECT, "-f", str(f), "down", "-v", "--remove-orphans",
            "--timeout", "2"])  # fmt: skip
    sh(["docker", "volume", "rm", "-f", f"{PROJECT}-home"])
    shutil.rmtree(e.work, ignore_errors=True)
    shutil.rmtree(e.roots, ignore_errors=True)
    shutil.rmtree(e.vault, ignore_errors=True)
    left = sh(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split()
    nets = sh(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split()
    vols = sh(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split()
    ours = [x for x in left + nets + vols if NAME in x]
    new_vols = sorted(set(sh(["docker", "volume", "ls", "-q"]).stdout.split()) - before_vols)
    rec(
        not ours and not new_vols and not any(p.exists() for p in (e.work, e.roots, e.vault)),
        "cleanup (containers, networks, volumes, dirs, secret store; no keychain items made)",
        f"leftovers {ours} {new_vols}",
    )


def finish() -> int:
    fails = [r for r in RESULTS if r[0] == "FAIL"]
    print(
        f"\nSUMMARY: {sum(r[0] == 'PASS' for r in RESULTS)} pass, {len(fails)} fail, "
        f"{sum(r[0] == 'SKIP' for r in RESULTS)} skip"
    )
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
