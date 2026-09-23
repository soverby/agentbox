#!/usr/bin/env python3
"""P5 smoke test (PLAN §5 P5) against real Docker: model routing.

(a) Host Ollama path: a fake Ollama (tests/isolation/fake_ollama.py) on host
    127.0.0.1:11434 answers one canned text on /v1/messages (Claude),
    /v1/responses (Codex), /v1/chat/completions (Pi), /api/chat (ollama CLI).
    `agentbox run --agent X --model ollama/<m>` must print it, through the
    real ollama-gate. With --live-ollama --live-model <m> the real host
    Ollama is used instead (no canned text: any answer, plus doctor 15/18).
(b) Router path: an HTTPS OpenAI-compatible stub (the same fake, TLS +
    bearer) at `stub.agentbox-test:443`. Reaching it through squid:
    squid denies private destination IPs, so the stub runs on a harness-only
    Docker network with a documentation-range subnet (203.0.113.0/24,
    TEST-NET-3, not in the always-denied list) that only the egress
    container joins (`docker network connect`). The squid config stays the
    production render (checked byte for byte). The router must trust the
    stub's test CA: the harness adds `litellm_settings.ssl_verify` to the
    router config and restarts the router once (test-only; the production
    render is diffed against the file first). `claude` and `codex` (and `pi`)
    with `--model remote/<name>` must print the stub's canned text.
Also: doctor 13 (router), 21 router-* (admin routes, api_base override,
health); leak audit (router master key and remote key never in host argv /
ps, logs, compose config, docker inspect, run records; the remote key never
in the agent).

Runs the real CLI with AGENTBOX_CONFIG_HOME / AGENTBOX_STATE_HOME in a temp
dir and the `env` secret backend (no keychain). Removes everything it made.

Usage: python3 tests/integration/p5_smoke.py [--live-ollama --live-model M]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TAG = secrets.token_hex(3)
NAME = f"it5-{TAG}"
PROJECT = f"agentbox-{NAME}"
PREFIX = f"agentbox-test-{TAG}"
TESTNET = f"agentbox-p5test-{TAG}"
TESTNET_SUBNET = "203.0.113.0/24"
STUB_IP = "203.0.113.10"
STUB_HOST = "stub.agentbox-test"
STUB_NAME = f"agentbox-p5stub-{TAG}"
FAKE = ROOT / "tests" / "isolation" / "fake_ollama.py"
MODEL = "llama3.2:latest"  # a local model of the fake's /api/tags
CANNED_OLLAMA = f"CANNED-OLLAMA-{TAG}-7431"
CANNED_REMOTE = f"CANNED-REMOTE-{TAG}-9152"
sys.path.insert(0, str(ROOT / "cli"))

RESULTS: list[tuple[str, str, str]] = []

PROFILE = """
[box]
agents = ["claude", "codex", "pi"]

[[mount]]
host = "{proj}"
mode = "rw"
allow_dotpath = true

[network]
mode = "strict"
presets = ["anthropic", "openai", "github"]

[secrets]
STUB_KEY = {{}}

[models]
ollama = "local"

[models.remote.stubv]
api_base = "https://{stub}/v1"
key = "STUB_KEY"
model = "upstream/vllm-model"
provider = "vllm"

[models.remote.stubo]
api_base = "https://{stub}/v1"
key = "STUB_KEY"
model = "upstream-openai-model"
"""


def marker(label: str) -> str:
    return f"MARK{TAG}{label}{secrets.token_hex(12)}"


def rec(ok: bool | None, name: str, detail: str = "") -> bool:
    st = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    RESULTS.append((st, name, detail))
    print(f"{st} {name}" + (f": {detail}" if detail else ""), flush=True)
    return bool(ok)


def sh(args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


def port_free(port: int) -> bool:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


class Env:
    def __init__(self, live: bool) -> None:
        self.live = live
        self.roots = Path(tempfile.mkdtemp(prefix="agentbox-p5-"))
        self.vault = Path(tempfile.mkdtemp(prefix="agentbox-p5-store-"))
        self.work = Path.home() / f".agentbox-it5-{TAG}"
        self.proj = self.work / "proj"
        self.proj.mkdir(parents=True)
        self.certs = self.roots / "certs"
        self.logs = self.roots / "logs"
        self.logs.mkdir()
        cfg = self.roots / "config"
        (cfg / "profiles").mkdir(parents=True)
        (cfg / "config.toml").write_text(f'secret_backend = "env"\nsecret_prefix = "{PREFIX}"\n')
        (cfg / "profiles" / f"{NAME}.toml").write_text(
            PROFILE.format(proj=self.proj, stub=STUB_HOST)
        )
        self.env = dict(
            os.environ,
            AGENTBOX_CONFIG_HOME=str(cfg),
            AGENTBOX_STATE_HOME=str(self.roots / "state"),
            AGENTBOX_TEST_SECRET_STORE=str(self.vault / "store.json"),
            PYTHONPATH=str(ROOT / "cli"),
        )
        self.env.pop("AGENTBOX_REPO", None)
        self.procs: list[subprocess.Popen] = []
        self.ps_samples: list[str] = []
        self.sampling = False

    def ab(self, *args, input=None, timeout=1800) -> subprocess.CompletedProcess:
        return sh(
            [sys.executable, "-m", "agentbox.cli", *args],
            env=self.env, cwd=str(self.proj), timeout=timeout, input=input,
            stdin=None if input is not None else subprocess.DEVNULL,
        )  # fmt: skip

    @property
    def state(self) -> Path:
        return self.roots / "state" / NAME

    def compose(self, *args) -> subprocess.CompletedProcess:
        return sh(["docker", "compose", "-p", PROJECT, "-f", str(self.state / "compose.json"),
                   *args])  # fmt: skip

    def box(self, script: str, input=None) -> subprocess.CompletedProcess:
        return self.ab("shell", NAME, "--", "sh", "-c", script, input=input, timeout=600)

    def run(self, agent: str, model: str, prompt: str) -> tuple[int, str, str]:
        pf = self.roots / f"prompt-{agent}.txt"
        pf.write_text(prompt + "\n")
        r = self.ab("run", NAME, "--agent", agent, "--model", model, "--prompt-file", str(pf),
                    timeout=900)  # fmt: skip
        line = next((x for x in r.stdout.splitlines() if x.startswith("run: ")), "")
        rd = Path(line[5:].rsplit(" (exit", 1)[0]) if line else None
        text = (rd / "transcript.log").read_text() if rd and rd.is_dir() else ""
        return r.returncode, text, r.stderr

    # --- host + box process sampler (argv leak audit) ---
    def start_sampler(self) -> None:
        self.sampling = True

        def loop():
            while self.sampling:
                out = sh(["ps", "-axww", "-o", "args"]).stdout
                ids = container_ids()
                for cid in ids.values():
                    out += sh(["docker", "top", cid, "-eo", "args"]).stdout
                self.ps_samples.append(out)
                time.sleep(0.3)

        self.sampler = threading.Thread(target=loop, daemon=True)
        self.sampler.start()

    def stop_sampler(self) -> None:
        self.sampling = False
        if getattr(self, "sampler", None):
            self.sampler.join(timeout=10)


def container_ids() -> dict[str, str]:
    out = sh(
        ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={PROJECT}",
         "--format", '{{.Label "com.docker.compose.service"}} {{.ID}}']
    ).stdout  # fmt: skip
    return dict(line.split() for line in out.splitlines() if line.strip())


def make_certs(d: Path) -> None:
    d.mkdir()
    o = ["openssl"]
    sh([*o, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj",
        "/CN=agentbox-p5-test-ca", "-keyout", str(d / "ca.key"), "-out", str(d / "ca.pem"),
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext",
        "keyUsage=critical,keyCertSign,cRLSign"], check=True)  # fmt: skip
    sh([*o, "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={STUB_HOST}",
        "-keyout", str(d / "server.key"), "-out", str(d / "server.csr")], check=True)  # fmt: skip
    (d / "ext.cnf").write_text(
        f"subjectAltName=DNS:{STUB_HOST}\nbasicConstraints=CA:FALSE\n"
        "extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n"
    )
    sh([*o, "x509", "-req", "-in", str(d / "server.csr"), "-CA", str(d / "ca.pem"),
        "-CAkey", str(d / "ca.key"), "-CAcreateserial", "-days", "2",
        "-extfile", str(d / "ext.cnf"), "-out", str(d / "server.pem")], check=True)  # fmt: skip
    for f in d.iterdir():
        os.chmod(f, 0o644)


def fake_log(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text().splitlines():
        with contextlib.suppress(ValueError):
            out.append(json.loads(line))
    return out


def start_fake_ollama(e: Env) -> None:
    p = subprocess.Popen(
        [sys.executable, str(FAKE), "--host", "127.0.0.1", "--port", "11434",
         "--canned", CANNED_OLLAMA, "--log", str(e.logs / "fake-ollama.jsonl")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
    )  # fmt: skip
    e.procs.append(p)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", 11434), timeout=1).close()
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("fake ollama did not start")


def start_stub(e: Env, stub_key: str, image: str) -> None:
    """The key goes in a file (not argv): the leak audit samples host `ps`."""
    kf = e.certs / "stub-key"
    kf.write_text(stub_key)
    os.chmod(kf, 0o644)
    ipam = sh(["docker", "network", "create", "--subnet", TESTNET_SUBNET, TESTNET])
    if ipam.returncode != 0:
        raise RuntimeError(f"test network: {ipam.stderr.strip()}")
    r = sh(["docker", "run", "-d", "--name", STUB_NAME, "--network", TESTNET, "--ip", STUB_IP,
            "--network-alias", STUB_HOST, "--user", "0", "--entrypoint", "python3",
            "-v", f"{FAKE}:/fake.py:ro", "-v", f"{e.certs}:/c:ro", "-v", f"{e.logs}:/logs",
            image, "-u", "/fake.py", "--port", "443", "--tls", "/c/server.pem", "/c/server.key",
            "--bearer-file", "/c/stub-key", "--canned", CANNED_REMOTE,
            "--log", "/logs/stub.jsonl"])  # fmt: skip
    if r.returncode != 0:
        raise RuntimeError(f"stub: {r.stderr.strip()}")


def connect_egress(e: Env) -> None:
    cid = container_ids()["egress"]
    r = sh(["docker", "network", "connect", TESTNET, cid])
    if r.returncode != 0 and "already exists" not in r.stderr:
        raise RuntimeError(f"connect egress: {r.stderr.strip()}")


def trust_stub_ca(e: Env) -> None:
    """Test-only: the router trusts the stub's CA (ssl_verify), then restarts."""
    d = e.state / "router"
    shutil.copy(e.certs / "ca.pem", d / "p5-test-ca.pem")
    os.chmod(d / "p5-test-ca.pem", 0o644)
    cfg = json.loads((d / "config.yaml").read_text())
    cfg["litellm_settings"]["ssl_verify"] = "/etc/router/p5-test-ca.pem"
    (d / "config.yaml").write_text(json.dumps(cfg, indent=1))
    e.compose("restart", "router")
    for _ in range(180):
        cid = container_ids().get("router", "")
        st = sh(["docker", "inspect", "--format", "{{.State.Health.Status}}", cid]).stdout.strip()
        if st == "healthy":
            return
        time.sleep(1)
    raise RuntimeError("router not healthy after the test restart")


def router_probe(e: Env, script: str) -> str:
    return sh(["docker", "compose", "-p", PROJECT, "-f", str(e.state / "compose.json"), "exec",
               "-T", "router", "python3", "-c", script]).stdout.strip()  # fmt: skip


CONNECT_PY = r"""
import http.client, sys
out = []
for hp in sys.argv[1:]:
    c = http.client.HTTPConnection("egress", 3128, timeout=15)
    try:
        c.request("CONNECT", hp, headers={"Host": hp})
        out.append(f"{hp}={c.getresponse().status}")
    except OSError as ex:
        out.append(f"{hp}=error")
    finally:
        c.close()
print(" ".join(out))
"""


def doctor(e: Env) -> dict[str, tuple[str, str]]:
    r = e.ab("doctor", NAME, timeout=1800)
    res = {}
    for line in r.stdout.splitlines():
        for st in ("PASS", "FAIL", "SKIP", "WARN"):
            if line.startswith(st + " "):
                check, _, detail = line[len(st) + 1 :].partition(": ")
                res[check.strip()] = (st, detail)
    return res


def audit(e: Env, markers: dict[str, str], agent_forbidden: dict[str, str], tag: str) -> None:
    """markers: never in host/box argv, logs, compose config, inspect, state
    (except the router master key in box-tokens.json, 0600 by design).
    agent_forbidden: never anywhere in the agent (env, /run/secrets, home)."""
    hits: list[str] = []

    def scan(where: str, data: str | bytes, names=markers) -> None:
        b = data.encode() if isinstance(data, str) else data
        hits.extend(f"{n} in {where}" for n, v in names.items() if v and v.encode() in b)

    for f in sorted(e.state.rglob("*")):
        if f.is_file():
            names = {k: v for k, v in markers.items()
                     if not (f.name == "box-tokens.json" and k.startswith("router"))}  # fmt: skip
            scan(f"state:{f.relative_to(e.state)}", f.read_bytes(), names)
    for svc, cid in container_ids().items():
        scan(f"docker inspect {svc}", sh(["docker", "inspect", cid]).stdout)
    scan("docker compose config", e.compose("config").stdout)
    scan("docker compose logs", e.compose("logs", "--no-color").stdout)
    scan("host/box ps samples", "\n".join(e.ps_samples))
    scan("gate log", "".join(p.read_text() for p in (e.state / "logs").rglob("*.log")))
    r = e.box("env; cat /run/secrets/* 2>/dev/null; ps -eww -o args")
    scan("agent env + /run/secrets + ps", r.stdout, agent_forbidden)
    r = e.box("grep -rl -F -f - ~ 2>/dev/null || true",
              input="\n".join(v for v in agent_forbidden.values() if v) + "\n")  # fmt: skip
    if r.stdout.strip():
        hits.append(f"forbidden values in agent home files: {' '.join(r.stdout.split())[:200]}")
    rec(not hits, f"leak audit ({tag})", "; ".join(hits))


def main() -> int:  # noqa: C901 (linear scenario)
    ap = argparse.ArgumentParser()
    ap.add_argument("--live-ollama", action="store_true", help="use the real host Ollama")
    ap.add_argument("--live-model", help="host Ollama model for --live-ollama")
    a = ap.parse_args()
    if a.live_ollama and not a.live_model:
        ap.error("--live-ollama needs --live-model")
    model = a.live_model if a.live_ollama else MODEL
    before_vols = set(sh(["docker", "volume", "ls", "-q"]).stdout.split())
    e = Env(a.live_ollama)
    print(f"== roots {e.roots}, work {e.work}, name {NAME}", flush=True)
    stub_key = marker("stubkey")
    oauth = marker("oauth")
    try:
        from agentbox import box as boxmod
        from agentbox import images, router

        if not a.live_ollama:
            if not rec(port_free(11434), "host port 11434 free for the fake Ollama",
                       "a host Ollama listens: stop it or use --live-ollama"):  # fmt: skip
                return finish()
            start_fake_ollama(e)
        make_certs(e.certs)
        for n, v in (("STUB_KEY", stub_key),):
            r = e.ab("secret", "set", NAME, n, "--stdin", input=v + "\n")
            rec(r.returncode == 0, f"secret set {n}", r.stderr.strip())
        r = e.ab("secret", "set", "--shared", "CLAUDE_CODE_OAUTH_TOKEN", "--stdin",
                 input=oauth + "\n")  # fmt: skip
        rec(r.returncode == 0, "secret set --shared CLAUDE_CODE_OAUTH_TOKEN (marker)")

        t0 = time.time()
        r = e.ab("up", NAME)
        rec(r.returncode == 0, "up (router included)",
            f"{time.time() - t0:.1f}s " + " ".join(r.stderr.split())[-400:])  # fmt: skip
        ids = container_ids()
        rec("router" in ids, "router container runs", ", ".join(sorted(ids)))
        doc = json.loads((e.state / "compose.json").read_text())
        rs = doc["services"]["router"]
        ok = list(rs["networks"]) == ["internal"]
        ip_ok = rs["networks"]["internal"]["ipv4_address"].endswith(".11")
        env_ok = rs["environment"]["NO_PROXY"] == "localhost,127.0.0.1" and rs["environment"][
            "HTTPS_PROXY"].startswith("http://egress:")  # fmt: skip
        hard = rs["cap_drop"] == ["ALL"] and rs["security_opt"] == ["no-new-privileges:true"]
        user = sh(["docker", "inspect", "--format", "{{.Config.User}}", ids["router"]]).stdout
        rec(
            ok
            and ip_ok
            and env_ok
            and hard
            and "mem_limit" in rs
            and "pids_limit" in rs
            and user.strip() == "10003:10003"
            and "read_only" not in rs,
            "router service: internal only, .11, NO_PROXY localhost only, cap_drop ALL, "
            "no-new-privileges, limits, uid 10003 (owns no image file)",
            json.dumps({k: rs.get(k) for k in ("networks", "user")}) + f" user={user.strip()}",
        )
        # -- production renders are what runs (before any test-only step)
        os.environ.update({k: e.env[k] for k in ("AGENTBOX_CONFIG_HOME", "AGENTBOX_STATE_HOME")})
        b = boxmod.load(NAME)
        ctx = boxmod.ctx_for(b, b.subnet_index())
        prod_squid = boxmod.render_egress(b, ctx)
        on_disk = boxmod.read_conf(ctx.conf_dir)
        rec(on_disk == prod_squid, "squid config on disk == production render (no test override)")
        prod_router = router.config_text(b.profile)
        cfgf = e.state / "router" / "config.yaml"
        rec(cfgf.read_text() == prod_router, "router config on disk == production render")
        rcfg = json.loads(prod_router)
        rec(rcfg["general_settings"]["allowed_routes"] == router.ALLOWED_ROUTES
            and rcfg["general_settings"]["store_model_in_db"] is False
            and "database_url" not in json.dumps(rcfg).lower(),
            "router config: exact allowed_routes, no DB, store_model_in_db off")  # fmt: skip
        allow = (ctx.conf_dir / "router.allow").read_text().split()
        rec(allow == [STUB_HOST], "router egress allowlist = api_base host names", str(allow))

        # (a) host Ollama through ollama-gate
        e.start_sampler()
        want = None if a.live_ollama else CANNED_OLLAMA
        for agent in ("claude", "codex", "pi"):
            rc, text, err = e.run(agent, f"ollama/{model}", "Reply with the canned answer.")
            ok = rc == 0 and (want in text if want else bool(text.strip()))
            rec(
                ok,
                f"(a) run --agent {agent} --model ollama/{model} answers via ollama-gate",
                f"exit {rc}; " + " ".join(text.split())[-300:] + " " + err.strip()[-200:],
            )
        if not a.live_ollama:
            log = fake_log(e.logs / "fake-ollama.jsonl")
            paths = [x["path"].split("?")[0] for x in log if x["method"] == "POST"]
            rec({"/v1/messages", "/v1/responses", "/v1/chat/completions"} <= set(paths),
                "(a) fake Ollama saw /v1/messages, /v1/responses, /v1/chat/completions",
                str(sorted(set(paths))))  # fmt: skip
            auths = {x["headers"].get("Authorization") or x["headers"].get("authorization")
                     for x in log if x["path"].startswith("/v1/messages")}  # fmt: skip
            rec(
                not any(oauth in (h or "") for x in log for h in x["headers"].values()),
                "(a) the Claude subscription token never reaches ollama-gate / Ollama",
                f"Authorization on /v1/messages: {sorted(map(str, auths))}",
            )
        r = e.box("ollama list")
        rec(model.split(":")[0] in r.stdout and "gpt-oss" not in r.stdout,
            "(a) `ollama list` shows host models (allowed ones only)",
            " ".join((r.stdout + r.stderr).split())[:200])  # fmt: skip
        r = e.box(f"ollama show {model}")
        rec(r.returncode == 0, "(a) `ollama show` works through the gate",
            " ".join((r.stdout + r.stderr).split())[:200])  # fmt: skip
        if not a.live_ollama:
            r = e.box(f"ollama run {MODEL} hello")
            rec(CANNED_OLLAMA in r.stdout, "(a) `ollama run` answers",
                (r.stdout + r.stderr).strip()[-200:])  # fmt: skip

        # (b) router: stub upstream through squid
        gate_img = images.sidecar_tag(ROOT, "ollama-gate")
        start_stub(e, stub_key, gate_img)
        out = router_probe(e, CONNECT_PY.replace("sys.argv[1:]", f"['{STUB_HOST}:443']"))
        rec(
            out == f"{STUB_HOST}:443=403" or "error" in out or "=503" in out or "=502" in out,
            "(b) control: before the harness network, the router cannot reach the stub",
            out,
        )
        connect_egress(e)
        # squid caches the failed lookup of the control (negative_dns_ttl):
        # retry until the stub answers, then check the full set.
        probe_stub = CONNECT_PY.replace("sys.argv[1:]", f"['{STUB_HOST}:443']")
        for _ in range(60):
            if router_probe(e, probe_stub) == f"{STUB_HOST}:443=200":
                break
            time.sleep(2)
        out = router_probe(e, CONNECT_PY.replace(
            "sys.argv[1:]", f"['{STUB_HOST}:443', 'example.com:443', 'github.com:443', "
            f"'{STUB_IP}:443', '1.1.1.1:443', 'host.docker.internal:11434']"))  # fmt: skip
        want_c = (
            f"{STUB_HOST}:443=200 example.com:443=403 github.com:443=403 "
            f"{STUB_IP}:443=403 1.1.1.1:443=403 host.docker.internal:11434=403"
        )
        rec(out == want_c, "(b) router via proxy: only its allowlist (stub 200, others 403)", out)
        r = e.box(f"curl -s -o /dev/null -w '%{{http_code}}' -m 10 https://{STUB_HOST}/v1/models")
        rec(r.stdout.strip() in ("000", "403"),
            "(b) the agent cannot reach the remote upstream through its own proxy ACL",
            r.stdout.strip())  # fmt: skip
        trust_stub_ca(e)
        for agent, rm in (("claude", "stubv"), ("codex", "stubv"), ("claude", "stubo"),
                          ("codex", "stubo"), ("pi", "stubv")):  # fmt: skip
            rc, text, err = e.run(agent, f"remote/{rm}", "Reply with the canned answer.")
            rec(
                rc == 0 and CANNED_REMOTE in text,
                f"(b) run --agent {agent} --model remote/{rm} answers via the router",
                f"exit {rc}; " + " ".join(text.split())[-300:] + " " + err.strip()[-200:],
            )
        slog = fake_log(e.logs / "stub.jsonl")
        models = sorted({json.loads(x["body"]).get("model") for x in slog if x["body"]})
        bearer_ok = all(x["headers"].get("Authorization") == f"Bearer {stub_key}"
                        for x in slog if x["method"] == "POST")  # fmt: skip
        rec(slog and bearer_ok and models == ["upstream-openai-model", "upstream/vllm-model"],
            "(b) stub saw chat completions with the remote key and the upstream model ids",
            f"{len(slog)} requests; models {models}")  # fmt: skip
        rec(all(x["path"] == "/v1/chat/completions" for x in slog if x["method"] == "POST"),
            "(b) Responses and Messages reach the upstream as chat completions (bridge)",
            str(sorted({x['path'] for x in slog})))  # fmt: skip
        e.stop_sampler()
        # what the real clients send beyond the allowed union (names only)
        logs = e.compose("logs", "--no-color", "router").stdout
        dropped = sorted({x.split("dropped fields: ", 1)[1].strip()
                          for x in logs.splitlines() if "dropped fields: " in x})  # fmt: skip
        rec(
            True,
            "(b) guard: fields dropped from real client requests (names)",
            "; ".join(dropped) or "none",
        )  # fmt: skip: 13 (router), 21 router-*
        res = doctor(e)
        for c in ("13 (router)", "13 (mcp-gateway)", "21 router-health", "21 router-routes",
                  "21 router-api-base", "21 router-headers", "21 router-fs",
                  "21 router-residual", "11"):  # fmt: skip
            st, detail = res.get(c, ("MISSING", ""))
            rec(st == "PASS", f"doctor {c}", detail[:300])
        if a.live_ollama:
            for c in ("15", "18"):
                st, detail = res.get(c, ("MISSING", ""))
                rec(st == "PASS", f"doctor {c} (live host Ollama)", detail[:300])
        rk = json.loads((e.state / "box-tokens.json").read_text())["AGENTBOX_ROUTER_MASTER_KEY"]
        slog = fake_log(e.logs / "stub.jsonl")
        leaked = [x for x in slog
                  if any(k.lower() == "x-probe" for k in x["headers"])
                  or x["headers"].get("Host", STUB_HOST) != STUB_HOST
                  or (x["method"] == "POST"
                      and x["headers"].get("Authorization") != f"Bearer {stub_key}")]  # fmt: skip
        rec(slog and not leaked,
            "(b) stub never saw injected headers / keys (after doctor 21 router-headers)",
            f"{len(slog)} requests; bad {[x['headers'] for x in leaked][:2]}")  # fmt: skip
        audit(e, {"router master key": rk, "remote key": stub_key},
              {"remote key": stub_key}, "running box")  # fmt: skip
        r = e.ab("down", NAME)
        rec(r.returncode == 0, "down")
        rk2 = json.loads((e.state / "box-tokens.json").read_text())["AGENTBOX_ROUTER_MASTER_KEY"]
        rec(rk2 != rk and rk2.startswith("sk-"), "router master key rotated at down")
    except Exception as ex:  # noqa: BLE001
        rec(False, "smoke harness", repr(ex))
    finally:
        e.stop_sampler()
        cleanup(e, before_vols)
    return finish()


def cleanup(e: Env, before_vols: set[str]) -> None:
    for p in e.procs:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
    sh(["docker", "rm", "-f", STUB_NAME])
    f = e.state / "compose.json"
    if f.exists():
        sh(["docker", "compose", "-p", PROJECT, "-f", str(f), "down", "-v", "--remove-orphans",
            "--timeout", "2"])  # fmt: skip
    sh(["docker", "network", "rm", TESTNET])
    sh(["docker", "volume", "rm", "-f", f"{PROJECT}-home"])
    shutil.rmtree(e.work, ignore_errors=True)
    shutil.rmtree(e.roots, ignore_errors=True)
    shutil.rmtree(e.vault, ignore_errors=True)
    left = sh(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split()
    nets = sh(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split()
    vols = sh(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split()
    ours = [x for x in left + nets + vols if NAME in x or TAG in x]
    new_vols = sorted(set(sh(["docker", "volume", "ls", "-q"]).stdout.split()) - before_vols)
    alive = [p.pid for p in e.procs if p.poll() is None]
    rec(
        not ours and not new_vols and not alive and port_free(11434)
        and not any(p.exists() for p in (e.work, e.roots, e.vault)),
        "cleanup (containers, networks, volumes, dirs, fake processes)",
        f"leftovers {ours} {new_vols} {alive}",
    )  # fmt: skip


def finish() -> int:
    fails = [r for r in RESULTS if r[0] == "FAIL"]
    print(
        f"\nSUMMARY: {sum(r[0] == 'PASS' for r in RESULTS)} pass, {len(fails)} fail, "
        f"{sum(r[0] == 'SKIP' for r in RESULTS)} skip"
    )
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
