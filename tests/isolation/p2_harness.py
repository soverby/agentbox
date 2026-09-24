#!/usr/bin/env python3
"""P2 isolation harness (PLAN §5 P2): egress, networks, subnets, ollama-gate.

Renders a Compose project with the real P2 modules (egress.py, network.py,
presets.py) into a temp state dir, brings it up, runs the in-box checks
(doctor_checks.sh) plus harness-only checks, and always tears everything down.

Usage: python3 tests/isolation/p2_harness.py [--mode strict|open|both]
                                             [--live-ollama --live-model NAME]
Stdlib only. Needs docker + compose on the host.

Linux hosts (PLAN §6): egress and ollama-gate get
`extra_hosts: host.docker.internal:host-gateway`, which is the docker0 bridge
gateway (usually 172.17.0.1). A host service bound to 127.0.0.1 is NOT
reachable there. The harness binds its stub host MCP server to that gateway
IP on Linux. Host Ollama must listen there too: `OLLAMA_HOST=172.17.0.1:11434`
(or `0.0.0.0:11434` behind a host firewall). On macOS, Docker Desktop reaches
127.0.0.1-bound host services, so the stub binds 127.0.0.1.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "cli"))

from agentbox import egress, network, presets  # noqa: E402

HERE = Path(__file__).resolve().parent
UBUNTU = "ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"
PYTHON = "python:3.13-slim@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0"
IMG = {
    "egress": "agentbox/egress:p2test",
    "gate": "agentbox/ollama-gate:p2test",
    "stub": "agentbox/p2-stub:test",
    "fake": "agentbox/p2-fake-ollama:test",
}
STUB_DOCKERFILE = f"""\
FROM {UBUNTU}
RUN apt-get update && apt-get install -y --no-install-recommends \\
    curl ca-certificates jq bind9-dnsutils \\
 && rm -rf /var/lib/apt/lists/* && userdel -r ubuntu && useradd -u 1000 -m agent
"""
FAKE_DOCKERFILE = f"""\
FROM {PYTHON}
COPY fake_ollama.py /
CMD ["python3", "-u", "/fake_ollama.py"]
"""
AGENT_ALLOW_EXTRA = ["example.com", "one.one.one.one"]  # PTR name of 1.1.1.1 (check 5)
PTR_IP, PTR_NAME = "1.1.1.1", "one.one.one.one"
LIST_GATE_IP_HOST = 14
# Harness-only IPv6 test names, served to squid by a `hosts_file` (Docker
# Desktop DNS returns no AAAA). Every address must be denied by private_dst.
V6_HOSTS = {
    "unspec": "::",
    "loop": "::1",
    "compat": "::8.8.8.8",
    "mapped": "::ffff:10.1.2.3",
    "discard": "100::1",
    "teredo": "2001::1",
    "doc": "2001:db8::1",
    "nat64local": "64:ff9b:1::1",
    "ula": "fd00::1",
    "linklocal": "fe80::1",
    "sitelocal": "fec0::1",
    "mcast": "ff02::1",
    "sixtofour": "2002:a01:203::1",
}
V6_ZONE = ".v6.agentbox-test"
V6_NAMES = " ".join(n + V6_ZONE for n in V6_HOSTS)
TEST_HOSTS = "127.0.0.1 localhost\n::1 localhost\n" + "".join(
    f"{a} {n}{V6_ZONE}\n" for n, a in V6_HOSTS.items()
)
LIST_GATE_MODELS = ["llama3.2:latest", "sneaky:latest"]
EGRESS_UID, GATE_UID = 13, 10001
LIMITS = {"mem_limit": "256m", "pids_limit": 128}
ROUTER_ALLOW = ["example.org"]
GATEWAY_ALLOW = ["example.net"]
RELOAD_DOMAIN = "www.wikipedia.org"
FAKE_MODEL = "llama3.2:latest"
MARKER = "agentbox-body-marker-7f3a"

RESULTS: list[tuple[str, str, str]] = []  # (run, line, status)


def sh(args, check=True, input=None, env=None, timeout=600) -> subprocess.CompletedProcess:
    r = subprocess.run(args, input=input, capture_output=True, text=True, env=env, timeout=timeout)
    if check and r.returncode != 0:
        cmd = " ".join(map(str, args))
        raise RuntimeError(f"{cmd} failed ({r.returncode}):\n{r.stdout}\n{r.stderr}")
    return r


def build_images() -> None:
    sh(["docker", "build", "-q", "-t", IMG["egress"], str(ROOT / "images/egress")])
    sh(["docker", "build", "-q", "-t", IMG["gate"], str(ROOT / "images/ollama-gate")])
    with tempfile.TemporaryDirectory() as d:
        Path(d, "Dockerfile").write_text(STUB_DOCKERFILE)
        sh(["docker", "build", "-q", "-t", IMG["stub"], d])
    with tempfile.TemporaryDirectory() as d:
        Path(d, "Dockerfile").write_text(FAKE_DOCKERFILE)
        shutil.copy(HERE / "fake_ollama.py", d)
        sh(["docker", "build", "-q", "-t", IMG["fake"], d])


def docker_subnets() -> list[tuple[str, str]]:
    """(compose project label, subnet) for every IPAM subnet Docker uses."""
    ids = sh(["docker", "network", "ls", "-q"]).stdout.split()
    out = sh(
        [
            "docker",
            "network",
            "inspect",
            *ids,
            "--format",
            '{{index .Labels "com.docker.compose.project"}}|'
            "{{range .IPAM.Config}}{{.Subnet}} {{end}}",
        ]
    ).stdout
    return [
        (proj, cidr)
        for proj, _, nets in (line.partition("|") for line in out.splitlines())
        for cidr in nets.split()
    ]


class McpStub(BaseHTTPRequestHandler):
    """Fake host MCP server (plain HTTP) on the host loopback."""

    def do_GET(self):
        data = b"host-mcp-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def host_bind_ip() -> str:
    """Address a host service must bind so host.docker.internal reaches it."""
    if sys.platform.startswith("linux"):
        return sh(
            [
                "docker",
                "network",
                "inspect",
                "bridge",
                "--format",
                "{{(index .IPAM.Config 0).Gateway}}",
            ]
        ).stdout.strip()
    return "127.0.0.1"


def free_port(ip: str) -> int:
    with socket.socket() as s:
        s.bind((ip, 0))
        return s.getsockname()[1]


def svc(image, ip, **kw):
    d = {"image": image, "networks": {"internal": {"ipv4_address": ip}}}
    d.update(kw)
    return d


SIDECAR_HARDEN = {
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "read_only": True,
    **LIMITS,
}
HARDEN = {
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "init": True,
    "user": "1000:1000",
    "command": ["sleep", "infinity"],
}


def proxy_env(no_proxy: str) -> dict:
    p = f"http://egress:{egress.PORT}"
    return {
        "HTTPS_PROXY": p,
        "HTTP_PROXY": p,
        "https_proxy": p,
        "http_proxy": p,
        "NO_PROXY": no_proxy,
        "no_proxy": no_proxy,
    }


class Box:
    def __init__(self, mode: str, state_root: Path, live: bool, mcp_port: int, base: str):
        self.mode = mode
        self.live = live
        self.base = base
        self.tag = uuid.uuid4().hex[:6]
        self.profile = f"p2t-{mode}-{self.tag}"
        self.other = f"p2t-other-{self.tag}"
        self.project = f"agentbox-{self.profile}"
        self.other_project = f"agentbox-{self.other}"
        self.state_root = state_root
        self.state = state_root / self.profile
        self.conf = self.state / "egress"
        self.logs = self.state / "logs"
        self.egress_logs = self.logs / "egress"
        self.gate_logs = self.logs / "gate"
        self.mcp_port = mcp_port
        in_use = docker_subnets()
        self.n = network.allocate(state_root, self.profile, in_use, base)
        self.n_other = network.allocate(state_root, self.other, in_use, base)
        self.list_gate_ip = str(
            network.subnet_for(self.n, base).network_address + LIST_GATE_IP_HOST
        )
        self.ips = network.fixed_ips(self.n, base)
        self.other_ips = network.fixed_ips(self.n_other, base)

    # -- render
    def agent_domains(self, extra=()) -> list[str]:
        return presets.agent_allowlist(
            ["anthropic", "openai", "github", "dev"], AGENT_ALLOW_EXTRA + list(extra)
        )

    def render_egress(self, extra=()) -> None:
        files = egress.render(
            self.mode,
            [
                egress.Client("agent", self.ips["agent"], self.agent_domains(extra)),
                egress.Client("router", self.ips["router"], ROUTER_ALLOW),
                egress.Client("mcp-gateway", self.ips["mcp-gateway"], GATEWAY_ALLOW),
            ],
            allow_http=False,
            host_mcp_ports=[self.mcp_port],
        )
        # Harness only: squid reads the IPv6 test names from a hosts file.
        # All other names still resolve through Docker's embedded DNS, and no
        # resolver is added to any network.
        files["test_hosts"] = TEST_HOSTS
        files["squid.conf"] += f"hosts_file {egress.CONF_DIR}/test_hosts\n"
        egress.write(self.conf, files)

    def compose(self) -> dict:
        ips = self.ips
        upstream = "http://host.docker.internal:11434" if self.live else "http://fake-ollama:11434"
        services = {
            "egress": {
                "image": IMG["egress"],
                "networks": {"internal": {"ipv4_address": ips["egress"]}, "external": {}},
                "volumes": [
                    f"{self.conf}:{egress.CONF_DIR}:ro",
                    f"{self.egress_logs}:{egress.LOG_DIR}",
                ],
                "tmpfs": [f"/run/squid:uid={EGRESS_UID},gid={EGRESS_UID}", "/tmp"],
                **SIDECAR_HARDEN,
            },
            "ollama-gate": self.gate_service(
                upstream, "local", ips["ollama-gate"], "ollama-gate.log"
            ),
            "ollama-gate-list": self.gate_service(
                upstream, json.dumps(LIST_GATE_MODELS), self.list_gate_ip, "ollama-gate-list.log"
            ),
            "agent": svc(
                IMG["stub"],
                ips["agent"],
                **HARDEN,
                environment=proxy_env("router,mcp-gateway,ollama-gate,localhost,127.0.0.1"),
                volumes=[f"{HERE}:/opt/doctor:ro"],
            ),
            "router": svc(
                IMG["stub"],
                ips["router"],
                **HARDEN,
                environment=proxy_env("localhost,127.0.0.1"),
                volumes=[f"{HERE}:/opt/doctor:ro"],
            ),
            "mcp-gateway": svc(
                IMG["stub"],
                ips["mcp-gateway"],
                **HARDEN,
                environment=proxy_env("localhost,127.0.0.1"),
                volumes=[f"{HERE}:/opt/doctor:ro"],
            ),
        }
        if sys.platform.startswith("linux"):  # PLAN §6 Linux note
            for name in ("egress", "ollama-gate"):
                services[name]["extra_hosts"] = ["host.docker.internal:host-gateway"]
        if not self.live:
            services["fake-ollama"] = {"image": IMG["fake"], "networks": {"external": {}}}
        return {
            "name": self.project,
            "services": services,
            "networks": {
                "internal": {
                    "internal": True,
                    "ipam": {"config": [{"subnet": str(network.subnet_for(self.n, self.base))}]},
                },
                "external": {},
            },
        }

    def gate_service(self, upstream, models, ip, log_name) -> dict:
        return {
            "image": IMG["gate"],
            "networks": {"internal": {"ipv4_address": ip}, "external": {}},
            "environment": {
                "GATE_UPSTREAM": upstream,
                "GATE_MODELS": models,
                "GATE_REFRESH": "5",
                "GATE_LOG": f"/var/log/agentbox/{log_name}",
            },
            "volumes": [f"{self.gate_logs}:/var/log/agentbox"],
            **SIDECAR_HARDEN,
        }

    def compose_other(self) -> dict:
        return {
            "name": self.other_project,
            "services": {"victim": svc(IMG["fake"], self.other_ips["agent"])},
            "networks": {
                "internal": {
                    "internal": True,
                    "ipam": {
                        "config": [{"subnet": str(network.subnet_for(self.n_other, self.base))}]
                    },
                }
            },
        }

    # -- lifecycle
    def dc(self, *args, project=None, check=True, timeout=600):
        proj = project or self.project
        f = self.state / f"{proj}.compose.json"
        return sh(
            ["docker", "compose", "-p", proj, "-f", str(f), *args], check=check, timeout=timeout
        )

    def up(self) -> None:
        # F8: state dir private to the user; one log dir per writer.
        self.state.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state, 0o700)
        for d, uid in ((self.egress_logs, EGRESS_UID), (self.gate_logs, GATE_UID)):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o755)
            if sys.platform.startswith("linux"):
                # Linux bind mounts keep host uids: give the dir to the writer uid.
                # (Docker Desktop on macOS maps all container writes to the host
                # user, so the 0755 user-owned dir is writable there; verified.)
                sh(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--user",
                        "0",
                        "--entrypoint",
                        "sh",
                        "-v",
                        f"{d}:/d",
                        IMG["gate"],
                        "-c",
                        'chown -R "$1:$2" /d && chmod 2770 /d && chmod -R g+rwX /d',
                        "sh",
                        str(uid),
                        str(os.getgid()),
                    ]
                )
        in_use = docker_subnets()
        network.verify(self.n, in_use, self.base, exclude_project=self.project)
        network.verify(self.n_other, in_use, self.base, exclude_project=self.other_project)
        self.render_egress()
        r = sh(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{self.conf}:{egress.CONF_DIR}:ro",
                "--entrypoint",
                "squid",
                IMG["egress"],
                "-k",
                "parse",
                "-f",
                f"{egress.CONF_DIR}/squid.conf",
            ],
            check=False,
        )
        bad = [
            x
            for x in (r.stdout + r.stderr).splitlines()
            if ("ERROR" in x or "FATAL" in x or "WARNING" in x)
            and "empty ACL" not in x
            and "requires the use of Via" not in x
        ]
        if r.returncode != 0 or bad:
            raise RuntimeError("squid -k parse:\n" + "\n".join(bad or [r.stderr]))
        docs = ((self.project, self.compose()), (self.other_project, self.compose_other()))
        for proj, doc in docs:
            (self.state / f"{proj}.compose.json").write_text(json.dumps(doc, indent=1))
            self.dc("up", "-d", "--quiet-pull", project=proj)
        self.wait_ready()

    def wait_ready(self) -> None:
        deadline = time.time() + 60
        while time.time() < deadline:
            cl = self.egress_logs / "cache.log"
            logs = cl.read_text() if cl.exists() else ""
            gate_ok = True
            for name in ("ollama-gate.log", "ollama-gate-list.log"):
                gl = self.gate_logs / name
                gate_ok &= gl.exists() and (self.live or '"event": "refresh"' in gl.read_text())
            if "Accepting HTTP Socket connections" in logs and gate_ok:
                return
            time.sleep(1)
        tail = self.dc("logs", check=False).stdout[-3000:]
        raise RuntimeError("egress / ollama-gate not ready:\n" + tail)

    def down(self) -> None:
        for proj in (self.project, self.other_project):
            f = self.state / f"{proj}.compose.json"
            if f.exists():
                self.dc(
                    "down", "-v", "--remove-orphans", "--timeout", "2", project=proj, check=False
                )
        network.release(self.state_root, self.profile)
        network.release(self.state_root, self.other)

    def exec(self, service, args, env=None, check=False, timeout=900):
        e = []
        for k, v in (env or {}).items():
            e += ["-e", f"{k}={v}"]
        return self.dc("exec", "-T", *e, service, *args, check=check, timeout=timeout)

    def container_state(self) -> dict:
        ids = self.dc("ps", "-q").stdout.split()
        out = sh(
            [
                "docker",
                "inspect",
                *ids,
                "--format",
                "{{.Name}} {{.Id}} {{.State.StartedAt}} {{.RestartCount}}",
            ]
        ).stdout
        return dict(line.split(" ", 1) for line in out.strip().splitlines())


def record(run: str, text: str) -> None:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("PASS", "FAIL", "SKIP")):
            RESULTS.append((run, line, line.split()[0]))
            print(f"[{run}] {line}", flush=True)


def run_doctor(box: Box, run: str, args: argparse.Namespace) -> None:
    model = args.live_model if box.live else FAKE_MODEL
    common = {
        "DOCTOR_MODE": box.mode,
        "DOCTOR_MCP_PORTS": str(box.mcp_port),
        "DOCTOR_GATE_MODEL": model or "",
    }
    agent_env = dict(
        common,
        DOCTOR_ROLE="agent",
        DOCTOR_ALLOWED="example.com",
        DOCTOR_DENIED="example.org",
        DOCTOR_BLOCKED_TCP=" ".join(
            [f"{box.ips['egress']}:80", f"{network.gateway_ip(box.n, box.base)}:80"]
        ),
        DOCTOR_OTHER_TARGETS=f"{box.other_ips['agent']}:11434",
        DOCTOR_PTR_IP=PTR_IP,
        DOCTOR_PTR_NAME=PTR_NAME,
        DOCTOR_V6_NAMES=V6_NAMES,
    )
    checks = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "12", "15", "19"]
    if not box.live or args.live_ollama:
        checks.append("18")
    r = box.exec("agent", ["bash", "/opt/doctor/doctor_checks.sh", *checks], env=agent_env)
    record(run, r.stdout + r.stderr)
    for role, allowed in (("router", ROUTER_ALLOW[0]), ("mcp-gateway", GATEWAY_ALLOW[0])):
        env = dict(common, DOCTOR_ROLE=role, DOCTOR_ALLOWED=allowed, DOCTOR_DENIED="example.com")
        r = box.exec(role, ["bash", "/opt/doctor/doctor_checks.sh", "13"], env=env)
        record(run, r.stdout + r.stderr)


def check_gate_upstream(box: Box, run: str) -> None:
    """Harness-only: what did the fake upstream receive, and what did the gate log."""
    reasons = []
    body = json.dumps(
        {
            "model": FAKE_MODEL,
            "messages": [{"role": "user", "content": MARKER}],
            "options": {"a": 1, "a ": 2},
        },
        indent=2,
    )
    r = box.exec(
        "agent",
        [
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--noproxy",
            "*",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            body,
            "http://ollama-gate:11434/api/chat",
        ],
    )
    if r.stdout.strip() != "200":
        reasons.append(f"marker chat -> {r.stdout.strip()}")
    fake = box.dc("exec", "-T", "fake-ollama", "cat", "/tmp/requests.log", check=False).stdout
    reqs = [json.loads(x) for x in fake.splitlines() if x.strip()]
    allowed_paths = {"/api/tags", "/api/show", "/api/chat", "/api/version", "/api/ps", "/v1/models"}
    for q in reqs:
        if q["path"] not in allowed_paths and not q["path"].startswith("/v1/models/"):
            reasons.append(f"upstream saw {q['method']} {q['path']}")
        b = q["body"]
        if b:
            parsed = json.loads(b)
            m = parsed.get("model") or parsed.get("name")
            if m not in (FAKE_MODEL, "gpt-oss:120b-cloud", "sneaky:latest") or (
                q["path"] != "/api/show" and m != FAKE_MODEL
            ):
                reasons.append(f"upstream saw model {m!r} on {q['path']}")
            if b != json.dumps(parsed, separators=(",", ":")):
                reasons.append(f"upstream body not re-serialized: {b[:80]!r}")
            if q["headers"].get("Content-Length") != str(len(b.encode())):
                reasons.append("bad upstream Content-Length")
            if "Transfer-Encoding" in q["headers"] or "Content-Encoding" in q["headers"]:
                reasons.append("upstream got TE/CE header")
    marker = [q for q in reqs if MARKER in q["body"]]
    if len(marker) != 1:
        reasons.append(f"marker request seen {len(marker)} times upstream")
    glog = (box.gate_logs / "ollama-gate.log").read_text()
    if MARKER in glog:
        reasons.append("gate log contains a request body")
    recs = [json.loads(x) for x in glog.splitlines()]
    if not any(
        x.get("path") == "/api/chat" and x.get("status") == 200 and x.get("bytes_out") for x in recs
    ):
        reasons.append("gate log lacks chat record with status/bytes")
    if any("error" in x.get("event", "") for x in recs):
        reasons.append("gate refresh errors in log")
    status = "PASS" if not reasons else "FAIL"
    record(
        run,
        f"{status} 15-upstream (fake upstream saw only allowed, re-serialized requests; "
        f"no bodies in gate log){': ' + '; '.join(reasons) if reasons else ''}",
    )


def check_list_gate(box: Box, run: str) -> None:
    """F2: list mode allows list ∩ local; a listed model whose /api/show has a
    remote_host (sneaky) is denied."""
    want = {"llama3.2:latest": "200", "sneaky:latest": "403", "gpt-oss:120b-cloud": "403"}
    got = {}
    for m in want:
        body = json.dumps({"model": m, "messages": []})
        r = box.exec(
            "agent",
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--noproxy",
                "*",
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                body,
                f"http://{box.list_gate_ip}:11434/api/chat",
            ],
        )
        got[m] = r.stdout.strip()
    ok = got == want
    record(run, f"{'PASS' if ok else 'FAIL'} 15-list (GATE_MODELS={LIST_GATE_MODELS}: {got})")


def check_no_dns(box: Box, run: str) -> None:
    """No resolver on the internal subnet answers the agent for an external name."""
    net = network.subnet_for(box.n, box.base)
    script = (
        "for i in $(seq 1 254); do ( a=$(dig +short +time=2 +tries=1 @"
        + ".".join(str(net.network_address).split(".")[:3])
        + ".$i example.com A 2>/dev/null | grep -E '^[0-9.]+$'); "
        '[ -n "$a" ] && echo "ANSWER $i $a" ) & done; '
        "a=$(dig +short +time=2 +tries=1 @127.0.0.11 example.com A | grep -E '^[0-9.]+$'); "
        '[ -n "$a" ] && echo "ANSWER 127.0.0.11 $a"; wait'
    )
    r = box.exec("agent", ["bash", "-c", script])
    answers = [x for x in r.stdout.splitlines() if x.startswith("ANSWER")]
    ok = not answers and r.returncode == 0
    record(
        run,
        f"{'PASS' if ok else 'FAIL'} dns (agent: no A answer for example.com from "
        f"{net}:53 or 127.0.0.11){': ' + '; '.join(answers) if answers else ''}",
    )


def check_egress_log(box: Box, run: str) -> None:
    p = box.egress_logs / "egress.log"
    txt = p.read_text() if p.exists() else ""
    ok = "TCP_DENIED/403" in txt and box.ips["agent"] in txt
    record(
        run,
        f"{'PASS' if ok else 'FAIL'} log (egress access log written to host "
        f"state dir: {len(txt.splitlines())} lines)",
    )


def check_live_reload(box: Box, run: str) -> None:
    code = [
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-x",
        "http://egress:3128",
        "-m",
        "15",
        "-w",
        "%{http_connect}",
        f"https://{RELOAD_DOMAIN}/",
    ]
    before_state = box.container_state()
    before = box.exec("agent", code).stdout.strip()
    box.render_egress(extra=[RELOAD_DOMAIN])
    r = box.dc(
        "exec",
        "-T",
        "egress",
        "squid",
        "-k",
        "reconfigure",
        "-f",
        f"{egress.CONF_DIR}/squid.conf",
        check=False,
    )
    after = "000"
    for _ in range(20):
        time.sleep(0.5)
        after = box.exec("agent", code).stdout.strip()
        if after == "200":
            break
    after_state = box.container_state()
    reasons = []
    if before != "403":
        reasons.append(f"before -> {before}")
    if r.returncode != 0:
        reasons.append(f"reconfigure rc {r.returncode}: {r.stderr.strip()}")
    if after != "200":
        reasons.append(f"after -> {after}")
    if before_state != after_state:
        reasons.append("a container restarted")
    box.render_egress()  # restore
    box.dc(
        "exec",
        "-T",
        "egress",
        "squid",
        "-k",
        "reconfigure",
        "-f",
        f"{egress.CONF_DIR}/squid.conf",
        check=False,
    )
    record(
        run,
        f"{'PASS' if not reasons else 'FAIL'} reload ({RELOAD_DOMAIN}: {before} -> "
        f"{after} after squid -k reconfigure, containers not restarted)"
        + (f": {'; '.join(reasons)}" if reasons else ""),
    )


def run_mode(mode: str, args, state_root: Path, mcp_port: int) -> None:
    run = mode + ("+live" if args.live_ollama else "")
    box = Box(mode, state_root, args.live_ollama, mcp_port, args.base)
    print(
        f"== {run}: project {box.project}, internal subnet "
        f"{network.subnet_for(box.n, args.base)}, other profile "
        f"{network.subnet_for(box.n_other, args.base)}",
        flush=True,
    )
    try:
        box.up()
        run_doctor(box, run, args)
        if not args.live_ollama:
            check_gate_upstream(box, run)
            check_list_gate(box, run)
        check_no_dns(box, run)
        check_egress_log(box, run)
        if mode == "strict":
            check_live_reload(box, run)
    except Exception as e:
        record(run, f"FAIL harness: {e}")
    finally:
        box.down()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["strict", "open", "both"], default="both")
    ap.add_argument(
        "--live-ollama",
        action="store_true",
        help="gate upstream = host Ollama (host.docker.internal:11434); runs check 18",
    )
    ap.add_argument("--live-model", default="", help="an installed local model (check 15)")
    ap.add_argument("--base", default=network.DEFAULT_BASE)
    args = ap.parse_args()
    if args.live_ollama and not args.live_model:
        ap.error("--live-ollama needs --live-model")

    build_images()
    bind_ip = host_bind_ip()
    mcp_port = free_port(bind_ip)
    srv = ThreadingHTTPServer((bind_ip, mcp_port), McpStub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state_root = Path(tempfile.mkdtemp(prefix="agentbox-p2-"))
    signal.signal(signal.SIGTERM, lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        for mode in ["strict", "open"] if args.mode == "both" else [args.mode]:
            run_mode(mode, args, state_root, mcp_port)
    finally:
        srv.shutdown()
        shutil.rmtree(state_root, ignore_errors=True)
    fails = [r for r in RESULTS if r[2] == "FAIL"]
    print(
        f"\nSUMMARY: {sum(r[2] == 'PASS' for r in RESULTS)} pass, {len(fails)} fail, "
        f"{sum(r[2] == 'SKIP' for r in RESULTS)} skip"
    )
    for r in fails:
        print(f"  [{r[0]}] {r[1]}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
