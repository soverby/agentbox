"""`agentbox doctor` (PLAN §4): in-box checks from tests/isolation/doctor_checks.sh
plus CLI-side checks 10, 12 (targets), 16.

The check script reaches the box on stdin (`bash -s`): nothing is written into
the container, so the agent cannot swap the script before a run.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import time
from dataclasses import dataclass

from . import box as boxmod
from . import compose, docker, egress, network, paths
from .denied import allow_matches

FAST = ["1", "2", "6", "9"]
INBOX_FULL = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
NOT_IN_P3 = {
    "11": "secrets delivery is P4",
    "13": "no router / mcp-gateway in this profile (P5/P6)",
    "14": "MCP gateway is P6",
    "17": "headless run with env-delivered tokens is P4",
}
ALLOWED_PREF = ("example.com", "github.com", "pypi.org", "www.wikipedia.org")
DENIED_PREF = ("example.org", "example.net", "iana.org", "www.w3.org")
PTR_IP, PTR_NAME = "1.1.1.1", "one.one.one.one"


@dataclass
class Result:
    status: str  # PASS FAIL SKIP
    check: str
    detail: str = ""

    def line(self) -> str:
        return f"{self.status} {self.check}" + (f": {self.detail}" if self.detail else "")


def parse_lines(text: str) -> list[Result]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        for st in ("PASS", "FAIL", "SKIP"):
            if line.startswith(st + " "):
                rest = line[len(st) + 1 :]
                check, _, detail = rest.partition(": ")
                out.append(Result(st, check.strip(), detail.strip()))
    return out


def pick_allowed(mode: str, allowlist: list[str]) -> str:
    if mode == "open":
        return ALLOWED_PREF[0]
    for d in ALLOWED_PREF:
        if allow_matches(d, allowlist):
            return d
    for d in allowlist:
        if not d.startswith("."):
            return d
    raise boxmod.BoxError("allowlist has no plain domain for check 3")


def pick_denied(allowlist: list[str]) -> str:
    for d in DENIED_PREF:
        if not allow_matches(d, allowlist):
            return d
    raise boxmod.BoxError("no public test domain is outside the allowlist for check 2")


def _ptr(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    except OSError:
        return None


def ptr_pair(mode: str, allowlist: list[str], allowed: str, resolve=socket.gethostbyname, ptr=_ptr):
    """Check 5 target: (ip, name, live_ptr).

    live_ptr True: `name` is the PTR of `ip` and is allowed, so the live test
    covers the PTR case. Else `name` is the check-3 domain and `ip` one of its
    addresses: the live test proves IP-literal denial, and the PTR case relies
    on the config check (the running squid.conf equals the render, whose
    `dstdomain -n` + `deny ip_literal` the P2 harness negative controls prove).
    """
    if mode == "open" or allow_matches(PTR_NAME, allowlist):
        return PTR_IP, PTR_NAME, True
    try:
        ip = resolve(allowed)
    except OSError:
        return None
    name = ptr(ip)
    if name and allow_matches(name, allowlist):
        return ip, name, True
    return ip, allowed, False


def check_config(b: boxmod.Box) -> list[str]:
    """Files the running egress reads == the CLI render (byte-equal)."""
    ctx = boxmod.ctx_for(b, b.subnet_index())
    want = boxmod.render_egress(b, ctx)
    reasons = []
    r = boxmod.dc(b, "exec", "-T", "egress", "ls", "-A", egress.CONF_DIR, check=False)
    have = {x for x in r.stdout.split() if not x.startswith(".")}
    if r.returncode != 0:
        return [f"cannot list {egress.CONF_DIR} in egress: {r.stderr.strip()[-200:]}"]
    if have != set(want):
        reasons.append(f"egress config files {sorted(have)} != render {sorted(want)}")
    for name, text in sorted(want.items()):
        r = boxmod.dc(b, "exec", "-T", "egress", "cat", f"{egress.CONF_DIR}/{name}", check=False)
        if r.returncode != 0 or r.stdout != text:
            reasons.append(
                f"running egress {name} differs from the CLI render "
                "(run `agentbox up` to restore it)"
            )
    return reasons


def script_text() -> str:
    return (paths.repo_root() / "tests" / "isolation" / "doctor_checks.sh").read_text()


WINDOWS_FILE = "doctor-windows.jsonl"
# Clock rounding: squid logs ms timestamps from the Docker VM clock; the window
# is taken from the host clock. The UA nonce is the real filter, so 2 s of
# slack cannot hide other traffic.
WINDOW_SLACK = 2.0
MAX_WINDOWS = 500


def new_ua() -> str:
    return f"agentbox-doctor/{secrets.token_hex(8)}"


def record_window(state, start: float, end: float, ua: str) -> None:
    """Doctor probes make denials on purpose; `denied` drops lines with this
    run's nonce User-Agent inside this run's window."""
    f = state / WINDOWS_FILE
    lines = f.read_text().splitlines() if f.is_file() else []
    lines.append(json.dumps({"start": start - WINDOW_SLACK, "end": end + WINDOW_SLACK, "ua": ua}))
    tmp = f.with_suffix(".tmp")
    tmp.write_text("\n".join(lines[-MAX_WINDOWS:]) + "\n")
    tmp.replace(f)


def load_windows(state) -> list[tuple[float, float, str]]:
    f = state / WINDOWS_FILE
    out = []
    if f.is_file():
        for line in f.read_text().splitlines():
            try:
                d = json.loads(line)
                out.append((float(d["start"]), float(d["end"]), str(d["ua"])))
            except (ValueError, TypeError, KeyError):
                continue  # includes round-2 [start, end] entries: never used to hide
    return out


def run_script(b: boxmod.Box, checks: list[str], env: dict[str, str]) -> list[Result]:
    ua = new_ua()
    env = {**env, "DOCTOR_UA": ua}
    t0 = time.time()
    try:
        r = boxmod.exec_in(
            b, ["bash", "-s", "--", *checks], env=env, input=script_text(), timeout=900
        )
    finally:
        record_window(b.state, t0, time.time(), ua)
    res = parse_lines(r.stdout + r.stderr)
    seen = {x.check.split()[0] for x in res}
    for c in checks:
        if c not in seen:
            res.append(Result("FAIL", c, f"no result (exit {r.returncode}): {r.stderr[-300:]}"))
    return res


def base_env(b: boxmod.Box) -> dict[str, str]:
    p = b.profile
    allowlist = [] if p.network.mode == "open" else boxmod.agent_domains(p)
    ips = b.ips()
    n = b.subnet_index()
    env = {
        "DOCTOR_MODE": p.network.mode,
        "DOCTOR_ROLE": "agent",
        "DOCTOR_ALLOWED": pick_allowed(p.network.mode, allowlist),
        "DOCTOR_BLOCKED_TCP": f"{ips['egress']}:80 {network.gateway_ip(n, b.cfg.subnet_base)}:80",
    }
    if p.network.mode == "strict":
        env["DOCTOR_DENIED"] = pick_denied(allowlist)
    return env


def fast(b: boxmod.Box) -> list[Result]:
    return run_script(b, FAST, base_env(b))


def agent_container(b: boxmod.Box) -> str:
    cid = boxmod.dc(b, "ps", "-q", "agent").stdout.strip()
    if not cid:
        raise boxmod.BoxError("agent container is not running")
    return cid


# Mount points the runtime adds on its own (not host paths from the profile).
RUNTIME_MOUNTS = (
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/sbin/docker-init",
    "/usr/sbin/docker-init",
)
RUNTIME_PREFIXES = ("/proc", "/sys", "/dev")


def check_10(b: boxmod.Box, ci: bool | None = None) -> Result:
    """Only declared mounts present (Docker's view and the box's own view);
    ro mounts reject writes."""
    ci = sys.platform == "darwin" if ci is None else ci
    reasons = []
    p = b.profile
    mounts = json.loads(
        docker.run(["docker", "inspect", "--format", "{{json .Mounts}}", agent_container(b)]).stdout
    )
    want = {m.path: m for m in p.mounts}
    got = {}
    for m in mounts:
        dst = m["Destination"]
        got[dst] = m
        if dst == compose.HOME:
            if m.get("Type") != "volume" or m.get("Name") != compose.home_volume(p.name):
                reasons.append(f"{dst}: not the profile home volume")
        elif dst in want:
            pm = want[dst]
            src = m.get("Source", "")
            norm = (lambda s: s.casefold()) if ci else (lambda s: s)
            if m.get("Type") != "bind" or norm(src) != norm(pm.host_real):
                reasons.append(f"{dst}: source {src} != {pm.host_real}")
            if bool(m.get("RW")) != (pm.mode == "rw"):
                reasons.append(f"{dst}: RW={m.get('RW')} but mode {pm.mode}")
        else:
            reasons.append(f"undeclared mount {m.get('Source')} -> {dst}")
    for dst in want:
        if dst not in got:
            reasons.append(f"declared mount {dst} missing")
    if compose.HOME not in got:
        reasons.append("home volume missing")
    # The box's own view: mount points from /proc/self/mountinfo.
    r = boxmod.exec_in(b, ["awk", "{print $5}", "/proc/self/mountinfo"], timeout=30)
    allowed = set(want) | {compose.HOME, "/"} | set(RUNTIME_MOUNTS)
    for mp in r.stdout.split():
        if mp in allowed or any(mp == x or mp.startswith(x + "/") for x in RUNTIME_PREFIXES):
            continue
        reasons.append(f"in-box mount point {mp} not declared")
    # Writes: ro must fail, rw must work.
    for m in p.mounts:
        probe = f"{m.path.rstrip('/')}/.agentbox-doctor-probe-{os.getpid()}"
        r = boxmod.exec_in(b, ["sh", "-c", 'touch "$1" && rm -f "$1"', "sh", probe], timeout=30)
        if m.mode == "ro" and r.returncode == 0:
            reasons.append(f"ro mount {m.path} accepted a write")
        if m.mode == "rw" and r.returncode != 0:
            reasons.append(f"rw mount {m.path} rejected a write")
    return Result("FAIL" if reasons else "PASS", "10", "; ".join(reasons))


CHECK_16 = r"""
set -u
r=()
o=$(for d in /usr /etc /opt $(printf '%s' "$PATH" | tr : ' '); do
      [ -e "$d" ] && find "$d" -xdev -writable 2>/dev/null; done | sort -u |
    grep -v '^/home/agent\(/\|$\)')
[ -z "$o" ] || r+=("writable: $(printf '%s ' $o | cut -c1-300)")
seen=0
for d in $(printf '%s' "$PATH" | tr : ' '); do
  case $d in
    /home/*) seen=1 ;;
    *) [ $seen = 1 ] && r+=("system PATH entry $d after a home entry") ;;
  esac
done
s=$(find / -xdev -perm /6000 -type f 2>/dev/null)
[ -z "$s" ] || r+=("setuid/setgid: $(printf '%s ' $s | cut -c1-300)")
m=$(stat -c '%U:%G %a' /etc/claude-code/managed-mcp.json /etc/claude-code 2>&1)
[ "$m" = "$(printf 'root:root 644\nroot:root 755')" ] || r+=("managed-mcp.json: $m")
if test -w /etc/claude-code/managed-mcp.json || test -w /etc/claude-code; then
  r+=("managed-mcp.json writable")
fi
if [ ${#r[@]} -eq 0 ]; then echo "PASS 16"; else echo "FAIL 16: $(IFS='; '; echo "${r[*]}")"; fi
"""


def check_16(b: boxmod.Box) -> Result:
    r = boxmod.exec_in(b, ["bash", "-s"], input=CHECK_16, timeout=300)
    res = parse_lines(r.stdout)
    return res[0] if res else Result("FAIL", "16", f"no result: {r.stderr[-300:]}")


def other_targets(b: boxmod.Box) -> list[str]:
    """host:port of listening services in other running agentbox profiles (12)."""
    targets = []
    for proj, services in sorted(docker.running_projects().items()):
        if proj == b.project:
            continue
        for svc, port in (("egress", 3128), ("ollama-gate", 11434), ("agent", 22)):
            if svc not in services:
                continue
            ids = docker.run(
                ["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={proj}",
                 "--filter", f"label=com.docker.compose.service={svc}"]
            ).stdout.split()  # fmt: skip
            for cid in ids:
                out = docker.run(
                    ["docker", "inspect", "--format",
                     "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}",
                     cid]
                ).stdout.split()  # fmt: skip
                for kv in out:
                    k, _, ip = kv.partition("=")
                    if k.endswith("_internal") and ip:
                        targets.append(f"{ip}:{port}")
    return targets


def gate_probe(b: boxmod.Box) -> tuple[bool, str | None]:
    """(host Ollama reachable through the gate, an allowed local model or None)."""
    r = boxmod.exec_in(
        b, ["curl", "-s", "--noproxy", "*", "-m", "5", "http://ollama-gate:11434/api/tags"],
        timeout=30,
    )  # fmt: skip
    try:
        tags = json.loads(r.stdout)
    except ValueError:
        return False, None
    if not isinstance(tags, dict) or "models" not in tags:
        return False, None
    for m in tags.get("models") or []:
        if not m.get("remote_host") and not str(m.get("name", "")).endswith("cloud"):
            return True, m["name"]
    return True, None


def full(b: boxmod.Box) -> list[Result]:
    p = b.profile
    env = base_env(b)
    allowlist = [] if p.network.mode == "open" else boxmod.agent_domains(p)
    checks = list(INBOX_FULL)
    pair = ptr_pair(p.network.mode, allowlist, env["DOCTOR_ALLOWED"])
    pre: list[Result] = []
    if pair is None:
        checks.remove("5")
        pre.append(Result("FAIL", "5", "cannot resolve a target IP on the host"))
    else:
        env["DOCTOR_PTR_IP"], env["DOCTOR_PTR_NAME"] = pair[0], pair[1]
    others = other_targets(b)
    if others:
        env["DOCTOR_OTHER_TARGETS"] = " ".join(others)
        checks.append("12")
    reachable, model = gate_probe(b)
    if reachable:
        checks.append("18")
        if model:
            env["DOCTOR_GATE_MODEL"] = model
            checks.append("15")
    checks.append("19")
    res = pre + run_script(b, checks, env)
    cfg = check_config(b)
    for x in res:
        if x.check != "5":
            continue
        notes = [x.detail] if x.detail else []
        if cfg:
            x.status = "FAIL"
            notes += cfg
        elif pair and pair[2]:
            notes.append(f"live PTR case: {pair[0]} (PTR {pair[1]}); running config == render")
        elif pair:
            notes.append(
                f"live IP-literal case: {pair[0]} of {pair[1]}; PTR of {pair[0]} is not "
                "allowlisted, so the PTR case relies on the config check (running config "
                "== render)"
            )
        x.detail = "; ".join(notes)
    res.append(check_10(b))
    res.append(check_16(b))
    if not others:
        res.append(Result("SKIP", "12", "no other agentbox profile is running"))
    if not reachable:
        why = "host Ollama not reachable through ollama-gate"
        res += [Result("SKIP", "15", why), Result("SKIP", "18", why)]
    elif not model:
        res.append(Result("SKIP", "15", "no allowed local model on host Ollama"))
    res += [Result("SKIP", c, why) for c, why in NOT_IN_P3.items()]
    return sorted(res, key=lambda x: (_num(x.check), x.check))


def _num(check: str) -> int:
    head = check.split()[0].split("-")[0]
    return int(head) if head.isdigit() else 999
