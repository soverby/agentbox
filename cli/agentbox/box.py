"""Box lifecycle: render, up, down, exec (PLAN §2, §2.1, §2.2)."""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import (
    compose,
    delivery,
    docker,
    egress,
    images,
    mcpgw,
    mountstate,
    network,
    paths,
    presets,
    router,
    secretstore,
    term,
)
from .launch import WITH_SECRETS
from .profile import Profile, ProfileError, load_profile


class BoxError(Exception):
    pass


@dataclass
class Box:
    name: str
    profile: Profile
    state: Path
    cfg: paths.Config
    lock_fd: object = None  # this process's session.lock file while it holds it

    @property
    def project(self) -> str:
        return compose.project_name(self.name)

    @property
    def compose_file(self) -> Path:
        return self.state / "compose.json"

    def ips(self) -> dict[str, str]:
        return network.fixed_ips(self.subnet_index(), self.cfg.subnet_base)

    def subnet_index(self) -> int:
        f = self.state / network.SUBNET_FILE
        if not f.is_file():
            raise BoxError(f"profile {self.name} has no subnet yet; run `agentbox up`")
        return int(f.read_text().strip())


def load(name: str) -> Box:
    f = paths.profile_file(name)
    if not f.is_file():
        raise BoxError(f"no profile {name!r} ({f}); create it with `agentbox init`")
    try:
        prof = load_profile(f, name, host_checks=True)
    except ProfileError as e:
        raise BoxError(f"profile {name} is invalid:\n{e}") from None
    problems = mountstate.symlink_problems(prof)
    if problems:
        raise BoxError(f"profile {name}: " + "; ".join(problems))
    return Box(name, prof, paths.state_dir(name), paths.load_config())


def dc(box: Box, *args: str, **kw) -> subprocess.CompletedProcess:
    return docker.run(
        ["docker", "compose", "-p", box.project, "-f", str(box.compose_file), *args], **kw
    )


def is_running(box: Box) -> bool:
    if not box.compose_file.is_file():
        return False
    r = dc(box, "ps", "--status", "running", "--services", check=False)
    running = set(r.stdout.split()) if r.returncode == 0 else set()
    want = {"agent", "egress", "ollama-gate", mcpgw.SERVICE}
    if compose.has_router(box.profile):
        want.add(router.SERVICE)
    return want <= running


def agent_domains(profile: Profile) -> list[str]:
    return presets.agent_allowlist(
        profile.network.presets, profile.network.allow, paths.repo_root() / "presets"
    )


def ctx_for(
    box: Box,
    n: int,
    agent_image="",
    egress_image="",
    gate_image="",
    gateway_image="",
    router_image="",
) -> compose.Ctx:
    return compose.Ctx(
        profile=box.profile,
        n=n,
        base=box.cfg.subnet_base,
        state=box.state,
        agent_image=agent_image,
        egress_image=egress_image,
        gate_image=gate_image,
        gateway_image=gateway_image,
        router_image=router_image,
    )


def render_egress(box: Box, ctx: compose.Ctx) -> dict[str, str]:
    p = box.profile
    domains = [] if p.network.mode == "open" else agent_domains(p)
    return egress.render(
        p.network.mode,
        compose.egress_clients(ctx, domains),
        allow_http=p.network.allow_http,
        host_mcp_ports=mcpgw.host_ports(p),
        partial=True,
    )


def _prepare_log_dirs(box: Box, ctx: compose.Ctx, gate_image: str) -> None:
    for d, uid in (
        (ctx.egress_logs, compose.EGRESS_UID),
        (ctx.gate_logs, compose.GATE_UID),
        (mcpgw.log_dir(ctx), mcpgw.GW_UID),
    ):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o755)
        if sys.platform.startswith("linux"):
            # Linux bind mounts keep host uids: give the dir to the writer uid.
            # Docker Desktop (macOS) maps container writes to the host user.
            docker.run(
                ["docker", "run", "--rm", "--user", "0", "--entrypoint", "chown",
                 "-v", f"{d}:/d", gate_image, f"{uid}:{uid}", "/d"]
            )  # fmt: skip


def exec_in(
    box: Box,
    cmd: list[str],
    *,
    env: dict | None = None,
    input: str | None = None,
    check: bool = False,
    timeout: float | None = 600,
    workdir: str | None = None,
):
    """Non-interactive exec in the agent container, always through with-secrets."""
    args = ["exec", "-T"]
    for k, v in (env or {}).items():
        args += ["-e", f"{k}={v}"]
    if workdir:
        args += ["-w", workdir]
    return dc(box, *args, "agent", WITH_SECRETS, *cmd, check=check, input=input, timeout=timeout)


READY_SCRIPT = (
    "for i in $(seq 1 120); do "
    "(exec 3<>/dev/tcp/egress/3128) 2>/dev/null && "
    "(exec 3<>/dev/tcp/ollama-gate/11434) 2>/dev/null && "
    "(exec 3<>/dev/tcp/mcp-gateway/8080) 2>/dev/null && exit 0; sleep 0.5; done; exit 1"
)


def wait_ready(box: Box) -> None:
    r = exec_in(box, ["bash", "-c", READY_SCRIPT], timeout=120)
    if r.returncode != 0:
        tail = dc(
            box, "logs", "--tail", "40", "egress", "ollama-gate", mcpgw.SERVICE, check=False
        ).stdout
        raise BoxError(f"egress / ollama-gate / mcp-gateway not ready:\n{tail}")
    if compose.has_router(box.profile):
        wait_router(box)


ROUTER_WAIT = 180.0


def router_health(box: Box) -> str:
    cid = dc(box, "ps", "-q", router.SERVICE, check=False).stdout.strip()
    if not cid:
        return "missing"
    r = docker.run(["docker", "inspect", "--format", "{{.State.Health.Status}}", cid], check=False)
    return r.stdout.strip() or "unknown"


def wait_router(box: Box, timeout: float = ROUTER_WAIT) -> None:
    """The router healthcheck (`/health/liveliness` on 127.0.0.1) turns healthy."""
    deadline = time.monotonic() + timeout
    st = router_health(box)
    while st != "healthy" and time.monotonic() < deadline:
        time.sleep(1)
        st = router_health(box)
    if st != "healthy":
        tail = dc(box, "logs", "--tail", "40", router.SERVICE, check=False).stdout
        raise BoxError(f"router not healthy ({st}):\n{tail}")


def host_git(key: str) -> str | None:
    r = docker.run(["git", "config", "--global", "--get", key], check=False)
    v = r.stdout.strip()
    return v or None


def git_setup(box: Box, agent_secrets: list[str] | None = None) -> None:
    """Host identity + HTTPS rewrite into the box ~/.gitconfig (PLAN §2.1), and
    `gh auth setup-git` when GH_TOKEN is delivered to the agent."""
    cmds = [["git", "config", "--global", "url.https://github.com/.insteadOf", "git@github.com:"]]
    for key in ("user.name", "user.email"):
        v = host_git(key)
        if v is not None:
            cmds.append(["git", "config", "--global", key, v])
    for c in cmds:
        r = exec_in(box, c, timeout=30)
        if r.returncode != 0:
            raise BoxError(f"git setup failed: {' '.join(c[:4])}: {r.stderr.strip()}")
    if "GH_TOKEN" in (agent_secrets or []):
        gh_setup_git(box)


def gh_setup_git(box: Box) -> None:
    """`gh auth setup-git` through with-secrets: git uses gh (and so GH_TOKEN,
    read at each git call) as credential helper for github.com."""
    r = exec_in(box, ["gh", "auth", "setup-git", "--hostname", "github.com"], timeout=60)
    if r.returncode != 0:
        raise BoxError(f"`gh auth setup-git` failed in the box: {r.stderr.strip()[-300:]}")


def warn(msg: str) -> None:
    print(f"agentbox: {term.clean(msg, multiline=True)}", file=sys.stderr, flush=True)


def secret_problems(d: delivery.Delivery, profile: Profile) -> None:
    """One line per missing secret (the Claude token gets the setup hint)."""
    hint = delivery.claude_hint(d, profile)
    if hint:
        warn(hint)
    for m in d.missing:
        if m.name == "CLAUDE_CODE_OAUTH_TOKEN" and hint:
            continue
        scope = profile.secrets[m.name].scope
        where = "--shared" if scope == "shared" else profile.name
        how = f"`agentbox secret set {where} {m.name}`" if scope else f"store it at {m.ref}"
        warn(f"secret {m.name} ({m.ref}) is missing, so it is not delivered: {how}")


def up(box: Box, accept_mount_change: bool = False, explicit: bool = False) -> None:
    """Render and start the box. Idempotent for a running box.

    Every `up` ends with `squid -k parse` + `squid -k reconfigure`: the egress
    config is a bind mount whose content Compose does not hash, so a changed
    `[network]` must be applied explicitly (a label with the config hash also
    recreates egress when the render changes).
    """
    with up_lock(box):  # one `up` / `down` per profile at a time
        _up(box, accept_mount_change, explicit)


LOCK_TIMEOUT = 300.0


@contextmanager
def up_lock(box: Box, timeout: float = LOCK_TIMEOUT):
    """Exclusive up.lock: `up`, `down`, and run's stop-if-idle never interleave."""
    with (box.state / "up.lock").open("a") as lk:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise BoxError(
                        f"{box.name}: another agentbox up/down holds {lk.name} "
                        f"for more than {timeout:.0f}s"
                    ) from None
                time.sleep(0.2)
        yield


def sessions_active(box: Box) -> bool:
    """True when another process holds session.lock (a session uses the box).

    macOS flock does not upgrade in place (it releases first), so the probe
    never converts a lock: under an exclusive probe.lock (one prober at a
    time) it drops this process's own shared lock, tries a non-blocking
    exclusive lock on a fresh descriptor, and takes the shared lock back.
    Callers hold up.lock, so no other up/down/stop runs meanwhile. A session
    that starts inside the window holds a shared lock and counts as active.
    """
    with (box.state / "probe.lock").open("a") as pl:
        fcntl.flock(pl, fcntl.LOCK_EX)
        own = box.lock_fd
        if own is not None:
            fcntl.flock(own, fcntl.LOCK_UN)
        try:
            with (box.state / "session.lock").open("a") as g:
                try:
                    fcntl.flock(g, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return False
                except BlockingIOError:
                    return True
        finally:
            if own is not None:
                fcntl.flock(own, fcntl.LOCK_SH)


def running_label(box: Box, service: str = "agent") -> str | None:
    cid = dc(box, "ps", "-q", service, check=False).stdout.strip()
    if not cid:
        return None
    r = docker.run(
        ["docker", "inspect", "--format", f'{{{{index .Config.Labels "{delivery.LABEL}"}}}}', cid],
        check=False,
    )
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


DEFER_MSG = "secret change applies after sessions end or `agentbox down {name}`"


def keep_running_secrets(box: Box, doc: dict, old_doc: dict | None, dl) -> bool:
    """If the agent's secret set changed while other sessions use the box, put
    the running label and secret list back into `doc` (no recreate)."""
    agent = doc["services"]["agent"]
    new = agent.get("labels", {}).get(delivery.LABEL)
    old = running_label(box)
    if not old or old == new or not old_doc:
        return False
    old_agent = old_doc.get("services", {}).get("agent", {})
    # A name the running container has but the backend no longer gives cannot
    # be restored (its env var would be unset): recreate instead.
    if any(e["source"] not in dl.values for e in old_agent.get("secrets", [])):
        return False
    if not sessions_active(box):
        return False
    agent["labels"][delivery.LABEL] = old
    if old_agent.get("secrets"):
        agent["secrets"] = old_agent["secrets"]
    else:
        agent.pop("secrets", None)
    used = sorted({e["source"] for svc in doc["services"].values() for e in svc.get("secrets", [])})
    if used:
        doc["secrets"] = {n: {"environment": delivery.env_var(n)} for n in used}
    else:
        doc.pop("secrets", None)
    return True


def _up(box: Box, accept_mount_change: bool, explicit: bool = False) -> None:
    mountstate.check_and_record(box.state, box.profile, accept_mount_change)
    repo = paths.repo_root()
    p = box.profile
    agent_image = images.ensure_agent(repo)
    if p.box.packages:
        agent_image = images.ensure_pkgs(agent_image, p.box.packages)
    egress_image = images.ensure_sidecar(repo, "egress")
    gate_image = images.ensure_sidecar(repo, "ollama-gate")
    try:
        mcpgw.check(p)
        router.check(p)
    except (mcpgw.McpError, router.RouterError) as e:
        raise BoxError(str(e)) from None
    gateway_image = images.ensure_sidecar(repo, mcpgw.SERVICE)
    router_image = images.ensure_sidecar(repo, router.SERVICE) if compose.has_router(p) else ""

    base = box.cfg.subnet_base
    in_use = docker.subnets()
    n = network.allocate(paths.state_home(), box.name, in_use, base)
    network.verify(n, in_use, base, exclude_project=box.project)

    ctx = ctx_for(box, n, agent_image, egress_image, gate_image, gateway_image, router_image)
    _prepare_log_dirs(box, ctx, gate_image)
    write_gateway_config(ctx)
    write_router_config(ctx)
    files = render_egress(box, ctx)
    old = read_conf(ctx.conf_dir)
    egress.write(ctx.conf_dir, files)
    # Label = hash of squid.conf (mode, ACL layout): a change recreates egress.
    # Allowlist-only changes (`allow`) apply by reconfigure, without a restart.
    ctx.egress_config_hash = compose.config_hash({"squid.conf": files["squid.conf"]})
    doc = compose.render(ctx)
    try:
        dl = delivery.collect(p, box.cfg, box.state, set(doc["services"]))
    except secretstore.SecretError as e:
        raise BoxError(f"secrets: {e}") from None
    running = is_running(box)
    if explicit or not running:  # not on every session attach to a running box
        secret_problems(dl, p)
    delivery.apply(doc, dl, delivery.hmac_key(box.state))
    old_doc = None
    if running and box.compose_file.is_file():
        try:
            old_doc = json.loads(box.compose_file.read_text())
        except ValueError:
            old_doc = None
    if running and keep_running_secrets(box, doc, old_doc, dl):
        warn(DEFER_MSG.format(name=box.name))
    compose.write_json(box.compose_file, doc)  # names only, never values
    # Values reach only this process's environment (Compose `environment:` source).
    # Only the backend fills AGENTBOX_SECRET_*: drop any inherited from the shell.
    base = {k: v for k, v in os.environ.items() if not k.startswith(delivery.ENV_PREFIX)}
    env = {**base, **delivery.compose_env(dl, doc)}
    try:
        dc(box, "up", "-d", "--remove-orphans", "--quiet-pull", timeout=900, env=env)
    except docker.DockerError as e:
        msg = str(e)
        for v in dl.values.values():
            msg = secretstore.scrub(msg, v)
        raise BoxError(msg) from None
    wait_ready(box)
    rotate_egress_log(box, ctx)
    # Unchanged files are what the running squid already loaded (the CLI is the
    # only writer); skip the reload so session starts do not disturb traffic.
    if files != old:
        apply_egress(box, ctx.conf_dir, old)
    git_setup(box, dl.names_for("agent"))
    if (explicit or not running) and p.mcp_servers:
        warn_upstreams(box)


EGRESS_LOG_MAX = 20 * 1024 * 1024


def rotate_egress_log(box: Box, ctx: compose.Ctx, max_bytes: int = EGRESS_LOG_MAX) -> bool:
    """At `up`: egress.log over max_bytes -> egress.log.1 (one old file kept),
    then `squid -k rotate`, which (logfile_rotate 0) only reopens the logs, so
    squid writes a fresh egress.log. `denied` reads both files."""
    f = ctx.egress_logs / "egress.log"
    try:
        if f.stat().st_size <= max_bytes:
            return False
    except FileNotFoundError:
        return False
    os.replace(f, f.with_name("egress.log.1"))
    r = dc(box, "exec", "-T", "egress", "squid", "-k", "rotate", "-f", SQUID_CONF, check=False)
    if r.returncode != 0:
        warn(f"egress log rotated, but `squid -k rotate` failed: {r.stderr.strip()[-200:]}")
    return True


def gateway_status(box: Box) -> dict:
    """Refresh the gateway's upstream status (`gateway.py probe` in the
    gateway container; it also writes logs/mcp/status.json). Names and short
    reasons only: the probe scrubs bearer values from reasons."""
    r = dc(box, "exec", "-T", mcpgw.SERVICE, *mcpgw.PROBE_ARGV, check=False, timeout=300)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise BoxError(
            f"mcp-gateway status probe failed (exit {r.returncode}): {r.stderr.strip()[-300:]}"
        ) from None


def warn_upstreams(box: Box) -> None:
    """One warning line per MCP upstream that does not connect."""
    try:
        st = gateway_status(box)
    except BoxError as e:
        warn(str(e))
        return
    for name, s in sorted(st.get("servers", {}).items()):
        if s.get("state") != "connected":
            warn(f"MCP server {name} is not reachable from mcp-gateway: {s.get('reason', '?')}; "
                 "its tools are not available (see `agentbox doctor`)")  # fmt: skip


def write_gateway_config(ctx: compose.Ctx) -> None:
    """Gateway config (names only, no secret values), in a dir bind-mounted ro."""
    d = mcpgw.conf_dir(ctx)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o755)
    egress.write(d, {"config.json": mcpgw.config_text(ctx.profile)})


def write_router_config(ctx: compose.Ctx) -> None:
    """Router config (names and `os.environ/<NAME>` refs only), bind-mounted ro."""
    if not compose.has_router(ctx.profile):
        return
    d = router.conf_dir(ctx)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o755)
    egress.write(d, {router.CONFIG_NAME: router.config_text(ctx.profile)})


def down(box: Box, volumes: bool = False) -> None:
    """Stop the box; replace the per-box tokens for the next `up`."""
    with up_lock(box):
        down_locked(box, volumes)


def down_locked(box: Box, volumes: bool = False) -> None:
    """`down` for a caller that already holds up.lock."""
    if box.compose_file.is_file():
        args = ["down", "--remove-orphans", "--timeout", "3"]
        if volumes:
            args.append("-v")
        dc(box, *args, timeout=300)
    delivery.rotate_box_tokens(box.state)


SQUID_CONF = f"{egress.CONF_DIR}/squid.conf"


def squid_problems(output: str) -> list[str]:
    return [x for x in output.splitlines() if "FATAL" in x or "ERROR" in x]


def read_conf(conf: Path) -> dict[str, str]:
    if not conf.is_dir():
        return {}
    return {
        f.name: f.read_text() for f in conf.iterdir() if f.is_file() and not f.name.startswith(".")
    }


def apply_egress(box: Box, conf: Path, old: dict[str, str]) -> None:
    """`squid -k parse` the files now in `conf`, then `squid -k reconfigure`.
    On a parse failure restore `old` (the running squid keeps its config) and fail."""
    r = dc(box, "exec", "-T", "egress", "squid", "-k", "parse", "-f", SQUID_CONF, check=False)
    bad = squid_problems(r.stdout + r.stderr)
    if r.returncode != 0 or bad:
        if old:
            for f in conf.iterdir():
                if f.is_file() and not f.name.startswith(".") and f.name not in old:
                    f.unlink()
            egress.write(conf, old)
        raise BoxError(
            "egress config rejected by `squid -k parse`; previous config restored and still "
            "active: " + "; ".join(bad or [r.stderr.strip()[-500:]])
        )
    r = dc(box, "exec", "-T", "egress", "squid", "-k", "reconfigure", "-f", SQUID_CONF, check=False)
    if r.returncode != 0:
        raise BoxError(f"squid -k reconfigure failed: {r.stderr.strip()[-500:]}")


def reload_egress(box: Box) -> None:
    """Re-render the allowlist, parse, reconfigure (restore on parse failure)."""
    ctx = ctx_for(box, box.subnet_index())
    old = read_conf(ctx.conf_dir)
    egress.write(ctx.conf_dir, render_egress(box, ctx))
    apply_egress(box, ctx.conf_dir, old)


@contextmanager
def session_lock(box: Box):
    """Shared lock held by every CLI session (shell, agents, run) for its whole
    life; `run` stops a box it started only if it can take it exclusively."""
    f = (box.state / "session.lock").open("a")
    try:
        fcntl.flock(f, fcntl.LOCK_SH)
        box.lock_fd = f
        yield f
    finally:
        box.lock_fd = None
        f.close()


def stop_if_idle(box: Box) -> str | None:
    """Stop a box that `run` started unless someone else uses it. Holds up.lock
    for the whole decision, so no `up` can start a session in between.
    Returns why the box stays up, or None when it was stopped."""
    with up_lock(box):
        if sessions_active(box):
            return "another agentbox session uses the box"
        try:
            others = other_processes(box)
        except Exception as e:  # noqa: BLE001
            return f"cannot list box processes ({e})"
        if others:
            return f"other processes run in the box ({others[0]!r})"
        down_locked(box)
        return None


IDLE_PROCS = ("sleep infinity", "/sbin/docker-init", "docker-init")


def other_processes(box: Box) -> list[str]:
    """Processes in the agent container other than init and `sleep infinity`."""
    cid = dc(box, "ps", "-q", "agent", check=False).stdout.strip()
    if not cid:
        return []
    out = docker.run(["docker", "top", cid, "-eo", "pid,args"], check=False).stdout
    procs = []
    for line in out.splitlines()[1:]:
        args = line.strip().split(None, 1)[1] if len(line.split()) > 1 else ""
        if not any(args == x or args.startswith(x + " ") for x in IDLE_PROCS):
            procs.append(args)
    return procs
