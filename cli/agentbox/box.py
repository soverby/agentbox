"""Box lifecycle: render, up, down, exec (PLAN §2, §2.1, §2.2)."""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import compose, docker, egress, images, mountstate, network, paths, presets
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
    return {"agent", "egress", "ollama-gate"} <= running


def agent_domains(profile: Profile) -> list[str]:
    return presets.agent_allowlist(
        profile.network.presets, profile.network.allow, paths.repo_root() / "presets"
    )


def ctx_for(box: Box, n: int, agent_image="", egress_image="", gate_image="") -> compose.Ctx:
    return compose.Ctx(
        profile=box.profile,
        n=n,
        base=box.cfg.subnet_base,
        state=box.state,
        agent_image=agent_image,
        egress_image=egress_image,
        gate_image=gate_image,
    )


def render_egress(box: Box, ctx: compose.Ctx) -> dict[str, str]:
    p = box.profile
    domains = [] if p.network.mode == "open" else agent_domains(p)
    return egress.render(
        p.network.mode,
        compose.egress_clients(ctx, domains),
        allow_http=p.network.allow_http,
        partial=True,
    )


def _prepare_log_dirs(box: Box, ctx: compose.Ctx, gate_image: str) -> None:
    for d, uid in ((ctx.egress_logs, compose.EGRESS_UID), (ctx.gate_logs, compose.GATE_UID)):
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
    "(exec 3<>/dev/tcp/ollama-gate/11434) 2>/dev/null && exit 0; sleep 0.5; done; exit 1"
)


def wait_ready(box: Box) -> None:
    r = exec_in(box, ["bash", "-c", READY_SCRIPT], timeout=120)
    if r.returncode != 0:
        tail = dc(box, "logs", "--tail", "40", "egress", "ollama-gate", check=False).stdout
        raise BoxError(f"egress / ollama-gate not ready:\n{tail}")


def host_git(key: str) -> str | None:
    r = docker.run(["git", "config", "--global", "--get", key], check=False)
    v = r.stdout.strip()
    return v or None


def git_setup(box: Box) -> None:
    """Host identity + HTTPS rewrite into the box ~/.gitconfig (PLAN §2.1).
    `gh auth setup-git` needs GH_TOKEN: P4 hook `gh_setup_git`."""
    cmds = [["git", "config", "--global", "url.https://github.com/.insteadOf", "git@github.com:"]]
    for key in ("user.name", "user.email"):
        v = host_git(key)
        if v is not None:
            cmds.append(["git", "config", "--global", key, v])
    for c in cmds:
        r = exec_in(box, c, timeout=30)
        if r.returncode != 0:
            raise BoxError(f"git setup failed: {' '.join(c[:4])}: {r.stderr.strip()}")
    gh_setup_git(box)


def gh_setup_git(box: Box) -> None:
    """P4: `gh auth setup-git` once GH_TOKEN is delivered."""


def up(box: Box, accept_mount_change: bool = False) -> None:
    """Render and start the box. Idempotent for a running box.

    Every `up` ends with `squid -k parse` + `squid -k reconfigure`: the egress
    config is a bind mount whose content Compose does not hash, so a changed
    `[network]` must be applied explicitly (a label with the config hash also
    recreates egress when the render changes).
    """
    with (box.state / "up.lock").open("a") as lk:  # one `up` per profile at a time
        fcntl.flock(lk, fcntl.LOCK_EX)
        _up(box, accept_mount_change)


def _up(box: Box, accept_mount_change: bool) -> None:
    mountstate.check_and_record(box.state, box.profile, accept_mount_change)
    repo = paths.repo_root()
    p = box.profile
    agent_image = images.ensure_agent(repo)
    if p.box.packages:
        agent_image = images.ensure_pkgs(agent_image, p.box.packages)
    egress_image = images.ensure_sidecar(repo, "egress")
    gate_image = images.ensure_sidecar(repo, "ollama-gate")

    base = box.cfg.subnet_base
    in_use = docker.subnets()
    n = network.allocate(paths.state_home(), box.name, in_use, base)
    network.verify(n, in_use, base, exclude_project=box.project)

    ctx = ctx_for(box, n, agent_image, egress_image, gate_image)
    _prepare_log_dirs(box, ctx, gate_image)
    files = render_egress(box, ctx)
    old = read_conf(ctx.conf_dir)
    egress.write(ctx.conf_dir, files)
    # Label = hash of squid.conf (mode, ACL layout): a change recreates egress.
    # Allowlist-only changes (`allow`) apply by reconfigure, without a restart.
    ctx.egress_config_hash = compose.config_hash({"squid.conf": files["squid.conf"]})
    compose.write_json(box.compose_file, compose.render(ctx))
    dc(box, "up", "-d", "--remove-orphans", "--quiet-pull", timeout=900)
    wait_ready(box)
    # Unchanged files are what the running squid already loaded (the CLI is the
    # only writer); skip the reload so session starts do not disturb traffic.
    if files != old:
        apply_egress(box, ctx.conf_dir, old)
    git_setup(box)


def down(box: Box, volumes: bool = False) -> None:
    if not box.compose_file.is_file():
        return
    args = ["down", "--remove-orphans", "--timeout", "3"]
    if volumes:
        args.append("-v")
    dc(box, *args, timeout=300)


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
        yield f
    finally:
        f.close()


def try_exclusive(f) -> bool:
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


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
