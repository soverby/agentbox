"""Agent launch argv, working dir mapping, profile resolution (PLAN §2.3).

Pure functions: no Docker calls.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .profile import Profile, ProfileError, load_profile

WITH_SECRETS = "/usr/local/bin/with-secrets"
CODEX_OVERRIDES = (
    "-c", "features.apps=false",
    "-c", "features.remote_plugin=false",
    "-c", "apps._default.enabled=false",
)  # fmt: skip


class ResolveError(Exception):
    pass


def agent_argv(profile: Profile, agent: str, args: list[str], headless: bool = False):
    """argv for an agent inside the box (without with-secrets).

    headless: `run` mode (`claude -p`, `codex exec --skip-git-repo-check -`, `pi -p`).
    The prompt is never in argv: it goes on stdin (no option parsing of prompt
    text, no argv size limit). Verified against the image: `claude -p` and
    `codex exec -` read stdin; Pi prepends piped stdin to the prompt.
    """
    box = profile.box
    if agent not in box.agents:
        raise ResolveError(f"agent {agent!r} is not in [box] agents of {profile.name}")
    if agent == "claude":
        argv = ["claude"]
        if box.skip_permissions:
            argv.append("--dangerously-skip-permissions")
        if not box.web_tools:
            argv += ["--disallowedTools", "WebFetch", "WebSearch"]
        if headless:
            argv.append("-p")
    elif agent == "codex":
        argv = ["codex"]
        if headless:
            argv.append("exec")
        argv += [*CODEX_OVERRIDES, "--dangerously-bypass-approvals-and-sandbox"]
        if not box.web_tools:
            argv += ["-c", "web_search=disabled"]
        if headless:
            argv += ["--skip-git-repo-check", "-"]
    elif agent == "pi":
        argv = ["pi"]
        if headless:
            argv.append("-p")
    else:
        raise ResolveError(f"unknown agent {agent!r}")
    return argv + list(args)


def _norm(p: str, ci: bool) -> str:
    return p.casefold() if ci else p


def mount_for(profile: Profile, host_dir: str, ci: bool | None = None):
    """(mount, relative parts) for the deepest mount containing host_dir, or None."""
    ci = sys.platform == "darwin" if ci is None else ci
    real = os.path.realpath(host_dir)
    best = None
    for m in profile.mounts:
        root = m.host_real or os.path.realpath(os.path.expanduser(m.host))
        r, c = _norm(root.rstrip("/") or "/", ci), _norm(real, ci)
        if c == r or c.startswith(r.rstrip("/") + "/"):
            rel = real[len(root.rstrip("/")) :].lstrip("/")
            if best is None or len(root) > len(best[2]):
                best = (m, rel, root)
    return None if best is None else best[:2]


def container_workdir(profile: Profile, host_dir: str, ci: bool | None = None) -> str:
    """Container dir for host_dir if it is inside a mount, else the first mount."""
    hit = mount_for(profile, host_dir, ci)
    if hit is None:
        return profile.mounts[0].path
    m, rel = hit
    return m.path if not rel else m.path.rstrip("/") + "/" + rel


def exec_argv(project: str, compose_file: str, workdir: str, cmd: list[str], tty: bool):
    """`docker compose exec` through with-secrets. Never a login shell."""
    argv = ["docker", "compose", "-p", project, "-f", compose_file, "exec"]
    if not tty:
        argv.append("-T")
    return [*argv, "-w", workdir, "agent", WITH_SECRETS, *cmd]


def list_profiles(pdir: Path) -> list[str]:
    return sorted(p.stem for p in pdir.glob("*.toml")) if pdir.is_dir() else []


def resolve_profile(pdir: Path, cwd: str, ci: bool | None = None) -> str:
    """Profile whose mount contains cwd. Error lists candidates when none or many."""
    names = list_profiles(pdir)
    hits, bad = [], []
    for n in names:
        try:
            prof = load_profile(pdir / f"{n}.toml", host_checks=False)
        except ProfileError:
            bad.append(n)
            continue
        if mount_for(prof, cwd, ci) is not None:
            hits.append(n)
    if len(hits) == 1:
        return hits[0]
    note = f" (invalid, skipped: {', '.join(bad)})" if bad else ""
    if not hits:
        cands = ", ".join(names) or "none; create one with `agentbox init`"
        raise ResolveError(f"no profile mounts {cwd}; name one explicitly. Profiles: {cands}{note}")
    raise ResolveError(f"several profiles mount {cwd}: {', '.join(hits)}; name one{note}")
