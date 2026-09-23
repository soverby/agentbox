"""agentbox command line (PLAN §2.3)."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from . import (
    __version__,
    allowedit,
    compose,
    denied,
    docker,
    egress,
    images,
    launch,
    mountstate,
    network,
    paths,
    presets,
)
from . import box as boxmod
from . import doctor as doc
from . import runs as runsmod
from . import update as upd
from .profile import AGENTS, PROFILE_NAME_RE, ProfileError, load_profile, parse_profile
from .template import render_default_profile


class CliError(Exception):
    pass


def err(msg: str) -> None:
    print(f"agentbox: {msg}", file=sys.stderr, flush=True)


def is_tty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def resolve(name: str | None) -> str:
    if name:
        return name
    return launch.resolve_profile(paths.profiles_dir(), os.getcwd())


def print_results(results: list[doc.Result]) -> bool:
    for r in results:
        print(r.line(), flush=True)
    return not any(r.status == "FAIL" for r in results)


def ensure_up(b: boxmod.Box, accept_mount_change: bool = False) -> None:
    """`up` + fast doctor subset (1, 2, 6, 9). Refuses sessions on failure."""
    boxmod.up(b, accept_mount_change)
    res = doc.fast(b)
    bad = [r for r in res if r.status == "FAIL"]
    if bad:
        raise CliError(
            "fast isolation checks failed, so no session starts (the box is up for "
            "inspection):\n  "
            + "\n  ".join(r.line() for r in bad)
            + f"\nFix the cause (details: `agentbox doctor {b.name}`), then run "
            f"`agentbox up {b.name}`."
        )


# ---------------------------------------------------------------- commands
def cmd_validate(args) -> int:
    try:
        profile = load_profile(args.file, name=args.name)
    except ProfileError as e:
        for path, msg in e.problems:
            print(f"error: {path}: {msg}", file=sys.stderr)
        return 1
    print(json.dumps(dataclasses.asdict(profile), indent=2))
    return 0


def cmd_init(args) -> int:
    name = args.name
    if not PROFILE_NAME_RE.fullmatch(name):
        raise CliError(f"profile name {name!r} must match {PROFILE_NAME_RE.pattern}")
    f = paths.profile_file(name)
    if f.exists():
        raise CliError(f"{f} exists; not overwriting")
    agents = None
    if args.agents:
        agents = [a for x in args.agents for a in x.split(",") if a]
        for a in agents:
            if a not in AGENTS:
                raise CliError(f"unknown agent {a!r} (one of {', '.join(AGENTS)})")
    mount = os.path.abspath(os.path.expanduser(args.mount))
    text = render_default_profile(name, mount, agents, args.open, args.allow_dotpath)
    try:
        parse_profile(tomllib.loads(text), name, host_checks=True)
    except ProfileError as e:
        raise CliError(f"profile not written:\n{e}") from None
    f.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    print(f"wrote {f}")
    return 0


def cmd_up(args) -> int:
    b = boxmod.load(resolve(args.profile))
    with boxmod.session_lock(b):
        ensure_up(b, args.accept_mount_change)
    print(f"{b.name}: up ({b.project})")
    return 0


def cmd_down(args) -> int:
    b = boxmod.load(resolve(args.profile))
    boxmod.down(b)
    print(f"{b.name}: down")
    return 0


def cmd_ls(args) -> int:
    names = launch.list_profiles(paths.profiles_dir())
    running = docker.running_projects()
    rows = []
    for n in names:
        try:
            p = load_profile(paths.profile_file(n), n)
            info = f"{p.network.mode:<6}  " + ", ".join(f"{m.host} ({m.mode})" for m in p.mounts)
        except ProfileError:
            info = "invalid profile (run `agentbox validate`)"
        state = "running" if "agent" in running.get(compose.project_name(n), []) else "stopped"
        rows.append(f"{n:<20}  {state:<7}  {info}")
    print("\n".join(rows) if rows else "no profiles; create one with `agentbox init`")
    return 0


def session(b: boxmod.Box, cmd: list[str]) -> int:
    with boxmod.session_lock(b):
        ensure_up(b)
        wd = launch.container_workdir(b.profile, os.getcwd())
        argv = launch.exec_argv(b.project, str(b.compose_file), wd, cmd, is_tty())
        return subprocess.call(argv)


def cmd_shell(args) -> int:
    b = boxmod.load(resolve(args.profile))
    return session(b, args.rest or ["bash"])


def cmd_agent(args) -> int:
    b = boxmod.load(resolve(args.profile))
    return session(b, launch.agent_argv(b.profile, args.command, args.rest))


def cmd_run(args) -> int:
    b = boxmod.load(args.profile)
    prompt_file = Path(args.prompt_file)
    try:
        prompt = prompt_file.read_bytes()
    except OSError as e:
        raise CliError(f"cannot read prompt file: {e}") from None
    argv = launch.agent_argv(b.profile, args.agent, [], headless=True)
    rd = runsmod.new_run_dir(b.state / "runs", args.agent)
    meta = {
        "profile": b.name,
        "agent": args.agent,
        "argv": argv,
        "prompt": "stdin",
        "prompt_file": str(prompt_file.resolve()),
        "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
        "started": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    transcript = runsmod.transcript_path(rd)
    rc = 125  # the box could not start / the run did not happen
    done = False
    with boxmod.session_lock(b) as lock:
        was_running = boxmod.is_running(b)
        meta["box_was_running"] = was_running
        try:
            try:
                ensure_up(b)
            except Exception as e:
                transcript.write_text(f"agentbox: box start failed: {e}\n")
                raise
            wd = launch.container_workdir(b.profile, os.getcwd())
            meta["workdir"] = wd
            cmd = launch.exec_argv(b.project, str(b.compose_file), wd, argv, tty=False)
            with transcript.open("w") as t, prompt_file.open("rb") as stdin:
                rc = subprocess.run(cmd, stdout=t, stderr=subprocess.STDOUT, stdin=stdin).returncode
            runsmod.finish(rd, rc, meta)
            done = True
        finally:
            if not done:
                runsmod.finish(rd, rc, meta)
            if not was_running:
                stop_if_idle(b, lock)
    print(f"run: {rd} (exit {rc})")
    return rc


def stop_if_idle(b: boxmod.Box, lock) -> None:
    """Stop a box `run` started, unless another session joined it."""
    if not boxmod.try_exclusive(lock):
        err(f"{b.name}: another agentbox session uses the box; leaving it up")
        return
    try:
        others = boxmod.other_processes(b)
    except Exception as e:  # noqa: BLE001
        err(f"{b.name}: cannot list box processes ({e}); leaving it up")
        return
    if others:
        err(f"{b.name}: other processes run in the box ({others[0]!r}); leaving it up")
        return
    with contextlib.suppress(Exception):
        boxmod.down(b)


def cmd_allow(args) -> int:
    if args.domain is None:
        name, domain = resolve(None), args.first
    else:
        name, domain = args.first, args.domain
    return allow_domain(name, domain)


def allow_domain(name: str, domain: str) -> int:
    f = paths.profile_file(name)
    if not f.is_file():
        raise CliError(f"no profile {name!r}")
    old_text = f.read_text(encoding="utf-8")
    try:
        new_text, changed = allowedit.add_allow(old_text, domain)
    except allowedit.AllowEditError as e:
        raise CliError(str(e)) from None
    try:
        parse_profile(tomllib.loads(new_text), name)
    except ProfileError as e:
        raise CliError(f"not changed: {e}") from None
    if changed:
        _atomic_write(f, new_text)
    b = boxmod.load(name)
    if not boxmod.is_running(b):
        print(f"{domain}: {'added' if changed else 'already allowed'}; applies at next up")
        return 0
    try:
        boxmod.reload_egress(b)
    except boxmod.BoxError as e:
        if changed:
            _atomic_write(f, old_text)
        raise CliError(f"reload failed, profile and allowlist restored: {e}") from None
    print(f"{domain}: {'added' if changed else 'already allowed'}; egress reloaded")
    return 0


def _atomic_write(f: Path, text: str) -> None:
    tmp = f.with_name(f".{f.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, f.stat().st_mode & 0o777)
    tmp.replace(f)


def cmd_denied(args) -> int:
    name = resolve(args.profile)
    b = boxmod.load(name)
    log = b.state / "logs" / "egress" / "egress.log"
    since = denied.parse_since(args.since) if args.since else 0.0
    allowlist = [] if b.profile.network.mode == "open" else boxmod.agent_domains(b.profile)
    lines = log.read_text(errors="replace").splitlines() if log.is_file() else []
    items = denied.parse(lines, b.ips()["agent"], allowlist, since, doc.load_windows(b.state))
    if args.json:
        print(json.dumps([d.as_json() for d in items], indent=1))
        return 0
    if not items:
        print("no denied requests")
        return 0
    for d in items:
        print(f"{d.count:>5}  {d.host:<40}  ports {','.join(sorted(d.ports))}  {d.reason}")
    if is_tty():
        for d in items:
            if not d.allowable:
                continue
            ans = input(f"allow {d.host}? [y/N] ").strip().lower()
            if ans in ("y", "yes"):
                allow_domain(name, d.host)
    return 0


def cmd_doctor(args) -> int:
    b = boxmod.load(resolve(args.profile))
    if not boxmod.is_running(b):  # a running box is tested as it is, not re-rendered
        boxmod.up(b)
    ok = print_results(doc.full(b))
    return 0 if ok else 1


def cmd_update(args) -> int:
    repo = paths.repo_root()
    env_file = repo / "images/agent/versions.env"
    current = upd.read_env(env_file.read_text())
    latest = upd.lookup(current)
    print(upd.format_table(upd.table(current, latest)))
    failed = sorted(k for k, v in latest.items() if v.startswith(upd.FAILED))
    if failed:
        print(f"agentbox update: {len(failed)} lookup(s) failed; those pins are left unchanged")
    if args.check:
        return 0

    def build() -> None:
        images.build_agent(repo)
        want = f"{images.AGENT_REPO}:{images.agent_hash(repo)}"
        if docker.image_id(want) is None:
            raise upd.UpdateError(f"build did not tag {want}")

    def relock() -> None:
        docker.run(["bash", str(repo / "images/agent/pi-mcp-adapter/lock.sh")], capture=False)

    ok = upd.apply(repo, latest, build, scratch_doctor, relock)
    return 0 if ok else 1


def scratch_doctor() -> bool:
    """Full doctor on a throwaway profile with its own config/state roots."""
    tag = secrets.token_hex(4)
    work = Path.home() / f".agentbox-update-{tag}"
    roots = Path(tempfile.mkdtemp(prefix="agentbox-update-"))
    saved = {k: os.environ.get(k) for k in ("AGENTBOX_CONFIG_HOME", "AGENTBOX_STATE_HOME")}
    real_cfg = paths.config_home()
    work.mkdir()
    b = None
    try:
        os.environ["AGENTBOX_CONFIG_HOME"] = str(roots / "config")
        os.environ["AGENTBOX_STATE_HOME"] = str(roots / "state")
        (roots / "config").mkdir()
        if (real_cfg / "config.toml").is_file():
            shutil.copy(real_cfg / "config.toml", roots / "config" / "config.toml")
        name = f"scratch-{tag}"
        cmd_init(argparse.Namespace(name=name, mount=str(work), agents=None, open=False,
                                    allow_dotpath=True))  # fmt: skip
        b = boxmod.load(name)
        ensure_up(b)
        return print_results(doc.full(b))
    except Exception as e:
        err(f"scratch doctor: {e}")
        return False
    finally:
        if b is not None:
            with contextlib.suppress(Exception):
                boxmod.down(b, volumes=True)
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(roots, ignore_errors=True)


# ---------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentbox", description="Docker sandboxes for AI agents")
    parser.add_argument("--version", action="version", version=f"agentbox {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    p = sub.add_parser("validate", help="validate a profile file and print it resolved")
    p.add_argument("file")
    p.add_argument("--name", help="profile name (default: file name without .toml)")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("init", help="create a profile")
    p.add_argument("name")
    p.add_argument("--mount", required=True, help="host path to mount rw")
    p.add_argument("--agents", action="append", help="comma-separated (default: all)")
    p.add_argument("--open", action="store_true", help='network mode "open"')
    p.add_argument("--allow-dotpath", action="store_true", help="mount is a dot-path under $HOME")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("up", help="start the box")
    p.add_argument("profile", nargs="?")
    p.add_argument(
        "--accept-mount-change",
        action="store_true",
        help="accept mounts whose resolved host path changed since the last up",
    )
    p.set_defaults(func=cmd_up)
    for cmd, fn, hlp in (
        ("down", cmd_down, "stop the box (keeps the home volume)"),
        ("doctor", cmd_doctor, "full isolation self-test"),
    ):
        p = sub.add_parser(cmd, help=hlp)
        p.add_argument("profile", nargs="?")
        p.set_defaults(func=fn)

    p = sub.add_parser("ls", help="list profiles")
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("shell", help="bash in the box [-- cmd ...]")
    p.add_argument("profile", nargs="?")
    p.set_defaults(func=cmd_shell)
    for a in AGENTS:
        p = sub.add_parser(a, help=f"{a} in the box [-- args ...]")
        p.add_argument("profile", nargs="?")
        p.set_defaults(func=cmd_agent)

    p = sub.add_parser("run", help="headless agent run")
    p.add_argument("profile")
    p.add_argument("--agent", required=True, choices=AGENTS)
    p.add_argument("--prompt-file", required=True)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("allow", help="allow a domain: allow [profile] <domain>")
    p.add_argument("first")
    p.add_argument("domain", nargs="?")
    p.set_defaults(func=cmd_allow)

    p = sub.add_parser("denied", help="recent denied domains")
    p.add_argument("profile", nargs="?")
    p.add_argument("--since", help="30m, 2h, 1d, or ISO date/time")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_denied)

    p = sub.add_parser("update", help="bump versions.env, rebuild, doctor")
    p.add_argument("--check", action="store_true", help="only list current vs latest")
    p.set_defaults(func=cmd_update)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    rest: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, rest = argv[:i], argv[i + 1 :]
    args = build_parser().parse_args(argv)
    if rest and args.func not in (cmd_shell, cmd_agent):
        err("`--` arguments are only for shell, claude, codex, pi")
        return 2
    args.rest = rest
    try:
        return args.func(args)
    except (
        CliError,
        boxmod.BoxError,
        launch.ResolveError,
        docker.DockerError,
        images.ImageError,
        paths.ConfigError,
        denied.DeniedError,
        upd.UpdateError,
        egress.EgressError,
        network.NetworkError,
        presets.PresetError,
        mountstate.MountChangeError,
    ) as e:
        err(str(e))
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
