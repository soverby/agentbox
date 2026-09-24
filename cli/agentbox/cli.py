"""agentbox command line (PLAN §2.3)."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import getpass
import hashlib
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import (
    __version__,
    allowedit,
    compose,
    delivery,
    denied,
    docker,
    egress,
    hostscan,
    images,
    launch,
    mcpcmd,
    mcpoauth,
    mountstate,
    network,
    paths,
    presets,
    schedule,
    secretstore,
    term,
)
from . import box as boxmod
from . import doctor as doc
from . import runs as runsmod
from . import update as upd
from .profile import (
    AGENTS,
    CLAUDE_TOKEN,
    OAUTH_PREFIX,
    PROFILE_NAME_RE,
    ProfileError,
    code_mount_problem,
    load_profile,
    oauth_secret_name,
    parse_profile,
    secret_name_problem,
)
from .template import render_default_profile


class CliError(Exception):
    pass


def err(msg: str) -> None:
    print(f"agentbox: {term.clean(msg, multiline=True)}", file=sys.stderr, flush=True)


def is_tty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def resolve(name: str | None) -> str:
    if name:
        return name
    return launch.resolve_profile(paths.profiles_dir(), os.getcwd())


def print_results(results: list[doc.Result]) -> bool:
    for r in results:
        print(term.clean(r.line()), flush=True)
    return not any(r.status == "FAIL" for r in results)


def ensure_up(b: boxmod.Box, accept_mount_change: bool = False, explicit: bool = False) -> None:
    """`up` + fast doctor subset (1, 2, 6, 9). Refuses sessions on failure."""
    boxmod.up(b, accept_mount_change, explicit)
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
            print(term.clean(f"error: {path}: {msg}", multiline=True), file=sys.stderr)
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
        ensure_up(b, args.accept_mount_change, explicit=True)
        boxmod.pin(b)
    print(f"{b.name}: up ({b.project})")
    return 0


def cmd_down(args) -> int:
    b = boxmod.load(resolve(args.profile))
    volumes = getattr(args, "volumes", False)
    boxmod.down(b, volumes=volumes)
    if volumes:
        print(f"{b.name}: down; home and OAuth volumes removed (log in to Codex/Pi again)")
    else:
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


def host_scan_start(b: boxmod.Box, path: Path) -> None:
    """Snapshot host-executed config in the rw mounts (PLAN §1); never blocks."""
    try:
        hostscan.save(path, hostscan.snapshot(b.profile))
    except Exception as e:  # noqa: BLE001 - detection is warn-only
        err(f"host config snapshot failed: {e}")


def host_scan_end(b: boxmod.Box, path: Path) -> tuple[list[str], bool]:
    """(changes, incomplete) since host_scan_start; removes the snapshot."""
    old = hostscan.load(path)
    path.unlink(missing_ok=True)
    if old is None:
        return [], False
    try:
        new = hostscan.snapshot(b.profile)
    except Exception as e:  # noqa: BLE001
        return [f"host config re-scan failed: {term.clean(e)}"], True
    return hostscan.diff(old, new), bool(old.get("incomplete") or new.get("incomplete"))


def session(b: boxmod.Box, cmd: list[str], env: dict[str, str] | None = None) -> int:
    with boxmod.session_lock(b):
        ensure_up(b)
        boxmod.pin(b)
        wd = launch.container_workdir(b.profile, os.getcwd())
        argv = launch.exec_argv(b.project, str(b.compose_file), wd, cmd, is_tty(), env)
        snap = b.state / "hostscan" / f"session-{os.getpid()}-{secrets.token_hex(4)}.json"
        host_scan_start(b, snap)
        try:
            return subprocess.call(argv)
        finally:
            changes, incomplete = host_scan_end(b, snap)
            if msg := hostscan.report(changes, incomplete):
                print(msg, file=sys.stderr, flush=True)


def cmd_shell(args) -> int:
    b = boxmod.load(resolve(args.profile))
    return session(b, args.rest or ["bash"])


def cmd_agent(args) -> int:
    b = boxmod.load(resolve(args.profile))
    route = launch.parse_model(b.profile, args.model)
    ln = launch.agent_launch(b.profile, args.command, args.rest, model=route)
    return session(b, ln.argv, ln.env)


def cmd_run(args) -> int:
    b = boxmod.load(args.profile)
    timeout = schedule.parse_timeout(args.timeout) if args.timeout else None
    rc, rd = run_headless(b, args.agent, Path(args.prompt_file), args.model, os.getcwd(),
                          timeout=timeout)  # fmt: skip
    print(term.clean(f"run: {rd} (exit {rc})"))
    return rc


Terminated = schedule.Terminated
RC_TIMEOUT = 124
RC_TERMINATED = 143


def kill_run(b: boxmod.Box, run_id: str, proc: subprocess.Popen, all_procs: bool = False) -> None:
    """Kill the `docker compose exec` client and the run's processes in the box
    (`all_procs`: every process but init and the box main process)."""
    with contextlib.suppress(Exception):
        proc.kill()
    script = runsmod.kill_all_script() if all_procs else runsmod.kill_script(run_id)
    with contextlib.suppress(Exception):
        boxmod.dc(b, "exec", "-T", "agent", "sh", "-c", script, check=False, timeout=60)


def run_headless(
    b: boxmod.Box,
    agent: str,
    prompt_file: Path,
    model: str | None,
    host_dir: str,
    made: list[Path] | None = None,
    timeout: float | None = None,
) -> tuple[int, Path]:
    """`run` bookkeeping; `made` gets the run dir as soon as it exists.
    Always ends with stop_if_idle (a pinned box stays up)."""
    try:
        prompt = prompt_file.read_bytes()
    except OSError as e:
        raise CliError(f"cannot read prompt file: {e}") from None
    route = launch.parse_model(b.profile, model)
    ln = launch.agent_launch(b.profile, agent, [], headless=True, model=route)
    argv = ln.argv
    rd = runsmod.new_run_dir(b.state / "runs", agent)
    if made is not None:
        made.append(rd)
    runsmod.prune(b.state / "runs", b.cfg.runs_keep, current=rd)
    meta = {
        "profile": b.name,
        "agent": agent,
        "model": model,
        "argv": argv,
        "env": ln.env,
        "prompt": "stdin",
        "prompt_file": str(prompt_file.resolve()),
        "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
        "started": datetime.now(UTC).isoformat(timespec="seconds"),
        "timeout": timeout,
    }
    transcript = runsmod.transcript_path(rd)
    rc = 125  # the box could not start / the run did not happen
    with boxmod.session_lock(b):
        was_running = boxmod.is_running(b)
        meta["box_was_running"] = was_running
        if not was_running:  # a pin from an earlier `up` no longer describes this box
            (b.state / boxmod.PIN_FILE).unlink(missing_ok=True)
        try:
            try:
                ensure_up(b)
            except Exception as e:
                transcript.write_text(f"agentbox: box start failed: {e}\n")
                raise
            wd = launch.container_workdir(b.profile, host_dir)
            meta["workdir"] = wd
            host_scan_start(b, rd / "hostscan.json")
            env = {**ln.env, runsmod.RUN_ENV: rd.name}
            cmd = launch.exec_argv(b.project, str(b.compose_file), wd, argv, tty=False, env=env)
            with transcript.open("wb") as t, prompt_file.open("rb") as stdin:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        stdin=stdin)  # fmt: skip
                copier = threading.Thread(target=runsmod.copy_capped, args=(proc.stdout, t),
                                          daemon=True)  # fmt: skip
                copier.start()
                try:
                    rc = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    # An unpinned box is the run's own: leftovers die too.
                    kill_run(b, rd.name, proc, all_procs=not boxmod.is_pinned(b))
                    proc.wait()
                    rc = RC_TIMEOUT
                    meta["killed"] = f"timeout after {timeout:.0f} s"
                except BaseException as e:
                    kill_run(b, rd.name, proc)
                    with contextlib.suppress(Exception):
                        proc.wait(timeout=30)
                    rc = RC_TERMINATED if isinstance(e, Terminated | KeyboardInterrupt) else rc
                    meta["killed"] = str(e) or type(e).__name__
                    raise
                finally:
                    copier.join(timeout=30)
                    if "killed" in meta:
                        t.write(f"\n[agentbox: run killed: {meta['killed']}]\n".encode())
            runsmod.finish(rd, rc, meta)
        except (Terminated, KeyboardInterrupt) as e:
            rc = RC_TERMINATED
            meta.setdefault("killed", str(e) or type(e).__name__)
            raise
        finally:
            changes, incomplete = host_scan_end(b, rd / "hostscan.json")
            if changes:
                meta["host_config_changes"] = changes
            if incomplete:
                meta["host_config_scan"] = hostscan.INCOMPLETE
            if msg := hostscan.report(changes, incomplete):
                print(msg, file=sys.stderr, flush=True)
            runsmod.finish(rd, rc, meta)
            note: list[str] = []
            why = stop_if_idle(b, note)
            if why:
                meta["left_up"] = why
            if note:
                meta["stopped"] = note[0]
            if why or note:
                runsmod.finish(rd, rc, meta)
    return rc, rd


def stop_if_idle(b: boxmod.Box, note: list[str] | None = None) -> str | None:
    """Stop the box after a headless run unless it is pinned or in use."""
    try:
        why = boxmod.stop_if_idle(b, note)
    except Exception as e:  # noqa: BLE001
        why = f"stop failed ({e})"
    if why and why != boxmod.PINNED:
        err(f"{b.name}: {why}; leaving it up")
        return why
    return None


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
    logdir = b.state / "logs" / "egress"
    since = denied.parse_since(args.since) if args.since else 0.0
    allowlist = [] if b.profile.network.mode == "open" else boxmod.agent_domains(b.profile)

    def lines():
        # rotated file first; at most denied.READ_MAX bytes from the end of each
        for log in (logdir / "egress.log.1", logdir / "egress.log"):
            if log.is_file():
                yield from denied.tail_lines(log)

    stats: dict = {}
    items = denied.parse(
        lines(), b.ips()["agent"], allowlist, since, doc.load_windows(b.state), stats=stats
    )
    if stats.get("dropped"):
        print(
            f"note: {stats['dropped']} denied request(s) to more than "
            f"{denied.MAX_HOSTS} hosts not listed",
            file=sys.stderr,
        )
    if args.json:
        print(json.dumps([d.as_json() for d in items], indent=1))
        return 0
    if not items:
        print("no denied requests")
        return 0
    for d in items:
        line = f"{d.count:>5}  {d.host:<40}  ports {','.join(sorted(d.ports))}  {d.reason}"
        print(term.clean(line))
    if is_tty():
        for d in items:
            if not d.allowable:
                continue
            ans = input(term.clean(f"allow {d.host}? [y/N] ")).strip().lower()
            if ans in ("y", "yes"):
                allow_domain(name, d.host)
    return 0


def cmd_doctor(args) -> int:
    b = boxmod.load(resolve(args.profile))
    with boxmod.session_lock(b):  # a headless run's stop-if-idle sees doctor
        started = not boxmod.is_running(b)
        if started:  # a running box is tested as it is, not re-rendered
            (b.state / boxmod.PIN_FILE).unlink(missing_ok=True)  # stale: box is down
            boxmod.up(b)
        try:
            ok = print_results(doc.full(b))
        finally:
            if started:  # stop it again unless pinned or another session uses it
                why = stop_if_idle(b)
                if why is None and not boxmod.is_pinned(b):
                    print(f"{b.name}: stopped again (doctor started it)")
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
        return print_results(doc.full(b, scratch=True))
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


# ---------------------------------------------------------------- secrets
@dataclasses.dataclass
class SecretTarget:
    name: str
    ref: str
    where: str  # "shared" or the profile name


def secret_target(shared: bool, first: str, second: str | None) -> SecretTarget:
    """`[--shared | <profile>] NAME` -> where the value lives."""
    cfg = paths.load_config()
    if shared:
        if second is not None:
            raise CliError("give either --shared or a profile, not both")
        name = first
    else:
        prof_name, name = (first, second) if second is not None else (resolve(None), first)
    if name == secretstore.OP_SA_NAME:
        # Host-only: the per-profile 1Password service-account token (PLAN §2.4).
        if shared:
            raise CliError(f"{name} is per profile only; give the profile, not --shared")
        return SecretTarget(name, secretstore.sa_token_ref(cfg, prof_name), prof_name)
    if msg := secret_name_problem(name):
        raise CliError(msg)
    if shared:
        return SecretTarget(name, secretstore.default_ref(cfg, "_shared", name), "shared")
    f = paths.profile_file(prof_name)
    if not f.is_file():
        raise CliError(f"no profile {prof_name!r} ({f})")
    try:
        prof = load_profile(f, prof_name)
    except ProfileError as e:
        raise CliError(f"profile {prof_name} is invalid:\n{e}") from None
    s = prof.secrets.get(name)
    if s is None:
        err(f"{name} is not in [secrets] of {prof_name}; it is not delivered until you add it")
        return SecretTarget(name, secretstore.default_ref(cfg, prof_name, name), prof_name)
    if s.scope == "shared":
        raise CliError(f"{name} is shared in profile {prof_name}: use `--shared {name}`")
    return SecretTarget(name, secretstore.ref_for(s, prof_name, cfg), prof_name)


def read_value(prompt: str, from_stdin: bool) -> str:
    """One value: hidden prompt, or one line from stdin (one trailing newline removed)."""
    if from_stdin:
        v = sys.stdin.read()
        v = v[:-1] if v.endswith("\n") else v
        v = v[:-1] if v.endswith("\r") else v
    else:
        if not sys.stdin.isatty():
            raise CliError("stdin is not a terminal: use --stdin to pipe the value")
        v = getpass.getpass(prompt)
    if msg := secretstore.value_problem(v):
        raise CliError(msg)
    return v


def cmd_secret_set(args) -> int:
    t = secret_target(args.shared, args.first, args.second)
    value = read_value(f"{t.name} (input hidden): ", args.stdin)
    secretstore.set(t.ref, value)
    print(f"{t.name}: stored ({t.where}, {t.ref})")
    return 0


def cmd_secret_rm(args) -> int:
    t = secret_target(args.shared, args.first, args.second)
    if not secretstore.delete(t.ref):
        raise CliError(f"{t.name}: not found at {t.ref}")
    print(f"{t.name}: removed ({t.where}, {t.ref})")
    return 0


def present(ref: str, fetch) -> bool:
    """op refs need the profile's service-account token; others use exists()."""
    return fetch(ref) is not None if ref.startswith("op://") else secretstore.exists(ref)


def secret_rows(prof, cfg) -> list[tuple[str, str, str, str, str]]:
    """(name, scope, status, targets, ref) for a profile. Never values."""
    rows = []
    fetch = secretstore.fetcher(cfg, prof.name)
    for s in sorted(prof.secrets.values(), key=lambda x: x.name):
        ref = secretstore.ref_for(s, prof.name, cfg)
        status = "present" if present(ref, fetch) else "missing"
        scope = s.scope or "ref"
        rows.append((s.name, scope, status, ",".join(s.to), ref))
    for n, targets in delivery.BOX_TOKENS.items():
        if delivery.TOKEN_NEEDS.get(n) == "router" and not compose.has_router(prof):
            continue
        rows.append((n, "box", "made at up", ",".join(targets), "(state, rotated at down)"))
    sa = secretstore.sa_token_ref(cfg, prof.name)
    if secretstore.exists(sa):
        rows.append((secretstore.OP_SA_NAME, "host", "present", "-", sa))
    return rows


def cmd_secret_ls(args) -> int:
    cfg = paths.load_config()
    if args.shared:
        if args.profile:
            raise CliError("give either --shared or a profile, not both")
        users: dict[str, list[str]] = {CLAUDE_TOKEN: []}
        for n in launch.list_profiles(paths.profiles_dir()):
            try:
                prof = load_profile(paths.profile_file(n), n)
            except ProfileError:
                continue
            for s in prof.secrets.values():
                if s.scope == "shared":
                    users.setdefault(s.name, []).append(n)
        print(f"{'NAME':<32} {'STATUS':<8} USED BY")
        for name in sorted(users):
            ref = secretstore.default_ref(cfg, "_shared", name)
            status = "present" if secretstore.exists(ref) else "missing"
            print(f"{name:<32} {status:<8} {', '.join(users[name]) or '-'}")
        return 0
    name = resolve(args.profile)
    try:
        prof = load_profile(paths.profile_file(name), name)
    except (ProfileError, OSError) as e:
        raise CliError(f"profile {name}: {e}") from None
    print(f"{'NAME':<32} {'SCOPE':<8} {'STATUS':<10} {'TARGETS':<24} REF")
    for r in secret_rows(prof, cfg):
        print(f"{r[0]:<32} {r[1]:<8} {r[2]:<10} {r[3]:<24} {r[4]}")
    return 0


# ---------------------------------------------------------------- setup, login
CLAUDE_TOKEN_PREFIX = "sk-ant-oat01-"
MIN_OLLAMA = (0, 14, 0)


def ollama_note(url: str = "http://127.0.0.1:11434/api/version") -> str:
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=3) as r:  # noqa: S310 - fixed local URL
            v = json.loads(r.read()).get("version", "")
    except (OSError, ValueError):
        return "host Ollama: not running (optional; start it for local models)"
    try:
        parts = tuple(int(x) for x in v.split("-")[0].split(".")[:3])
    except ValueError:
        return f"host Ollama {v}: cannot parse the version"
    if parts < MIN_OLLAMA:
        return f"host Ollama {v}: older than 0.14.0; update it (the gate needs >= 0.14.0)"
    return f"host Ollama {v}: ok"


def claude_token_problem(v: str) -> str | None:
    if not v.startswith(CLAUDE_TOKEN_PREFIX):
        return f"the token must start with {CLAUDE_TOKEN_PREFIX} (output of `claude setup-token`)"
    return secretstore.value_problem(v)


def setup_token(from_stdin: bool) -> None:
    cfg = paths.load_config()
    ref = secretstore.default_ref(cfg, "_shared", CLAUDE_TOKEN)
    if secretstore.exists(ref):
        if from_stdin or not is_tty():
            print(f"{CLAUDE_TOKEN}: already stored ({ref}); keeping it")
            return
        if input(f"{CLAUDE_TOKEN} is already stored. Replace it? [y/N] ").strip().lower() not in (
            "y",
            "yes",
        ):
            print(f"{CLAUDE_TOKEN}: kept")
            return
    if not from_stdin:
        print(
            "Run `claude setup-token` on the host (it opens a browser and prints a one-year "
            "token),\nthen paste the token here. The input is hidden."
        )
    v = read_value("Claude token: ", from_stdin)
    if msg := claude_token_problem(v):
        raise CliError(msg)
    secretstore.set(ref, v)
    print(f"{CLAUDE_TOKEN}: stored ({ref})")


def cmd_setup(args) -> int:
    vals = paths.read_config_values()
    backend = vals.get("secret_backend")
    if backend in (None, "keychain") and not secretstore.keychain_available():
        where = "no secret_backend in" if backend is None else "secret_backend = keychain in"
        raise CliError(f"{where} {paths.config_file()}: {secretstore.KEYCHAIN_ONLY_MAC}; "
                       "then run setup again")  # fmt: skip
    r = docker.run(["docker", "info", "--format", "{{.ServerVersion}}"], check=False)
    if r.returncode != 0:
        raise CliError("Docker is not running (start Docker Desktop, then run setup again)")
    print(f"docker: engine {r.stdout.strip()}")
    repo = paths.repo_root()
    print(
        "images: building or reusing agentbox/agent, egress, ollama-gate, mcp-gateway ...",
        flush=True,
    )
    print(f"images: {images.ensure_agent(repo)}")
    for side in ("egress", "ollama-gate", "mcp-gateway"):
        print(f"images: {images.ensure_sidecar(repo, side)}")
    if backend is None:
        vals["secret_backend"] = "keychain"
        print(f"config: wrote {paths.write_config(vals)} (secret_backend = keychain)")
    else:
        print(f"config: {paths.config_file()} (secret_backend = {vals['secret_backend']})")
    if not args.skip_token:
        setup_token(args.token_stdin)
    print(ollama_note())
    if args.skip_doctor:
        return 0
    print("doctor: full isolation self-test on a scratch profile ...", flush=True)
    return 0 if scratch_doctor() else 1


LOGIN_HINTS = {
    "codex": (
        "Codex device-code login. First, in ChatGPT (web) open Settings > Security and turn "
        'on "Allow device code login". Then open the URL that Codex prints in your host '
        "browser and enter the code. The login stays in this profile's home volume."
    ),
    "pi": (
        "Pi login. In Pi, type /login and choose the provider (for ChatGPT: openai-codex). "
        "Open the printed URL in your host browser and sign in. The browser then goes to a "
        "localhost URL that does not load (Pi runs in the box): copy that full URL from the "
        "address bar and paste it into Pi. Quit Pi with /quit or Ctrl+C twice. The login "
        "stays in this profile's home volume."
    ),
}


def cmd_login(args) -> int:
    b = boxmod.load(args.profile)
    if args.agent not in b.profile.box.agents:
        raise CliError(f"{args.agent} is not in [box] agents of {b.name}")
    if not is_tty():
        raise CliError("login is interactive: run it in a terminal")
    print(LOGIN_HINTS[args.agent], flush=True)
    if args.agent == "codex":
        cmd = ["codex", "login", "--device-auth"]
    else:
        cmd = launch.agent_argv(b.profile, "pi", [])
    return session(b, cmd)


# ---------------------------------------------------------------- mcp (P6b)
def cmd_mcp_login(args) -> int:
    return mcpcmd.login(args.profile, args.server, no_browser=args.no_browser,
                        timeout=args.timeout, redirect_port=args.redirect_port)  # fmt: skip


def cmd_mcp_status(args) -> int:
    return mcpcmd.status(resolve(args.profile))


def cmd_mcp_logout(args) -> int:
    return mcpcmd.logout(args.profile, args.server)


# ---------------------------------------------------------------- schedule
class RunFailed(Exception):
    def __init__(self, msg: str, run_dir: Path | None, rc: int | None = None) -> None:
        super().__init__(msg)
        self.run_dir = run_dir
        self.rc = rc


def sched_runner(profile: str, agent: str, prompt: str, model: str | None, timeout=None):
    """In-process `run` for `schedule _fire`; the host dir "/" selects the first mount."""
    made: list[Path] = []
    try:
        b = boxmod.load(profile)
        return run_headless(b, agent, Path(prompt), model, "/", made, timeout=timeout)
    except Terminated as e:
        raise RunFailed(str(e), made[0] if made else None, RC_TERMINATED) from e
    except Exception as e:
        raise RunFailed(str(e), made[0] if made else None) from e


def secret_fix(prof, m) -> str:
    if m.name.startswith(OAUTH_PREFIX):
        srv = next((n for n in prof.mcp_servers if oauth_secret_name(n) == m.name), "?")
        return f"MCP server {srv} is not logged in: `agentbox mcp login {prof.name} {srv}`"
    if m.name == CLAUDE_TOKEN:
        return f"{m.name} is missing: run `agentbox setup` (it stores the shared token)"
    scope = prof.secrets[m.name].scope
    where = "--shared" if scope == "shared" else prof.name
    how = f"`agentbox secret set {where} {m.name}`" if scope else f"store it at {m.ref}"
    return f"{m.name} ({m.ref}) is missing: {how}"


def agent_credential(prof, agent: str, model: str | None) -> str | None:
    """The secret the chosen agent itself needs, if a missing one is detectable.
    Claude needs the shared token unless --model routes to ollama/ or remote/.
    Codex and Pi log in inside the box (not cheaply detectable): None."""
    if agent != "claude":
        return None
    route = launch.parse_model(prof, model)
    if route is not None and route.kind in ("ollama", "remote"):
        return None
    return CLAUDE_TOKEN


def sched_check(prof, cfg, agent: str, model: str | None) -> tuple[str | None, list[str]]:
    """(error, warnings): error only for the agent's own missing credential."""
    need = agent_credential(prof, agent, model)
    error, warnings = None, []
    for m in delivery.collect(prof, cfg, None).missing:
        if m.name == need:
            error = secret_fix(prof, m)
        elif m.name != CLAUDE_TOKEN:  # not needed by this agent/route
            warnings.append(secret_fix(prof, m))
    return error, warnings


def sched_preflight(profile: str, agent: str, model: str | None = None, code: tuple = ()):
    try:
        b = boxmod.load(profile)
        if agent not in b.profile.box.agents:
            return f"{agent} is not in [box] agents of {profile}", []
        if msg := code_mount_problem(b.profile, tuple(code)):
            return msg, []
        return sched_check(b.profile, b.cfg, agent, model)
    except Exception as e:  # noqa: BLE001
        return f"preflight failed: {e}", []


def _schedule_name(profile: str | None, name: str | None = None) -> None:
    if profile is not None and not PROFILE_NAME_RE.fullmatch(profile):
        raise CliError(f"profile name {profile!r} must match {PROFILE_NAME_RE.pattern}")
    if name is not None:
        schedule.validate_name(name)


def cmd_schedule_add(args) -> int:
    _schedule_name(args.profile, args.name)
    b = boxmod.load(args.profile)
    if args.agent not in b.profile.box.agents:
        raise CliError(f"{args.agent} is not in [box] agents of {b.name}")
    launch.parse_model(b.profile, args.model)
    spec = schedule.make_spec(args.cron, args.every, args.at, args.days)
    schedule.validate_for_platform(spec)
    now = datetime.now()
    fires = schedule.next_fires(spec, now)
    if not fires or fires[0] - now > timedelta(days=366):
        raise CliError(f"{spec.text()} never fires within a year; check the day and month fields")
    timeout = schedule.parse_timeout(args.timeout) if args.timeout else schedule.DEFAULT_TIMEOUT
    jd = schedule.job_dir(b.name, args.name)
    old = None
    if (jd / "job.json").is_file():
        if not args.force:
            raise CliError(f"schedule {args.name} exists for {b.name}; use --force to replace it")
        old = schedule.load_job(b.name, args.name)
    try:
        prompt = Path(args.prompt_file).read_bytes()
    except OSError as e:
        raise CliError(f"cannot read prompt file: {e}") from None
    prog, extra = schedule.program_args()
    label = schedule.label_for(b.name, args.name)
    job = {
        "profile": b.name,
        "name": args.name,
        "agent": args.agent,
        "model": args.model,
        "schedule": spec.as_json(),
        "timeout": timeout,
        "dir": str(jd),
        "label": label,
        "plist": str(schedule.launchagents_dir() / f"{label}.plist"),
        "argv": schedule.fire_argv(prog, b.name, args.name),
        "env": schedule.job_env(extra),
        "created": schedule.now_iso(),
    }
    if msg := code_mount_problem(b.profile, schedule.job_code_paths(job)):
        raise CliError(msg)
    schedule.check_render(job)  # before anything is written
    if old is not None:
        schedule.uninstall(old)
    existed = jd.exists()
    try:
        jd.mkdir(parents=True, exist_ok=True)
        os.chmod(jd, 0o700)
        schedule.write_private(jd / "prompt.md", prompt)
        schedule.write_private(jd / "job.json", (json.dumps(job, indent=1) + "\n").encode())
        schedule.install(job)
    except BaseException:
        with contextlib.suppress(Exception):
            schedule.uninstall(job)
        if not existed:
            shutil.rmtree(jd, ignore_errors=True)
        else:
            (jd / "job.json").unlink(missing_ok=True)
        raise
    where = job["plist"] if schedule.is_macos() else "crontab"
    tmo = schedule.fmt_every(timeout) if timeout else "none"
    print(term.clean(f"{b.name}/{args.name}: {spec.text()}, timeout {tmo} ({where})"))
    approx = " (approximate: launchd counts the interval from load and wake)" if spec.every else ""
    print("next runs" + approx + ":")
    for t in fires:
        print(f"  {t.astimezone().isoformat(timespec='minutes')}")
    print(f"test it now: agentbox schedule run-now {b.name} {args.name}")
    names = sorted(k for k in job["env"] if k not in ("PATH", "HOME"))
    print("job environment: PATH, HOME" + (", " + ", ".join(names) if names else ""))
    for w in schedule_warnings(b, args.agent, args.model, extra):
        err(w)
    return 0


def schedule_warnings(b: boxmod.Box, agent: str, model: str | None, extra: dict) -> list[str]:
    error, warns = sched_check(b.profile, b.cfg, agent, model)
    out = [f"warning: {x}" for x in ([error] if error else []) + warns]
    if "PYTHONPATH" in extra:
        out.append(
            "warning: no installed `agentbox` command was found, so the job runs "
            f"{sys.executable} -m agentbox.cli; install it with `uv tool install -e ./cli` "
            "and re-add the job with --force"
        )
    uses_op = b.cfg.secret_backend == "op" or any(
        s.scope is None and s.ref.startswith("op://") for s in b.profile.secrets.values()
    )
    if uses_op and not secretstore.exists(secretstore.sa_token_ref(b.cfg, b.name)):
        out.append(
            f"warning: {b.name} reads secrets from 1Password without a service-account token; "
            "a scheduled job cannot answer a 1Password prompt. Store one: "
            f"`agentbox secret set {b.name} {secretstore.OP_SA_NAME}`"
        )
    if agent in ("codex", "pi"):
        out.append(
            f"note: {agent} login is not checked here; if the job fails with an auth "
            f"error, run `agentbox login {b.name} {agent}`"
        )
    return out


def cmd_schedule_edit(args) -> int:
    _schedule_name(args.profile, args.name)
    job = schedule.load_job(args.profile, args.name)
    if args.prompt_file is None and args.timeout is None:
        raise CliError("give --prompt-file and/or --timeout")
    jd = Path(job["dir"])
    if args.prompt_file is not None:
        try:
            prompt = Path(args.prompt_file).read_bytes()
        except OSError as e:
            raise CliError(f"cannot read prompt file: {e}") from None
        schedule.write_private(jd / "prompt.md", prompt)
        print(f"{args.profile}/{args.name}: prompt replaced")
    if args.timeout is not None:
        job["timeout"] = schedule.parse_timeout(args.timeout)
        schedule.write_private(jd / "job.json", (json.dumps(job, indent=1) + "\n").encode())
        print(f"{args.profile}/{args.name}: timeout {args.timeout}")
    return 0


def cmd_schedule_ls(args) -> int:
    _schedule_name(args.profile)
    jobs = schedule.list_jobs(args.profile)
    if not jobs:
        print("no schedules; add one with `agentbox schedule add`")
        return 0
    now = datetime.now()
    for j in jobs:
        spec = schedule.Spec.from_json(j["schedule"])
        jd = Path(j["dir"])
        try:
            nxt = schedule.next_fires(spec, now, 1)
            nxt_s = nxt[0].astimezone().isoformat(timespec="minutes") if nxt else "-"
            if spec.every:
                nxt_s = "~" + nxt_s
        except schedule.ScheduleError:
            nxt_s = "-"
        last = schedule.read_last(j["profile"], j["name"]) or {}
        status = last.get("status", "-")
        if status == "running" and schedule.lock_free(jd):
            status = "running (stale: the fire process is gone)"
        rc = last.get("exit_code")
        lines = [
            f"{j['profile']}/{j['name']}  agent={j['agent']}  {spec.text()}  "
            f"[{schedule.installed(j)}]",
            f"  next: {nxt_s}",
            f"  last: {last.get('start', 'never')}  status={status}  "
            f"exit={'-' if rc is None else rc}",
            f"  transcript: {last.get('transcript') or '-'}",
        ]
        if last.get("message"):
            lines.append(f"  message: {last['message']}")
        if last.get("left_up"):
            lines.append(f"  {last['left_up']}")
        if last.get("stopped"):
            lines.append(f"  {last['stopped']}")
        for c in last.get("host_config_changes") or []:
            lines.append(f"  WARNING host config changed: {c}")
        for w in last.get("warnings") or []:
            lines.append(f"  warning: {w}")
        if sk := schedule.skip_summary(jd):
            lines.append(f"  {sk}")
        print(term.clean("\n".join(lines), multiline=True))
    return 0


def cmd_schedule_rm(args) -> int:
    _schedule_name(args.profile, args.name)
    jd = schedule.job_dir(args.profile, args.name)
    try:
        job = schedule.load_job(args.profile, args.name)
    except schedule.ScheduleError:
        label = schedule.label_for(args.profile, args.name)
        job = {"profile": args.profile, "name": args.name, "label": label,
               "plist": str(schedule.launchagents_dir() / f"{label}.plist")}  # fmt: skip
        if not jd.exists() and not Path(job["plist"]).exists():
            raise
    schedule.uninstall(job)
    shutil.rmtree(jd, ignore_errors=True)
    print(f"{args.profile}/{args.name}: removed (run records stay in runs/)")
    return 0


def cmd_schedule_run_now(args) -> int:
    _schedule_name(args.profile, args.name)
    job = schedule.load_job(args.profile, args.name)
    print(term.clean(f"running as the scheduler would: {' '.join(job['argv'])}"), flush=True)
    rc = subprocess.run(job["argv"], env=job["env"], cwd="/", stdin=subprocess.DEVNULL).returncode
    if rc == schedule.RC_SKIPPED:
        print(schedule.SKIP_MSG)
        return rc
    last = schedule.read_last(args.profile, args.name) or {}
    print(term.clean(f"exit {rc}; transcript: {last.get('transcript') or '-'}"))
    if last.get("message"):
        print(term.clean(f"message: {last['message']}"))
    return rc


def cmd_schedule_fire(args) -> int:
    _schedule_name(args.profile, args.name)

    def on_signal(signum, frame):
        for s in (signal.SIGTERM, signal.SIGINT):  # one unwind; cleanup is not interrupted
            signal.signal(s, signal.SIG_IGN)
        raise Terminated(signum)

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    return schedule.fire(args.profile, args.name, sched_runner, sched_preflight)


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
        if cmd == "down":
            p.add_argument(
                "-v",
                "--volumes",
                action="store_true",
                help="also remove the home volume (logins, caches, anything the agent left "
                "there) and the gateway OAuth volume: a full reset",
            )
        p.set_defaults(func=fn)

    p = sub.add_parser("ls", help="list profiles")
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("shell", help="bash in the box [-- cmd ...]")
    p.add_argument("profile", nargs="?")
    p.set_defaults(func=cmd_shell)
    model_help = (
        "ollama/<model> (host Ollama), remote/<name> ([models.remote.<name>]), or a model name"
    )
    for a in AGENTS:
        p = sub.add_parser(a, help=f"{a} in the box [-- args ...]")
        p.add_argument("profile", nargs="?")
        p.add_argument("--model", help=model_help)
        p.set_defaults(func=cmd_agent)

    p = sub.add_parser("run", help="headless agent run")
    p.add_argument("profile")
    p.add_argument("--agent", required=True, choices=AGENTS)
    p.add_argument("--prompt-file", required=True)
    p.add_argument("--model", help=model_help)
    p.add_argument("--timeout", help="kill the run after this long: 30m, 2h (rc 124)")
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

    p = sub.add_parser("secret", help="manage secrets: set / ls / rm")
    ssub = p.add_subparsers(dest="secret_command", metavar="<set|ls|rm>")
    ssub.required = True
    for cmd, fn, hlp in (
        ("set", cmd_secret_set, "store a secret: set [--shared | <profile>] NAME [--stdin]"),
        ("rm", cmd_secret_rm, "delete a secret: rm [--shared | <profile>] NAME"),
    ):
        q = ssub.add_parser(cmd, help=hlp)
        q.add_argument("--shared", action="store_true", help="shared scope (agentbox/_shared)")
        q.add_argument("first", metavar="profile|NAME")
        q.add_argument("second", nargs="?", metavar="NAME")
        if cmd == "set":
            q.add_argument("--stdin", action="store_true", help="read one value from stdin")
        else:
            q.set_defaults(stdin=False)
        q.set_defaults(func=fn)
    q = ssub.add_parser("ls", help="names, scope, present/missing, targets (never values)")
    q.add_argument("--shared", action="store_true")
    q.add_argument("profile", nargs="?")
    q.set_defaults(func=cmd_secret_ls)

    p = sub.add_parser("setup", help="first run: Docker, images, config, Claude token, doctor")
    p.add_argument("--skip-token", action="store_true", help="do not ask for the Claude token")
    p.add_argument("--token-stdin", action="store_true", help="read the Claude token from stdin")
    p.add_argument("--skip-doctor", action="store_true", help="do not run the scratch doctor")
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("login", help="subscription login in the box: login <profile> codex|pi")
    p.add_argument("profile")
    p.add_argument("agent", choices=("codex", "pi"))
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("mcp", help="OAuth MCP servers: login / status / logout")
    ssub = p.add_subparsers(dest="mcp_command", metavar="<login|status|logout>")
    ssub.required = True
    q = ssub.add_parser("login", help="OAuth login on the host: login <profile> <server>")
    q.add_argument("profile")
    q.add_argument("server")
    q.add_argument("--no-browser", action="store_true", help=argparse.SUPPRESS)
    q.add_argument("--timeout", type=float, help=argparse.SUPPRESS)
    q.add_argument("--redirect-port", type=int, default=0,
                   help="fixed loopback port (for a pre-registered client_id)")  # fmt: skip
    q.set_defaults(func=cmd_mcp_login)
    q = ssub.add_parser("status", help="per OAuth server: logged in, expiry, refresh, needs login")
    q.add_argument("profile", nargs="?")
    q.set_defaults(func=cmd_mcp_status)
    q = ssub.add_parser("logout", help="delete the token set (backend + gateway volume), revoke")
    q.add_argument("profile")
    q.add_argument("server")
    q.set_defaults(func=cmd_mcp_logout)

    p = sub.add_parser("schedule", help="scheduled headless runs: add / ls / rm / run-now / edit")
    ssub = p.add_subparsers(dest="schedule_command", metavar="<add|ls|rm|run-now|edit>")
    ssub.required = True
    q = ssub.add_parser("add", help="add a job: add <profile> --name N --agent A --prompt-file F")
    q.add_argument("profile")
    q.add_argument("--name", required=True)
    q.add_argument("--agent", required=True, choices=AGENTS)
    q.add_argument("--prompt-file", required=True, help="copied into the state dir at add")
    q.add_argument("--model", help=model_help)
    q.add_argument("--cron", help='5 fields, local time: "m h dom mon dow"')
    q.add_argument("--every", help="interval: 30m, 2h, 1d")
    q.add_argument("--at", help="HH:MM local time, every day or --days")
    q.add_argument("--days", help="with --at: mon-fri, sat-sun, mon,wed,fri")
    q.add_argument("--timeout", help="kill a run after this long (default 2h; none = no limit)")
    q.add_argument("--force", action="store_true", help="replace a job with the same name")
    q.set_defaults(func=cmd_schedule_add)
    q = ssub.add_parser("ls", help="jobs, next run, last result")
    q.add_argument("profile", nargs="?")
    q.set_defaults(func=cmd_schedule_ls)
    for cmd, fn, hlp in (
        ("rm", cmd_schedule_rm, "unload and remove a job"),
        ("run-now", cmd_schedule_run_now, "run a job now, exactly as the scheduler does"),
        ("edit", cmd_schedule_edit, "replace the prompt: edit <profile> <name> --prompt-file F"),
        ("_fire", cmd_schedule_fire, None),  # hidden: the scheduler calls it
    ):
        q = ssub.add_parser(cmd, **({"help": hlp} if hlp else {}))
        q.add_argument("profile")
        q.add_argument("name")
        if cmd == "edit":
            q.add_argument("--prompt-file")
            q.add_argument("--timeout", help="30m, 2h, 1d, or none")
        q.set_defaults(func=fn)

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
        secretstore.SecretError,
        schedule.ScheduleError,
        mcpcmd.McpCmdError,
        mcpoauth.OAuthError,
    ) as e:
        err(str(e))
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
