"""Stack secrets (PLAN §2.11): Keychain secrets for a plain Compose stack.

A directory with `agentbox-stack.toml` (names only) declares the secrets of a
stack. `run` fetches them on the host and execs a command (no shell) with the
values only in that process environment. Nothing is written to disk and no
value is placed in argv.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import secretstore
from .delivery import item_key, webhook_item
from .paths import Config
from .profile import ref_ok, secret_name_problem

MANIFEST = "agentbox-stack.toml"
NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
ENV_PREFIX = "AGENTBOX_SECRET_"
RC_MISSING = 2
RC_NOT_FOUND = 127
RC_NOT_EXEC = 126


class StackError(Exception):
    pass


@dataclass
class Entry:
    name: str
    ref: str
    explicit: bool  # the manifest names the ref (else the stack default)


@dataclass
class Stack:
    name: str
    dir: Path
    entries: list[Entry] = field(default_factory=list)
    compose_files: list[str] = field(default_factory=list)


def name_problem(name: str) -> str | None:
    if NAME_RE.fullmatch(name) is None:
        return f"invalid stack name {name!r} (use a-z, 0-9, '-'; at most 32 characters)"
    return None


def scope(name: str) -> str:
    return f"_stack/{name}"


def default_ref(cfg: Config, stack: str, name: str) -> str:
    """Ref of the default item: Keychain `<prefix>/_stack/<stack>/<NAME>`. The
    op backend allows only vault/item/field, so the stack joins the item."""
    if cfg.secret_backend == "op":
        return secretstore.default_ref(cfg, f"_stack-{stack}", name)
    return secretstore.default_ref(cfg, scope(stack), name)


def _is_under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def load(directory: str | Path, cfg: Config) -> Stack:
    """Parse and validate `<directory>/agentbox-stack.toml`; all problems at once."""
    d = Path(directory).expanduser()
    if not d.is_dir():
        raise StackError(f"{d} is not a directory")
    d = d.resolve()
    f = d / MANIFEST
    if not f.is_file():
        raise StackError(f"no {MANIFEST} in {d}")
    try:
        data = tomllib.loads(f.read_text())
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise StackError(f"{f}: {e}") from None
    problems: list[str] = []

    def bad(key: str, msg: str) -> None:
        problems.append(f"{key}: {msg}")

    for k in sorted(set(data) - {"stack", "secrets"}):
        bad(k, "unknown key")
    st = data.get("stack")
    name = ""
    files: list[str] = []
    if not isinstance(st, dict):
        bad("stack", "a [stack] table with name is required")
        st = {}
    for k in sorted(set(st) - {"name", "compose_files"}):
        bad(f"stack.{k}", "unknown key")
    n = st.get("name")
    if not isinstance(n, str):
        bad("stack.name", "required, a string")
    elif msg := name_problem(n):
        bad("stack.name", msg)
    else:
        name = n
    cf = st.get("compose_files")
    if cf is not None:
        if not isinstance(cf, list) or not cf or not all(isinstance(x, str) for x in cf):
            bad("stack.compose_files", "must be a list of one or more relative paths")
        else:
            for p in cf:
                if not p or os.path.isabs(p) or os.pathsep in p or "\x00" in p:
                    bad("stack.compose_files", f"{p!r}: must be a relative path")
                    continue
                target = (d / p).resolve()
                if not _is_under(target, d):
                    bad("stack.compose_files", f"{p}: must be under {d}, not above it")
                elif not target.is_file():
                    bad("stack.compose_files", f"{p}: no such file under {d}")
                else:
                    files.append(p)
    secs = data.get("secrets", {})
    if not isinstance(secs, dict):
        bad("secrets", "must be a table")
        secs = {}
    hook = webhook_item(cfg)
    entries: list[Entry] = []
    for sname, sv in secs.items():
        key = f"secrets.{sname}"
        if msg := secret_name_problem(sname):
            bad(key, msg)
            continue
        if not isinstance(sv, dict):
            bad(key, 'must be a table: NAME = {} or NAME = { ref = "..." }')
            continue
        for k in sorted(set(sv) - {"ref"}):
            bad(f"{key}.{k}", "unknown key")
        ref = sv.get("ref")
        if ref is not None and (not isinstance(ref, str) or not ref_ok(ref)):
            bad(f"{key}.ref", "must be keychain:<service>, op://<vault>/<item>/<field>, "
                "or env:<VAR>")  # fmt: skip
            continue
        explicit = ref is not None
        if ref is None:
            if not name:
                continue  # the stack name is invalid; the default ref is unknown
            try:
                ref = default_ref(cfg, name, sname)
            except secretstore.SecretError as e:
                bad(key, str(e))
                continue
        if hook is not None and item_key(ref) == hook:
            bad(key, "points at the notification webhook (notify_webhook_secret = "
                f"{cfg.notify_webhook_secret!r}), which stays on the host; "
                "use another item")  # fmt: skip
            continue
        entries.append(Entry(sname, ref, explicit))
    if problems:
        raise StackError(f"{f} is invalid:\n" + "\n".join(f"  {p}" for p in problems))
    entries.sort(key=lambda e: e.name)
    return Stack(name, d, entries, files)


def _need_backend(stack: Stack) -> None:
    owned = any(e.ref.startswith((secretstore.OWNED, "keychain:")) for e in stack.entries)
    if owned and not secretstore.keychain_available():
        raise StackError(secretstore.KEYCHAIN_ONLY_MAC)


def rows(stack: Stack) -> list[tuple[str, str, str]]:
    """(name, ref, present|missing|unreadable). Never values."""
    _need_backend(stack)
    out = []
    for e in stack.entries:
        try:
            if e.ref.startswith("op://"):
                ok = secretstore.get(e.ref) is not None  # ambient op session
            else:
                ok = secretstore.exists(e.ref)
            status = "present" if ok else "missing"
        except secretstore.SecretError:
            status = "unreadable"
        out.append((e.name, e.ref, status))
    return out


def fetch_all(stack: Stack, fetch=None) -> tuple[dict[str, str], list[str]]:
    """(values, problems). A problem is a name with `missing` or `unreadable`
    plus a scrubbed reason. Nothing is raised for a single secret."""
    _need_backend(stack)
    fetch = fetch or secretstore.get  # op refs: ambient session, no SA token
    values: dict[str, str] = {}
    failed: list[tuple[str, str]] = []
    for e in stack.entries:
        try:
            v = fetch(e.ref)
        except secretstore.SecretError as ex:
            failed.append((e.name, f"unreadable: {ex}"))
            continue
        if v is None:
            failed.append((e.name, "missing"))
        elif msg := secretstore.value_problem(v):
            failed.append((e.name, f"unreadable: {msg}"))
        else:
            values[e.name] = v
    problems = []
    for name, why in failed:
        for v in values.values():
            why = secretstore.scrub(why, v)
        problems.append(f"{name} ({why})")
    return values, problems


def environment(stack: Stack, values: dict[str, str], base: dict[str, str]) -> dict[str, str]:
    env = dict(base)
    for n, v in values.items():
        env[ENV_PREFIX + n] = v
        env[n] = v
    if stack.compose_files:
        env["COMPOSE_FILE"] = os.pathsep.join(stack.compose_files)
    return env


def run(stack: Stack, command: list[str], err=None) -> int:
    """Exec `command` in the stack dir with the secrets in its environment.
    Returns only when nothing was exec'd (missing secret: 2; no command: 127)."""
    err = err or (lambda m: print(f"agentbox: {m}", file=sys.stderr, flush=True))
    values, problems = fetch_all(stack)
    if problems:
        err(f"stack {stack.name}: cannot start the command; these secrets are not available: "
            + ", ".join(problems)
            + f". Store with `agentbox secret set --stack {stack.name} NAME`.")  # fmt: skip
        return RC_MISSING
    env = environment(stack, values, dict(os.environ))
    try:
        os.chdir(stack.dir)
        sys.stdout.flush()
        sys.stderr.flush()
        os.execvpe(command[0], command, env)
    except FileNotFoundError:
        err(f"{command[0]}: command not found")
        return RC_NOT_FOUND
    except OSError as e:
        err(f"{command[0]}: cannot run: {e.strerror or type(e).__name__}")
        return RC_NOT_EXEC
    return RC_NOT_EXEC  # unreachable unless exec is stubbed


# ---------------------------------------------------------------- listing


def list_items(cfg: Config, stack: str) -> list[tuple[str, str]]:
    """(NAME, ref) of items present in the store under scope `_stack/<stack>`.
    Only what the store can enumerate: Keychain (account `agentbox`) and the
    env test store. The op backend cannot list."""
    if cfg.secret_backend == "op":
        raise secretstore.SecretError(
            "the op backend cannot list items; run `agentbox stack ls` in the stack directory"
        )
    service_prefix = f"{cfg.secret_prefix}/{scope(stack)}/"
    names: set[str] = set()
    if cfg.secret_backend == "env":
        pre = secretstore._env_var(service_prefix)
        sf = os.environ.get(secretstore.ENV_STORE)
        if sf:
            p = Path(sf)
            keys = list(json.loads(p.read_text())) if p.is_file() else []
        else:
            keys = list(os.environ)
        names = {k[len(pre) :] for k in keys if k.startswith(pre) and len(k) > len(pre)}
        return [(n, secretstore.default_ref(cfg, scope(stack), n)) for n in sorted(names)]
    if not secretstore.keychain_available():
        raise secretstore.SecretError(secretstore.KEYCHAIN_ONLY_MAC)
    try:
        r = subprocess.run(["security", "dump-keychain"], capture_output=True, text=True)
    except FileNotFoundError:
        raise secretstore.SecretError("security: command not found") from None
    if r.returncode != 0:
        raise secretstore.SecretError(f"keychain listing failed: {r.stderr.strip()[-300:]}")
    acct = svce = None
    for line in r.stdout.splitlines() + ["keychain:"]:
        if line.startswith("keychain:"):  # next item: close the previous one
            if acct == secretstore.ACCOUNT and svce and svce.startswith(service_prefix):
                rest = svce[len(service_prefix) :]
                if rest and "/" not in rest:
                    names.add(rest)
            acct = svce = None
            continue
        m = re.match(r'\s*"(acct|svce)"<blob>="(.*)"\s*$', line)
        if m:
            if m.group(1) == "acct":
                acct = m.group(2)
            else:
                svce = m.group(2)
    return [(n, secretstore.default_ref(cfg, scope(stack), n)) for n in sorted(names)]
