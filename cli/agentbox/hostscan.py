"""Host-side detection of agent-planted host-executed config (PLAN §1).

At session / run start the CLI snapshots, in each rw mount, the config that
host tools run: risky `.git/config` keys, non-sample `.git/hooks` files, a
`.git/commondir` file, a `.git` that is a file (worktree `gitdir:`),
`.envrc`, `.vscode/tasks.json`. At the end it re-scans and reports every
change. Warn-only.

Rules: git is never run on these dirs (agent-controlled); files are parsed
directly. Symlinks are never followed (lstat): a symlink is recorded as such.
Reads are size-capped; the scan has a hook count cap and a time budget. The
snapshot holds hashes, key names, and values truncated to SHOW chars only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from . import term

READ_MAX = 256 * 1024
MAX_HOOKS = 200
BUDGET = 1.0  # seconds per scan
SHOW = 60  # value chars kept / shown
MAX_SUBDIRS = 200  # direct subdirs of a mount root checked for a repo
FILES = (".envrc", ".vscode/tasks.json", ".vscode/settings.json", ".vscode/launch.json")
INCOMPLETE = "scan incomplete"

REVIEW_HINT = (
    "Review before you run host tools there: `cat .git/config`, `ls -la .git/hooks`, "
    "`cat .git/commondir`, `cat .envrc`, `ls -la .vscode`. Do not run host git (or "
    "direnv, VS Code tasks) in that directory "
    "until you have reviewed it."
)


class Budget:
    def __init__(self, seconds: float = BUDGET) -> None:
        self.end = time.monotonic() + seconds
        self.hit = False

    def over(self) -> bool:
        if time.monotonic() > self.end:
            self.hit = True
        return self.hit


# ---------------------------------------------------------------- git config


def _value(raw: str) -> str:
    """A git config value: quotes removed, escapes resolved, comments cut."""
    out, q, i = [], False, 0
    while i < len(raw):
        c = raw[i]
        if c == "\\" and i + 1 < len(raw):
            out.append({"n": "\n", "t": "\t", "b": "\b"}.get(raw[i + 1], raw[i + 1]))
            i += 2
            continue
        if c == '"':
            q = not q
        elif c in "#;" and not q:
            break
        else:
            out.append(c)
        i += 1
    return "".join(out).strip()


_SECTION = re.compile(r'\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]')


def parse_git_config(text: str) -> list[tuple[str, str]]:
    """(name, value) pairs; name = section[.subsection].key with section and
    key lowercased, subsection as written (legacy [a.B] lowercased). Tolerant:
    never raises; unparsable lines are skipped. A key without `=` is "true"."""
    return parse_git_config_ex(text)[0]


def parse_git_config_ex(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """`parse_git_config` plus the lines it could not classify. git may read
    such lines differently, so a change in them is reported (PLAN §1)."""
    out: list[tuple[str, str]] = []
    unparsed: list[str] = []
    section = ""
    text = text.removeprefix("\ufeff")  # git accepts a UTF-8 BOM
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        # continuation: a trailing unescaped backslash joins the next line
        while line.endswith("\\") and not line.endswith("\\\\") and i < len(lines):
            line = line[:-1] + lines[i]
            i += 1
        s = line.strip()
        while s.startswith("["):
            m = _SECTION.match(s)
            if not m:
                unparsed.append(s)
                s = ""
                break
            name, sub = m.group(1), m.group(2)
            if sub is not None:
                sub = re.sub(r"\\(.)", r"\1", sub)
                section = f"{name.lower()}.{sub}"
            elif "." in name:
                head, _, rest = name.partition(".")
                section = f"{head.lower()}.{rest.lower()}"
            else:
                section = name.lower()
            s = s[m.end() :].strip()  # `[core] fsmonitor = x` on one line
        if not s or s[0] in "#;":
            continue
        key, eq, raw = s.partition("=")
        key = key.strip()
        if not section or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", key):
            unparsed.append(s)
            continue
        out.append((f"{section}.{key.lower()}", _value(raw) if eq else "true"))
    return out, unparsed


def risky_key(name: str, value: str) -> bool:
    """PLAN §1 list: keys whose value a host git runs or loads."""
    parts = name.split(".")
    sec, key = parts[0], parts[-1]
    sub = len(parts) > 2
    if sec == "core" and not sub:
        return key in (
            "fsmonitor", "hookspath", "sshcommand", "pager", "editor", "askpass", "gitproxy",
        )  # fmt: skip
    if sec == "alias":
        return value.lstrip().startswith("!")
    if sec in ("filter", "pager"):
        return True
    if sec == "diff":
        return key == "external" if not sub else key in ("textconv", "command")
    if sec == "sequence":
        return key == "editor"
    if sec == "gpg":
        return key == "program"  # gpg.program and gpg.<format>.program
    if sec == "merge" and sub:
        return key == "driver"
    if sec in ("difftool", "mergetool") and sub:
        return key == "cmd"
    if sec == "remote" and sub:
        return key in ("uploadpack", "receivepack")
    if sec == "credential":
        return key == "helper"
    if sec == "include":
        return key == "path"
    if sec == "includeif":
        return key == "path"
    return False


# ---------------------------------------------------------------- scanning


def _lkind(p: Path) -> tuple[str, os.stat_result | None]:
    try:
        st = os.lstat(p)
    except OSError:
        return "missing", None
    if stat.S_ISLNK(st.st_mode):
        return "symlink", st
    if stat.S_ISDIR(st.st_mode):
        return "dir", st
    if stat.S_ISREG(st.st_mode):
        return "file", st
    return "other", st


def _read(p: Path) -> bytes | None:
    """Up to READ_MAX bytes of a regular file, opened without following a
    symlink at the last component."""
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, READ_MAX + 1)
    finally:
        os.close(fd)


def _digest(p: Path) -> str:
    kind, st = _lkind(p)
    if kind != "file":
        return kind
    data = _read(p)
    if data is None:
        return "unreadable"
    tail = f" (first {READ_MAX} of {st.st_size} bytes)" if len(data) > READ_MAX else ""
    return "sha256:" + hashlib.sha256(data[:READ_MAX]).hexdigest()[:16] + tail


def _show(v: str) -> str:
    v = term.clean(v)
    return v[:SHOW] + ("…" if len(v) > SHOW else "")


def _scan_repo(out: dict, label: str, repo: Path, b: Budget) -> None:
    g = repo / ".git"
    kind, _ = _lkind(g)
    if kind == "missing":
        return
    if kind != "dir":
        # a worktree / submodule `gitdir:` file, or a symlink: not followed
        out[f"{label}.git"] = f"{kind} {_digest(g)}" if kind == "file" else kind
        return
    out[f"{label}.git"] = "dir"
    cfg = g / "config"
    ck, _ = _lkind(cfg)
    if ck != "file":
        out[f"{label}.git/config"] = ck
    else:
        data = _read(cfg) or b""
        if len(data) > READ_MAX:
            out[f"{label}.git/config"] = f"larger than {READ_MAX} bytes"
        try:
            text = data[:READ_MAX].decode("utf-8")
        except UnicodeDecodeError:
            text = data[:READ_MAX].decode("utf-8", "replace")
            out[f"{label}.git/config (not UTF-8)"] = _digest(cfg)
        pairs, unparsed = parse_git_config_ex(text)
        if unparsed:
            h = hashlib.sha256("\n".join(unparsed).encode()).hexdigest()[:12]
            out[f"{label}.git/config (unparsed lines)"] = f"{h} {len(unparsed)} line(s)"
        seen: dict[str, int] = {}
        for name, value in pairs:
            if not risky_key(name, value):
                continue
            n = seen[name] = seen.get(name, 0) + 1
            key = name if n == 1 else f"{name}#{n}"
            h = hashlib.sha256(value.encode()).hexdigest()[:12]
            out[f"{label}.git/config [{key}]"] = f"{h} {_show(value)}"
    out[f"{label}.git/commondir"] = _digest(g / "commondir")
    hk, _ = _lkind(g / "hooks")
    if hk != "dir":
        out[f"{label}.git/hooks"] = hk
        return
    try:
        names = sorted(os.listdir(g / "hooks"))
    except OSError:
        out[f"{label}.git/hooks"] = "unreadable"
        return
    count = 0
    for n in names:
        if n.endswith(".sample"):
            continue
        count += 1
        if count > MAX_HOOKS or b.over():
            b.hit = True
            break
        out[f"{label}.git/hooks/{n}"] = _digest(g / "hooks" / n)


def _scan_files(out: dict, label: str, d: Path) -> None:
    for f in FILES:
        out[f"{label}{f}"] = _digest(d / f)


def scan_mount(root: str, out: dict, b: Budget, mlabel: str) -> None:
    r = Path(root)
    _scan_repo(out, f"{mlabel}: ", r, b)
    _scan_files(out, f"{mlabel}: ", r)
    # the repo the mount sits in (its .git is outside the mount, but reported)
    for anc in r.parents:
        if b.over():
            return
        if _lkind(anc / ".git")[0] != "missing":
            _scan_repo(out, f"{mlabel}: (enclosing repo {anc}) ", anc, b)
            break
    try:
        subs = sorted(os.scandir(r), key=lambda e: e.name)
    except OSError:
        return
    n = 0
    for e in subs:
        if b.over():
            return
        if not e.is_dir(follow_symlinks=False):
            continue
        n += 1
        if n > MAX_SUBDIRS:
            b.hit = True
            return
        sub = Path(e.path)
        if _lkind(sub / ".git")[0] != "missing":
            _scan_repo(out, f"{mlabel}: {e.name}/", sub, b)
            _scan_files(out, f"{mlabel}: {e.name}/", sub)


def snapshot(profile, budget: float = BUDGET) -> dict:
    """{"items": {id: descriptor}, "incomplete": bool} for every rw mount."""
    b = Budget(budget)
    items: dict[str, str] = {}
    for m in profile.mounts:
        if m.mode != "rw" or not m.host_real:
            continue
        scan_mount(m.host_real, items, b, m.host_real)
    return {"items": items, "incomplete": b.hit}


def diff(old: dict, new: dict) -> list[str]:
    """One line per changed item (term-clean)."""
    a, z = old.get("items", {}), new.get("items", {})
    out = []
    for k in sorted(set(a) | set(z)):
        va, vz = a.get(k, "missing"), z.get(k, "missing")
        if va == vz:
            continue
        if va == "missing":
            what = f"added: {vz}"
        elif vz == "missing":
            what = "removed"
        else:
            what = f"changed: {va} -> {vz}"
        out.append(term.clean(f"{k}: {what}"))
    return out


def report(changes: list[str], incomplete: bool) -> str | None:
    if not changes and not incomplete:
        return None
    lines = []
    if changes:
        lines.append(
            "agentbox: WARNING: host-executed config changed in a rw mount during this session:"
        )
        lines += [f"  {c}" for c in changes]
        lines.append(REVIEW_HINT)
    if incomplete:
        lines.append(f"agentbox: note: host config {INCOMPLETE} (time or file-count cap)")
    return "\n".join(lines)


def save(path: Path, snap: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(snap, fh)


def load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None
