"""Add a domain to a profile's `[network] allow` array as a text edit, so
comments and layout in the rest of the file are kept (PLAN §2.2 `allow`).

The result is re-parsed: it must equal the old document except for the new
entry in network.allow. Anything else is an error, and nothing is written.
"""

from __future__ import annotations

import copy
import json
import re
import tomllib

from .presets import forbidden_problem
from .profile import hostname_problem


class AllowEditError(Exception):
    pass


HEADER_RE = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$")
ALLOW_RE = re.compile(r"^(\s*)allow\s*=\s*\[")


def domain_problem(domain: str) -> str | None:
    return hostname_problem(domain) or forbidden_problem(domain)


def _array_end(text: str, start: int) -> int:
    """Index just after the `]` that closes the array whose `[` is at start."""
    i, depth = start, 0
    while i < len(text):
        c = text[i]
        if c == "#":
            i = text.find("\n", i)
            if i < 0:
                break
            continue
        if c in "\"'":
            triple = text.startswith(c * 3, i)
            q = c * 3 if triple else c
            j = i + len(q)
            while j < len(text):
                if c == '"' and text[j] == "\\":
                    j += 2
                    continue
                if text.startswith(q, j):
                    break
                j += 1
            i = j + len(q)
            continue
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise AllowEditError("unterminated allow array")


def _network_span(lines: list[str]) -> tuple[int, int] | None:
    """(first line after [network], end line) or None when there is no [network]."""
    start = None
    for i, line in enumerate(lines):
        m = HEADER_RE.match(line)
        if not m:
            continue
        if start is not None:
            return start, i
        if m.group(1) == "network" and not line.lstrip().startswith("[["):
            start = i + 1
    return None if start is None else (start, len(lines))


def add_allow(text: str, domain: str) -> tuple[str, bool]:
    """Return (new text, changed). Idempotent: an entry already present
    (case-insensitive) returns the text unchanged."""
    if msg := domain_problem(domain):
        raise AllowEditError(f"{domain!r}: {msg}")
    if "\r\n" in text:  # keep CRLF files CRLF
        if "\n" in text.replace("\r\n", ""):
            raise AllowEditError("mixed LF and CRLF line endings; edit the file by hand")
        new, changed = add_allow(text.replace("\r\n", "\n"), domain)
        return (new.replace("\n", "\r\n"), True) if changed else (text, False)
    domain = domain.lower()
    try:
        before = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise AllowEditError(f"profile is not valid TOML: {e}") from None
    net = before.get("network", {})
    if not isinstance(net, dict):
        raise AllowEditError("[network] is not a table")
    current = net.get("allow", [])
    if not isinstance(current, list):
        raise AllowEditError("network.allow is not an array")
    if domain in (str(x).lower() for x in current):
        return text, False

    lit = json.dumps(domain)
    lines = text.splitlines(keepends=True)
    span = _network_span(lines)
    if span is None:
        if "network" in before:  # inline table or dotted keys: do not guess
            raise AllowEditError("[network] is not a plain table; edit the file by hand")
        sep = "" if text.endswith("\n") or not text else "\n"
        new = f"{text}{sep}\n[network]\nallow = [{lit}]\n"
    else:
        s, e = span
        offs = [0]
        for line in lines:
            offs.append(offs[-1] + len(line))
        key_line = next((i for i in range(s, e) if ALLOW_RE.match(lines[i])), None)
        if key_line is None:
            if "allow" in net:
                raise AllowEditError("network.allow is not a plain `allow = [...]` line")
            last = max(
                (
                    i
                    for i in range(s, e)
                    if lines[i].strip() and not lines[i].lstrip().startswith("#")
                ),
                default=s - 1,
            )
            nl = "" if lines[last].endswith("\n") else "\n"
            ins = offs[last + 1]
            new = text[:ins] + nl + f"allow = [{lit}]\n" + text[ins:]
        else:
            m = ALLOW_RE.match(lines[key_line])
            open_idx = offs[key_line] + m.end() - 1
            close = _array_end(text, open_idx) - 1  # index of "]"
            body = text[open_idx + 1 : close]
            if "\n" not in body:
                inner = body.strip()
                if not inner:
                    new_body = lit
                else:
                    new_body = body.rstrip().rstrip(",").strip() + ", " + lit
                    new_body = new_body.lstrip()
                new = text[: open_idx + 1] + new_body + text[close:]
            else:
                # Multi-line: insert a line before the line that holds "]".
                line_start = text.rfind("\n", 0, close) + 1
                indent = re.match(r"[ \t]*", body.lstrip("\n")).group(0) or "  "
                prefix_ws = text[line_start:close]
                # Ensure the previous element ends with a comma.
                head = text[:line_start]
                k = len(head.rstrip())
                # Skip a trailing comment on the last element line.
                last_line_start = head.rfind("\n", 0, k) + 1
                last_line = head[last_line_start:k]
                code = _strip_comment(last_line)
                if code.strip() and not code.rstrip().endswith((",", "[")):
                    pos = last_line_start + len(code.rstrip())
                    head = head[:pos] + "," + head[pos:]
                if prefix_ws.strip():  # "]" shares a line with an element
                    new = text[:close].rstrip() + ",\n" + indent + lit + ",\n" + text[close:]
                else:
                    new = head + indent + lit + ",\n" + text[line_start:]
    try:
        after = tomllib.loads(new)
    except tomllib.TOMLDecodeError as e:
        raise AllowEditError(f"edit produced invalid TOML ({e}); file not changed") from None
    exp = copy.deepcopy(before)
    exp.setdefault("network", {}).setdefault("allow", []).append(domain)
    if after != exp:
        raise AllowEditError("edit changed more than network.allow; file not changed")
    return new, True


def _strip_comment(line: str) -> str:
    """Line without a trailing # comment (quotes respected)."""
    q = None
    i = 0
    while i < len(line):
        c = line[i]
        if q:
            if c == "\\" and q == '"':
                i += 1
            elif c == q:
                q = None
        elif c in "\"'":
            q = c
        elif c == "#":
            return line[:i]
        i += 1
    return line
