"""`agentbox update` (PLAN §2.3, §6): look up current releases for the
versions.env pins; apply = write versions.env, rebuild, full doctor on a
scratch profile, and keep the previous `latest` tag when anything fails.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import docker, images

UA = {"User-Agent": "agentbox-update"}
LINE_RE = re.compile(r"([A-Z][A-Z0-9_]*)=(.*)")
# Pins that are not looked up (public key fingerprints: changed by hand after
# checking the vendor docs).
MANUAL = ("CLAUDE_KEY_FPR", "GH_KEY_FPRS")
FAILED = "(failed"  # prefix of a lookup value that could not be fetched


class UpdateError(Exception):
    pass


def read_env(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = LINE_RE.fullmatch(line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


def write_env(text: str, new: dict[str, str]) -> str:
    """Replace values in place, keeping comments and order. Unknown key: error."""
    have = read_env(text)
    for k in new:
        if k not in have:
            raise UpdateError(f"versions.env has no {k}")
    out = []
    for line in text.splitlines(keepends=True):
        m = LINE_RE.fullmatch(line.strip())
        if m and m.group(1) in new:
            nl = "\n" if line.endswith("\n") else ""
            line = f"{m.group(1)}={new[m.group(1)]}{nl}"
        out.append(line)
    return "".join(out)


def vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


_GH_TOKEN: list[str | None] = []


def github_token() -> str | None:
    """The host user's GitHub token (env, else `gh auth token`), for the API
    rate limit only. Sent to api.github.com and nowhere else."""
    if not _GH_TOKEN:
        tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not tok and shutil.which("gh"):
            r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
            tok = r.stdout.strip() if r.returncode == 0 else None
        _GH_TOKEN.append(tok or None)
    return _GH_TOKEN[0]


def _get(url: str) -> bytes:
    headers = dict(UA)
    if url.startswith("https://api.github.com/") and (tok := github_token()):
        headers["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def _json(url: str):
    return json.loads(_get(url))


def apt_latest(packages_text: str, package: str) -> str:
    best = None
    for stanza in packages_text.split("\n\n"):
        f = dict(
            line.split(": ", 1) for line in stanza.splitlines() if ": " in line and line[0] != " "
        )
        if (
            f.get("Package") == package
            and "Version" in f
            and (best is None or vkey(f["Version"]) > vkey(best))
        ):
            best = f["Version"]
    if best is None:
        raise UpdateError(f"package {package} not in Packages index")
    return best


def node_latest(index: list, major: str) -> str:
    for rel in index:  # index.json is newest first
        if rel["version"].startswith(f"v{major}."):
            return rel["version"][1:]
    raise UpdateError(f"no Node.js v{major} release")


def python_latest(releases: list) -> str:
    finals = [
        r["name"].split()[-1]
        for r in releases
        if not r.get("pre_release") and re.fullmatch(r"Python 3\.\d+\.\d+", r.get("name", ""))
    ]
    if not finals:
        raise UpdateError("no final CPython release found")
    return max(finals, key=vkey)


def gh_release(repo: str, asset: str, fetch=_json) -> tuple[str, str]:
    d = fetch(f"https://api.github.com/repos/{repo}/releases/latest")
    tag = d["tag_name"].lstrip("v")
    for a in d.get("assets", []):
        if a["name"] == asset:
            dig = a.get("digest") or ""
            if not dig.startswith("sha256:"):
                raise UpdateError(f"{repo} {asset}: no sha256 digest")
            return tag, dig.split(":", 1)[1]
    raise UpdateError(f"{repo}: asset {asset} missing")


LOOKUP_ERRORS = (UpdateError, urllib.error.URLError, OSError, KeyError, ValueError)


def _try(out: dict[str, str], keys: tuple[str, ...], fn: Callable[[], object]) -> None:
    """Run one source lookup; on failure mark only its keys as failed."""
    try:
        vals = fn()
    except LOOKUP_ERRORS as e:
        reason = str(e).splitlines()[0][:80] if str(e) else type(e).__name__
        for k in keys:
            out[k] = f"{FAILED}: {reason})"
        return
    if len(keys) == 1:
        vals = (vals,)
    out.update(zip(keys, vals, strict=True))


def lookup(current: dict[str, str], fetch_json=_json, fetch=_get) -> dict[str, str]:
    """Latest value for each pin (and its paired checksum). Network I/O.
    A source that fails marks its keys with a FAILED value; others still resolve."""
    out: dict[str, str] = {}
    claude = (
        "https://downloads.claude.ai/claude-code/apt/stable/dists/stable/main/binary-amd64/Packages"
    )
    _try(out, ("CLAUDE_CODE_VERSION",), lambda: apt_latest(fetch(claude).decode(), "claude-code"))
    gh = "https://cli.github.com/packages/dists/stable/main/binary-amd64/Packages"
    _try(out, ("GH_VERSION",), lambda: apt_latest(fetch(gh).decode(), "gh"))

    def node() -> tuple[str, str]:
        major = current.get("NODE_VERSION", "24").split(".")[0]
        v = node_latest(fetch_json("https://nodejs.org/dist/index.json"), major)
        sums = fetch(f"https://nodejs.org/dist/v{v}/SHASUMS256.txt").decode()
        fname = f"node-v{v}-linux-x64.tar.xz"
        m = re.search(rf"^([0-9a-f]{{64}})  {re.escape(fname)}$", sums, re.M)
        if not m:
            raise UpdateError(f"{fname} not in SHASUMS256.txt")
        return v, m.group(1)

    _try(out, ("NODE_VERSION", "NODE_SHA256"), node)
    for key, pkg in (
        ("CODEX_VERSION", "@openai/codex"),
        ("PI_VERSION", "@earendil-works/pi-coding-agent"),
        ("PI_MCP_ADAPTER_VERSION", "pi-mcp-adapter"),
    ):
        _try(
            out,
            (key,),
            lambda pkg=pkg: fetch_json(f"https://registry.npmjs.org/{pkg}/latest")["version"],
        )
    _try(
        out,
        ("OLLAMA_VERSION", "OLLAMA_SHA256"),
        lambda: gh_release("ollama/ollama", "ollama-linux-amd64.tar.zst", fetch_json),
    )
    _try(
        out,
        ("UV_VERSION", "UV_SHA256"),
        lambda: gh_release("astral-sh/uv", "uv-x86_64-unknown-linux-gnu.tar.gz", fetch_json),
    )
    _try(
        out,
        ("PYTHON_VERSION",),
        lambda: python_latest(
            fetch_json("https://www.python.org/api/v2/downloads/release/?is_published=true")
        ),
    )

    def ubuntu() -> str:
        img = current.get("UBUNTU_IMAGE", "ubuntu:24.04@").split("@")[0]
        r = docker.run(
            ["docker", "buildx", "imagetools", "inspect", img, "--format", "{{json .Manifest}}"]
        )
        return f"{img}@{json.loads(r.stdout)['digest']}"

    _try(out, ("UBUNTU_IMAGE",), ubuntu)
    return out


@dataclass
class Row:
    key: str
    current: str
    latest: str

    @property
    def status(self) -> str:
        if self.latest == "(manual)":
            return "manual"
        if self.latest.startswith(FAILED):
            return "failed"
        return "current" if self.current == self.latest else "newer"


def table(current: dict[str, str], latest: dict[str, str]) -> list[Row]:
    return [Row(k, v, latest.get(k, "(manual)")) for k, v in current.items()]


def format_table(rows: list[Row]) -> str:
    w = max(len(r.key) for r in rows)
    lines = [f"{'PIN':<{w}}  {'STATUS':<7}  CURRENT -> LATEST"]
    for r in rows:
        cur, lat = r.current, r.latest
        if len(cur) > 40:
            cur, lat = cur[:16] + "…" + cur[-8:], lat[:16] + "…" + lat[-8:]
        lines.append(
            f"{r.key:<{w}}  {r.status:<7}  {cur}"
            + {"newer": f" -> {lat}", "failed": f"  {r.latest}"}.get(r.status, "")
        )
    return "\n".join(lines)


def apply(
    repo: Path,
    latest: dict[str, str],
    build: Callable[[], None],
    doctor: Callable[[], bool],
    relock: Callable[[], None] | None = None,
) -> bool:
    """Write versions.env, rebuild, run doctor. On any failure restore
    versions.env (and the adapter lockfile) and re-point agentbox/agent:latest
    at the previous image. Returns True on success."""
    env_file = repo / "images/agent/versions.env"
    lock = repo / "images/agent/pi-mcp-adapter/package-lock.json"
    pkg = repo / "images/agent/pi-mcp-adapter/package.json"
    old_env, old_lock, old_pkg = env_file.read_text(), lock.read_bytes(), pkg.read_bytes()
    prev = docker.image_id(images.AGENT_LATEST)
    cur = read_env(old_env)
    changes = {
        k: v for k, v in latest.items() if k in cur and cur[k] != v and not v.startswith(FAILED)
    }
    if not changes:
        print("all pins are current")
        return True
    try:
        env_file.write_text(write_env(old_env, changes))
        if "PI_MCP_ADAPTER_VERSION" in changes:
            p = json.loads(old_pkg)
            p.setdefault("dependencies", {})["pi-mcp-adapter"] = changes["PI_MCP_ADAPTER_VERSION"]
            pkg.write_text(json.dumps(p, indent=2) + "\n")
            if relock is None:
                raise UpdateError("pi-mcp-adapter changed but no relock step")
            relock()
        build()
        if not doctor():
            raise UpdateError("doctor failed on the new image")
        return True
    except BaseException as e:  # also KeyboardInterrupt: never leave a half update
        print(f"agentbox update: {e!r}; rolling back")
        env_file.write_text(old_env)
        lock.write_bytes(old_lock)
        pkg.write_bytes(old_pkg)
        if prev is not None:
            docker.run(["docker", "tag", prev, images.AGENT_LATEST])
        if not isinstance(e, Exception):
            raise
        return False
