"""Python line and patch updates (PLAN §2.9).

- `patch`: `agentbox update --python-patch` (the daily host job). Newest final
  release of the pinned line, uv probe, apply (write, build, doctor, partial
  rollback), derived images, result record, Slack posts.
- `change_line`: `agentbox update --python-line X.Y --eol YYYY-MM`, with the
  offline lock check.
- `resolve`: the uv probe, shared with the full `agentbox update`.

The caller holds the update lock (`updatelock.hold`). Build and doctor are
passed in, so this module does not import the CLI.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import secrets
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from . import docker, images, launch, notify, paths, schedule, term, updatelock
from . import update as upd
from .profile import ProfileError, load_profile

UV_REPO = "astral-sh/uv"
UV_ASSET = "uv-x86_64-unknown-linux-gnu.tar.gz"
UV_URL = f"https://github.com/{UV_REPO}/releases/download/{{version}}/{UV_ASSET}"
UV_MAX = 200 * 1024 * 1024  # largest uv binary read from the tarball
PROBE_LIMIT = 120.0
LOCKCHECK_LIMIT = 120.0
HOST_JOB = "_update"  # the name the host job posts and logs under
EMOJI = "🐍"
RESULTS = ("current", "applied", "not_installable", "lookup_failed", "failed")
# Container flags for every probe and lock-check run: nothing is added, much is dropped.
CONTAINER_SAFE = ("--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges")
# A lock fails only on these uv errors (PLAN §2.9); backticks are removed before the match.
LOCK_MARKERS = (
    "marked as --no-build but has no binary distribution",
    "incompatible with the project's Python requirement",
)
REQUIRED_PINS = ("PYTHON_LINE", "PYTHON_VERSION", "PYTHON_LINE_EOL", "UV_VERSION", "UV_SHA256",
                 "UBUNTU_IMAGE")  # fmt: skip


class LookupFailed(upd.UpdateError):
    """A lookup, download, checksum or probe failed before anything was written."""


class NotInstallable(upd.UpdateError):
    """The target CPython is not available to the pinned or the latest uv."""


# ---------------------------------------------------------------- pins
def load_env(repo: Path) -> dict[str, str]:
    """versions.env with the Python pins checked. A missing or bad pin is a hard error."""
    env = upd.read_env((repo / "images/agent/versions.env").read_text())
    for k in REQUIRED_PINS:
        if k not in env:
            raise upd.UpdateError(f"versions.env has no {k}")
    for k in ("PYTHON_LINE", "PYTHON_VERSION", "PYTHON_LINE_EOL"):
        if why := upd.value_problem(k, env[k], env):
            raise upd.UpdateError(f"versions.env {k}: {why}")
    return env


def short_reason(e: BaseException) -> str:
    text = str(e).strip() or type(e).__name__
    return notify.clean_line(text.splitlines()[0], notify.REASON_CAP)


# ---------------------------------------------------------------- uv probe
# uv has no writable HOME in a probe container: it must not try to open a cache.
PROBE_ENV = ("-e", "UV_NO_CACHE=1")


def probe_args(target: str) -> list[str]:
    return ["uv", "python", "list", "--all-versions", "--only-downloads", "--output-format",
            "json", f"cpython@{target}"]  # fmt: skip


def parse_probe(text: str, target: str) -> bool:
    """True when the JSON list has an entry whose `version` equals `target`.
    `[]` is "absent" (the text form prints nothing and exits 0 as well)."""
    try:
        data = json.loads(text)
    except ValueError:
        raise upd.UpdateError("uv probe: the output is not JSON") from None
    if not isinstance(data, list):
        raise upd.UpdateError("uv probe: the output is not a JSON list")
    return any(isinstance(e, dict) and e.get("version") == target for e in data)


def _probe_result(r: subprocess.CompletedProcess, target: str) -> bool:
    if r.returncode != 0:
        tail = " ".join(((r.stderr or "") + (r.stdout or "")).split())[-200:]
        raise upd.UpdateError(f"uv probe failed (exit {r.returncode}): {tail}")
    return parse_probe(r.stdout, target)


def probe_image(ref: str, target: str) -> bool:
    """The probe in the current agent image (its pinned uv), no network."""
    r = docker.run(["docker", "run", "--rm", *CONTAINER_SAFE, *PROBE_ENV, ref, *probe_args(target)],
                   check=False, timeout=PROBE_LIMIT)  # fmt: skip
    return _probe_result(r, target)


def probe_tarball(ubuntu_image: str, uv_dir: Path, target: str) -> bool:
    """The probe with a verified uv binary, mounted read-only in a container
    of the pinned Ubuntu image, no network, an unwritable HOME."""
    args = ["docker", "run", "--rm", *CONTAINER_SAFE, "--platform", "linux/amd64",
            "--user", "1000:1000", "-e", "HOME=/nonexistent", *PROBE_ENV,
            "-v", f"{uv_dir}:/uvbin:ro", ubuntu_image,
            "/uvbin/uv", *probe_args(target)[1:]]  # fmt: skip
    return _probe_result(docker.run(args, check=False, timeout=PROBE_LIMIT), target)


def download_uv(version: str, sha256: str, dest: Path, fetch=upd._get) -> Path:
    """Download the uv tarball, check its sha256, write the `uv` binary to
    dest (0755). Only that one member is read; nothing is extracted by path."""
    for key, v in (("UV_VERSION", version), ("UV_SHA256", sha256)):
        if why := upd.value_problem(key, v):
            raise upd.UpdateError(f"{key}: {why}")
    data = fetch(UV_URL.format(version=version))
    if hashlib.sha256(data).hexdigest() != sha256:
        raise upd.UpdateError(f"uv {version}: the tarball does not match its sha256")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        member = next((m for m in tf.getmembers() if m.isreg() and m.name.split("/")[-1] == "uv"),
                      None)  # fmt: skip
        if member is None or member.size > UV_MAX:
            raise upd.UpdateError(f"uv {version}: no usable uv binary in the tarball")
        src = tf.extractfile(member)
        if src is None:
            raise upd.UpdateError(f"uv {version}: cannot read the uv binary")
        out = dest / "uv"
        out.write_bytes(src.read())
    os.chmod(out, 0o755)
    os.chmod(dest, 0o755)  # the container user is not the host user
    return out


def latest_uv(fetch_json=upd._json) -> tuple[str, str]:
    """(version, sha256) of the latest uv release (same source and checksum rule as `update`)."""
    ver, sha = upd.gh_release(UV_REPO, UV_ASSET, fetch_json)
    for key, v in (("UV_VERSION", ver), ("UV_SHA256", sha)):
        if why := upd.value_problem(key, v):
            raise upd.UpdateError(f"{key}: {why}")
    return ver, sha


@dataclass
class Resolution:
    uv: tuple[str, str] | None  # the uv to pin when the pinned one cannot install the target


PROBE_ERRORS = (
    *upd.LOOKUP_ERRORS,
    docker.DockerError,
    tarfile.TarError,
    subprocess.SubprocessError,
)


def _first_probe(env: dict[str, str], target: str) -> bool:
    """The current agent image (pinned uv); no image: the pinned UV_VERSION tarball."""
    if docker.image_id(images.AGENT_LATEST) is not None:
        return probe_image(images.AGENT_LATEST, target)
    with tempfile.TemporaryDirectory(prefix="agentbox-uv-") as d:
        download_uv(env["UV_VERSION"], env["UV_SHA256"], Path(d))
        return probe_tarball(env["UBUNTU_IMAGE"], Path(d), target)


def resolve(env: dict[str, str], target: str, uv: tuple[str, str] | None = None) -> Resolution:
    """Can the image install CPython `target`? (PLAN §2.9 "uv coupling".)
    `uv` None: probe the pinned uv; when it has no such build, look up the
    latest uv, verify its tarball on the host, and probe that. `uv` given: probe
    only that one. Raises NotInstallable (no uv has it) or LookupFailed (a
    lookup, download, checksum or probe failed; nothing is written)."""
    try:
        if uv is None:
            if _first_probe(env, target):
                return Resolution(None)
            uv = latest_uv()
        with tempfile.TemporaryDirectory(prefix="agentbox-uv-") as d:
            download_uv(uv[0], uv[1], Path(d))
            found = probe_tarball(env["UBUNTU_IMAGE"], Path(d), target)
    except PROBE_ERRORS as e:
        raise LookupFailed(short_reason(e)) from None
    if not found:
        raise NotInstallable(f"uv has no build of Python {target} yet")
    return Resolution(uv)


def resolve_pin(current: dict[str, str], latest: dict[str, str]) -> None:
    """Full `update`: PYTHON_VERSION follows the line only when uv can install
    it. Not installable or probe failed: that one pin stays (the rest updates).
    A newer uv in `latest` is the one probed; else the pinned uv, then the latest."""
    target = latest.get("PYTHON_VERSION", "")
    if target.startswith(upd.FAILED) or target == current.get("PYTHON_VERSION"):
        return
    ver, sha = latest.get("UV_VERSION", ""), latest.get("UV_SHA256", "")
    newer = None
    if (
        ver
        and sha
        and not ver.startswith(upd.FAILED)
        and not sha.startswith(upd.FAILED)
        and (ver != current.get("UV_VERSION") or sha != current.get("UV_SHA256"))
    ):
        newer = (ver, sha)
    try:
        res = resolve(current, target, newer)
    except NotInstallable as e:
        print(f"agentbox update: {e}; PYTHON_VERSION stays {current['PYTHON_VERSION']}")
        latest["PYTHON_VERSION"] = current["PYTHON_VERSION"]
    except LookupFailed as e:
        latest["PYTHON_VERSION"] = f"{upd.FAILED}: uv probe: {e})"
    else:
        if res.uv:
            latest["UV_VERSION"], latest["UV_SHA256"] = res.uv


# ---------------------------------------------------------------- record and posts
def new_record(env: dict[str, str]) -> dict:
    return {
        "start": schedule.now_iso(),
        "end": None,
        "result": None,
        "step": None,
        "python_from": env["PYTHON_VERSION"],
        "python_to": None,
        "uv_from": env["UV_VERSION"],
        "uv_to": None,
        "image": None,
        "derived_warnings": [],
        "message": None,
        "notify": None,
        "reported": [],
    }


def read_history(d: Path) -> list[dict]:
    """Records of earlier runs, oldest first. A line that does not parse is skipped."""
    rows: list[dict] = []
    for name in ("history.jsonl.1", "history.jsonl"):
        try:
            text = (d / name).read_text()
        except OSError:
            continue
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def reported_keys(history: list[dict]) -> set[str]:
    return {k for row in history for k in (row.get("reported") or []) if isinstance(k, str)}


def normalize_reason(reason: str) -> str:
    """First line, hex ids and digits normalized (the "failed once" key)."""
    first = (reason.strip().splitlines() or [""])[0]
    first = re.sub(r"\b[0-9a-f]{7,}\b", "<id>", first)
    return re.sub(r"[0-9]+", "N", first)


def clean_reason(reason: str) -> str:
    """Untrusted text in a post: one line, capped, Slack-escaped."""
    return notify.slack_escape(notify.clean_line(reason, notify.REASON_CAP))


def applied_text(rec: dict, line: tuple[str, str] | None = None) -> str:
    uv = ""
    if rec["uv_to"] and rec["uv_to"] != rec["uv_from"]:
        uv = f" (uv {rec['uv_from']} -> {rec['uv_to']})"
    what = f"Python {rec['python_from']} -> {rec['python_to']}"
    if line:
        what = f"Python line {line[0]} -> {line[1]} ({rec['python_from']} -> {rec['python_to']})"
    derived = ""
    if rec["derived_warnings"]:
        derived = "; derived image failed: " + ", ".join(rec["derived_warnings"])
    image = (rec["image"] or "?").removeprefix("sha256:")[:12]
    return (f"{EMOJI} agentbox: {what} applied{uv}; new image {image}{derived}. "
            "Commit and release the pins.")  # fmt: skip


def failed_text(rec: dict) -> str:
    return (f"{EMOJI} agentbox: Python {rec['python_to']} update FAILED at {rec['step']}, "
            f"kept {rec['python_from']}: {clean_reason(rec['message'] or '')}")  # fmt: skip


def not_installable_text(rec: dict) -> str:
    return (f"{EMOJI} agentbox: Python {rec['python_to']} is out; uv has no build yet. "
            "Retrying daily.")  # fmt: skip


def lookup_failed_text(days: int, reason: str) -> str:
    return f"{EMOJI} agentbox: Python check has failed for {days} days: {clean_reason(reason)}"


def new_line_text(line: str, new: str) -> str:
    return (f"{EMOJI} agentbox: Python {new} is out; the box stays on {line} "
            f"(agentbox update --python-line {new}).")  # fmt: skip


def eol_text(line: str, eol: str) -> str:
    return (f"{EMOJI} agentbox: Python {line} security support ends {eol}. "
            "Plan a line change (agentbox update --python-line).")  # fmt: skip


def eol_ended_text(line: str, eol: str) -> str:
    return (f"{EMOJI} agentbox: Python {line} security support ended {eol}. "
            "Change the line now (agentbox update --python-line).")  # fmt: skip


def months_until(eol: str, today: date) -> int:
    y, m = (int(x) for x in eol.split("-"))
    return (y * 12 + m) - (today.year * 12 + today.month)


def notices(env: dict[str, str], releases: list, today: date) -> list[tuple[str, str]]:
    """(dedupe key, text) for the new-line and end-of-support notices.
    The new line: the python.org list has a final `3.(N+1).0`. End of support:
    each month of the 6 months before PYTHON_LINE_EOL and that month (once per month)."""
    out = []
    line = env["PYTHON_LINE"]
    if releases and (new := upd.python_new_line(releases, line)):
        out.append((f"new_line:{new}", new_line_text(line, new)))
    left = months_until(env["PYTHON_LINE_EOL"], today)
    if 0 <= left <= 6:  # the 6 months before and the end month itself
        out.append((f"eol:{line}:{today:%Y-%m}", eol_text(line, env["PYTHON_LINE_EOL"])))
    elif left < 0:  # after the end-of-support month: monthly
        text = eol_ended_text(line, env["PYTHON_LINE_EOL"])
        out.append((f"eol_ended:{line}:{today:%Y-%m}", text))
    return out


def lookup_failed_post(history: list[dict], today: date, reason: str) -> tuple[str, str] | None:
    """Silent for the first two days of a streak; a post on the third, then
    every 7th day while it lasts. A streak is the unbroken run of lookup_failed
    records up to now; its days are the distinct dates in it."""
    days = {today}
    last_post: date | None = None
    for row in reversed(history):
        if row.get("result") != "lookup_failed":
            break
        with contextlib.suppress(ValueError):
            days.add(date.fromisoformat(str(row.get("start", ""))[:10]))
        for k in row.get("reported") or []:
            if isinstance(k, str) and k.startswith("lookup_failed:"):
                try:
                    d = date.fromisoformat(k.split(":", 1)[1])
                except ValueError:
                    continue
                last_post = d if last_post is None else max(last_post, d)
    if len(days) < 3 or (last_post is not None and (today - last_post).days < 7):
        return None
    return f"lookup_failed:{today.isoformat()}", lookup_failed_text(len(days), reason)


def messages(rec: dict, env: dict[str, str], releases: list, history: list[dict],
             line_change: tuple[str, str] | None = None) -> list[tuple[str, str]]:  # fmt: skip
    """The posts of this run as (dedupe key, text), in order, after dedupe against
    `history` (the earlier records). Applied: every time. Failed: once per
    (target, step, normalized reason). Not installable: once per target."""
    seen = reported_keys(history)
    today = datetime.fromisoformat(rec["start"]).date()
    out: list[tuple[str, str]] = []
    result = rec["result"]
    if result == "applied":
        out.append((f"applied:{rec['python_to']}:{rec['start']}", applied_text(rec, line_change)))
    elif result == "failed":
        key = f"failed|{rec['python_to']}|{rec['step']}|{normalize_reason(rec['message'] or '')}"
        if key not in seen:
            out.append((key, failed_text(rec)))
    elif result == "not_installable":
        key = f"not_installable:{rec['python_to']}"
        if key not in seen:
            out.append((key, not_installable_text(rec)))
    elif result == "lookup_failed" and (
        post := lookup_failed_post(history, today, rec["message"] or "")
    ):
        out.append(post)
    if not line_change:
        out.extend(n for n in notices(env, releases, today) if n[0] not in seen)
    return out


def post_all(rec: dict, posts: list[tuple[str, str]]) -> None:
    """Post through the host webhook (notify.deliver_text: host only, 10 s,
    https, no redirect, scrubbed). A key joins rec["reported"] only after an "ok"
    post, so a failed post is tried again. Never raises, never changes the exit code."""
    if not posts:
        return
    try:
        cfg = paths.load_config()
    except Exception as e:  # noqa: BLE001 - a notice must not fail the update
        rec["notify"] = f"error: {notify.reason(e, None)}"
        return
    if cfg.notify_webhook_secret is None:
        return
    results = []
    for key, text in posts:
        r = notify.deliver_text(
            cfg,
            HOST_JOB,
            lambda t=text: notify.clean_line(t, 600),
            notify.NOTIFY_TIMEOUT,
            scrub=True,
        )
        results.append(r)
        if r == "ok":
            rec["reported"].append(key)
    rec["notify"] = next((r for r in results if r != "ok"), "ok")


def write_record(rec: dict, final: bool) -> None:
    """last.json always; history.jsonl only for the final write (as a fire does)."""
    schedule.record(updatelock.update_dir(), rec, history=final)


def finish(rec: dict, result: str, env: dict[str, str], releases: list,
           line_change: tuple[str, str] | None = None, **fields) -> dict:  # fmt: skip
    """Set the result, write the record, post, write the record again."""
    assert result in RESULTS
    rec.update(result=result, end=schedule.now_iso(), **fields)
    history = read_history(updatelock.update_dir())
    write_record(rec, final=False)  # the true outcome is on disk before the post
    post_all(rec, messages(rec, env, releases, history, line_change))
    rec["end"] = schedule.now_iso()
    write_record(rec, final=True)
    return rec


# ---------------------------------------------------------------- derived and unused images
def profiles_with_packages() -> list[tuple[str, list[str]]]:
    out = []
    for name in launch.list_profiles(paths.profiles_dir()):
        try:
            prof = load_profile(paths.profile_file(name), name)
        except ProfileError:
            continue
        if prof.box.packages:
            out.append((name, list(prof.box.packages)))
    return out


def build_derived(profs: list[tuple[str, list[str]]]) -> list[str]:
    """Build the derived image of every profile with `packages`, so no fire
    pays that build inside its timeout. Returns the profiles that failed."""
    bad = []
    for name, packages in profs:
        try:
            images.ensure_pkgs(images.AGENT_LATEST, packages)
        except (images.ImageError, docker.DockerError, OSError):
            bad.append(name)
    return bad


def unused_images(profs: list[tuple[str, list[str]]]) -> list[str]:
    """`repo:tag` of agent and derived images that `:latest`, the current derived
    tags and running containers do not use. Removes nothing."""
    ls = docker.run(["docker", "image", "ls", "--no-trunc", "--filter", "reference=agentbox/agent",
                     "--filter", "reference=agentbox/agent-pkgs", "--format",
                     "{{.ID}} {{.Repository}}:{{.Tag}}"], check=False)  # fmt: skip
    if ls.returncode != 0:
        return []
    keep: set[str | None] = {docker.image_id(images.AGENT_LATEST)}
    for _, packages in profs:
        base = docker.image_id(images.AGENT_LATEST)
        if base:
            keep.add(docker.image_id(images.pkgs_tag(base, packages)))
    ps = docker.run(["docker", "ps", "-q"], check=False)
    ids = ps.stdout.split() if ps.returncode == 0 else []
    if ids:
        ins = docker.run(["docker", "inspect", "--format", "{{.Image}}", *ids], check=False)
        keep.update(ins.stdout.split() if ins.returncode == 0 else [])
    tags = []
    for row in ls.stdout.splitlines():
        image, _, ref = row.partition(" ")
        if image and image not in keep and not ref.endswith(":<none>"):
            tags.append(ref)
    return sorted(tags)


def after_apply(rec: dict) -> None:
    """After a successful update: record the image, build the derived images
    (a failure is a warning), list the images that nothing uses. Nothing here
    can undo or fail the update: doctor has passed."""
    try:
        rec["image"] = docker.image_id(images.AGENT_LATEST)
        profs = profiles_with_packages()
        rec["derived_warnings"] = build_derived(profs)
        if rec["derived_warnings"]:
            print(f"warning: derived image failed for: {', '.join(rec['derived_warnings'])}")
        unused = unused_images(profs)
    except (docker.DockerError, OSError) as e:
        print(term.clean(f"warning: after the update: {e}"))
        return
    if unused:
        print("images that nothing uses (remove them if you want the space back):")
        print(f"  docker image rm {' '.join(unused)}")


# ---------------------------------------------------------------- patch
def say(rec: dict) -> None:
    r, frm, to = rec["result"], rec["python_from"], rec["python_to"]
    text = {
        "current": f"Python {frm} is current.",
        "applied": f"Python {frm} -> {to} applied; new image "
                   f"{(rec['image'] or '?').removeprefix('sha256:')[:12]}.",
        "not_installable": f"Python {to} is out; uv has no build yet. Nothing changed.",
        "lookup_failed": f"Python check failed: {rec['message']}",
        "failed": f"Python {to} update FAILED at {rec['step']}; kept {frm}: {rec['message']}",
    }[r]  # fmt: skip
    print(term.clean(f"agentbox update: {text}"))


def patch(
    repo: Path,
    *,
    build: Callable[[], None],
    doctor: Callable[[list[str]], bool],
    fetch_json=upd._json,
    docker_ready: Callable[[], bool] = lambda: True,
) -> dict:
    """`update --python-patch` (PLAN §2.9). Returns the record; exit 1 only for
    `failed`. `doctor(failed)` appends the ids of the failed checks."""
    env = load_env(repo)
    rec = new_record(env)
    releases: list = []
    if not docker_ready():
        finish(rec, "lookup_failed", env, releases, message="Docker did not come up")
        say(rec)
        return rec
    try:
        releases = fetch_json(upd.PYTHON_RELEASES)
        target = upd.python_latest(releases, env["PYTHON_LINE"])
    except upd.LOOKUP_ERRORS as e:
        finish(rec, "lookup_failed", env, [], message=short_reason(e))
        say(rec)
        return rec
    cur = env["PYTHON_VERSION"]
    rec["python_to"] = target
    if upd.vkey(target) <= upd.vkey(cur):  # never a downgrade
        rec["python_to"] = cur
        finish(rec, "current", env, releases)
        say(rec)
        return rec
    try:
        res = resolve(env, target)
    except NotInstallable as e:
        finish(rec, "not_installable", env, releases, message=short_reason(e))
    except LookupFailed as e:
        finish(rec, "lookup_failed", env, releases, message=short_reason(e))
    else:
        changes = {"PYTHON_VERSION": target}
        if res.uv:
            changes.update(UV_VERSION=res.uv[0], UV_SHA256=res.uv[1])
            rec["uv_to"] = res.uv[0]
        info: dict = {}
        failed_checks: list[str] = []
        ok = upd.apply(repo, changes, build, lambda: doctor(failed_checks), info=info)
        if ok:
            try:
                after_apply(rec)
            finally:  # a stop signal here must not lose the record or the post
                finish(rec, "applied", env, releases, derived_warnings=rec["derived_warnings"])
        else:
            step = info.get("step", "write")
            if step == "doctor" and failed_checks:
                step = f"doctor {failed_checks[0]}"
            finish(rec, "failed", env, releases, step=step, message=info.get("error", ""))
    say(rec)
    return rec


# ---------------------------------------------------------------- lock check
@dataclass
class LockResult:
    project: Path
    profiles: list[str]
    status: str  # ok | fail | undecided
    detail: str = ""


@dataclass
class Scan:
    projects: dict[Path, list[str]] = field(default_factory=dict)  # project dir -> profiles
    skipped: list[str] = field(default_factory=list)


def scan_mount(root: Path, max_depth: int = 2) -> list[Path]:
    """Directories at depth 0..max_depth under `root` that hold a regular-file
    `uv.lock`. No symlink is followed (a symlinked lock or directory is not
    used); dot-directories are skipped."""
    found: list[Path] = []

    def walk(d: Path, depth: int) -> None:
        try:
            if stat.S_ISREG(os.lstat(d / "uv.lock").st_mode):
                found.append(d)
        except OSError:
            pass
        if depth >= max_depth:
            return
        try:
            with os.scandir(d) as it:
                subs = sorted((e for e in it if not e.name.startswith(".")), key=lambda e: e.name)
        except OSError:
            return
        for e in subs:
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                walk(Path(e.path), depth + 1)

    walk(root, 0)
    return found


def scan_profiles() -> Scan:
    """Every `uv.lock` (depth 0-2) under every host mount of every profile."""
    out = Scan()
    for name in launch.list_profiles(paths.profiles_dir()):
        try:
            prof = load_profile(paths.profile_file(name), name, host_checks=True)
        except ProfileError:
            out.skipped.append(name)
            continue
        for m in prof.mounts:
            for proj in scan_mount(Path(m.host_real or m.host)):
                if name not in out.projects.setdefault(proj, []):
                    out.projects[proj].append(name)
    return out


def run_lock(image: str, project: Path) -> tuple[int, str]:
    """`uv sync --frozen --no-build --dry-run` in a plain container: no network, the
    project read-only, no secrets, no Compose project, no proxy; 120 s limit.
    These flags run no project code and write nothing. Returns (exit code, output)."""
    name = f"agentbox-lockcheck-{secrets.token_hex(4)}"
    args = ["docker", "run", "--rm", "--name", name, *CONTAINER_SAFE, "--user", "agent",
            "-v", f"{project}:/project:ro", "-w", "/project", "-e", "UV_OFFLINE=1",
            "-e", "UV_CACHE_DIR=/tmp/uv-cache", "-e", "UV_PROJECT_ENVIRONMENT=/tmp/venv",
            image, "uv", "sync", "--frozen", "--no-build", "--dry-run", "--python",
            "/usr/local/bin/python"]  # fmt: skip
    r = docker.run(args, check=False, timeout=LOCKCHECK_LIMIT)
    if r.returncode == docker.TIMEOUT_RC:  # the kill reached the client, not the container
        docker.run(["docker", "rm", "-f", name], check=False, timeout=60)
    return r.returncode, (r.stderr or "") + (r.stdout or "")


def lock_marker(output: str) -> str | None:
    """The marker that makes a candidate failure a lock failure, else None."""
    text = output.replace("`", "").replace("’", "'")
    return next((m for m in LOCK_MARKERS if m in text), None)


def lock_detail(output: str, marker: str) -> str:
    text = output.replace("`", "")
    if m := re.search(r"Distribution (\S+)", text):
        return f"package {m.group(1)}: {marker}"
    line = next((x.strip() for x in text.splitlines() if marker in x.replace("’", "'")), "")
    return notify.clean_line(line or marker, 200)


def first_line(output: str) -> str:
    lines = [x.strip() for x in output.replace("`", "").splitlines() if x.strip()]
    err = next((x for x in lines if x.startswith("error")), lines[0] if lines else "no output")
    return notify.clean_line(err, 200)


def check_one(current: str | None, cand: str, project: Path, profs: list[str],
              run=run_lock) -> LockResult:  # fmt: skip
    """Run the lock in the current and the candidate image. It fails only when the
    candidate fails with a marker and the current image passes; any other
    non-zero result is undecided."""
    if any(c in str(project) for c in ":,\n\r"):
        return LockResult(project, profs, "undecided", "the path has a : , or newline character")
    cand_rc, cand_out = run(cand, project)
    cur_rc, cur_out = run(current, project) if current is not None else (None, "")
    if cand_rc == 0:
        return LockResult(project, profs, "ok")
    marker = lock_marker(cand_out)
    if marker and cur_rc == 0:
        return LockResult(project, profs, "fail", lock_detail(cand_out, marker))
    why = first_line(cand_out)
    if current is None:
        why += " (no current image to compare)"
    elif marker:
        why += " (the current image fails too)"
    return LockResult(project, profs, "undecided", why)


def lock_check(current: str | None, cand: str, force: bool = False, scan: Scan | None = None,
               run=run_lock) -> bool:  # fmt: skip
    """The lock check (PLAN §2.9). Prints each project. False: at least one lock
    fails and `force` is not set. `force` prints the same and passes."""
    scan = scan if scan is not None else scan_profiles()
    for name in scan.skipped:
        print(term.clean(f"lock check: profile {name} does not load; its locks are not checked"))
    print(f"lock check: {len(scan.projects)} uv.lock project(s)")
    results = [check_one(current, cand, proj, profs, run) for proj, profs in scan.projects.items()]
    for r in results:
        label = {"ok": "ok", "fail": "FAIL", "undecided": "undecided"}[r.status]
        tail = f": {r.detail}" if r.detail else ""
        print(term.clean(f"  {label:<9} {r.project} (profile {', '.join(r.profiles)}){tail}"))
    failed = [r for r in results if r.status == "fail"]
    if failed and force:
        print(f"lock check: {len(failed)} project(s) fail; --force: going on")
        return True
    if failed:
        print(f"lock check: {len(failed)} project(s) fail on the new Python; rolling back")
    return not failed


# ---------------------------------------------------------------- line change
def change_line(repo: Path, new_line: str, eol: str, *, build: Callable[[], None],
                doctor: Callable[[list[str]], bool], force: bool = False,
                fetch_json=upd._json, lock=lock_check) -> dict:  # fmt: skip
    """`update --python-line X.Y --eol YYYY-MM` (PLAN §2.9). Raises UpdateError
    (exit 1) before anything is written; after that the result is in the record
    (`failed`: rolled back). Returns the record."""
    env = load_env(repo)
    if why := upd.value_problem("PYTHON_LINE", new_line):
        raise upd.UpdateError(f"--python-line: {why}")
    if why := upd.value_problem("PYTHON_LINE_EOL", eol):
        raise upd.UpdateError(f"--eol: {why}")
    if new_line == env["PYTHON_LINE"]:
        raise upd.UpdateError(f"PYTHON_LINE is already {new_line}; `agentbox update` patches it")
    try:
        releases = fetch_json(upd.PYTHON_RELEASES)
    except upd.LOOKUP_ERRORS as e:
        raise upd.UpdateError(f"python.org lookup failed: {short_reason(e)}") from None
    target = upd.python_latest(releases, new_line)
    try:
        res = resolve(env, target)
    except (NotInstallable, LookupFailed) as e:
        raise upd.UpdateError(f"{e}; nothing was written") from None
    changes = {"PYTHON_LINE": new_line, "PYTHON_LINE_EOL": eol, "PYTHON_VERSION": target}
    rec = new_record(env)
    rec["python_to"] = target
    if res.uv:
        changes.update(UV_VERSION=res.uv[0], UV_SHA256=res.uv[1])
        rec["uv_to"] = res.uv[0]
    prev = docker.image_id(images.AGENT_LATEST)

    def check() -> None:
        if not lock(prev, images.AGENT_LATEST, force):
            raise upd.UpdateError("lock check failed: a project would not install")

    info: dict = {}
    failed_checks: list[str] = []
    ok = upd.apply(repo, changes, build, lambda: doctor(failed_checks), check=check, info=info)
    change = (env["PYTHON_LINE"], new_line)
    if ok:
        try:
            after_apply(rec)
        finally:  # a stop signal here must not lose the record or the post
            finish(rec, "applied", env, releases, change, derived_warnings=rec["derived_warnings"])
    else:
        step = info.get("step", "write")
        if step == "doctor" and failed_checks:
            step = f"doctor {failed_checks[0]}"
        finish(rec, "failed", env, releases, change, step=step, message=info.get("error", ""))
    say(rec)
    return rec
