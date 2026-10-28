"""Image pruning (PLAN §2.10): remove the agentbox images that an update or a
build superseded, then the build cache unused for 24 h.

Only tags in the formats agentbox makes are managed. An image id is kept when
it is current, the one previous generation, derived from either, or used by
any container. Everything else loses all its managed tags with one
`docker image rm` (never `-f`). Every docker call goes through `docker.run`.

The caller holds the update lock (`updatelock.hold`), except for a dry run.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

from . import docker, images, schedule, term, updatelock

HEX12 = re.compile(r"[0-9a-f]{12}")
AGENT_TAG = re.compile(r"(?:base-)?[0-9a-f]{12}")
BUILD_CACHE_AGE = "24h"
LIST_LIMIT = 60.0  # seconds: image ls, ps, inspect
RM_LIMIT = 300.0
BUILDER_LIMIT = 600.0
DF_LIMIT = 120.0
ERROR_CAP = 200
GB_MIN = 100_000_000  # the applied post names freed space from 0.1 GB
PRUNE_FILE = "prune.json"
KEYS = ("end", "removed", "images", "kept_busy", "freed_bytes", "after", "error")


class PruneError(Exception):
    """The prune cannot go on safely; it removes nothing."""


# ---------------------------------------------------------------- managed tags
def kind_of(ref: str) -> str | None:
    """`agent`, `pkgs`, or the sidecar name for a tag agentbox makes; None for
    any other tag (`latest`, `p2test`, other repositories, `<none>`)."""
    repo, _, tag = ref.rpartition(":")
    if repo == images.AGENT_REPO:
        return "agent" if AGENT_TAG.fullmatch(tag) else None
    if repo == images.PKGS_REPO:
        return "pkgs" if HEX12.fullmatch(tag) else None
    for name in images.SIDECARS:
        if repo == f"agentbox/{name}":
            return name if HEX12.fullmatch(tag) else None
    return None


# ---------------------------------------------------------------- docker facts
def _ask(args: list[str], what: str) -> str:
    """stdout of a read-only docker call; any failure is a PruneError."""
    try:
        r = docker.run(args, check=False, timeout=LIST_LIMIT)
    except docker.DockerError as e:
        raise PruneError(f"{what} failed: {e}") from None
    if r.returncode != 0:
        raise PruneError(f"{what} failed ({r.returncode}): {first_line(r.stderr)}")
    return r.stdout


def first_line(text: str) -> str:
    lines = [x.strip() for x in (text or "").splitlines() if x.strip()]
    return (lines[0] if lines else "no output")[:ERROR_CAP]


def list_tags() -> list[tuple[str, str]]:
    """(image id, repo:tag) for every tag, ids in full (sha256:...)."""
    out = _ask(
        ["docker", "image", "ls", "--no-trunc", "--format", "{{.ID}} {{.Repository}}:{{.Tag}}"],
        "docker image ls",
    )
    rows = []
    for row in out.splitlines():
        image, _, ref = row.strip().partition(" ")
        if image and ref:
            rows.append((image, ref))
    return rows


def container_images() -> set[str]:
    """Ids of the images of every container, running or stopped."""
    ids = _ask(["docker", "ps", "-a", "-q", "--no-trunc"], "docker ps -a").split()
    if not ids:
        return set()
    out = _ask(["docker", "container", "inspect", "--format", "{{.Image}}", *ids],
               "docker container inspect")  # fmt: skip
    return set(out.split())


def parse_created(text: str) -> datetime:
    """`2026-10-28T10:27:24.120939523Z` (RFC 3339, nanoseconds) as an aware time."""
    t = re.sub(r"(\.\d{6})\d+", r"\1", text.strip())
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        raise PruneError(f"cannot read the image time {text!r}") from None
    return d if d.tzinfo else d.astimezone()


def created_of(ids: list[str]) -> dict[str, datetime]:
    out = _ask(["docker", "image", "inspect", "--format", "{{.Id}} {{.Created}}", *ids],
               "docker image inspect")  # fmt: skip
    res = {}
    for row in out.splitlines():
        image, _, when = row.strip().partition(" ")
        if image and when:
            res[image] = parse_created(when)
    for i in ids:
        if i not in res:
            raise PruneError(f"docker image inspect gave no time for {i}")
    return res


def newest(ids: set[str], created: dict[str, datetime]) -> str | None:
    """The newest id by Created (ties: the larger id, so the choice is stable).
    One id needs no time."""
    if len(ids) < 2:
        return next(iter(ids), None)
    return max(ids, key=lambda i: (created[i], i))


# ---------------------------------------------------------------- the plan
def plan(repo: Path, profs: list[tuple[str, list[str]]]) -> dict[str, list[str]]:
    """Image id -> managed tags to remove. Raises PruneError (nothing is
    removed) when a docker listing fails or the current image is unknown."""
    rows = list_tags()
    tag_id = {ref: image for image, ref in rows}
    managed: dict[str, dict[str, set[str]]] = {}  # kind -> id -> tags
    for image, ref in rows:
        if (k := kind_of(ref)) is not None:
            managed.setdefault(k, {}).setdefault(image, set()).add(ref)
    in_use = container_images()
    try:
        agent_want = f"{images.AGENT_REPO}:{images.agent_hash(repo)}"
        side_want = {n: images.sidecar_tag(repo, n) for n in images.SIDECARS}
    except (images.ImageError, OSError) as e:
        raise PruneError(f"cannot compute the current image tags: {e}") from None
    current = {i for ref in (images.AGENT_LATEST, agent_want) if (i := tag_id.get(ref))}
    agents = set(managed.get("agent", {}))
    if agents and not current:
        raise PruneError(f"no current agent image ({images.AGENT_LATEST} is missing)")
    # Previous generation: the newest id that is not current, per group.
    groups = {"agent": agents - current}
    for n in images.SIDECARS:
        groups[n] = set(managed.get(n, {})) - {tag_id.get(side_want[n])}
    need = sorted(set().union(*(g for g in groups.values() if len(g) > 1)))
    created = created_of(need) if need else {}
    previous = {k: newest(g, created) for k, g in groups.items()}
    keep = set(current) | in_use | {p for p in previous.values() if p}
    for n in images.SIDECARS:
        if cur := tag_id.get(side_want[n]):
            keep.add(cur)
    for _, packages in profs:  # derived images of the current and previous agent
        for base in current | ({previous["agent"]} if previous["agent"] else set()):
            if derived := tag_id.get(images.pkgs_tag(base, packages)):
                keep.add(derived)
    drop: dict[str, list[str]] = {}
    for by_id in managed.values():
        for image, tags in by_id.items():
            if image not in keep:
                drop.setdefault(image, []).extend(sorted(tags))
    return {i: sorted(set(t)) for i, t in drop.items()}


# ---------------------------------------------------------------- disk use
def disk_args() -> list[str]:
    """`df` in a throwaway container of the current agent image. The overlay root
    of a container reports the filesystem that holds the images and the cache."""
    from . import pyupdate  # late: pyupdate imports this module

    return ["docker", "run", "--rm", "--pull", "never", *pyupdate.CONTAINER_SAFE,
            "--entrypoint", "df", images.AGENT_LATEST,
            "-B1", "--output=used,size", "/"]  # fmt: skip


def parse_df(text: str) -> dict[str, int]:
    """`{"disk_used": bytes, "disk_size": bytes}` from `df -B1 --output=used,size /`:
    a header line and one row of two integers."""
    rows = [x.split() for x in text.splitlines() if x.strip()]
    if len(rows) != 2 or len(rows[1]) != 2 or not all(t.isdecimal() for t in rows[1]):
        raise ValueError(f"cannot read the df output {text!r}")
    used, size = int(rows[1][0]), int(rows[1][1])
    if size == 0:
        raise ValueError("df reports a disk of size 0")
    return {"disk_used": used, "disk_size": size}


def disk_use() -> dict[str, int] | None:
    """Used and total bytes of the Docker disk, or None when the measurement fails."""
    try:
        r = docker.run(disk_args(), check=False, timeout=DF_LIMIT)
        return parse_df(r.stdout) if r.returncode == 0 else None
    except (docker.DockerError, ValueError):
        return None


# ---------------------------------------------------------------- removal
def remove(image: str, tags: list[str]) -> dict:
    """One `docker image rm` for the image: {untagged, deleted, busy, error}."""
    res: dict = {"untagged": [], "deleted": False, "busy": False, "error": None}
    try:
        r = docker.run(["docker", "image", "rm", *tags], check=False, timeout=RM_LIMIT)
    except docker.DockerError as e:
        res["error"] = str(e)[:ERROR_CAP]
        return res
    for line in r.stdout.splitlines():
        head, _, value = line.partition(":")
        if head == "Untagged" and value.strip():
            res["untagged"].append(value.strip())
        elif head == "Deleted" and value.strip() == image:
            res["deleted"] = True
    if res["deleted"]:
        return res
    if r.returncode == 0:  # a non-managed tag keeps the image
        res["busy"] = True
    elif r.returncode == 1 and "conflict" in (r.stderr or "").lower():
        res["busy"] = True  # a container made after the list
    else:
        res["error"] = first_line(r.stderr)
    return res


def new_record() -> dict:
    return {"end": None, "removed": [], "images": [], "kept_busy": [], "freed_bytes": None,
            "after": None, "error": None}  # fmt: skip


def builder_prune() -> str | None:
    """Prune the build cache unused for 24 h. An error text, or None."""
    try:
        r = docker.run(
            ["docker", "builder", "prune", "--force", "--filter", f"until={BUILD_CACHE_AGE}"],
            check=False,
            timeout=BUILDER_LIMIT,
        )
    except docker.DockerError as e:
        return f"docker builder prune failed: {str(e)[:ERROR_CAP]}"
    if r.returncode != 0:
        return f"docker builder prune failed ({r.returncode}): {first_line(r.stderr)}"
    return None


def run(repo: Path, profs: list[tuple[str, list[str]]], *, dry_run: bool = False) -> dict:
    """The prune of PLAN §2.10. Returns the record object; never raises (except
    for a stop signal). A dry run removes nothing and returns the tags it would
    remove in `removed` (and `dry_run`: true)."""
    rec = new_record()
    try:
        drop = plan(repo, profs)
    except PruneError as e:
        rec.update(end=schedule.now_iso(), error=str(e)[:ERROR_CAP])
        return rec
    except Exception as e:  # noqa: BLE001 - a prune must not fail the update
        rec.update(end=schedule.now_iso(), error=f"{type(e).__name__}: {e}"[:ERROR_CAP])
        return rec
    # Derived images first: removing a child lets docker delete its parent too.
    order = sorted(drop, key=lambda i: (not any(kind_of(t) == "pkgs" for t in drop[i]), i))
    if dry_run:
        rec.update(end=schedule.now_iso(), dry_run=True, images=order,
                   removed=sorted(t for i in order for t in drop[i]))  # fmt: skip
        return rec
    errors: list[str] = []
    try:
        before = disk_use()
        for image in order:
            res = remove(image, drop[image])
            rec["removed"] += res["untagged"]
            if res["deleted"]:
                rec["images"].append(image)
            if res["busy"]:
                rec["kept_busy"].append(image)
            if res["error"]:
                errors.append(f"docker image rm {image[:19]}: {res['error']}")
        if (err := builder_prune()) is not None:
            errors.append(err)
        after = disk_use()
        rec["after"] = after
        if before is not None and after is not None:
            rec["freed_bytes"] = max(0, before["disk_used"] - after["disk_used"])
    except Exception as e:  # noqa: BLE001 - a prune must not fail the update
        errors.append(f"{type(e).__name__}: {e}"[:ERROR_CAP])
    rec["end"] = schedule.now_iso()
    rec["error"] = "; ".join(errors)[: 2 * ERROR_CAP] or None
    return rec


def error_record(message: str) -> dict:
    rec = new_record()
    rec.update(end=schedule.now_iso(), error=message[:ERROR_CAP])
    return rec


def write(rec: dict) -> None:
    """`_update/prune.json` (0600): the prune of a run that has no patch record."""
    data = {k: rec.get(k) for k in KEYS}
    schedule.write_private(
        updatelock.update_dir() / PRUNE_FILE,
        (json.dumps(data, indent=1, sort_keys=True) + "\n").encode(),
    )


# ---------------------------------------------------------------- text
def gb(n: int) -> str:
    """Decimal GB with one digit: 4_251_000_000 -> `4.3`."""
    return str((Decimal(n) / Decimal(10**9)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def freed_text(rec: dict) -> str:
    n = rec.get("freed_bytes")
    return "freed unknown" if n is None else f"freed {gb(n)} GB"


def disk_text(rec: dict) -> str:
    """`A GB used of B GB`, or "" when the measurement failed."""
    after = rec.get("after")
    if not after:
        return ""
    return f"{gb(after['disk_used'])} GB used of {gb(after['disk_size'])} GB"


def lines(rec: dict) -> list[str]:
    """The output lines of a prune, cleaned for the terminal."""
    out = []
    if rec.get("dry_run"):
        tags = rec["removed"]
        n = len(rec["images"])
        out.append(f"would remove {n} image{'s' if n != 1 else ''} ({len(tags)} tags):")
        out += [f"  {t}" for t in tags]
    elif not rec["error"] or rec["images"] or rec["removed"]:
        n = len(rec["images"])
        extra = f" (Docker disk {disk_text(rec)})" if disk_text(rec) else ""
        out.append(f"pruned {n} image{'s' if n != 1 else ''}, {freed_text(rec)}{extra}")
    if rec["error"]:
        out.append(f"prune failed: {rec['error']}")
    return [term.clean(x) for x in out]


def fleet_line(rec: dict, at: str) -> str:
    """The fleet report line (PLAN §2.8); `at` is HH:MM."""
    if rec.get("error"):
        return f"Docker disk: prune failed at {at}: {rec['error']}"
    n = len(rec["images"])
    disk = disk_text(rec)
    return (f"Docker disk: pruned {n} image{'s' if n != 1 else ''}, {freed_text(rec)} at {at}"
            + (f"; {disk}" if disk else ""))  # fmt: skip


def post_suffix(freed: int | None) -> str:
    """`; freed X.Y GB` for the applied post when freed is at least 0.1 GB."""
    return f"; freed {gb(freed)} GB" if freed is not None and freed >= GB_MIN else ""
