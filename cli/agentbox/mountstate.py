"""Mount integrity across `up`s (PLAN §2.3, T1).

- The realpath validated at the first `up` is stored in <state>/mounts.json.
  A later `up` refuses a mount whose realpath changed (an agent in a rw mount
  can swap a symlink the profile path goes through) until the user re-runs
  with `--accept-mount-change`.
- A mount whose host path traverses a symlink located inside another rw mount
  of the same profile is refused outright: the agent controls that symlink.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .profile import Profile

STATE_FILE = "mounts.json"


class MountChangeError(Exception):
    pass


def _norm(p: str, ci: bool) -> str:
    return p.casefold() if ci else p


def _inside(p: str, root: str, ci: bool) -> bool:
    p, root = _norm(p, ci), _norm(root.rstrip("/") or "/", ci)
    return p == root or p.startswith(root + "/")


def symlinks_on_path(path: str) -> list[str]:
    """Location (parent resolved) of every symlink the path goes through."""
    out = []
    cur = "/"
    for comp in Path(path).parts[1:]:
        cur = os.path.join(cur, comp)
        if os.path.islink(cur):
            out.append(os.path.join(os.path.realpath(os.path.dirname(cur)), comp))
    return out


def symlink_problems(profile: Profile, ci: bool | None = None) -> list[str]:
    ci = sys.platform == "darwin" if ci is None else ci
    problems = []
    for m in profile.mounts:
        path = os.path.abspath(os.path.expanduser(m.host))
        for link in symlinks_on_path(path):
            for o in profile.mounts:
                if o is m or o.mode != "rw":
                    continue
                root = o.host_real or os.path.realpath(os.path.expanduser(o.host))
                if _inside(link, root, ci):
                    problems.append(
                        f"mount {m.host!r} goes through symlink {link}, which is inside "
                        f"the rw mount {o.host!r} (the agent can change it)"
                    )
    return problems


def check_and_record(state: Path, profile: Profile, accept: bool) -> None:
    f = state / STATE_FILE
    try:
        rec = json.loads(f.read_text()) if f.is_file() else {}
    except ValueError:
        raise MountChangeError(f"{f}: corrupt; check it and delete it to re-record") from None
    if not isinstance(rec, dict):
        raise MountChangeError(f"{f}: corrupt; check it and delete it to re-record")
    changed = []
    for m in profile.mounts:
        if not m.host_real:
            raise MountChangeError(f"mount {m.host!r} was not validated on the host")
        old = rec.get(m.host)
        if old is not None and old != m.host_real:
            changed.append(f"{m.host!r}: was {old}, now {m.host_real}")
    if changed and not accept:
        raise MountChangeError(
            "mount target changed since the last up: "
            + "; ".join(changed)
            + ". Check that this is intended, then run `agentbox up "
            + f"{profile.name} --accept-mount-change`"
        )
    new = {m.host: m.host_real for m in profile.mounts}
    if new != rec:
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps(new, indent=1, sort_keys=True) + "\n")
        tmp.replace(f)
