"""A fake Docker daemon for the image-prune tests (PLAN §2.10): tags, ids,
containers, `docker image rm` with its output lines, `docker system df`. It
answers through `docker.run`, so no test touches a real daemon."""

import json
import subprocess

GB = 10**9


def sha(n: int) -> str:
    return "sha256:" + f"{n:02x}" * 32


def when(day: int) -> str:
    """Created time of an image: later day, newer image (docker prints nanoseconds)."""
    return f"2026-10-{day:02d}T10:27:24.120939523Z"


class FakeDocker:
    def __init__(self, calls: list | None = None):
        self.calls = calls if calls is not None else []
        self.tags: dict[str, str] = {}  # repo:tag -> image id
        self.created: dict[str, str] = {}  # image id -> RFC 3339
        self.sizes: dict[str, int] = {}  # image id -> bytes
        self.containers: list[str] = []  # image id of each container, running or stopped
        self.cache = 0  # Build Cache Reclaimable, bytes
        self.cache_after_prune = 0
        self.fail: dict[str, tuple[int, str]] = {}  # command key -> (rc, stderr)
        self.busy_ids: set[str] = set()  # `image rm` of these ids hits a conflict
        self.df_text: str | None = None  # replaces the df output

    def image(self, n: int, refs: list[str], day: int | None = None, size: int = GB) -> str:
        """Add an image id `sha(n)` with its tags."""
        i = sha(n)
        self.created[i] = when(day if day is not None else n % 28 + 1)
        self.sizes[i] = size
        for r in refs:
            self.tags[r] = i
        return i

    def ids(self) -> list[str]:
        return list(dict.fromkeys(self.tags.values()))

    def images_bytes(self) -> int:
        return sum(self.sizes[i] for i in self.ids())

    def result(self, args, rc=0, out="", err=""):
        return subprocess.CompletedProcess(args, rc, out, err)

    def key(self, args: list[str]) -> str:
        if args[:3] == ["docker", "image", "ls"]:
            return "image ls"
        if args[:3] == ["docker", "image", "rm"]:
            return "image rm"
        if args[:3] == ["docker", "image", "inspect"]:
            return "image inspect"
        if args[:3] == ["docker", "ps", "-a"]:
            return "ps -a"
        if args[:3] == ["docker", "container", "inspect"]:
            return "container inspect"
        if args[:3] == ["docker", "builder", "prune"]:
            return "builder prune"
        if args[:3] == ["docker", "system", "df"]:
            return "df"
        return " ".join(args[:3])

    def run(self, args, **kw):
        self.calls.append(list(args))
        key = self.key(args)
        if key in self.fail:
            rc, err = self.fail[key]
            return self.result(args, rc, "", err)
        if key == "image ls":
            return self.result(args, out="".join(f"{i} {r}\n" for r, i in self.tags.items()))
        if key == "ps -a":
            return self.result(args, out="".join(f"c{n}\n" for n in range(len(self.containers))))
        if key == "container inspect":
            return self.result(args, out="".join(f"{i}\n" for i in self.containers))
        if key == "image inspect":
            if args[3:5] == ["--format", "{{.Id}}"]:  # docker.image_id
                i = self.tags.get(args[5])
                return self.result(
                    args, 0 if i else 1, f"{i}\n" if i else "", "" if i else "No such image"
                )
            return self.result(args, out="".join(f"{i} {self.created[i]}\n" for i in args[5:]))
        if key == "image rm":
            return self.rm(args, args[3:])
        if args[:2] == ["docker", "tag"]:
            src = self.tags.get(args[2], args[2])
            if src not in self.created:
                return self.result(args, 1, "", f"No such image: {args[2]}")
            self.tags[args[3]] = src
            return self.result(args)
        if key == "builder prune":
            self.cache = self.cache_after_prune
            return self.result(args, out="Total:\t0B\n")
        if key == "df":
            if self.df_text is not None:
                return self.result(args, out=self.df_text)
            rows = [
                {"Type": "Images", "Size": f"{self.images_bytes() / GB:.3f}GB",
                 "Reclaimable": "1GB (5%)"},
                {"Type": "Containers", "Size": "7.565MB", "Reclaimable": "0B (0%)"},
                {"Type": "Build Cache", "Size": "15.36GB",
                 "Reclaimable": f"{self.cache / GB:.3f}GB"},
            ]  # fmt: skip
            return self.result(args, out="".join(json.dumps(r) + "\n" for r in rows))
        return self.result(args)

    def rm(self, args, refs):
        out, errs = [], []
        for ref in refs:
            i = self.tags.get(ref)
            if i is None:
                errs.append(f"Error response from daemon: No such image: {ref}")
                continue
            last = sum(1 for v in self.tags.values() if v == i) == 1
            if last and (i in self.busy_ids or i in self.containers):
                errs.append(
                    f"Error response from daemon: conflict: unable to delete {i[7:19]} "
                    "(cannot be forced) - image is being used by stopped container abc123"
                )
                continue
            del self.tags[ref]
            out.append(f"Untagged: {ref}")
            if last:
                out.append(f"Deleted: {i}")
        rc = 1 if errs else 0
        return self.result(
            args, rc, "".join(x + "\n" for x in out), "".join(x + "\n" for x in errs)
        )
