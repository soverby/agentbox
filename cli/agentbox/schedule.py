"""Host scheduling of headless runs (PLAN §2.7).

A job is `<state>/<profile>/schedules/<name>/` with job.json (agent, model,
schedule), prompt.md (0600 copy of the prompt), last.json (last fire),
history.jsonl (every fire), fire.lock, and launchd.{out,err}.

macOS: a launchd agent plist (`StartCalendarInterval` from cron / --at, or
`StartInterval` for --every) that runs `agentbox schedule _fire`. Linux: one
crontab entry after a tag comment `# agentbox:<profile>:<name>`.

Cron support (5 fields: minute hour day-of-month month day-of-week): `*`,
numbers, lists `a,b`, ranges `a-b`, steps `*/n`, `a-b/n`, `a/n`, month and
weekday names (jan..dec, sun..sat), weekday 7 = Sunday. launchd has no step
or range syntax, so the CLI expands the fields into explicit calendar
entries; more than EXPAND_CAP entries is refused (use --every). Not
supported (refused): `@reboot`/`@daily` macros, `L`, `W`, `#`, `?`, six
fields, and `* * * * *` (use --every 1m). When both day-of-month and
day-of-week are restricted, cron fires when either matches; the plist gets
separate Day and Weekday entries for the same result.
"""

from __future__ import annotations

import contextlib
import fcntl
import itertools
import json
import os
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from . import paths

EXPAND_CAP = 500
DEFAULT_TIMEOUT = 7200
LOG_ROTATE = 5 * 1024 * 1024
DOCKER_WAIT = 120.0
DOCKER_POLL = 3.0
DOCKER_APP_BIN = "/Applications/Docker.app/Contents/Resources/bin"
BASE_PATH = ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")
# Non-secret env that the job needs to find the same roots as `add` did.
PASS_ENV = (
    "AGENTBOX_CONFIG_HOME",
    "AGENTBOX_STATE_HOME",
    "AGENTBOX_REPO",
    "AGENTBOX_TEST_SECRET_STORE",
    "AGENTBOX_DOCKER_WAIT",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
)
RC_DOCKER_DOWN = 69
RC_PREFLIGHT = 78
RC_SKIPPED = 75  # EX_TEMPFAIL
RC_TERMINATED = 143
SKIP_MSG = "skipped: a run is active"


class Terminated(Exception):
    """SIGTERM/SIGINT during `_fire`: unwinds so every finally block runs."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"terminated by signal {signum}")
        self.signum = signum


class ScheduleError(Exception):
    pass


# ---------------------------------------------------------------- cron parsing
FIELDS = (  # name, low, high, names
    ("minute", 0, 59, None),
    ("hour", 0, 23, None),
    ("day-of-month", 1, 31, None),
    (
        "month",
        1,
        12,
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"],
    ),
    ("day-of-week", 0, 7, ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]),
)
_ITEM = re.compile(r"(\*|[a-z0-9]+(?:-[a-z0-9]+)?)(?:/(\d+))?")


@dataclass(frozen=True)
class Cron:
    minute: tuple[int, ...]
    hour: tuple[int, ...]
    dom: tuple[int, ...] | None  # None = `*`
    month: tuple[int, ...] | None
    dow: tuple[int, ...] | None  # 0 = Sunday


def _num(tok: str, lo: int, names: list[str] | None, field: str) -> int:
    if tok.isdigit():
        return int(tok)
    if names and tok in names:
        return names.index(tok) + (lo if lo == 1 else 0)
    raise ScheduleError(f"cron {field}: {tok!r} is not a number" + (" or name" if names else ""))


def _field(text: str, i: int) -> tuple[int, ...] | None:
    field, lo, hi, names = FIELDS[i]
    text = text.lower()
    if any(c in text for c in "#?") or re.search(r"(^|[\d,])[lw]($|,)|\d[lw]", text):
        raise ScheduleError(f"cron {field}: L, W, # and ? are not supported by launchd")
    if text == "*":
        return None
    vals: set[int] = set()
    for item in text.split(","):
        m = _ITEM.fullmatch(item)
        if not m:
            raise ScheduleError(f"cron {field}: cannot parse {item!r}")
        rng, step = m.group(1), m.group(2)
        if rng == "*":
            a, b = lo, hi
        elif "-" in rng:
            x, y = rng.split("-")
            a, b = _num(x, lo, names, field), _num(y, lo, names, field)
        else:
            a = _num(rng, lo, names, field)
            b = hi if step else a
        n = int(step) if step else 1
        if n < 1:
            raise ScheduleError(f"cron {field}: step must be >= 1")
        if not (lo <= a <= hi and lo <= b <= hi) or a > b:
            raise ScheduleError(f"cron {field}: {item!r} is outside {lo}-{hi}")
        vals.update(range(a, b + 1, n))
    if i == 4:
        vals = {0 if v == 7 else v for v in vals}
        if vals == set(range(7)):
            return None
    elif vals == set(range(lo, hi + 1)):
        return None
    return tuple(sorted(vals))


def parse_cron(expr: str) -> Cron:
    if expr.strip().startswith("@"):
        raise ScheduleError(f"cron macros like {expr.split()[0]!r} are not supported; use 5 fields")
    parts = expr.split()
    if len(parts) != 5:
        raise ScheduleError(
            f"cron needs 5 fields (minute hour day-of-month month day-of-week), got {len(parts)}"
        )
    f = [_field(p, i) for i, p in enumerate(parts)]
    c = Cron(f[0] or tuple(range(60)), f[1] or tuple(range(24)), f[2], f[3], f[4])
    if all(x is None for x in f):
        raise ScheduleError("cron `* * * * *` (every minute): use --every 1m")
    return c


DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]


def parse_days(spec: str) -> str:
    """--days mon-fri | mon,wed,fri | sat-sun | daily -> cron day-of-week."""
    s = spec.strip().lower()
    if s in ("daily", "*", "all"):
        return "*"
    out = []
    for item in s.split(","):
        a, sep, b = item.partition("-")
        for x in (a, b) if sep else (a,):
            if x not in DAYS:
                raise ScheduleError(f"--days: {x!r} is not one of {', '.join(DAYS)}")
        if sep:
            ia, ib = DAYS.index(a), DAYS.index(b)
            if ia > ib:  # sat-sun, fri-mon: wrap past Saturday
                out += DAYS[ia:] + DAYS[: ib + 1]
            else:
                out += DAYS[ia : ib + 1]
        else:
            out.append(a)
    return ",".join(str(DAYS.index(d)) for d in dict.fromkeys(out))


def at_to_cron(at: str, days: str | None) -> str:
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", at.strip())
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise ScheduleError(f"--at {at!r}: use HH:MM (24 h, local time)")
    dow = parse_days(days) if days else "*"
    return f"{int(m.group(2))} {int(m.group(1))} * * {dow}"


def parse_every(spec: str) -> int:
    m = re.fullmatch(r"(\d+)([mhd])", spec.strip())
    if not m or int(m.group(1)) < 1:
        raise ScheduleError(f"--every {spec!r}: use <n>m, <n>h, or <n>d (for example 30m, 2h, 1d)")
    return int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400}[m.group(2)]


def parse_timeout(spec: str) -> int | None:
    """--timeout 30m | 2h | 1d | none (no limit) -> seconds."""
    if spec.strip().lower() in ("none", "0"):
        return None
    try:
        return parse_every(spec)
    except ScheduleError:
        raise ScheduleError(f"--timeout {spec!r}: use <n>m, <n>h, <n>d, or none") from None


def fmt_every(sec: int) -> str:
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if sec % n == 0:
            return f"{sec // n}{unit}"
    return f"{sec}s"


# ---------------------------------------------------------------- spec
@dataclass(frozen=True)
class Spec:
    cron: str | None = None
    every: int | None = None  # seconds

    def text(self) -> str:
        return f"every {fmt_every(self.every)}" if self.every else f"cron {self.cron}"

    def as_json(self) -> dict:
        return {"cron": self.cron} if self.cron else {"every": self.every}

    @staticmethod
    def from_json(d: dict) -> Spec:
        if "cron" in d:
            return Spec(cron=d["cron"])
        if "every" in d:
            return Spec(every=int(d["every"]))
        raise ScheduleError(f"job schedule {d!r} has neither cron nor every")


def make_spec(cron: str | None, every: str | None, at: str | None, days: str | None) -> Spec:
    given = [x for x in (cron, every, at) if x is not None]
    if len(given) != 1:
        raise ScheduleError("give exactly one of --cron, --every, --at")
    if days is not None and at is None:
        raise ScheduleError("--days works only with --at")
    if every is not None:
        return Spec(every=parse_every(every))
    expr = cron if cron is not None else at_to_cron(at, days)
    parse_cron(expr)
    return Spec(cron=" ".join(expr.split()))


# ---------------------------------------------------------------- launchd dicts
def launchd_calendar(expr: str) -> list[dict[str, int]]:
    c = parse_cron(expr)
    base = [("Minute", c.minute if len(c.minute) < 60 else None),
            ("Hour", c.hour if len(c.hour) < 24 else None), ("Month", c.month)]  # fmt: skip
    days: list[tuple[str, tuple[int, ...] | None]]
    if c.dom is not None and c.dow is not None:
        days = [("Day", c.dom), ("Weekday", c.dow)]  # cron: either matches
    elif c.dom is not None:
        days = [("Day", c.dom)]
    elif c.dow is not None:
        days = [("Weekday", c.dow)]
    else:
        days = [("", None)]
    out: list[dict[str, int]] = []
    for dkey, dvals in days:
        keys = [(k, v) for k, v in base + [(dkey, dvals)] if v is not None and k]
        for combo in itertools.product(*(v for _, v in keys)):
            out.append(dict(zip((k for k, _ in keys), combo, strict=True)))
    if len(out) > EXPAND_CAP:
        raise ScheduleError(
            f"cron {expr!r} needs {len(out)} launchd calendar entries (limit {EXPAND_CAP}); "
            "use fewer values or --every"
        )
    return out


def next_fires(spec: Spec, now: datetime, n: int = 3) -> list[datetime]:
    """Next n local fire times. --every: from now (launchd counts from load)."""
    now = now.replace(second=0, microsecond=0)
    if spec.every:
        return [now + timedelta(seconds=spec.every * (i + 1)) for i in range(n)]
    c = parse_cron(spec.cron)
    out: list[datetime] = []
    day = now.date()
    for _ in range(366 * 5):
        dow = (day.weekday() + 1) % 7
        if c.month is None or day.month in c.month:
            dm = c.dom is None or day.day in c.dom
            ww = c.dow is None or dow in c.dow
            either = c.dom is not None and c.dow is not None
            if (dm or ww) if either else (dm and ww):
                for h in c.hour:
                    for mi in c.minute:
                        t = datetime(day.year, day.month, day.day, h, mi)
                        if t > now:
                            out.append(t)
                            if len(out) == n:
                                return out
        day += timedelta(days=1)
    return out


# ---------------------------------------------------------------- locations
def validate_name(name: str) -> None:
    from .profile import PROFILE_NAME_RE

    if not PROFILE_NAME_RE.fullmatch(name):
        raise ScheduleError(f"schedule name {name!r} must match {PROFILE_NAME_RE.pattern}")


def job_dir(profile: str, name: str) -> Path:
    return paths.state_home() / profile / "schedules" / name


def launchagents_dir() -> Path:
    v = os.environ.get("AGENTBOX_LAUNCHAGENTS_DIR")
    return Path(v) if v else Path.home() / "Library" / "LaunchAgents"


def label_for(profile: str, name: str) -> str:
    prefix = os.environ.get("AGENTBOX_LAUNCHD_PREFIX", "com.agentbox")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,100}", prefix):
        raise ScheduleError(f"AGENTBOX_LAUNCHD_PREFIX {prefix!r} is not a valid label prefix")
    return f"{prefix}.{profile}.{name}"


def write_private(f: Path, data: bytes, mode: int = 0o600) -> None:
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(f".{f.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, mode)
    tmp.replace(f)


def load_job(profile: str, name: str) -> dict:
    f = job_dir(profile, name) / "job.json"
    if not f.is_file():
        raise ScheduleError(f"no schedule {name!r} for profile {profile!r} ({f})")
    return json.loads(f.read_text())


def list_jobs(profile: str | None = None) -> list[dict]:
    root = paths.state_home()
    if not root.is_dir():
        return []
    profs = [profile] if profile else sorted(p.name for p in root.iterdir() if p.is_dir())
    out = []
    for p in profs:
        d = root / p / "schedules"
        if d.is_dir():
            for j in sorted(d.iterdir()):
                f = j / "job.json"
                if f.is_file():
                    out.append(json.loads(f.read_text()))
    return out


def read_last(profile: str, name: str) -> dict | None:
    f = job_dir(profile, name) / "last.json"
    try:
        return json.loads(f.read_text())
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------- program + env
def program_args(argv0: str | None = None) -> tuple[list[str], dict[str, str]]:
    """Absolute argv prefix for agentbox, plus env it needs (PYTHONPATH on fallback)."""
    argv0 = sys.argv[0] if argv0 is None else argv0
    if argv0 and Path(argv0).name == "agentbox":
        p = Path(shutil.which(argv0) or argv0)
        if p.is_file() and os.access(p, os.X_OK):
            return [str(p.absolute())], {}
    found = shutil.which("agentbox")
    if found:
        return [str(Path(found).absolute())], {}
    pkg_parent = str(Path(__file__).resolve().parents[1])
    return [str(Path(sys.executable).absolute()), "-m", "agentbox.cli"], {"PYTHONPATH": pkg_parent}


def job_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """PATH (docker's dir first, Docker Desktop's CLI dir), HOME, and the
    non-secret AGENTBOX_*/DOCKER_* location overrides. Never a secret."""
    docker = shutil.which("docker")
    if not docker:
        raise ScheduleError("docker is not on PATH; install Docker Desktop first")
    dirs = [str(Path(docker).absolute().parent), DOCKER_APP_BIN, *BASE_PATH]
    env = {"PATH": ":".join(dict.fromkeys(dirs)), "HOME": str(Path.home())}
    for k in PASS_ENV:
        if os.environ.get(k):
            env[k] = os.environ[k]
    env.update(extra or {})
    return env


def job_code_paths(job: dict) -> tuple[str, ...]:
    """Host code a job executes: its program (agentbox or the interpreter) and
    the PYTHONPATH entries recorded in its environment."""
    env = job.get("env") or {}
    pp = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
    return tuple([job["argv"][0], *pp]) if job.get("argv") else tuple(pp)


def fire_argv(prog: list[str], profile: str, name: str) -> list[str]:
    return [*prog, "schedule", "_fire", profile, name]


def render_plist(job: dict) -> dict:
    jd = Path(job["dir"])
    d: dict = {
        "Label": job["label"],
        "ProgramArguments": job["argv"],
        "EnvironmentVariables": job["env"],
        "WorkingDirectory": "/",
        "StandardOutPath": str(jd / "launchd.out"),
        "StandardErrorPath": str(jd / "launchd.err"),
        "RunAtLoad": False,
        "ProcessType": "Background",
        "ExitTimeOut": 90,  # SIGTERM -> SIGKILL grace: cleanup stops the box
    }
    spec = Spec.from_json(job["schedule"])
    if spec.every:
        d["StartInterval"] = spec.every
    else:
        d["StartCalendarInterval"] = launchd_calendar(spec.cron)
    return d


def check_render(job: dict) -> bytes:
    """Render the scheduler entry fully (plist bytes or crontab line); raise
    ScheduleError on any problem, before anything is written."""
    try:
        if is_macos():
            return plistlib.dumps(render_plist(job))
        return cron_line(job).encode()
    except (ValueError, TypeError, OverflowError) as e:
        raise ScheduleError(f"cannot render the scheduler entry: {e}") from None


# ---------------------------------------------------------------- launchctl
def _domain() -> str:
    return f"gui/{os.getuid()}"


def launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl", *args], capture_output=True, text=True)


def is_loaded(label: str) -> bool:
    return launchctl("print", f"{_domain()}/{label}").returncode == 0


def unload(label: str) -> None:
    if is_loaded(label):
        r = launchctl("bootout", f"{_domain()}/{label}")
        if r.returncode != 0 and is_loaded(label):
            raise ScheduleError(f"launchctl bootout {label} failed: {r.stderr.strip()}")


def load(plist: Path, label: str) -> None:
    unload(label)
    r = launchctl("bootstrap", _domain(), str(plist))
    if r.returncode != 0:
        raise ScheduleError(f"launchctl bootstrap {plist} failed: {r.stderr.strip()}")


# ---------------------------------------------------------------- crontab
def tag(profile: str, name: str) -> str:
    return f"# agentbox:{profile}:{name}"


def every_to_cron(sec: int) -> str:
    if sec % 86400 == 0 and sec == 86400:
        return "0 0 * * *"
    if sec % 3600 == 0 and 24 % (sec // 3600) == 0:
        h = sec // 3600
        return "0 * * * *" if h == 1 else f"0 */{h} * * *"
    if sec % 60 == 0 and 60 % (sec // 60) == 0:
        m = sec // 60
        return "* * * * *" if m == 1 else f"*/{m} * * * *"
    raise ScheduleError(
        f"--every {fmt_every(sec)} has no exact cron form; use a divisor of 60m or 24h, or 1d"
    )


def cron_line(job: dict) -> str:
    spec = Spec.from_json(job["schedule"])
    when = every_to_cron(spec.every) if spec.every else spec.cron
    jd = Path(job["dir"])
    env = " ".join(f"{k}={shlex.quote(v)}" for k, v in job["env"].items())
    cmd = " ".join(shlex.quote(a) for a in job["argv"])
    out = shlex.quote(str(jd / "launchd.out"))
    errf = shlex.quote(str(jd / "launchd.err"))
    line = f"{when} cd / && {env} {cmd} </dev/null >>{out} 2>>{errf}"
    if "\n" in line or "%" in line:
        raise ScheduleError("crontab line would contain a newline or % (cron treats % as newline)")
    return line


def crontab_remove(text: str, profile: str, name: str) -> str:
    lines, out, skip = text.splitlines(), [], False
    t = tag(profile, name)
    for ln in lines:
        if skip:
            skip = False
            continue
        if ln.strip() == t:
            skip = True
            continue
        out.append(ln)
    return "\n".join(out) + ("\n" if out else "")


def crontab_set(text: str, profile: str, name: str, line: str) -> str:
    base = crontab_remove(text, profile, name)
    return base + f"{tag(profile, name)}\n{line}\n"


def crontab_read() -> str:
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if r.returncode != 0:
        if "no crontab" in r.stderr.lower():
            return ""
        raise ScheduleError(f"crontab -l failed: {r.stderr.strip()}")
    return r.stdout


def crontab_write(text: str) -> None:
    r = subprocess.run(["crontab", "-"], input=text, capture_output=True, text=True)
    if r.returncode != 0:
        raise ScheduleError(f"crontab - failed: {r.stderr.strip()}")


# ---------------------------------------------------------------- install
def is_macos() -> bool:
    return sys.platform == "darwin"


def validate_for_platform(spec: Spec) -> None:
    if is_macos():
        if spec.cron:
            launchd_calendar(spec.cron)
    elif spec.every:
        every_to_cron(spec.every)


def install(job: dict) -> None:
    if is_macos():
        plist = Path(job["plist"])
        plist.parent.mkdir(parents=True, exist_ok=True)
        write_private(plist, plistlib.dumps(render_plist(job)), 0o644)
        load(plist, job["label"])
    else:
        crontab_write(crontab_set(crontab_read(), job["profile"], job["name"], cron_line(job)))


def uninstall(job: dict) -> None:
    if is_macos():
        unload(job["label"])
        with contextlib.suppress(FileNotFoundError):
            Path(job["plist"]).unlink()
    else:
        text = crontab_read()
        new = crontab_remove(text, job["profile"], job["name"])
        if new != text:
            crontab_write(new)


def installed(job: dict) -> str:
    if is_macos():
        return "loaded" if is_loaded(job["label"]) else "not loaded"
    try:
        return "in crontab" if tag(job["profile"], job["name"]) in crontab_read() else "no crontab"
    except ScheduleError:
        return "unknown"


# ---------------------------------------------------------------- fire
def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def log(profile: str, name: str, msg: str) -> None:
    print(f"{now_iso()} agentbox schedule {profile}/{name}: {msg}", file=sys.stderr, flush=True)


def rotate(f: Path, limit: int = LOG_ROTATE) -> None:
    """Keep one old copy (<f>.1) once f is over limit."""
    with contextlib.suppress(OSError):
        if f.stat().st_size > limit:
            f.replace(f.with_name(f.name + ".1"))


def lock_free(jd: Path) -> bool:
    """True when no `_fire` holds the job's fire.lock."""
    try:
        with (jd / "fire.lock").open("a") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(lk, fcntl.LOCK_UN)
            return True
    except BlockingIOError:
        return False
    except OSError:
        return True


def skip_summary(jd: Path) -> str | None:
    """ "skipped N since <t>": skips after the last real fire."""
    f = jd / "history.jsonl"
    try:
        rows = [json.loads(x) for x in f.read_text().splitlines() if x.strip()]
    except (OSError, ValueError):
        return None
    n, first = 0, None
    for r in reversed(rows):
        if r.get("status") != "skipped":
            break
        n, first = n + 1, r.get("start")
    return f"skipped {n} since {first}" if n else None


def record(jd: Path, rec: dict, last: bool = True) -> None:
    rotate(jd / "history.jsonl")
    if last:
        write_private(jd / "last.json", (json.dumps(rec, indent=1, sort_keys=True) + "\n").encode())
    with (jd / "history.jsonl").open("a") as h:
        h.write(json.dumps(rec, sort_keys=True) + "\n")
    os.chmod(jd / "history.jsonl", 0o600)


def docker_up() -> bool:
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def ensure_docker(profile: str, name: str, wait: float, poll: float) -> bool:
    if docker_up():
        return True
    if not is_macos():
        log(profile, name, "Docker is not reachable (`docker info` failed)")
        return False
    log(profile, name, "Docker is not reachable; starting Docker Desktop (open -ga Docker)")
    with contextlib.suppress(OSError):
        subprocess.run(["open", "-ga", "Docker"], capture_output=True, timeout=30)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        time.sleep(poll)
        if docker_up():
            log(profile, name, "Docker is up")
            return True
    return False


def run_meta(rd, key: str) -> str | None:
    if not rd:
        return None
    try:
        v = json.loads((Path(rd) / "meta.json").read_text()).get(key)
    except (OSError, ValueError):
        return None
    return v if isinstance(v, str) else None


def host_changes(rd) -> list[str]:
    """host_config_changes from the run's meta.json (PLAN §1 detection)."""
    if not rd:
        return []
    try:
        v = json.loads((Path(rd) / "meta.json").read_text()).get("host_config_changes")
    except (OSError, ValueError):
        return []
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def left_up(rd) -> str | None:
    """Why the run's box stayed up (from the run's meta.json), if it did."""
    return run_meta(rd, "left_up")


def stopped_note(rd) -> str | None:
    """ "killed leftover processes (...)" when the run's stop found some."""
    return run_meta(rd, "stopped")


def fire(profile: str, name: str, runner, preflight, wait: float | None = None,
         poll: float = DOCKER_POLL) -> int:  # fmt: skip
    """One scheduled run. runner(profile, agent, prompt_path, model, timeout) ->
    (rc, run_dir); an exception may carry .run_dir and .rc. preflight(profile,
    agent, model) -> (error or None, warnings). Never interactive."""
    if wait is None:
        wait = float(os.environ.get("AGENTBOX_DOCKER_WAIT", DOCKER_WAIT))
    job = load_job(profile, name)
    jd = Path(job["dir"])
    for f in ("launchd.out", "launchd.err"):
        rotate(jd / f)
    base = {"profile": profile, "name": name, "agent": job["agent"], "start": now_iso()}
    with (jd / "fire.lock").open("a") as lk:
        try:
            fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log(profile, name, SKIP_MSG)
            skip = {**base, "status": "skipped", "end": now_iso(), "exit_code": RC_SKIPPED,
                    "message": SKIP_MSG}  # fmt: skip
            record(jd, skip, last=False)
            write_private(jd / "skipped.json", (json.dumps(skip, indent=1) + "\n").encode())
            return RC_SKIPPED
        rec = {**base, "status": "running", "end": None, "exit_code": None, "run_dir": None,
               "transcript": None, "message": None, "warnings": [], "pid": os.getpid()}  # fmt: skip
        write_private(jd / "last.json", (json.dumps(rec, indent=1, sort_keys=True) + "\n").encode())
        rc, rd, msg, status = RC_PREFLIGHT, None, None, None
        try:
            if not ensure_docker(profile, name, wait, poll):
                rc = RC_DOCKER_DOWN
                msg = (
                    f"Docker did not come up within {wait:.0f} s; the job did not run. Start "
                    f"Docker Desktop, then run `agentbox schedule run-now {profile} {name}`"
                )
                log(profile, name, msg)
            else:
                msg, rec["warnings"] = preflight(profile, job["agent"], job.get("model"),
                                                 job_code_paths(job))  # fmt: skip
                for w in rec["warnings"]:
                    log(profile, name, f"warning: {w}")
                if msg is not None:
                    log(profile, name, msg)
                else:
                    tmo = job.get("timeout", DEFAULT_TIMEOUT)
                    prompt = str(jd / "prompt.md")
                    rc, rd = runner(profile, job["agent"], prompt, job.get("model"), tmo)
                    log(profile, name, f"run {rd} exit {rc}")
                    if why := left_up(rd):
                        rec["left_up"] = f"left up: {why}"
                    if note := stopped_note(rd):
                        rec["stopped"] = f"stopped: {note}"
                    if hc := host_changes(rd):
                        rec["host_config_changes"] = hc
        except Terminated as e:
            rc, status, msg = RC_TERMINATED, "terminated", str(e)
            rd = getattr(e, "run_dir", None) or rd
            if note := stopped_note(rd):
                rec["stopped"] = f"stopped: {note}"
            if hc := host_changes(rd):
                rec["host_config_changes"] = hc
            log(profile, name, msg)
        except Exception as e:  # noqa: BLE001 - every failure is recorded
            msg = f"run failed: {e}"
            rd = getattr(e, "run_dir", None)
            if why := left_up(rd):
                rec["left_up"] = f"left up: {why}"
            if note := stopped_note(rd):
                rec["stopped"] = f"stopped: {note}"
            if hc := host_changes(rd):
                rec["host_config_changes"] = hc
            rc = getattr(e, "rc", None) or 125
            if rc == RC_TERMINATED:
                status = "terminated"
            log(profile, name, msg)
        if rc == 124 and msg is None:
            msg = f"killed after the timeout ({fmt_every(job.get('timeout', DEFAULT_TIMEOUT))})"
        rec.update(
            status=status or ("ok" if rc == 0 else "failed"),
            end=now_iso(),
            exit_code=rc,
            run_dir=str(rd) if rd else None,
            transcript=str(Path(rd) / "transcript.log") if rd else None,
            message=msg,
        )
        rec.pop("pid", None)
        record(jd, rec)
        return rc
