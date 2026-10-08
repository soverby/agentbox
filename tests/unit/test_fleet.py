"""Fleet report facts (PLAN §2.8): window, due times, matching, classes, causes,
idle boxes, drift, the investigator. No network, no Docker, no real launchd or
crontab: every host fact is replaced. The time zone is Europe/Lisbon."""

import fcntl
import json
import os
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from agentbox import docker, fleet, paths, schedule
from agentbox.schedule import Spec

SECRET = "sk-ant-oat01-ZZZZ-fleet-test-secret-value-1234567890"
WEBHOOK = "https://hooks.slack.com/services/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4"


def tzset():
    if hasattr(time, "tzset"):  # some builds omit it; datetime then re-reads TZ itself
        time.tzset()


@pytest.fixture(autouse=True)
def lisbon():
    old = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Lisbon"
    tzset()
    yield
    if old is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = old
    tzset()


def T(text: str) -> datetime:
    """Aware local (Lisbon) time from 'YYYY-MM-DD HH:MM[:SS]'."""
    return datetime.fromisoformat(text).astimezone()


NOW = T("2026-10-08 10:00")


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Isolated roots; no Docker, no launchctl, no boot-time source."""
    for k, v in (("CONFIG_HOME", "cfg"), ("STATE_HOME", "state"), ("LAUNCHAGENTS_DIR", "la")):
        monkeypatch.setenv(f"AGENTBOX_{k}", str(tmp_path / v))
    monkeypatch.setenv("AGENTBOX_LAUNCHD_PREFIX", "com.agentbox-unit")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()

    def no_docker(*a, **k):
        raise docker.DockerError("docker: command not found")

    monkeypatch.setattr(docker, "run", no_docker)
    monkeypatch.setattr(docker, "running_projects", no_docker)
    monkeypatch.setattr(schedule, "installed", lambda job: "loaded")
    monkeypatch.setattr(schedule, "is_macos", lambda: True)
    monkeypatch.setattr(fleet, "PROC_STAT", str(tmp_path / "no-proc-stat"))
    w = SimpleNamespace(tmp=tmp_path, state=tmp_path / "state", cfg=tmp_path / "cfg", n=0)
    w.state.mkdir()
    (w.cfg / "profiles").mkdir(parents=True)
    return w


def mkjob(w, profile="p", name="j", cron="30 8 * * *", every=None, created="2026-10-01 00:00",
          kind="cmd", **extra):  # fmt: skip
    jd = w.state / profile / "schedules" / name
    jd.mkdir(parents=True, exist_ok=True)
    spec = {"every": every} if every else {"cron": cron}
    job = {
        "profile": profile, "name": name, "kind": kind,
        "agent": None if kind == "cmd" else "claude", "model": None, "schedule": spec,
        "timeout": 540, "dir": str(jd), "label": f"com.agentbox-unit.{profile}.{name}",
        "plist": str(w.tmp / "la" / f"{profile}.{name}.plist"), "argv": ["/x/agentbox"],
        "env": {"PATH": "/usr/bin", "HOME": str(w.tmp / "home")},
        "created": fleet.iso(T(created)), **extra,
    }  # fmt: skip
    (jd / "job.json").write_text(json.dumps(job))
    (jd / "command.sh").write_text("true\n")
    return job


def addrow(w, job, start, *, status="ok", rc=0, trigger="schedule", message=None,
           transcript=None, meta=None, left_up=None, notify=None, run_dir=True,
           last_only=False, **extra):  # fmt: skip
    """Append a fire row (shape of the real history.jsonl). trigger None: no key."""
    jd = Path(job["dir"])
    w.n += 1
    row = {
        "profile": job["profile"], "name": job["name"], "kind": job["kind"], "agent": job["agent"],
        "start": fleet.iso(T(start)), "end": fleet.iso(T(start) + timedelta(seconds=40)),
        "status": status, "exit_code": rc, "message": message, "warnings": [],
        "run_dir": None, "transcript": None, **extra,
    }  # fmt: skip
    if trigger is not None:
        row["trigger"] = trigger
    if run_dir:
        rd = jd.parent.parent / "runs" / f"run{w.n}"
        rd.mkdir(parents=True)
        (rd / "meta.json").write_text(json.dumps({"env": {"X": "1"}, **(meta or {})}))
        row["run_dir"] = str(rd)
        if transcript is not None:
            (rd / "transcript.log").write_text(transcript)
            row["transcript"] = str(rd / "transcript.log")
    if left_up:
        row["left_up"] = left_up
    if notify:
        row["notify"] = notify
    if last_only:
        (jd / "last.json").write_text(json.dumps(row))
    else:
        with (jd / "history.jsonl").open("a") as h:
            h.write(json.dumps(row) + "\n")
    return row


def run_report(w, now=NOW, since="24h", post=False, **kw):
    kw.setdefault("investigate", False)
    kw.setdefault("cfg", paths.Config())
    return fleet.build_report(now, fleet.parse_since(since), post=post, **kw)


def classes(rep, job=None):
    return [(f.cls, f.origin) for f in rep.fires if job is None or f.job == job]


def hold_lock(path: Path):
    """Hold an exclusive flock on `path` through another descriptor."""
    f = path.open("a")
    fcntl.flock(f, fcntl.LOCK_EX)
    return f


# ---------------------------------------------------------------- since and window
def test_parse_since():
    assert fleet.parse_since("24h") == timedelta(hours=24)
    assert fleet.parse_since("3d") == timedelta(days=3)
    assert fleet.parse_since("14d") == timedelta(days=14)
    assert fleet.parse_since("1h") == timedelta(hours=1)
    for bad in ("0h", "15d", "337h", "24", "1w", "h", "-3h", "1.5h", "24H"):
        with pytest.raises(fleet.FleetError):
            fleet.parse_since(bad)


def test_window_without_post(world):
    start, end, carried = fleet.resolve_window(NOW, timedelta(hours=72), post=False)
    assert (start, end, carried) == (NOW - timedelta(hours=72), NOW, [])


def write_last(w, window_end, carry=()):
    d = fleet.report_dir()
    (d / "last.json").write_text(json.dumps({"window_end": window_end, "carry": list(carry)}))


def test_post_window_anchors_on_the_previous_report(world):
    write_last(world, fleet.iso(T("2026-10-07 09:30")))
    start, end, _ = fleet.resolve_window(NOW, timedelta(hours=24), post=True)
    assert (start, end) == (T("2026-10-07 09:30"), NOW)  # no gap, no overlap
    # without --post the file is ignored
    assert fleet.resolve_window(NOW, timedelta(hours=24), post=False)[0] == NOW - timedelta(
        hours=24
    )


def test_post_window_fallbacks_and_cap(world):
    d = fleet.report_dir()
    since = timedelta(hours=24)
    # no file
    assert fleet.resolve_window(NOW, since, post=True)[0] == NOW - since
    # unreadable, wrong shape, window_end after now: now - since, nothing carried
    carry = [{"job": "p/j", "due": fleet.iso(T("2026-10-08 09:20"))}]
    for text in (
        "{not json",
        "[]",
        json.dumps({"window_end": "garbage"}),
        json.dumps({"window_end": fleet.iso(NOW + timedelta(hours=1)), "carry": carry}),
        json.dumps({"window_end": fleet.iso(T("2026-10-07 09:30")), "carry": "x"}),
        json.dumps({"window_end": fleet.iso(T("2026-10-07 09:30")), "carry": [{"job": "p/j"}]}),
    ):
        (d / "last.json").write_text(text)
        assert fleet.resolve_window(NOW, since, post=True) == (NOW - since, NOW, [])
    # at most 14 d back
    write_last(world, fleet.iso(NOW - timedelta(days=30)))
    assert fleet.resolve_window(NOW, since, post=True)[0] == NOW - timedelta(days=14)


def test_report_dir_is_private_and_named_underscore_report(world):
    d = fleet.report_dir()
    assert d == world.state / "_report" and d.stat().st_mode & 0o777 == 0o700
    assert "_report" not in [p.name for p in paths.state_home().glob("*/schedules")]


# ---------------------------------------------------------------- fires_between and DST
def hm(ts):
    return [t.strftime("%m-%d %H:%M") for t in ts]


def test_fires_between_skips_the_spring_forward_gap():
    day = Spec(cron="30 1 * * *")
    got = schedule.fires_between(day, T("2026-03-28 00:00"), T("2026-03-31 00:00"))
    assert hm(got) == ["03-28 01:30", "03-30 01:30"]  # 03-29 01:30 does not exist
    assert hm(schedule.fires_between(Spec(cron="30 2 * * *"), T("2026-03-28 00:00"),
                                     T("2026-03-31 00:00"))) == [
        "03-28 02:30", "03-29 02:30", "03-30 02:30"]  # fmt: skip
    hourly = schedule.fires_between(Spec(cron="0 * * * *"), T("2026-03-29 00:00"),
                                    T("2026-03-30 00:00"))  # fmt: skip
    assert len(hourly) == 23 and "03-29 01:00" not in hm(hourly)
    assert all(t.tzinfo is not None for t in hourly)


def test_fires_between_fall_back_is_due_once():
    once = schedule.fires_between(Spec(cron="30 1 * * *"), T("2026-10-24 00:00"),
                                  T("2026-10-27 00:00"))  # fmt: skip
    assert hm(once) == ["10-24 01:30", "10-25 01:30", "10-26 01:30"]
    assert once[1].utcoffset() == timedelta(hours=1)  # fold 0: the first 01:30
    hourly = schedule.fires_between(Spec(cron="0 * * * *"), T("2026-10-25 00:00"),
                                    T("2026-10-26 00:00"))  # fmt: skip
    assert len(hourly) == 24  # the repeated hour counts once


def test_fires_between_bounds_and_every():
    spec = Spec(cron="0 7 * * *")
    got = schedule.fires_between(spec, T("2026-10-07 07:00"), T("2026-10-09 07:00"))
    assert hm(got) == ["10-07 07:00", "10-08 07:00"]  # [start, end)
    assert schedule.next_fires(spec, T("2026-10-07 07:00").replace(tzinfo=None), 1)  # unchanged
    with pytest.raises(schedule.ScheduleError):
        schedule.fires_between(Spec(every=60), NOW, NOW)


def test_fires_between_follows_dom_dow_rule():
    spec = Spec(cron="0 9 1 * 1")  # the 1st OR any Monday
    got = schedule.fires_between(spec, T("2026-10-01 00:00"), T("2026-10-13 00:00"))
    assert hm(got) == ["10-01 09:00", "10-05 09:00", "10-12 09:00"]


def test_created_after_window_start_limits_the_due_times(world):
    job = mkjob(world, cron="0 7,13 * * *", created="2026-10-07 12:00")
    rep = run_report(world, since="48h")
    dues = [fleet.label(fleet.parse_dt(f.due)) for f in rep.fires]
    assert dues == ["10-07 13:00", "10-08 07:00"]  # 10-07 07:00 is before `created`
    job["created"] = fleet.iso(T("2026-10-01 00:00"))
    (Path(job["dir"]) / "job.json").write_text(json.dumps(job))
    assert len(run_report(world, since="48h").fires) == 4  # 10-06 13:00 and 10-07 07:00 too
    # a job without a valid `created` is a hard error, never a default
    del job["created"]
    (Path(job["dir"]) / "job.json").write_text(json.dumps(job))
    with pytest.raises(fleet.FleetError, match="created"):
        run_report(world)


# ---------------------------------------------------------------- every jobs
def test_every_job_on_macos_is_never_missed(world):
    job = mkjob(world, every=1800, created="2026-10-07 00:00")
    for s in ("2026-10-08 06:00:03", "2026-10-08 06:30:01", "2026-10-08 08:00:00"):
        addrow(world, job, s, trigger=None)  # gaps are normal: launchd skips sleeping intervals
    addrow(world, job, "2026-10-08 09:00:00", status="failed", rc=1, transcript="boom line\n")
    rep = run_report(world, since="24h")
    assert [f.cls for f in rep.fires] == ["ok", "ok", "ok", "failed"]
    assert {f.origin for f in rep.fires} == {"every"} and rep.scheduled == 4
    assert rep.every_jobs == [{"job": "p/j", "runs": 4, "expected": 48}]
    assert not [f for f in rep.fires if f.cls in ("missed", "not_run_yet", "pending")]


def test_every_job_on_linux_is_cron_exact(world, monkeypatch):
    monkeypatch.setattr(schedule, "is_macos", lambda: False)
    job = mkjob(world, every=3600, created="2026-10-07 00:00")  # cron `0 * * * *`
    addrow(world, job, "2026-10-08 07:00:05")
    addrow(world, job, "2026-10-08 09:00:02")
    rep = run_report(world, since="3h")
    assert [(fleet.hhmm(fleet.parse_dt(f.due)), f.cls) for f in rep.fires] == [
        ("07:00", "ok"), ("08:00", "missed"), ("09:00", "ok")]  # fmt: skip
    assert rep.every_jobs == []
    # an interval with no cron form (never added on Linux) falls back to "about N runs"
    job2 = mkjob(world, name="odd", every=1000, created="2026-10-07 00:00")
    addrow(world, job2, "2026-10-08 07:00:05")
    rep = run_report(world, since="3h")
    assert [i["job"] for i in rep.every_jobs] == ["p/odd"]


# ---------------------------------------------------------------- matching
def test_row_early_and_late_edges(world):
    job = mkjob(world, cron="0 7 * * *")
    addrow(world, job, "2026-10-08 06:58:00")  # d - 2 min: matches
    rep = run_report(world)
    assert classes(rep) == [("ok", "due")]
    (Path(job["dir"]) / "history.jsonl").unlink()
    addrow(world, job, "2026-10-08 06:57:59")  # too early: extra, and the due time is missed
    late = run_report(world, now=T("2026-10-08 20:00"))
    assert sorted(classes(late)) == [("missed", "due"), ("ok", "extra")]


def test_late_match_within_six_hours(world):
    job = mkjob(world, cron="0 7 * * *")
    addrow(world, job, "2026-10-08 12:59:59")
    assert classes(run_report(world, now=T("2026-10-08 20:00"))) == [("ok", "due")]
    (Path(job["dir"]) / "history.jsonl").unlink()
    addrow(world, job, "2026-10-08 13:00:00")  # d + 6 h: out
    got = sorted(classes(run_report(world, now=T("2026-10-08 20:00"))))
    assert got == [("missed", "due"), ("ok", "extra")]


def test_late_match_stops_at_the_next_due_time(world):
    job = mkjob(world, cron="0 7,8 * * *")
    addrow(world, job, "2026-10-08 08:30:00")  # belongs to 08:00, not to 07:00
    rep = run_report(world, now=T("2026-10-08 20:00"))
    assert [(fleet.hhmm(fleet.parse_dt(f.due)), f.cls) for f in rep.fires] == [
        ("07:00", "missed"), ("08:00", "ok")]  # fmt: skip


def test_catch_up_coalescing_on_macos(world):
    job = mkjob(world, cron="5,35 7,8 * * *")  # four due times in the morning
    addrow(world, job, "2026-10-08 09:00:30")  # one catch-up fire after wake
    rep = run_report(world)
    got = [(fleet.hhmm(fleet.parse_dt(f.due)), f.cls, f.cause) for f in rep.fires]
    gone = "coalesced into the catch-up fire at 09:00"
    assert got == [("07:05", "missed", gone), ("07:35", "missed", gone),
                   ("08:05", "missed", gone), ("08:35", "ok", None)]  # fmt: skip
    assert rep.scheduled == 4 and rep.completed == 1


def test_no_coalescing_on_linux(world, monkeypatch):
    monkeypatch.setattr(schedule, "is_macos", lambda: False)
    job = mkjob(world, cron="5,35 7,8 * * *")
    addrow(world, job, "2026-10-08 09:00:30")
    rep = run_report(world)
    assert [f.cause for f in rep.fires][:3] == ["no fire recorded"] * 3


def test_pending_not_run_yet_missed_transitions(world):
    mkjob(world, name="recent", cron="50 9 * * *")  # due 10 min ago
    mkjob(world, name="wait", cron="0 9 * * *")  # due 60 min ago, still inside the late window
    mkjob(world, name="old", cron="0 2 * * *")  # due 8 h ago
    mkjob(world, name="hourly", cron="0 * * * *", created="2026-10-08 00:00")
    rep = run_report(world, since="24h")
    by = {f.job: f for f in rep.fires if f.job != "p/hourly"}
    assert by["p/recent"].cls == "pending" and not by["p/recent"].counted
    assert by["p/wait"].cls == "not_run_yet" and by["p/wait"].counted
    assert by["p/wait"].cause is None  # no rule found a cause
    assert by["p/old"].cls == "missed" and by["p/old"].cause == "no fire recorded"
    # the next due time ends the late window: 09:00 of an hourly job is missed at 10:00
    hourly = {fleet.hhmm(fleet.parse_dt(f.due)): f.cls for f in rep.fires if f.job == "p/hourly"}
    assert hourly["09:00"] == "missed" and hourly["00:00"] == "missed" and "10:00" not in hourly
    assert sorted(rep.carry, key=lambda c: c["job"]) == [
        {"job": "p/recent", "due": fleet.iso(T("2026-10-08 09:50")), "state": "pending"},
        {"job": "p/wait", "due": fleet.iso(T("2026-10-08 09:00")), "state": "not_run_yet"},
    ]
    assert rep.scheduled == len([f for f in rep.fires if f.cls != "pending"])


def test_a_late_fire_after_the_report_matches_the_next_time(world):
    job = mkjob(world, cron="0 9 * * *")
    assert run_report(world).fires[0].cls == "not_run_yet"
    addrow(world, job, "2026-10-08 10:20:00")
    rep = run_report(world, now=T("2026-10-08 11:00"))
    assert classes(rep) == [("ok", "due")]


# ---------------------------------------------------------------- carry-over
def test_carried_due_time_matches_a_late_row(world):
    job = mkjob(world, cron="20 9 * * *")
    addrow(world, job, "2026-10-08 09:41:00", status="failed", rc=1, transcript="DIFFERENT\n")
    carry = [{"job": "p/j", "due": fleet.iso(T("2026-10-08 09:20"))}]
    write_last(world, fleet.iso(T("2026-10-08 09:30")), carry)
    rep = run_report(world, post=True)
    assert rep.window_start == fleet.iso(T("2026-10-08 09:30"))
    [f] = rep.fires
    assert (f.cls, f.origin, f.note, f.due) == ("failed", "due", "late, due 09:20",
                                                 fleet.iso(T("2026-10-08 09:20")))  # fmt: skip
    assert f.counted and rep.carry == []


def test_carried_due_time_that_is_still_open_stays_carried(world):
    mkjob(world, cron="0 9 * * *")
    write_last(world, fleet.iso(T("2026-10-08 09:30")),
               [{"job": "p/j", "due": fleet.iso(T("2026-10-08 09:00"))}])  # fmt: skip
    rep = run_report(world, post=True)
    assert classes(rep) == [("not_run_yet", "due")]
    assert rep.carry == [
        {"job": "p/j", "due": fleet.iso(T("2026-10-08 09:00")), "state": "not_run_yet"}
    ]


def test_carry_is_dropped_for_a_gone_job_or_before_created(world):
    mkjob(world, created="2026-10-08 09:25", cron="20 9 * * *")
    write_last(world, fleet.iso(T("2026-10-08 09:30")), [
        {"job": "p/j", "due": fleet.iso(T("2026-10-08 09:20"))},  # d < created
        {"job": "p/gone", "due": fleet.iso(T("2026-10-08 09:20"))},  # no such job
    ])  # fmt: skip
    rep = run_report(world, post=True)
    assert rep.fires == [] and rep.carry == []


def test_carry_is_ignored_when_last_json_is_in_the_future(world):
    mkjob(world, cron="20 9 * * *")
    write_last(world, fleet.iso(NOW + timedelta(hours=2)),
               [{"job": "p/j", "due": fleet.iso(T("2026-10-08 09:20"))}])  # fmt: skip
    rep = run_report(world, post=True)  # start = now - 24h: 09:20 is its own due time
    assert rep.window_start == fleet.iso(NOW - timedelta(hours=24))
    assert [(f.cls, f.note) for f in rep.fires] == [("not_run_yet", None)]


def test_save_last_report_writes_window_end_and_carry(world):
    mkjob(world, cron="50 9 * * *")
    rep = run_report(world, post=True)
    fleet.save_last_report(rep)
    f = fleet.report_dir() / "last.json"
    data = json.loads(f.read_text())
    assert data["window_end"] == fleet.iso(NOW) and data["carry"] == rep.carry != []
    assert f.stat().st_mode & 0o777 == 0o600
    assert fleet.resolve_window(NOW + timedelta(hours=1), timedelta(hours=1), post=True)[0] == NOW


# ---------------------------------------------------------------- classes
def test_classes_from_row_shapes(world):
    job = mkjob(world, cron="0 6 * * *")
    kill = "working\nlast words\n\n[agentbox: run killed: timeout after 540 s]\n"
    nomsg = dict(run_dir=False)
    rows = [
        ("06:00", dict(status="ok")),
        ("06:01", dict(status="failed", rc=124, meta={"killed": "timeout after 540 s"},
                       transcript=kill)),
        ("06:02", dict(status="failed", rc=124, meta={}, transcript="exit 124 by itself\n")),
        ("06:03", dict(status="failed", rc=69, message="Docker did not come up", **nomsg)),
        ("06:04", dict(status="failed", rc=78, message="CLAUDE_CODE_OAUTH_TOKEN is missing",
                       **nomsg)),
        ("06:05", dict(status="failed", rc=125, message="run failed: no compose", transcript="")),
        ("06:06", dict(status="terminated", rc=143, message="terminated by signal 15", **nomsg)),
        ("06:07", dict(status="skipped", rc=75, message="skipped: a run is active", **nomsg)),
        ("06:08", dict(status="failed", rc=78, transcript="a script's own 78\n")),
        ("06:09", dict(status="failed", rc=125, transcript="a script's own 125\n")),
        ("06:10", dict(status="failed", rc=1, transcript="boletim delta: DIFFERENT vs a\n")),
    ]  # fmt: skip
    for at, kw in rows:
        addrow(world, job, f"2026-10-08 {at}:00", trigger=None, **kw)
    rep = run_report(world, since="12h", now=T("2026-10-08 12:30"))
    got = {fleet.hhmm(fleet.parse_dt(f.when)): (f.cls, f.cause) for f in rep.fires}
    assert got["06:00"] == ("ok", None)
    assert got["06:01"] == ("timeout", "killed after the 9m timeout; last line: last words")
    assert got["06:02"] == ("failed", "exit 124 by itself")  # a script's own 124 is not a timeout
    assert got["06:03"] == ("docker_down", "Docker did not come up")
    assert got["06:04"] == ("preflight", "CLAUDE_CODE_OAUTH_TOKEN is missing")
    assert got["06:05"] == ("start_failed", "run failed: no compose")
    assert got["06:06"][0] == "terminated" and "logout" in got["06:06"][1]
    assert got["06:07"] == ("skipped", "a run of this job was still active")
    assert got["06:08"] == ("failed", "a script's own 78")
    assert got["06:09"] == ("failed", "a script's own 125")
    assert got["06:10"] == ("failed", "boletim delta: DIFFERENT vs a")
    unexplained = [fleet.hhmm(fleet.parse_dt(f.when)) for f in rep.fires if f.unexplained]
    assert unexplained == ["06:02", "06:08", "06:09", "06:10"]


def test_unknown_status_row_is_one_unexplained_line_and_the_report_goes_on(world):
    job = mkjob(world, cron="0 6 * * *")
    addrow(world, job, "2026-10-08 06:00:00", status="weird")
    rep = run_report(world)
    got = [(f.cls, f.origin, f.unexplained, f.cause, f.counted) for f in rep.fires]
    assert ("unknown", "unparsed", True, "history row not understood", False) in got
    assert ("not_run_yet", "due", False, None, True) in got
    assert len(got) == 2  # the row is not a match, and the due time is judged by the rules


def test_unparsable_history_lines_are_each_one_problem(world):
    job = mkjob(world, cron="0 6 * * *")
    jd = Path(job["dir"])
    with (jd / "history.jsonl").open("w") as h:
        h.write('{"torn": \n[1, 2]\n{"start": "not a time", "status": "ok"}\n\n')
    addrow(world, job, "2026-10-08 06:00:03")
    rep = run_report(world)
    bad = [f for f in rep.fires if f.cls == "unknown"]
    assert len(bad) == 3 and all(f.when == fleet.iso(NOW) for f in bad)
    assert [f.cls for f in rep.fires if f.cls != "unknown"] == ["ok"]


def test_running_row_with_lock_held_is_still_running(world):
    job = mkjob(world, cron="0 9 * * *")
    addrow(world, job, "2026-10-08 09:00:02", status="running", rc=None, last_only=True)
    lock = hold_lock(Path(job["dir"]) / "fire.lock")
    try:
        rep = run_report(world)
    finally:
        lock.close()
    [f] = rep.fires
    assert f.cls == "still_running" and not f.counted and not f.problem
    assert f.cause == "running since 10-08 09:00"
    assert rep.scheduled == 0


def test_running_row_with_lock_free_is_stale(world):
    job = mkjob(world, cron="0 9 * * *")
    addrow(world, job, "2026-10-08 09:00:02", status="running", rc=None, last_only=True)
    [f] = run_report(world).fires
    assert f.cls == "stale_running" and f.counted and f.problem
    assert f.cause == "the fire process ended without a record"


def running_job(world, cron, started):
    job = mkjob(world, cron=cron)
    addrow(world, job, started, status="running", rc=None, last_only=True)
    return job


def test_due_time_with_no_row_and_lock_held_is_still_running_when_the_fire_serves_it(world):
    job = running_job(world, "0 8,9 * * *", "2026-10-08 08:30:02")  # a long run
    lock = hold_lock(Path(job["dir"]) / "fire.lock")
    try:
        rep = run_report(world)
    finally:
        lock.close()
    assert [(fleet.hhmm(fleet.parse_dt(f.due)), f.cls, f.counted) for f in rep.fires] == [
        ("08:00", "still_running", False), ("09:00", "still_running", False)]  # fmt: skip
    assert rep.scheduled == 0


def test_earlier_due_time_with_no_row_is_not_hidden_by_a_running_fire(world):
    """Hourly job: 06:00 and 07:00 ran, 08:00 left no row, the 09:00 run holds the lock."""
    job = mkjob(world, cron="0 * * * *", created="2026-10-08 05:30")
    addrow(world, job, "2026-10-08 06:00:02")
    addrow(world, job, "2026-10-08 07:00:02")
    addrow(world, job, "2026-10-08 09:00:02", status="running", rc=None, last_only=True)
    lock = hold_lock(Path(job["dir"]) / "fire.lock")
    try:
        rep = run_report(world, now=T("2026-10-08 09:40"), since="6h")
    finally:
        lock.close()
    got = {fleet.hhmm(fleet.parse_dt(f.due)): f.cls for f in rep.fires}
    assert got == {"06:00": "ok", "07:00": "ok", "08:00": "missed", "09:00": "still_running"}


def test_a_lock_without_a_running_record_does_not_hide_a_due_time(world):
    job = mkjob(world, cron="0 8 * * *")
    lock = hold_lock(Path(job["dir"]) / "fire.lock")  # nobody wrote last.json
    try:
        [f] = run_report(world).fires
    finally:
        lock.close()
    assert f.cls == "not_run_yet"


def test_history_rotation_file_and_bad_lines_are_read(world):
    job = mkjob(world, cron="0 7 * * *")
    jd = Path(job["dir"])
    addrow(world, job, "2026-10-08 07:00:03")
    (jd / "history.jsonl").rename(jd / "history.jsonl.1")
    with (jd / "history.jsonl").open("w") as h:
        h.write("not json\n[1]\n" + json.dumps({"no": "start"}) + "\n")
    got = classes(run_report(world))
    assert got[0] == ("ok", "due") and got[1:] == [("unknown", "unparsed")] * 3


def test_notify_failed_is_an_extra_problem_on_an_ok_row(world):
    job = mkjob(world, cron="0 7 * * *")
    addrow(world, job, "2026-10-08 07:00:03", notify="error: network error: timed out")
    addrow(world, job, "2026-10-08 07:30:03", trigger="run-now", notify="ok")
    [f, m] = run_report(world).fires
    assert (f.cls, f.counted, f.notify_error) == ("ok", True, "network error: timed out")
    assert m.notify_error is None


def test_manual_and_extra_rows(world):
    job = mkjob(world, cron="0 9 * * *")
    addrow(world, job, "2026-09-30 09:00:00", trigger="run-now")  # outside the window
    addrow(world, job, "2026-10-08 09:00:05")
    addrow(world, job, "2026-10-08 09:20:00", trigger="run-now")
    addrow(world, job, "2026-10-08 09:40:00", trigger=None, status="failed", rc=1)  # old row
    rep = run_report(world)
    assert [(f.cls, f.origin, f.counted) for f in rep.fires] == [
        ("ok", "due", True), ("ok", "manual", False), ("failed", "extra", False)]  # fmt: skip
    assert rep.scheduled == 1 and rep.manual == 2
    # a manual run never takes the due time of a scheduled run
    (Path(job["dir"]) / "history.jsonl").unlink()
    addrow(world, job, "2026-10-08 09:00:05", trigger="run-now")
    rep = run_report(world, since="12h", now=T("2026-10-08 20:00"))
    assert sorted(classes(rep)) == [("missed", "due"), ("ok", "manual")]


def test_rows_before_created_count_with_their_own_status(world):
    job = mkjob(world, cron="5 7 * * *", created="2026-10-08 09:12:49")
    for d in ("06", "07", "08"):
        addrow(world, job, f"2026-10-{d} 07:30:00", status="failed" if d == "07" else "ok",
               rc=1 if d == "07" else 0, transcript="x\n")  # fmt: skip
    rep = run_report(world, since="72h")
    assert [(f.cls, f.origin, f.counted) for f in rep.fires] == [
        ("ok", "before_created", True), ("failed", "before_created", True),
        ("ok", "before_created", True)]  # fmt: skip
    assert rep.scheduled == 3 and rep.completed == 2  # no missed, no extra, 07:05 not due


# ---------------------------------------------------------------- missed causes
def test_missed_cause_order(world, monkeypatch):
    job = mkjob(world, cron="0 7 * * *")
    due = T("2026-10-08 07:00")
    facts = fleet.HostFacts()
    monkeypatch.setattr(fleet.HostFacts, "_read_boot", staticmethod(lambda: T("2026-10-08 08:00")))
    events = fleet.parse_pmset(
        "2026-10-08 06:50:12 +0100 Sleep   \tEntering Sleep state due to 'Idle Sleep'\n"
        "2026-10-08 08:59:58 +0100 Wake    \tWake from Normal Sleep\n"
    )
    monkeypatch.setattr(fleet.HostFacts, "sleep_events", lambda self: events)
    # 1. not loaded wins
    monkeypatch.setattr(schedule, "installed", lambda j: "not loaded")
    assert facts.cause(job, due) == "job not loaded"
    # 2. then the boot time
    facts = fleet.HostFacts()
    monkeypatch.setattr(schedule, "installed", lambda j: "loaded")
    assert facts.cause(job, due) == "host off or restarted (up since 10-08 08:00)"
    # 3. then pmset
    facts = fleet.HostFacts()
    monkeypatch.setattr(fleet.HostFacts, "_read_boot", staticmethod(lambda: T("2026-10-01 08:00")))
    assert facts.cause(job, due) == "Mac asleep 10-08 06:50–10-08 08:59"
    # 4. nothing found: the report adds the fallback
    assert fleet.HostFacts().cause(job, T("2026-10-08 12:00")) is None
    rep = run_report(world, facts=fleet.HostFacts())
    assert rep.fires[0].cause == "Mac asleep 10-08 06:50–10-08 08:59"
    # Linux: crontab tag missing counts as "not loaded"
    monkeypatch.setattr(schedule, "installed", lambda j: "no crontab")
    assert fleet.HostFacts().cause(job, due) == "job not loaded"
    monkeypatch.setattr(schedule, "installed", lambda j: "unknown")
    monkeypatch.setattr(schedule, "is_macos", lambda: False)
    assert fleet.HostFacts().cause(job, due) is None  # no pmset off macOS


def test_not_run_yet_carries_the_missed_cause_when_found(world, monkeypatch):
    mkjob(world, cron="0 9 * * *")
    monkeypatch.setattr(schedule, "installed", lambda j: "not loaded")
    [f] = run_report(world).fires
    assert (f.cls, f.cause) == ("not_run_yet", "job not loaded")


def test_host_facts_are_read_once_per_report(world, monkeypatch):
    calls = []
    monkeypatch.setattr(schedule, "installed", lambda j: calls.append("i") or "loaded")
    monkeypatch.setattr(fleet.HostFacts, "_read_boot",
                        staticmethod(lambda: calls.append("b"))
                        )  # fmt: skip
    seen = []

    def fake_run(argv, **kw):
        seen.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(docker, "run", fake_run)
    mkjob(world, cron="0 1,2,3 * * *")
    run_report(world)
    assert calls.count("i") == 1 and calls.count("b") == 1
    [(argv, kw)] = seen
    assert (
        argv == ["pmset", "-g", "log"] and kw["timeout"] == 20 and kw["max_capture"] == 16 * 1024**2
    )


PMSET = """\
2026-10-08 06:50:12 +0100 Sleep      \tEntering Sleep state due to 'Idle Sleep':TCPKeepAlive=active
2026-10-08 07:30:00 +0100 DarkWake   \tDarkWake from Normal Sleep [CDN] : due to EC.LidOpen
2026-10-08 08:59:58 +0100 Wake       \tWake from Normal Sleep [CDNVA] : due to EC.LidOpen
2026-10-08 09:10:00 +0100 Clamshell Sleep \tClamshell Sleep
2026-10-08 09:20:00 +0100 Sleep      \tEntering Sleep state due to 'Clamshell Sleep'
garbage line without a date
2026-10-08 09:40:00 +0100 Wake       \tWake from Normal Sleep
"""


def test_parse_pmset_fixture_lines():
    ev = fleet.parse_pmset(PMSET)
    assert [(e[0].strftime("%H:%M"), e[1]) for e in ev] == [
        ("06:50", "Sleep"), ("08:59", "Wake"), ("09:20", "Sleep"), ("09:40", "Wake")]  # fmt: skip
    assert fleet.asleep_around(ev, T("2026-10-08 07:05")) == "Mac asleep 10-08 06:50–10-08 08:59"
    assert fleet.asleep_around(ev, T("2026-10-08 09:30")) == "Mac asleep 10-08 09:20–10-08 09:40"
    assert fleet.asleep_around(ev, T("2026-10-08 09:00")) is None  # awake
    assert fleet.asleep_around(ev, T("2026-10-08 06:00")) is None
    assert fleet.asleep_around([], T("2026-10-08 06:00")) is None
    assert fleet.asleep_around(ev[:1], T("2026-10-08 07:05")) is None  # no Wake after it


def test_pmset_output_cap_and_failure_modes(world, monkeypatch):
    f = fleet.HostFacts()
    monkeypatch.setattr(docker, "run", lambda argv, **kw: subprocess.CompletedProcess(
        argv, docker.CAPPED_RC, PMSET, ""))  # fmt: skip
    assert len(f.sleep_events()) == 4  # over the cap: what was read still counts
    f = fleet.HostFacts()
    monkeypatch.setattr(docker, "run", lambda argv, **kw: subprocess.CompletedProcess(
        argv, docker.TIMEOUT_RC, PMSET, "timed out"))  # fmt: skip
    assert f.sleep_events() == []  # the 20 s limit ran out


def test_boot_time_sources(world, monkeypatch):
    monkeypatch.setattr(docker, "run", lambda argv, **kw: subprocess.CompletedProcess(
        argv, 0, "{ sec = 1759900000, usec = 5 } Wed Oct  8 05:46:40 2025\n", ""))  # fmt: skip
    assert fleet.HostFacts._read_boot() == datetime.fromtimestamp(1759900000).astimezone()
    monkeypatch.setattr(schedule, "is_macos", lambda: False)
    stat = world.tmp / "stat"
    stat.write_text("cpu  1 2 3\nbtime 1759900000\nprocesses 5\n")
    monkeypatch.setattr(fleet, "PROC_STAT", str(stat))
    assert fleet.HostFacts._read_boot() == datetime.fromtimestamp(1759900000).astimezone()
    stat.write_text("cpu 1\n")
    assert fleet.HostFacts._read_boot() is None


# ---------------------------------------------------------------- idle boxes
def fake_docker(monkeypatch, projects, started):
    """projects: {project: services}; started: {project: [StartedAt, ...]}."""
    monkeypatch.setattr(
        docker, "running_projects", lambda prefix="agentbox-", timeout=None: projects
    )

    def run(argv, **kw):
        assert kw.get("timeout")  # every call has a limit
        if argv[:3] == ["docker", "ps", "-q"]:
            proj = argv[-1].rsplit("=", 1)[1]
            return subprocess.CompletedProcess(
                argv, 0, "\n".join(f"{proj}#{i}" for i, _ in enumerate(started[proj])), ""
            )
        if argv[:2] == ["docker", "inspect"]:
            assert argv.count("--format") == 1 and len(argv) > 4  # one call for all containers
            out = []
            for cid in argv[4:]:
                proj, i = cid.split("#")
                out.append(started[proj][int(i)])
            return subprocess.CompletedProcess(argv, 0, "\n".join(out), "")
        return subprocess.CompletedProcess(argv, 1, "", "")  # sysctl, pmset: nothing found

    monkeypatch.setattr(docker, "run", run)


def started_ago(hours, now=NOW):
    t = (now - timedelta(hours=hours, minutes=1)).astimezone(UTC)
    return t.strftime("%Y-%m-%dT%H:%M:%S.123456789Z")


def mkstate(w, profile):
    d = w.state / profile
    d.mkdir(exist_ok=True)
    return d


def test_idle_boxes_and_their_causes(world, monkeypatch):
    for p in ("pin", "leftup", "plain", "recent", "fireheld", "sessionheld", "upheld", "stopped"):
        mkstate(world, p)
    jobs = {p: mkjob(world, profile=p) for p in ("leftup", "fireheld")}
    (world.state / "pin" / "pinned").touch()
    os.utime(world.state / "pin" / "pinned", (T("2026-10-06 18:52").timestamp(),) * 2)
    addrow(world, jobs["leftup"], "2026-10-07 08:00:00", trigger=None,
           left_up="left up: another agentbox session uses the box")  # fmt: skip
    addrow(world, jobs["leftup"], "2026-10-07 09:00:00", trigger=None)
    run_services = ["agent", "egress"]
    fake_docker(
        monkeypatch,
        {"agentbox-" + p: run_services for p in
         ("pin", "leftup", "plain", "recent", "fireheld", "sessionheld", "upheld")}
        | {"agentbox-other-tool": ["web"], "unrelated": ["agent"]},  # fmt: skip
        {"agentbox-pin": [started_ago(17), started_ago(16)], "agentbox-leftup": [started_ago(5)],
         "agentbox-plain": [started_ago(2)], "agentbox-recent": [started_ago(0.5)],
         "agentbox-fireheld": [started_ago(9)], "agentbox-sessionheld": [started_ago(9)],
         "agentbox-upheld": [started_ago(9)]},
    )  # fmt: skip
    fire = hold_lock(Path(jobs["fireheld"]["dir"]) / "fire.lock")
    session = (world.state / "sessionheld" / "session.lock").open("a")
    fcntl.flock(session, fcntl.LOCK_SH)
    up = hold_lock(world.state / "upheld" / "up.lock")
    try:
        rep = run_report(world)
    finally:
        for f in (fire, session, up):
            f.close()
    got = {b.profile: (b.up_hours, b.cause) for b in rep.idle_boxes}
    assert got == {
        "pin": (17, "pinned since 10-06 18:52 (manual `up` or an interactive session)"),
        "leftup": (5, "left up: another agentbox session uses the box"),
        "plain": (2, "running, not pinned, no run left it up"),
    }
    assert rep.idle_check == "ok"


def test_idle_check_skipped_when_docker_is_down(world):
    rep = run_report(world)  # the default fake raises DockerError
    assert rep.idle_boxes == [] and rep.idle_check == "idle-box check skipped: Docker not running"


def test_idle_check_skipped_when_docker_times_out(world, monkeypatch):
    def slow(prefix="agentbox-", timeout=None):
        assert timeout == 30
        raise docker.DockerError("docker ps timed out after 30s")

    monkeypatch.setattr(docker, "running_projects", slow)
    assert run_report(world).idle_check == "idle-box check skipped: Docker not running"


def test_idle_probe_uses_a_stub_box_and_no_profile_load(world, monkeypatch):
    mkstate(world, "ghost")  # no profile file: box.load would raise
    fake_docker(monkeypatch, {"agentbox-ghost": ["agent"]}, {"agentbox-ghost": [started_ago(3)]})
    from agentbox import box as boxmod

    seen = []
    real = boxmod.up_lock

    def spy(box, timeout=300.0):
        seen.append((box.name, box.profile, timeout))
        return real(box, timeout)

    monkeypatch.setattr(boxmod, "up_lock", spy)
    assert [b.profile for b in run_report(world).idle_boxes] == ["ghost"]
    assert seen == [("ghost", None, 0)]


# ---------------------------------------------------------------- job copy drift
def test_report_lists_drift_from_the_shared_reader(world):
    src = world.tmp / "brief.sh"
    src.write_text("echo new\n")
    mkjob(world, source=str(src))
    rep = run_report(world)
    [d] = rep.drift
    assert d["job"] == "p/j" and d["kind"] == "differs"
    assert d["text"].startswith(f"job copy differs from {src} (since ")
    assert "echo" not in json.dumps(rep.as_dict())  # no file content in the report
    (Path(mkjob(world)["dir"]) / "command.sh").write_text("echo new\n")
    mkjob(world, source=str(src))
    (world.state / "p" / "schedules" / "j" / "command.sh").write_text("echo new\n")
    assert run_report(world).drift == []  # same bytes
    src.unlink()
    assert run_report(world).drift == [{"job": "p/j", "kind": "gone", "text": "source gone"}]


# ---------------------------------------------------------------- report object
def test_json_schema_v1_shape(world):
    job = mkjob(world, cron="0 7 * * *")
    addrow(world, job, "2026-10-08 07:00:03", status="failed", rc=1, transcript="DIFFERENT\n")
    d = run_report(world).as_dict()
    assert d["version"] == 1
    assert set(d) == {"version", "generated", "window", "post", "scheduled", "completed",
                      "manual", "fires", "every_jobs", "idle_boxes", "idle_check", "drift",
                      "carry"}  # fmt: skip
    assert set(d["window"]) == {"start", "end"}
    assert set(d["fires"][0]) == set(fleet.Fire.PUBLIC)
    assert d["fires"][0]["cls"] == "failed" and d["fires"][0]["unexplained"] is True
    json.dumps(d)  # plain JSON types only
    assert "job_dict" not in d["fires"][0] and "row" not in d["fires"][0]


# ------------------------------------------------------ acceptance cases (real fleet shapes)
def test_acceptance_boletim_delta_failure(world):
    """10-08 08:15 delta failed with exit 1 and a DIFFERENT line: failed/unexplained."""
    job = mkjob(world, profile="boletim", name="delta", cron="15 8 * * 1,2,3,4,5",
                created="2026-10-05 20:31:14")  # fmt: skip
    addrow(world, job, "2026-10-06 08:15:01", trigger=None, transcript="boletim delta: same\n")
    addrow(world, job, "2026-10-07 08:15:00", trigger=None, transcript="boletim delta: same\n")
    addrow(world, job, "2026-10-08 08:15:02", trigger=None, status="failed", rc=1,
           transcript="reading\nboletim delta: DIFFERENT vs 2026-10-07 (3 lines)\n")  # fmt: skip
    rep = run_report(world, since="72h")
    assert [f.cls for f in rep.fires] == ["ok", "ok", "failed"]
    bad = rep.fires[2]
    assert bad.unexplained and bad.exit_code == 1 and bad.counted
    assert bad.cause == "boletim delta: DIFFERENT vs 2026-10-07 (3 lines)"
    assert (rep.scheduled, rep.completed) == (3, 2)


def test_acceptance_idle_boxes_of_10_06(world, monkeypatch):
    now = T("2026-10-07 09:00")
    for p in ("portfolio", "boletim"):
        (mkstate(world, p) / "pinned").touch()
        os.utime(world.state / p / "pinned", (T("2026-10-06 18:30").timestamp(),) * 2)
    fake_docker(
        monkeypatch,
        {"agentbox-portfolio": ["agent", "egress"], "agentbox-boletim": ["agent"]},
        {"agentbox-portfolio": [started_ago(17, now), started_ago(17, now)],
         "agentbox-boletim": [started_ago(15, now)]},
    )  # fmt: skip
    rep = run_report(world, now=now)
    assert {b.profile: b.up_hours for b in rep.idle_boxes} == {"portfolio": 17, "boletim": 15}
    assert all(b.cause.startswith("pinned since 10-06 18:30") for b in rep.idle_boxes)


def fx_job(world):
    return mkjob(world, profile="fx", name="eurusd", cron="30 17 * * 1,2,3,4,5",
                 created="2026-10-05 15:20:43")  # fmt: skip


def test_acceptance_fx_eurusd_ok_plus_two_extra(world):
    job = fx_job(world)
    addrow(world, job, "2026-10-05 17:30:00", transcript="== check: ECB date 2026-10-05\n")
    addrow(world, job, "2026-10-05 17:51:03", trigger=None, transcript="== check\n")
    addrow(world, job, "2026-10-05 17:51:48", trigger=None, transcript="== check\n")
    rep = run_report(world, now=T("2026-10-06 10:00"))
    assert [(f.cls, f.origin) for f in rep.fires] == [
        ("ok", "due"), ("ok", "extra"), ("ok", "extra")]  # fmt: skip
    assert (rep.scheduled, rep.completed, rep.manual) == (1, 1, 2)


def test_acceptance_fx_lone_late_row_matches_the_due_time(world):
    job = fx_job(world)
    addrow(world, job, "2026-10-05 17:51:03", trigger=None, transcript="== check\n")
    rep = run_report(world, now=T("2026-10-06 10:00"))
    assert [(f.cls, f.origin) for f in rep.fires] == [("ok", "due")]
    assert rep.fires[0].due == fleet.iso(T("2026-10-05 17:30"))


def test_acceptance_collect_am_created_after_its_rows(world):
    job = mkjob(world, profile="boletim", name="collect-am", cron="5 7 * * *",
                created="2026-10-08 09:12:49")  # fmt: skip
    for d in ("06", "07", "08"):
        addrow(world, job, f"2026-10-{d} 07:30:00", trigger=None, transcript="collected\n")
    rep = run_report(world, since="72h")
    assert [(f.cls, f.origin) for f in rep.fires] == [("ok", "before_created")] * 3
    assert rep.scheduled == 3 and not [f for f in rep.fires if f.cls in ("missed", "pending")]
    assert rep.carry == []


def test_acceptance_job_with_no_last_json_and_no_history(world):
    mkjob(world, profile="cves", name="household", cron="30 8 * * *", kind="agent",
          created="2026-10-05 16:14:25")  # fmt: skip
    rep = run_report(world, since="72h")
    got = [(fleet.label(fleet.parse_dt(f.due)), f.cls) for f in rep.fires]
    assert got == [("10-06 08:30", "missed"), ("10-07 08:30", "missed"),
                   ("10-08 08:30", "not_run_yet")]  # fmt: skip
    assert rep.scheduled == 3


# ---------------------------------------------------------------- investigator
INV_GOOD = """
[box]
agents = ["claude"]
web_tools = false
skip_permissions = false

[[mount]]
host = "{inv}"
mode = "ro"

[network]
mode = "strict"
presets = ["anthropic"]
"""
PROJ = """
[[mount]]
host = "{proj}"
"""


@pytest.fixture
def inv(world, monkeypatch):
    """Profiles `inv` (passes the safety check) and `p` (the job's profile)."""
    monkeypatch.setattr(
        "agentbox.profile.check_mount_host",
        lambda host, allow_dotpath=False, **kw: os.path.realpath(host),
    )
    world.inv_dir = world.tmp / "agentbox-investigator"
    world.proj = world.tmp / "proj"
    world.inv_dir.mkdir()
    world.proj.mkdir()
    world.write = lambda name, text: (world.cfg / "profiles" / f"{name}.toml").write_text(text)
    world.write("inv", INV_GOOD.format(inv=world.inv_dir))
    world.write("p", PROJ.format(proj=world.proj))
    return world


def problems(inv, text=None, **fmt):
    if text is not None:
        inv.write("inv", text.format(inv=inv.inv_dir, **fmt))
    return fleet.investigator_problems("inv")


def test_investigator_profile_that_passes(inv):
    assert fleet.investigator_problems("inv") == []


@pytest.mark.parametrize(
    "old,new,msg",
    [
        ('mode = "ro"', 'mode = "rw"', 'exactly one [[mount]] with mode = "ro"'),
        ('presets = ["anthropic"]', 'presets = ["anthropic", "github"]', "network must be strict"),
        ('presets = ["anthropic"]', 'presets = ["anthropic"]\nallow = ["example.com"]',
         "network must be strict"),
        ('mode = "strict"', 'mode = "open"', "network must be strict"),
        ('agents = ["claude"]', 'agents = ["claude", "codex"]', '[box] needs agents = ["claude"]'),
        ("web_tools = false", "web_tools = true", "[box] needs"),
        ("skip_permissions = false", "skip_permissions = true", "[box] needs"),
        ("skip_permissions = false\n", "", "[box] needs"),  # the default is true
        ("[network]", '[mcp.servers.x]\nurl = "https://mcp.example.com/mcp"\n\n[network]',
         "[mcp.servers] must be empty"),
        ("[network]", '[models]\nollama = ["llama3"]\n\n[network]',
         "[models] must be the defaults"),
        ("[network]", '[models.remote.big]\napi_base = "https://llm.example.com/v1"\n\n[network]',
         "[models] must be the defaults"),
        ("[network]", '[secrets]\nGH_TOKEN = "shared"\n\n[network]', "[secrets] may hold only"),
    ],
)  # fmt: skip
def test_investigator_profile_that_fails(inv, old, new, msg):
    text = INV_GOOD.replace(old, new)
    assert text != INV_GOOD
    got = problems(inv, text.replace("{inv}", "{inv}"))
    assert any(msg in g for g in got), got


def test_investigator_needs_exactly_one_mount(inv):
    extra = INV_GOOD + '\n[[mount]]\nhost = "{proj}"\nmode = "ro"\n'
    assert any("exactly one" in g for g in problems(inv, extra, proj=inv.proj))


def test_investigator_mount_must_be_an_empty_directory(inv):
    (inv.inv_dir / "notes.txt").write_text("x")
    assert any("is not empty" in g for g in problems(inv))
    (inv.inv_dir / "notes.txt").unlink()
    assert problems(inv) == []
    f = inv.tmp / "afile"
    f.write_text("x")
    text = INV_GOOD.replace("{inv}", str(f))
    inv.write("inv", text)
    assert any("not a directory" in g for g in fleet.investigator_problems("inv"))


def test_investigator_mount_must_not_overlap_another_profiles_mount(inv):
    inv.write("same", PROJ.format(proj=inv.inv_dir))
    assert any("overlaps a mount of profile same" in g for g in problems(inv))
    inv.write("same", PROJ.format(proj=inv.tmp))  # the investigator folder is inside it
    assert any("overlaps a mount of profile same" in g for g in problems(inv))
    (inv.inv_dir / "child").mkdir()
    inv.write("same", PROJ.format(proj=inv.inv_dir / "child"))  # around it
    got = problems(inv)
    assert any("overlaps a mount of profile same" in g for g in got)
    (inv.inv_dir / "child").rmdir()
    inv.write("same", PROJ.format(proj=inv.proj))
    assert problems(inv) == []


def test_investigator_check_fails_when_another_profile_does_not_load(inv):
    inv.write("broken", "this is [not toml")
    got = problems(inv)
    assert got == ["cannot verify against profile broken (it does not load)"]
    inv.write("broken", '[[mount]]\nhost = "~someone/x"\n')  # a ~user path cannot be resolved
    assert any("cannot verify against profile broken" in g for g in problems(inv))
    (inv.cfg / "profiles" / "broken.toml").unlink()
    assert problems(inv) == []


def test_investigator_check_with_missing_or_invalid_profile(inv):
    assert fleet.investigator_problems("nope") == ["no profile 'nope'"]
    inv.write("inv", "[box]\nagents = []\n")
    [msg] = fleet.investigator_problems("inv")
    assert msg.startswith("profile inv does not load")


class Stub:
    """Replaces fleet.run_investigator; records the call and the prompt file."""

    def __init__(self, world, answer="The input file changed upstream.", rc=0, stderr="",
                 line=True):  # fmt: skip
        self.world, self.answer, self.rc, self.stderr, self.line = world, answer, rc, stderr, line
        self.calls = []

    def __call__(self, argv, env):
        pf = Path(argv[argv.index("--prompt-file") + 1])
        self.calls.append({
            "argv": argv, "env": env, "prompt": pf.read_text(), "file": pf,
            "mode": pf.stat().st_mode & 0o777, "dir_mode": pf.parent.stat().st_mode & 0o777,
        })  # fmt: skip
        rd = self.world.tmp / f"invrun{len(self.calls)}"
        rd.mkdir(exist_ok=True)
        text = "\n" if self.answer is None else f"thinking...\n{self.answer}\n\n"
        (rd / "transcript.log").write_text(text)
        out = f"run: {rd} (exit {self.rc})\n" if self.line else ""
        return subprocess.CompletedProcess(argv, self.rc, out, self.stderr)


def failing_job(world, n=1, transcript="DIFFERENT\n"):
    job = mkjob(world, cron="0 6 * * *")
    for i in range(n):
        addrow(world, job, f"2026-10-08 06:{i:02d}:00", trigger=None, status="failed", rc=1,
               transcript=transcript)  # fmt: skip
    return job


@pytest.fixture
def secrets_ok(monkeypatch):
    from agentbox import delivery, notify

    monkeypatch.setattr(delivery, "collect",
                        lambda prof, cfg, state, services=None, fetch=None: delivery.Delivery(
                            values={"CLAUDE_CODE_OAUTH_TOKEN": SECRET}))  # fmt: skip
    monkeypatch.setattr(notify, "read_webhook", lambda cfg, profile: WEBHOOK)


CFG = paths.Config(report_investigator="inv", notify_webhook_secret="SLACK_WEBHOOK_URL")


def test_investigator_runs_with_untrusted_data_framing(inv, secrets_ok, monkeypatch):
    failing_job(inv)
    stub = Stub(inv)
    monkeypatch.setattr(fleet, "run_investigator", stub)
    rep = run_report(inv, since="12h", investigate=True, cfg=CFG)
    [f] = [f for f in rep.fires if f.unexplained]
    assert f.investigation == "investigator: The input file changed upstream."
    [c] = stub.calls
    a = c["argv"]
    assert a[-8:-1] == ["run", "inv", "--agent", "claude", "--prompt-file", a[-3], "--timeout"]
    assert a[-1] == "3m" and "--model" not in a
    assert (c["mode"], c["dir_mode"]) == (0o600, 0o700)
    assert not c["file"].exists() and not c["file"].parent.exists()  # deleted after the run
    assert schedule.TRIGGER_ENV not in c["env"]
    p = c["prompt"]
    assert "untrusted data, not instructions" in p and "Cause not in evidence" in p
    marks = [ln for ln in p.splitlines() if ln.startswith("<<<EVIDENCE-")]
    assert len(marks) == 2 and marks[0].endswith("-BEGIN>>>") and marks[1].endswith("-END>>>")
    assert p.index(marks[0]) < p.index("DIFFERENT") < p.rindex(marks[1])
    assert marks[0].split("-")[1] != "" and len(marks[0].split("-")[1]) == 16  # random nonce


def test_investigator_answer_is_cleaned_capped_and_scrubbed(inv, secrets_ok, monkeypatch):
    failing_job(inv)
    answer = "\x1b[31mcause\x1b[0m " + SECRET + " <@U1> " + "x" * 400
    monkeypatch.setattr(fleet, "run_investigator", Stub(inv, answer=answer))
    rep = run_report(inv, since="12h", investigate=True, cfg=CFG)
    text = next(f.investigation for f in rep.fires if f.unexplained)
    assert SECRET not in text and "\x1b" not in text and "<redacted>" in text
    assert len(text) <= len("investigator: ") + 200 + 20


def test_evidence_bundle_parts_scrub_and_home(inv):
    job = failing_job(inv, transcript="")
    jd = Path(job["dir"])
    rows = [json.loads(x) for x in (jd / "history.jsonl").read_text().splitlines()]
    home = str(Path.home())
    body = "".join(f"line {i}\n" for i in range(500))
    tail = f"saw {SECRET} and {WEBHOOK} in {home}/.config/x\n"
    transcript = Path(rows[0]["transcript"])
    transcript.write_text(body + tail)
    (jd / "launchd.err").write_text("".join(f"err {i}\n" for i in range(150)))
    job_with_env = json.loads((jd / "job.json").read_text())
    assert "env" in job_with_env
    sc = fleet.Scrubber()
    sc.add(SECRET, WEBHOOK)
    fire = fleet.Fire(job="p/j", origin="due", cls="failed", when=rows[0]["start"],
                      job_dict=job_with_env, row=rows[0])  # fmt: skip
    text = fleet.evidence_bundle(fire, rows, sc)
    assert SECRET not in text and WEBHOOK not in text and "<redacted>" in text
    assert home not in text and "~/.config/x" in text
    assert "line 100\n" not in text and "line 101\n" in text and "line 499\n" in text  # last 400
    assert "err 49\n" not in text and "err 50\n" in text and "err 149\n" in text  # last 100
    assert '"env"' not in text and '"X"' not in text  # job.json and meta.json lose `env`
    assert '"label"' in text and '"killed"' not in text
    for title in ("job.json", "fire rows in the window", "transcript, last 400",
                  "launchd.err, last 100", "run meta.json"):  # fmt: skip
        assert f"== {title}" in text


def test_evidence_reads_no_secret_or_token_files(inv, monkeypatch):
    job = failing_job(inv)
    state = Path(job["dir"]).parents[1]
    (state / "box-tokens.json").write_text('{"MCP_GATEWAY_TOKEN": "tok-should-not-be-read"}')
    (state / "secrets-hmac.key").write_bytes(b"k" * 32)
    rows = [json.loads(x) for x in (Path(job["dir"]) / "history.jsonl").read_text().splitlines()]
    fire = fleet.Fire(job="p/j", origin="due", cls="failed", when=rows[0]["start"],
                      job_dict=json.loads((Path(job["dir"]) / "job.json").read_text()),
                      row=rows[0])  # fmt: skip
    opened = []
    real_open = open
    monkeypatch.setattr(
        "builtins.open", lambda f, *a, **k: opened.append(str(f)) or real_open(f, *a, **k)
    )
    text = fleet.evidence_bundle(fire, rows, fleet.Scrubber())
    assert "tok-should-not-be-read" not in text
    assert not [o for o in opened if "box-tokens" in o or "hmac" in o]


def test_investigator_timeouts_and_errors_keep_the_rule_cause(inv, secrets_ok, monkeypatch):
    failing_job(inv)
    cases = [
        (dict(rc=124, stderr="agentbox: timed out after 240s, command killed", line=False),
         "(investigation failed: timed out after 4 min)"),
        (dict(rc=124), "(investigation failed: timed out after 3 min)"),  # `run --timeout`
        (dict(rc=1, stderr=f"agentbox: box start failed {SECRET}\n", line=False),
         "(investigation failed: exit 1: agentbox: box start failed <redacted>)"),
        (dict(rc=0, answer=None, line=True), "(investigation failed: no answer in the transcript)"),
        (dict(rc=0, line=False), "(investigation failed: exit 0)"),
    ]  # fmt: skip
    for kw, want in cases:
        monkeypatch.setattr(fleet, "run_investigator", Stub(inv, **kw))
        rep = run_report(inv, since="12h", investigate=True, cfg=CFG)
        f = next(f for f in rep.fires if f.unexplained)
        assert f.investigation == want, (kw, f.investigation)
        assert f.cause == "DIFFERENT"  # the rule cause stays

    def boom(argv, env):
        raise docker.DockerError("agentbox: command not found")

    monkeypatch.setattr(fleet, "run_investigator", boom)
    f = next(
        f for f in run_report(inv, since="12h", investigate=True, cfg=CFG).fires if f.unexplained
    )
    assert f.investigation == "(investigation failed: agentbox: command not found)"


def test_investigator_skips_when_secrets_cannot_be_read(inv, monkeypatch):
    from agentbox import delivery, notify, secretstore

    failing_job(inv)
    stub = Stub(inv)
    monkeypatch.setattr(fleet, "run_investigator", stub)

    def locked(*a, **k):
        raise secretstore.SecretError("keychain locked")

    monkeypatch.setattr(delivery, "collect", locked)
    monkeypatch.setattr(notify, "read_webhook", lambda cfg, profile: WEBHOOK)
    f = next(
        f for f in run_report(inv, since="12h", investigate=True, cfg=CFG).fires if f.unexplained
    )
    assert f.investigation == "(investigation skipped: secrets unreadable)"
    # the webhook alone unreadable has the same result
    monkeypatch.setattr(
        delivery, "collect", lambda *a, **k: delivery.Delivery(values={"A": SECRET})
    )
    monkeypatch.setattr(notify, "read_webhook", lambda *a: (_ for _ in ()).throw(
        notify.NotifyError("secret SLACK_WEBHOOK_URL is not stored")))  # fmt: skip
    f = next(
        f for f in run_report(inv, since="12h", investigate=True, cfg=CFG).fires if f.unexplained
    )
    assert f.investigation == "(investigation skipped: secrets unreadable)"
    assert stub.calls == []


def test_investigator_refused_profile_is_not_used(inv, secrets_ok, monkeypatch):
    failing_job(inv)
    inv.write(
        "inv", INV_GOOD.replace("web_tools = false", "web_tools = true").format(inv=inv.inv_dir)
    )
    stub = Stub(inv)
    monkeypatch.setattr(fleet, "run_investigator", stub)
    f = next(
        f for f in run_report(inv, since="12h", investigate=True, cfg=CFG).fires if f.unexplained
    )
    assert f.investigation.startswith("(investigation skipped: profile inv is refused: [box] needs")
    assert stub.calls == []


def test_at_most_five_investigations_per_report(inv, secrets_ok, monkeypatch):
    failing_job(inv, n=7)
    stub = Stub(inv)
    monkeypatch.setattr(fleet, "run_investigator", stub)
    rep = run_report(inv, since="12h", investigate=True, cfg=CFG)
    inf = [f.investigation for f in rep.fires]
    assert len(stub.calls) == 5
    assert sum(1 for x in inf if x and x.startswith("investigator:")) == 5
    assert inf[5:] == ["(investigation skipped: limit of 5 per report)"] * 2


def test_investigator_is_off_by_default_and_with_no_investigate(inv, secrets_ok, monkeypatch):
    failing_job(inv)
    stub = Stub(inv)
    monkeypatch.setattr(fleet, "run_investigator", stub)
    run_report(inv, since="12h", investigate=True, cfg=paths.Config())  # report_investigator unset
    run_report(inv, since="12h", investigate=False, cfg=CFG)  # --no-investigate
    assert stub.calls == []


def test_only_unexplained_problems_are_investigated(inv, secrets_ok, monkeypatch):
    job = mkjob(inv, cron="0 6 * * *")
    addrow(
        inv,
        job,
        "2026-10-08 06:00:00",
        status="failed",
        rc=124,
        meta={"killed": "timeout after 60 s"},
    )
    addrow(
        inv,
        job,
        "2026-10-08 06:10:00",
        status="failed",
        rc=69,
        run_dir=False,
        message="Docker did not come up",
    )
    addrow(inv, job, "2026-10-08 06:20:00", status="skipped", rc=75, run_dir=False)
    stub = Stub(inv)
    monkeypatch.setattr(fleet, "run_investigator", stub)
    run_report(inv, since="12h", investigate=True, cfg=CFG)
    assert stub.calls == []


def test_idle_boxes_are_found_before_the_investigator(inv, secrets_ok, monkeypatch):
    failing_job(inv)
    order = []
    real = fleet.find_idle_boxes
    monkeypatch.setattr(fleet, "find_idle_boxes", lambda *a: order.append("idle") or real(*a))
    stub = Stub(inv)

    def run(argv, env):
        order.append("investigator")
        return stub(argv, env)

    monkeypatch.setattr(fleet, "run_investigator", run)
    run_report(inv, since="12h", investigate=True, cfg=CFG)
    assert order == ["idle", "investigator"]


# ---------------------------------------------------------------- the command
@pytest.fixture
def cli_world(world, monkeypatch):
    """`agentbox schedule report` with the clock at NOW and a fake Slack."""
    import stat as statmod

    from agentbox import cli, notify

    class FakeDT(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW if tz is None else NOW.astimezone(tz)

    monkeypatch.setattr(cli, "datetime", FakeDT)
    bindir = world.tmp / "bin"
    bindir.mkdir()
    docker_bin = bindir / "docker"
    docker_bin.write_text("#!/bin/sh\nexit 0\n")
    docker_bin.chmod(docker_bin.stat().st_mode | statmod.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    world.posts = []
    world.post_error = None

    def post(url, text, timeout):
        if world.post_error:
            raise world.post_error
        world.posts.append((url, text))

    monkeypatch.setattr(notify, "read_webhook", lambda cfg, profile: WEBHOOK)
    monkeypatch.setattr(notify, "post", post)
    world.config = lambda text: (world.cfg / "config.toml").write_text(text)
    return world


def two_jobs(w):
    ok = mkjob(w, profile="fx", name="eurusd", cron="30 6 * * *")
    addrow(w, ok, "2026-10-08 06:30:01", trigger=None)
    bad = mkjob(w, profile="boletim", name="delta", cron="15 8 * * *")
    addrow(w, bad, "2026-10-08 08:15:02", trigger=None, status="failed", rc=1,
           transcript="boletim delta: DIFFERENT vs yesterday\n")  # fmt: skip


def test_report_prints_the_text_form(cli_world, capsys):
    from agentbox import cli

    two_jobs(cli_world)
    assert cli.main(["schedule", "report", "--since", "24h", "--no-investigate"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("⚠️ 1 of 2 scheduled runs completed normally, 1 failed")
    assert (
        "• boletim/delta 10-08 08:15 failed (exit 1): boletim delta: DIFFERENT vs yesterday" in out
    )
    assert cli_world.posts == [] and not (fleet.report_dir() / "last.json").exists()


def test_report_all_well_exit_zero(cli_world, capsys):
    from agentbox import cli

    job = mkjob(cli_world, cron="30 6 * * *")
    addrow(cli_world, job, "2026-10-08 06:30:01")
    assert cli.main(["schedule", "report"]) == 0
    assert capsys.readouterr().out.splitlines()[0] == (
        "🚦 1 scheduled run completed, idle-box check skipped: Docker not running"
    )


def test_report_json(cli_world, capsys):
    from agentbox import cli

    two_jobs(cli_world)
    assert cli.main(["schedule", "report", "--json", "--since", "1d"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["version"] == 1 and d["scheduled"] == 2 and d["completed"] == 1
    assert d["window"]["start"] == fleet.iso(NOW - timedelta(days=1))


def test_report_argument_errors_exit_1(cli_world, capsys):
    from agentbox import cli

    for argv, msg in (
        (["--since", "15d"], "1h to 14d"),
        (["--since", "soon"], "use <n>h or <n>d"),
        (["--json", "--post"], "cannot be combined"),
        (["--at", "08:00"], "--at works only with --install"),
        (["--install", "--uninstall"], "cannot be combined"),
        (["--install", "--post"], "cannot be combined with --install or --uninstall"),
        (["--uninstall", "--since", "2d"], "cannot be combined with --install or --uninstall"),
        (["--uninstall", "--at", "08:00"], "--at works only with --install"),
    ):
        assert cli.main(["schedule", "report", *argv]) == 1, argv
        assert msg in capsys.readouterr().err, argv


def test_report_post_delivers_through_slack_and_saves_the_window(cli_world, capsys):
    from agentbox import cli

    two_jobs(cli_world)
    cli_world.config('notify_webhook_secret = "HOOK"\n')
    assert cli.main(["schedule", "report", "--post", "--no-investigate"]) == 0
    [(url, text)] = cli_world.posts
    assert url == WEBHOOK and text.splitlines()[0].startswith("⚠️ 1 of 2 scheduled runs")
    assert "fleet report delivered: slack" in capsys.readouterr().out
    last = json.loads((fleet.report_dir() / "last.json").read_text())
    assert last["window_end"] == fleet.iso(NOW) and last["carry"] == []
    # the next posted report starts where this one ended: nothing in the old window repeats
    later = NOW + timedelta(hours=2)
    assert fleet.resolve_window(later, timedelta(hours=24), post=True)[0] == NOW


def test_report_post_to_several_outputs(cli_world, capsys, tmp_path):
    from agentbox import cli

    two_jobs(cli_world)
    out = tmp_path / "hook.json"
    hook = tmp_path / "hook.sh"
    hook.write_text(f"#!/bin/sh\ncat > {out}\n")
    hook.chmod(0o755)
    cli_world.config(
        'notify_webhook_secret = "HOOK"\nreport_outputs = "stdout,slack,command"\n'
        f'report_command = "{hook}"\n'
    )
    assert cli.main(["schedule", "report", "--post"]) == 0
    printed = capsys.readouterr().out
    assert printed.startswith("⚠️ 1 of 2") and len(cli_world.posts) == 1
    assert json.loads(out.read_text())["scheduled"] == 2


def test_report_post_without_webhook_setting_fails_and_prints_the_failed_line(cli_world, capsys):
    from agentbox import cli

    two_jobs(cli_world)
    assert cli.main(["schedule", "report", "--post"]) == 1
    out = capsys.readouterr().out.strip()
    assert (
        out == "🚦 fleet report FAILED: the slack output needs notify_webhook_secret in config.toml"
    )
    assert cli_world.posts == [] and not (fleet.report_dir() / "last.json").exists()


def test_failed_delivery_exits_1_posts_failed_line_and_keeps_the_window(cli_world, capsys):
    from agentbox import cli, notify

    two_jobs(cli_world)
    cli_world.config('notify_webhook_secret = "HOOK"\n')
    cli_world.post_error = notify.NotifyError(f"HTTP 500 for {WEBHOOK}")
    assert cli.main(["schedule", "report", "--post"]) == 1
    out = capsys.readouterr().out
    assert "🚦 fleet report FAILED: slack: " in out and "xyzSECRETSECRET" not in out
    assert not (fleet.report_dir() / "last.json").exists()  # a failed delivery leaves no window


def test_report_failure_posts_one_failed_line(cli_world, capsys, monkeypatch):
    from agentbox import cli

    mkjob(cli_world, cron="30 6 * * *")
    cli_world.config('notify_webhook_secret = "HOOK"\n')

    def boom(*a, **k):
        raise fleet.FleetError("p/j: job.json has no valid `created` time <@U1>")

    monkeypatch.setattr(fleet, "analyze_job", boom)
    assert cli.main(["schedule", "report", "--post"]) == 1
    [(_, text)] = cli_world.posts
    assert text == "🚦 fleet report FAILED: p/j: job.json has no valid `created` time &lt;@U1&gt;"
    assert capsys.readouterr().out.strip() == (
        "🚦 fleet report FAILED: p/j: job.json has no valid `created` time <@U1>"
    )
    # without --post: stderr, exit 1, nothing posted
    cli_world.posts.clear()
    assert cli.main(["schedule", "report"]) == 1
    assert "fleet report failed: p/j" in capsys.readouterr().err and cli_world.posts == []


def test_failed_line_is_scrubbed_against_every_value_read(inv, secrets_ok, capsys, monkeypatch):
    from agentbox import cli

    failing_job(inv)
    inv.config = lambda text: (inv.cfg / "config.toml").write_text(text)
    inv.config('notify_webhook_secret = "HOOK"\nreport_investigator = "inv"\n')

    class FakeDT(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(cli, "datetime", FakeDT)
    posted = []
    from agentbox import notify

    monkeypatch.setattr(notify, "post", lambda url, text, timeout: posted.append(text))

    def leak(argv, env):
        raise RuntimeError(f"cannot start: token {SECRET} and {WEBHOOK}")

    monkeypatch.setattr(fleet, "run_investigator", leak)
    assert cli.main(["schedule", "report", "--post", "--since", "12h"]) == 1
    out = capsys.readouterr().out
    for text in (out, *posted):
        assert SECRET not in text and WEBHOOK not in text and "SECRETSECRETSECRET1234" not in text
        assert "fleet report FAILED: RuntimeError: cannot start: token" in text
        assert "<redacted>" in text or "&lt;redacted&gt;" in text


def test_reason_text_scrubs_before_it_caps(world):
    from agentbox import cli

    sc = fleet.Scrubber()
    sc.add(SECRET)
    # the secret straddles the 200-character cap: it must still go
    e = RuntimeError("x" * 190 + SECRET)
    text = cli.reason_text(e, sc)
    assert SECRET[:16] not in text and SECRET[-16:] not in text and len(text) <= 200


# ---------------------------------------------------------------- install and uninstall
@pytest.fixture
def launchctl(cli_world, monkeypatch):
    """A fake launchctl: `print` says loaded once bootstrapped."""
    calls, loaded = [], set()

    def fake(*a):
        calls.append(a)
        label = a[1].rsplit("/", 1)[-1] if len(a) > 1 else ""
        if a[0] == "print":
            return subprocess.CompletedProcess(a, 0 if label in loaded else 1, "", "")
        if a[0] == "bootstrap":
            loaded.add(json_label(a[2]))
        if a[0] == "bootout":
            loaded.discard(label)
        return subprocess.CompletedProcess(a, 0, "", "")

    def json_label(plist):
        import plistlib

        return plistlib.loads(Path(plist).read_bytes())["Label"]

    monkeypatch.setattr(schedule, "launchctl", fake)
    cli_world.calls, cli_world.loaded = calls, loaded
    return cli_world


def test_install_writes_the_plist_with_its_own_label(launchctl, capsys):
    import plistlib

    from agentbox import cli

    assert cli.main(["schedule", "report", "--install"]) == 0
    plist = launchctl.tmp / "la" / "com.agentbox-unit._report.plist"
    d = plistlib.loads(plist.read_bytes())
    assert d["Label"] == "com.agentbox-unit._report"
    assert d["ProgramArguments"][-3:] == ["schedule", "report", "--post"]
    assert d["StartCalendarInterval"] == [{"Minute": 30, "Hour": 9}]  # default 09:30 daily
    rdir = launchctl.state / "_report"
    assert d["StandardOutPath"] == str(rdir / "launchd.out")
    assert d["StandardErrorPath"] == str(rdir / "launchd.err")
    assert rdir.stat().st_mode & 0o777 == 0o700
    assert d["EnvironmentVariables"]["AGENTBOX_STATE_HOME"] == str(launchctl.state)
    assert schedule.TRIGGER_ENV not in d["EnvironmentVariables"]
    boot = [c for c in launchctl.calls if c[0] == "bootstrap"]
    assert boot == [("bootstrap", f"gui/{os.getuid()}", str(plist))]
    assert "com.agentbox-unit._report" in launchctl.loaded
    assert "daily at 09:30" in capsys.readouterr().out
    # nothing that lists jobs or profiles sees `_report`
    assert schedule.list_jobs() == []
    assert not (rdir / "schedules").exists() and not (rdir / "subnet").exists()


def test_install_at_replaces_and_warns_without_a_webhook(launchctl, capsys):
    import plistlib

    from agentbox import cli

    assert cli.main(["schedule", "report", "--install", "--at", "08:45"]) == 0
    assert "report_outputs includes slack, but notify_webhook_secret is not set" in (
        capsys.readouterr().err)  # fmt: skip
    assert cli.main(["schedule", "report", "--install", "--at", "7:05"]) == 0
    plist = launchctl.tmp / "la" / "com.agentbox-unit._report.plist"
    assert plistlib.loads(plist.read_bytes())["StartCalendarInterval"] == [{"Minute": 5, "Hour": 7}]
    assert [c[0] for c in launchctl.calls].count("bootout") == 1  # the second install unloads first
    for bad in ("25:00", "9", "ab"):
        assert cli.main(["schedule", "report", "--install", "--at", bad]) == 1
        assert "HH:MM" in capsys.readouterr().err
    assert plistlib.loads(plist.read_bytes())["StartCalendarInterval"] == [{"Minute": 5, "Hour": 7}]


def test_uninstall_removes_the_plist_and_unloads(launchctl, capsys):
    from agentbox import cli

    assert cli.main(["schedule", "report", "--install"]) == 0
    capsys.readouterr()
    plist = launchctl.tmp / "la" / "com.agentbox-unit._report.plist"
    assert plist.exists()
    assert cli.main(["schedule", "report", "--uninstall"]) == 0
    assert not plist.exists() and "com.agentbox-unit._report" not in launchctl.loaded
    assert ("bootout", f"gui/{os.getuid()}/com.agentbox-unit._report") in launchctl.calls
    assert "removed" in capsys.readouterr().out
    assert (launchctl.state / "_report").is_dir()  # its files stay
    assert cli.main(["schedule", "report", "--uninstall"]) == 0
    assert "no fleet report job installed" in capsys.readouterr().out


def test_report_installed_states_on_macos(launchctl):
    assert schedule.report_installed() is None
    from agentbox import cli

    cli.main(["schedule", "report", "--install"])
    assert schedule.report_installed() == "loaded"
    launchctl.loaded.clear()
    assert schedule.report_installed() == "not loaded"  # plist is there, job is not loaded


@pytest.fixture
def crontab(cli_world, monkeypatch):
    monkeypatch.setattr(schedule, "is_macos", lambda: False)
    box = {"text": "0 1 * * * echo mine\n"}
    monkeypatch.setattr(schedule, "crontab_read", lambda: box["text"])
    monkeypatch.setattr(schedule, "crontab_write", lambda t: box.update(text=t))
    monkeypatch.setattr(schedule, "launchctl", lambda *a: pytest.fail("launchctl on Linux"))
    return box


def test_install_and_uninstall_in_the_crontab(crontab, cli_world, capsys):
    from agentbox import cli

    assert cli.main(["schedule", "report", "--install", "--at", "09:30"]) == 0
    text = crontab["text"]
    assert text.startswith("0 1 * * * echo mine\n# agentbox:_report\n30 9 * * * cd / && ")
    rdir = cli_world.state / "_report"
    line = text.splitlines()[-1]
    tail = f"schedule report --post </dev/null >>{rdir / 'launchd.out'} 2>>{rdir / 'launchd.err'}"
    assert line.endswith(tail)
    assert schedule.report_installed() == "in crontab"
    assert cli.main(["schedule", "report", "--install", "--at", "10:00"]) == 0
    assert crontab["text"].count("# agentbox:_report") == 1 and "0 10 * * *" in crontab["text"]
    assert cli.main(["schedule", "report", "--uninstall"]) == 0
    assert crontab["text"] == "0 1 * * * echo mine\n"
    assert schedule.report_installed() is None
    assert cli.main(["schedule", "report", "--uninstall"]) == 0
    assert "no fleet report job installed" in capsys.readouterr().out


def test_usage_example_investigator_profile_passes_the_safety_check(world, monkeypatch):
    """The profile in docs/USAGE.md is the one the check accepts."""
    import re

    usage = (Path(__file__).resolve().parents[2] / "docs" / "USAGE.md").read_text()
    m = re.search(r"profiles/investigator\.toml`:\n\n```toml\n(.*?)```", usage, re.S)
    assert m, "the example profile is missing from USAGE.md"
    monkeypatch.setattr(
        "agentbox.profile.check_mount_host",
        lambda host, allow_dotpath=False, **kw: os.path.realpath(os.path.expanduser(host)),
    )
    (world.tmp / "home" / "agentbox-investigator").mkdir()  # `mkdir ~/agentbox-investigator`
    (world.cfg / "profiles" / "investigator.toml").write_text(m.group(1))
    assert fleet.investigator_problems("investigator") == []
    (world.tmp / "home" / "agentbox-investigator" / "x").write_text("")
    assert any("is not empty" in p for p in fleet.investigator_problems("investigator"))
    setup = usage[usage.index("mkdir ~/agentbox-investigator") :].split("```")[0]
    for cmd in ("mkdir ~/agentbox-investigator", "report_investigator",
                "agentbox doctor investigator"):  # fmt: skip
        assert cmd in setup
    assert not re.search(r"agentbox doctor\s+#", setup)  # doctor needs the profile name


# ---------------------------------------------------------------- round 2
def test_carried_still_running_due_time_gets_the_late_row_with_no_note(world):
    job = mkjob(world, cron="30 8 * * *")
    jd = Path(job["dir"])
    addrow(world, job, "2026-10-08 08:30:02", status="running", rc=None, last_only=True)
    lock = hold_lock(jd / "fire.lock")  # a 2 h run is active at report 1
    try:
        rep1 = run_report(world, now=T("2026-10-08 09:00"), post=True)
    finally:
        lock.close()
    assert [(f.cls, f.counted) for f in rep1.fires] == [("still_running", False)]
    assert rep1.carry == [{"job": "p/j", "due": fleet.iso(T("2026-10-08 08:30")),
                           "state": "still_running"}]  # fmt: skip
    fleet.save_last_report(rep1)
    # the run fails later: history gets the row, last.json is rewritten, the lock is free
    (jd / "last.json").unlink()
    addrow(world, job, "2026-10-08 08:30:02", status="failed", rc=1, transcript="DIFFERENT\n")
    rep2 = run_report(world, now=T("2026-10-08 11:00"), post=True)
    assert rep2.window_start == fleet.iso(T("2026-10-08 09:00"))  # the row is before this window
    [f] = rep2.fires
    assert (f.cls, f.origin, f.counted, f.note, f.cause) == ("failed", "due", True, None,
                                                              "DIFFERENT")  # fmt: skip
    assert f.due == fleet.iso(T("2026-10-08 08:30")) and rep2.scheduled == 1 and rep2.carry == []


def test_carried_still_running_that_is_still_running_stays_carried(world):
    job = mkjob(world, cron="30 8 * * *")
    addrow(world, job, "2026-10-08 08:30:02", status="running", rc=None, last_only=True)
    write_last(world, fleet.iso(T("2026-10-08 09:00")),
               [{"job": "p/j", "due": fleet.iso(T("2026-10-08 08:30")),
                 "state": "still_running"}])  # fmt: skip
    lock = hold_lock(Path(job["dir"]) / "fire.lock")
    try:
        rep = run_report(world, now=T("2026-10-08 10:00"), post=True)
    finally:
        lock.close()
    assert [f.cls for f in rep.fires] == ["still_running"]
    assert rep.carry[0]["state"] == "still_running"


def test_old_carry_entries_without_a_state_still_load(world):
    write_last(world, fleet.iso(T("2026-10-08 09:00")),
               [{"job": "p/j", "due": fleet.iso(T("2026-10-08 08:30"))}])  # fmt: skip
    assert fleet.resolve_window(NOW, timedelta(hours=24), post=True)[2][0][2] == "pending"
    write_last(world, fleet.iso(T("2026-10-08 09:00")),
               [{"job": "p/j", "due": fleet.iso(T("2026-10-08 08:30")),
                 "state": "bogus"}])  # fmt: skip
    assert fleet.resolve_window(NOW, timedelta(hours=24), post=True)[2] == []


def test_due_times_before_the_window_are_not_judged_again(world):
    """Only carried due times reach back past the window start; the others were
    judged by the earlier report. An older row is never an extra run."""
    job = mkjob(world, cron="30 7,8 * * *")
    addrow(world, job, "2026-10-08 07:30:02")  # ran, and was in the earlier report
    write_last(world, fleet.iso(T("2026-10-08 09:00")),
               [{"job": "p/j", "due": fleet.iso(T("2026-10-08 08:30")),
                 "state": "not_run_yet"}])  # fmt: skip
    addrow(world, job, "2026-10-08 09:20:00", status="failed", rc=1, transcript="late\n")
    rep = run_report(world, now=T("2026-10-08 11:00"), post=True)
    assert [(f.cls, f.origin, f.note) for f in rep.fires] == [("failed", "due", "late, due 08:30")]


def test_fires_are_sorted_by_instant_across_the_fall_back_hour(world):
    job = mkjob(world, cron="0 12 * * *")
    # 01:45 WEST happens before 01:10 WET on 2026-10-25
    addrow(world, job, "2026-10-25T01:10:00+00:00", trigger="run-now")
    addrow(world, job, "2026-10-25T01:45:00+01:00", trigger="run-now")
    rep = run_report(world, now=T("2026-10-25 13:00"), since="24h")
    manual = [f.when for f in rep.fires if f.origin == "manual"]
    assert manual == ["2026-10-25T01:45:00+01:00", "2026-10-25T01:10:00+00:00"]
    assert sorted(manual) != manual  # the text order would be wrong


# ---------------------------------------------------------------- scrub before cut
TAIL = "x" * 105 + " " + SECRET  # the secret starts just past the 120-character cut


def assert_no_piece(text):
    for n in (8, 12, 15):
        assert SECRET[:n] not in text and SECRET[-n:] not in text, text


def test_investigator_stderr_tail_is_scrubbed_before_it_is_cut(inv, secrets_ok, monkeypatch):
    failing_job(inv)
    monkeypatch.setattr(fleet, "run_investigator", Stub(inv, rc=1, stderr=TAIL + "\n", line=False))
    f = next(
        f for f in run_report(inv, since="12h", investigate=True, cfg=CFG).fires if f.unexplained
    )
    assert f.investigation.startswith("(investigation failed: exit 1: xxx")
    assert "<redacted>" in f.investigation
    assert_no_piece(f.investigation)


def test_investigator_answer_is_scrubbed_before_it_is_cut(inv, secrets_ok, monkeypatch):
    failing_job(inv)
    for lead in (190, 195, 199, 200, 201):
        monkeypatch.setattr(fleet, "run_investigator", Stub(inv, answer="y" * lead + " " + SECRET))
        rep = run_report(inv, since="12h", investigate=True, cfg=CFG)
        text = next(f.investigation for f in rep.fires if f.unexplained)
        assert text.startswith("investigator: yyy"), text
        assert_no_piece(text)


def test_evidence_lines_are_scrubbed_before_they_are_cut(inv):
    job = failing_job(inv, transcript="")
    jd = Path(job["dir"])
    rows = [json.loads(x) for x in (jd / "history.jsonl").read_text().splitlines()]
    for lead in (950, 990, 999, 1000):
        Path(rows[0]["transcript"]).write_text("z" * lead + SECRET + "\n")
        job_json = json.loads((jd / "job.json").read_text())
        fire = fleet.Fire(job="p/j", origin="due", cls="failed", when=rows[0]["start"],
                          job_dict=job_json, row=rows[0])  # fmt: skip
        sc = fleet.Scrubber()
        sc.add(SECRET)
        assert_no_piece(fleet.evidence_bundle(fire, rows, sc))


def test_report_command_error_is_scrubbed_before_it_is_cut(
    inv, secrets_ok, capsys, monkeypatch, tmp_path
):
    from agentbox import cli, notify

    failing_job(inv)
    hook = tmp_path / "hook.sh"
    hook.write_text(f'#!/bin/sh\ncat >/dev/null\necho "{TAIL}" >&2\nexit 3\n')
    hook.chmod(0o755)
    (inv.cfg / "config.toml").write_text(
        'notify_webhook_secret = "HOOK"\nreport_investigator = "inv"\n'
        f'report_outputs = "command"\nreport_command = "{hook}"\n'
    )

    class FakeDT(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(cli, "datetime", FakeDT)
    monkeypatch.setattr(notify, "post", lambda *a: None)
    monkeypatch.setattr(fleet, "run_investigator", Stub(inv))
    assert cli.main(["schedule", "report", "--post", "--since", "12h"]) == 1
    out = capsys.readouterr().out
    assert "fleet report FAILED: report_command exited 3: xxx" in out
    assert "<redacted>" in out
    assert_no_piece(out)
