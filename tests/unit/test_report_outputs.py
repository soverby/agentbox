"""Fleet report outputs (PLAN §2.8): the exact lines and counts, escaping, the
20-line cap, the FAILED line, the fixed registry, slack and command delivery."""

import json
import stat
from pathlib import Path

import pytest
from agentbox import notify, paths, report_outputs
from agentbox.fleet import Fire, IdleBox, Report

WHEN = "2026-10-08T08:15:00+01:00"
URL = "https://hooks.slack.com/services/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4"


def fire(cls="ok", job="p/j", origin="due", when=WHEN, rc=0, cause=None, **kw):
    counted = origin in ("due", "before_created", "every") and cls not in (
        "pending", "still_running")  # fmt: skip
    return Fire(job=job, origin=origin, cls=cls, when=when, exit_code=rc, cause=cause,
                counted=counted, **kw)  # fmt: skip


def report(fires=(), idle=(), drift=(), idle_check="ok", every=()):
    return Report(
        generated=WHEN, window_start=WHEN, window_end=WHEN, post=False, fires=list(fires),
        idle_boxes=list(idle), drift=list(drift), idle_check=idle_check, every_jobs=list(every),
    )  # fmt: skip


# ---------------------------------------------------------------- the lines
def test_all_well():
    r = report([fire() for _ in range(8)])
    assert report_outputs.render_text(r) == "🚦 all 8 scheduled runs completed, no idle boxes"
    assert report_outputs.render_text(r, slack=True) == report_outputs.render_text(r)


def test_all_well_counts_manual_and_extra_runs():
    r = report([fire(), fire(), fire(origin="manual"), fire(origin="extra")])
    assert report_outputs.render_text(r) == (
        "🚦 all 2 scheduled runs completed, no idle boxes (+2 manual runs)")  # fmt: skip


def test_all_well_wording_for_one_and_for_no_run():
    one = report([fire()])
    assert report_outputs.render_text(one) == "🚦 1 scheduled run completed, no idle boxes"
    assert report_outputs.render_text(report([])) == "🚦 no scheduled runs were due, no idle boxes"
    why = "idle-box check skipped: Docker not running"
    assert report_outputs.render_text(report([], idle_check=why)) == (
        f"🚦 no scheduled runs were due, {why}")  # fmt: skip
    assert report_outputs.render_text(report([fire()], idle_check=why)) == (
        f"🚦 1 scheduled run completed, {why}")  # fmt: skip
    r = report([fire(origin="manual")])
    assert report_outputs.render_text(r) == (
        "🚦 no scheduled runs were due, no idle boxes (+1 manual runs)")  # fmt: skip


def test_pending_and_still_running_are_not_problems_and_not_counted():
    r = report([fire(), fire("pending", rc=None), fire("still_running", rc=None)])
    assert report_outputs.render_text(r) == "🚦 1 scheduled run completed, no idle boxes"


def test_problem_form_exact_lines_and_counts():
    fires = [fire() for _ in range(5)]
    fires.append(fire(job="fx/eurusd", notify_error="HTTP 500"))  # an ok row, post failed
    fires += [
        fire("failed", job="boletim/delta", rc=1, when="2026-10-08T08:15:02+01:00",
             cause="boletim delta: DIFFERENT vs 2026-10-07"),
        fire("timeout", job="cves/household", rc=124, cause="killed after the 1h timeout"),
        fire("skipped", rc=75, cause="a run of this job was still active"),
        fire("missed", rc=None, cause="host off or restarted (up since 10-08 08:00)"),
        fire("not_run_yet", rc=None),
    ]  # fmt: skip
    idle = [IdleBox("portfolio", 17, "pinned since 10-06 18:52 (manual `up`)"),
            IdleBox("boletim", 15, "running, not pinned, no run left it up")]  # fmt: skip
    drift = [{"job": "boletim/brief", "kind": "differs",
              "text": "job copy differs from /w/brief.sh (since 10-08 08:20)"}]  # fmt: skip
    text = report_outputs.render_text(report(fires, idle, drift))
    assert text.splitlines() == [
        "⚠️ 6 of 11 scheduled runs completed normally, 1 failed, 1 timed out, 1 skipped, "
        "1 missed, 1 not run yet, 2 idle boxes, 1 job copy changed, 1 status post failed",
        "• fx/eurusd 10-08 08:15 status post failed: HTTP 500",
        "• boletim/delta 10-08 08:15 failed (exit 1): boletim delta: DIFFERENT vs 2026-10-07",
        "• cves/household 10-08 08:15 timed out (exit 124): killed after the 1h timeout",
        "• p/j 10-08 08:15 skipped (exit 75): a run of this job was still active",
        "• p/j 10-08 08:15 missed: host off or restarted (up since 10-08 08:00)",
        "• p/j 10-08 08:15 not run yet",
        "• idle box portfolio (up 17 h): pinned since 10-06 18:52 (manual `up`)",
        "• idle box boletim (up 15 h): running, not pinned, no run left it up",
        "• boletim/brief: job copy differs from /w/brief.sh (since 10-08 08:20)",
    ]  # fmt: skip


def test_singular_forms():
    gone = {"job": "p/j", "kind": "gone", "text": "source gone"}
    r = report([fire()], idle=[IdleBox("a", 3, "c")], drift=[gone])
    assert report_outputs.render_text(r).splitlines()[0] == (
        "⚠️ 1 of 1 scheduled runs completed normally, 1 idle box, 1 job copy changed"
    )


def test_failed_manual_run_is_a_problem_line_outside_n():
    r = report([fire(), fire("failed", origin="manual", rc=2, cause="oops"),
                fire("timeout", origin="extra", rc=124, cause="slow")])  # fmt: skip
    assert report_outputs.render_text(r).splitlines() == [
        "⚠️ 1 of 1 scheduled runs completed normally, 1 manual run failed, 1 extra run failed",
        "• p/j 10-08 08:15 failed (exit 2) [manual]: oops",
        "• p/j 10-08 08:15 timed out (exit 124) [extra]: slow",
    ]


def test_classes_have_their_words():
    cases = {
        "docker_down": (69, "did not run (exit 69)"),
        "preflight": (78, "did not run (exit 78)"),
        "start_failed": (125, "run failed (exit 125)"),
        "terminated": (143, "terminated (exit 143)"),
        "stale_running": (None, "stale (the fire process is gone)"),
    }
    for cls, (rc, word) in cases.items():
        line = report_outputs.fire_line(fire(cls, rc=rc, cause="why"))
        assert line == f"• p/j 10-08 08:15 {word}: why"
    # stale rows are failures in the summary
    assert "1 failed" in report_outputs.summary(report([fire("stale_running", rc=None)]))


def test_carried_note_and_investigator_text():
    f = fire("failed", rc=1, cause="DIFFERENT", note="late, due 08:10",
             investigation="investigator: x")  # fmt: skip
    assert report_outputs.fire_line(f) == (
        "• p/j 10-08 08:15 failed (exit 1): DIFFERENT (late, due 08:10); investigator: x"
    )
    f.investigation = "(investigation failed: timed out after 3 min)"
    assert report_outputs.fire_line(f).endswith(
        "DIFFERENT (late, due 08:10) (investigation failed: timed out after 3 min)"
    )


def test_every_job_lines_only_in_the_text_form():
    r = report([fire()], every=[{"job": "fx/poll", "runs": 46, "expected": 48}])
    assert report_outputs.render_text(r).splitlines() == [
        "🚦 1 scheduled run completed, no idle boxes",
        "interval job fx/poll: 46 runs (about 48 expected)",
    ]
    assert report_outputs.render_text(r, slack=True).splitlines() == [
        "🚦 1 scheduled run completed, no idle boxes"]  # fmt: skip


def test_idle_check_skipped_is_said_not_hidden():
    why = "idle-box check skipped: Docker not running"
    ok = report_outputs.render_text(report([fire()], idle_check=why))
    assert ok == f"🚦 1 scheduled run completed, {why}" and "no idle boxes" not in ok
    bad = report_outputs.render_text(report([fire("failed", rc=1, cause="x")], idle_check=why))
    assert bad.splitlines()[-1] == why


# ---------------------------------------------------------------- escaping, cap
def test_lines_are_cleaned_and_slack_escaped():
    evil = "\x1b[31mred\x1b[0m <@U123> <!channel> & <http://evil.example|click> \x00‮ end"
    r = report([fire("failed", rc=1, cause=evil)], idle=[IdleBox("b<x>", 2, "a&b")])
    plain, slack = report_outputs.render_text(r), report_outputs.render_text(r, slack=True)
    for text in (plain, slack):
        assert "\x1b" not in text and "\x00" not in text and "‮" not in text
    assert "<@U123> <!channel> &" in plain
    assert "&lt;@U123&gt; &lt;!channel&gt; &amp;" in slack
    assert "<@" not in slack and "<!" not in slack and "<http" not in slack
    assert "idle box b&lt;x&gt; (up 2 h): a&amp;b" in slack


def test_each_line_is_capped_at_300_characters_before_escaping():
    r = report([fire("failed", rc=1, cause="<" * 400)])
    line = report_outputs.render_text(r, slack=True).splitlines()[1]
    assert line.endswith("…") and "&l…" not in line and "&lt" in line
    assert len(report_outputs.render_text(r).splitlines()[1]) == 300


def test_at_most_twenty_problem_lines_then_and_n_more():
    fires = [fire("failed", job=f"p/j{i:02d}", rc=1, cause=f"c{i}") for i in range(25)]
    lines = report_outputs.render_text(report(fires)).splitlines()
    assert len(lines) == 1 + 20 + 1
    assert lines[1].startswith("• p/j00") and lines[20].startswith("• p/j19")
    assert lines[-1] == "… and 5 more"
    assert lines[0].startswith("⚠️ 0 of 25 scheduled runs completed normally, 25 failed")
    assert report_outputs.render_text(report(fires[:20])).splitlines()[-1].startswith("• p/j19")


def test_failed_line():
    assert report_outputs.render_failed("boom") == "🚦 fleet report FAILED: boom"
    assert report_outputs.render_failed("<@U1> & x", slack=True) == (
        "🚦 fleet report FAILED: &lt;@U1&gt; &amp; x"
    )
    assert "\x1b" not in report_outputs.render_failed("a\x1b[31mb")
    assert len(report_outputs.render_failed("x" * 1000)) == 300


# ---------------------------------------------------------------- registry
def test_registry_is_fixed_and_matches_the_config_constant():
    assert tuple(report_outputs.OUTPUTS) == paths.REPORT_OUTPUTS == (
        "stdout", "json", "slack", "command")  # fmt: skip
    r = report([fire()])
    assert report_outputs.OUTPUTS["stdout"].render(r) == report_outputs.render_text(r)
    assert report_outputs.OUTPUTS["slack"].render(r) == report_outputs.render_text(r, slack=True)
    d = json.loads(report_outputs.OUTPUTS["json"].render(r))
    assert d["version"] == 1 and d["scheduled"] == 1
    assert report_outputs.OUTPUTS["command"].render(r) == report_outputs.OUTPUTS["json"].render(r)
    # nothing in config names code: the module imports nothing from a config value
    assert "importlib" not in Path(report_outputs.__file__).read_text()


def test_stdout_delivery(capsys):
    report_outputs.OUTPUTS["stdout"].deliver("hello", paths.Config())
    assert capsys.readouterr().out == "hello\n"


# ---------------------------------------------------------------- slack
def test_slack_delivery_uses_the_notify_webhook(monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "read_webhook", lambda cfg, profile: URL)
    monkeypatch.setattr(
        notify, "post", lambda url, text, timeout: sent.append((url, text, timeout))
    )
    cfg = paths.Config(notify_webhook_secret="HOOK")
    report_outputs.OUTPUTS["slack"].deliver("hi", cfg)
    assert sent == [(URL, "hi", notify.NOTIFY_TIMEOUT)]


def test_slack_needs_the_webhook_setting():
    with pytest.raises(report_outputs.OutputError, match="notify_webhook_secret"):
        report_outputs.OUTPUTS["slack"].deliver("hi", paths.Config())


def test_slack_failure_never_shows_the_url(monkeypatch):
    monkeypatch.setattr(notify, "read_webhook", lambda cfg, profile: URL)

    def boom(url, text, timeout):
        raise notify.NotifyError(f"cannot reach {URL}")

    monkeypatch.setattr(notify, "post", boom)
    with pytest.raises(report_outputs.OutputError) as e:
        report_outputs.OUTPUTS["slack"].deliver("hi", paths.Config(notify_webhook_secret="HOOK"))
    assert URL not in str(e.value) and "xyzSECRETSECRET" not in str(e.value)
    assert str(e.value).startswith("slack: ")


def test_post_failed_only_through_slack(monkeypatch):
    sent = []
    monkeypatch.setattr(notify, "read_webhook", lambda cfg, profile: URL)
    monkeypatch.setattr(notify, "post", lambda url, text, timeout: sent.append(text))
    cfg = paths.Config(notify_webhook_secret="HOOK")
    assert report_outputs.post_failed("<boom>", cfg) is True
    assert sent == ["🚦 fleet report FAILED: &lt;boom&gt;"]
    assert report_outputs.post_failed("x", paths.Config(report_outputs=("stdout",))) is False
    assert report_outputs.post_failed("x", paths.Config()) is False  # slack, but no webhook set


# ---------------------------------------------------------------- command
def script(tmp_path, body):
    f = tmp_path / "hook.sh"
    f.write_text("#!/bin/sh\n" + body)
    f.chmod(f.stat().st_mode | stat.S_IXUSR)
    return str(f)


def test_command_gets_the_json_on_stdin_without_a_shell(tmp_path):
    out = tmp_path / "got.json"
    sh = script(tmp_path, f'cat > {out}\nprintf "%s" "$1" > {tmp_path / "arg"}\n')
    cfg = paths.Config(report_command=(sh, "a;touch " + str(tmp_path / "pwned")))
    text = report_outputs.OUTPUTS["command"].render(report([fire()]))
    report_outputs.OUTPUTS["command"].deliver(text, cfg)
    assert json.loads(out.read_text())["version"] == 1
    assert (tmp_path / "arg").read_text().startswith("a;touch ")  # one argument, no shell
    assert not (tmp_path / "pwned").exists()


def test_command_failures(tmp_path, monkeypatch):
    bad = paths.Config(report_command=(script(tmp_path, "echo nope >&2\nexit 3\n"),))
    with pytest.raises(report_outputs.OutputError, match=r"exited 3: nope"):
        report_outputs.OUTPUTS["command"].deliver("{}", bad)
    monkeypatch.setattr(report_outputs, "COMMAND_LIMIT", 0.3)
    slow = paths.Config(report_command=(script(tmp_path, "sleep 5\n"),))
    with pytest.raises(report_outputs.OutputError, match="ran over"):
        report_outputs.OUTPUTS["command"].deliver("{}", slow)
    with pytest.raises(report_outputs.OutputError, match="report_command"):
        report_outputs.OUTPUTS["command"].deliver("{}", paths.Config(report_command=("/no/such",)))
    with pytest.raises(report_outputs.OutputError, match="needs report_command"):
        report_outputs.OUTPUTS["command"].deliver("{}", paths.Config())


def test_counts_are_for_due_fires_so_k_plus_counts_is_n():
    fires = [fire(), fire("failed", rc=1, cause="x"), fire("timeout", rc=124, cause="y"),
             fire("missed", rc=None, cause="z"), fire("not_run_yet", rc=None),
             fire("failed", origin="manual", rc=1, cause="m"),
             fire("skipped", origin="extra", rc=75, cause="e"),
             fire("failed", origin="extra", rc=1, cause="e2")]  # fmt: skip
    r = report(fires)
    first = report_outputs.render_text(r).splitlines()[0]
    assert first == (
        "⚠️ 1 of 5 scheduled runs completed normally, 1 failed, 1 timed out, 1 missed, "
        "1 not run yet, 1 manual run failed, 2 extra runs failed"
    )


def test_unknown_history_row_line():
    f = fire("unknown", origin="unparsed", rc=None, cause="history row not understood")
    r = report([fire(), f])
    assert report_outputs.render_text(r).splitlines() == [
        "⚠️ 1 of 1 scheduled runs completed normally, 1 history row not understood",
        "• p/j 10-08 08:15 history row not understood",
    ]
