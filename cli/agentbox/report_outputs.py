"""Fleet report outputs (PLAN §2.8): a fixed registry, never code from config.

An output has `render(report) -> str` and `deliver(text, cfg)`. The text and
Slack forms share the lines below; every line goes through
`notify.clean_line`, and Slack lines also through `notify.slack_escape`.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from . import notify, paths, schedule
from .fleet import NOT_UNDERSTOOD, Fire, Report, label, parse_dt

MAX_PROBLEM_LINES = 20
COMMAND_LIMIT = 60.0
FAILED_PREFIX = "🚦 fleet report FAILED: "
# Classes that count as "failed" in the summary (T, S, X and P have their own).
FAILED_CLASSES = (
    "failed",
    "docker_down",
    "preflight",
    "start_failed",
    "terminated",
    "stale_running",
)
WORDS = {
    "failed": "failed",
    "timeout": "timed out",
    "docker_down": "did not run",
    "preflight": "did not run",
    "start_failed": "run failed",
    "terminated": "terminated",
    "skipped": "skipped",
    "stale_running": "stale (the fire process is gone)",
    "missed": "missed",
    "not_run_yet": "not run yet",
    "unknown": NOT_UNDERSTOOD,
}


class OutputError(Exception):
    pass


# ---------------------------------------------------------------- lines
def full_cause(f: Fire) -> str:
    """The cause, the carry-over note, and the investigator text."""
    text = f.cause or ""
    if f.note:
        text += f" ({f.note})"
    if f.investigation:
        if not text:
            return f.investigation
        text += (" " if f.investigation.startswith("(") else "; ") + f.investigation
    return text


def fire_line(f: Fire) -> str:
    """`• boletim/delta 10-08 08:15 failed (exit 1): <cause>`."""
    when = label(parse_dt(f.when))
    if f.cls == "unknown":
        return f"• {f.job} {when} {WORDS['unknown']}"
    head = f"• {f.job} {when} {WORDS[f.cls]}"
    if f.exit_code is not None and f.cls not in ("missed", "stale_running"):
        head += f" (exit {f.exit_code})"
    if f.origin in ("manual", "extra"):
        head += f" [{f.origin}]"
    cause = full_cause(f)
    return f"{head}: {cause}" if cause else head


def problem_lines(report: Report) -> list[str]:
    """Every problem, uncapped: runs (a failed status post is its own line),
    then idle boxes, then job copy drift."""
    out = []
    for f in report.fires:
        if f.problem:
            out.append(fire_line(f))
        if f.notify_error:
            out.append(f"• {f.job} {label(parse_dt(f.when))} status post failed: {f.notify_error}")
    for b in report.idle_boxes:
        out.append(f"• idle box {b.profile} (up {b.up_hours} h): {b.cause}")
    for d in report.drift:
        out.append(f"• {d['job']}: {d['text']}")
    return out


def counts(report: Report) -> dict[str, int]:
    """F, T, S, X, P count due fires only (the ones in N), so K plus these
    equals N. Problem runs outside N (run-now, extra) are counted apart."""
    due = [f for f in report.fires if f.counted]
    side = [f for f in report.fires if f.origin in ("manual", "extra") and f.problem]
    return {
        "failed": sum(1 for f in due if f.cls in FAILED_CLASSES),
        "timed out": sum(1 for f in due if f.cls == "timeout"),
        "skipped": sum(1 for f in due if f.cls == "skipped"),
        "missed": sum(1 for f in due if f.cls == "missed"),
        "not run yet": sum(1 for f in due if f.cls == "not_run_yet"),
        "manual": sum(1 for f in side if f.origin == "manual"),
        "extra": sum(1 for f in side if f.origin == "extra"),
        "unknown": sum(1 for f in report.fires if f.cls == "unknown"),
        "idle": len(report.idle_boxes),
        "drift": len(report.drift),
        "posts": sum(1 for f in report.fires if f.notify_error),
    }


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def all_well(n: int, idle_note: str, manual: int) -> str:
    if n >= 2:
        text = f"🚦 all {n} scheduled runs completed, {idle_note}"
    elif n == 1:
        text = f"🚦 1 scheduled run completed, {idle_note}"
    else:
        text = f"🚦 no scheduled runs were due, {idle_note}"
    return text + (f" (+{manual} manual runs)" if manual else "")


def summary(report: Report) -> str:
    n, c = report.scheduled, counts(report)
    idle_note = "no idle boxes" if report.idle_check == "ok" else report.idle_check
    if not problem_lines(report):
        return all_well(n, idle_note, report.manual)
    parts = [f"{report.completed} of {n} scheduled runs completed normally"]
    for word in ("failed", "timed out", "skipped", "missed", "not run yet"):
        if c[word]:
            parts.append(f"{c[word]} {word}")
    for kind in ("manual", "extra"):
        if c[kind]:
            parts.append(_plural(c[kind], f"{kind} run failed", f"{kind} runs failed"))
    if c["unknown"]:
        parts.append(_plural(c["unknown"], "history row not understood",
                             "history rows not understood"))  # fmt: skip
    if c["idle"]:
        parts.append(_plural(c["idle"], "idle box", "idle boxes"))
    if c["drift"]:
        parts.append(_plural(c["drift"], "job copy changed", "job copies changed"))
    if c["posts"]:
        parts.append(_plural(c["posts"], "status post failed", "status posts failed"))
    return "⚠️ " + ", ".join(parts)


def every_lines(report: Report) -> list[str]:
    """Interval jobs have no exact due times: "N runs (about M expected)"."""
    return [
        f"interval job {e['job']}: {e['runs']} runs (about {e['expected']} expected)"
        for e in report.every_jobs
    ]


def render_text(report: Report, slack: bool = False) -> str:
    """The text form. Slack: no interval-job lines, and `&`, `<`, `>` escaped."""
    lines = [summary(report)]
    probs = problem_lines(report)
    lines += probs[:MAX_PROBLEM_LINES]
    if len(probs) > MAX_PROBLEM_LINES:
        lines.append(f"… and {len(probs) - MAX_PROBLEM_LINES} more")
    if report.idle_check != "ok" and probs:
        lines.append(report.idle_check)
    if not slack:
        lines += every_lines(report)
    lines = [notify.clean_line(x) for x in lines]
    return "\n".join(notify.slack_escape(x) for x in lines) if slack else "\n".join(lines)


def render_failed(reason: str, slack: bool = False) -> str:
    line = notify.clean_line(FAILED_PREFIX + reason)
    return notify.slack_escape(line) if slack else line


# ---------------------------------------------------------------- deliver
def deliver_stdout(text: str, cfg: paths.Config) -> None:
    print(text, flush=True)


def deliver_slack(text: str, cfg: paths.Config) -> None:
    """Through notify.read_webhook / notify.post: the same webhook as §2.7."""
    if cfg.notify_webhook_secret is None:
        raise OutputError("the slack output needs notify_webhook_secret in config.toml")
    url = None
    try:
        url = notify.read_webhook(cfg, schedule.REPORT_NAME)
        notify.post(url, text, notify.NOTIFY_TIMEOUT)
    except Exception as e:  # noqa: BLE001 - one scrubbed line, never the URL
        raise OutputError(f"slack: {notify.reason(e, url)}") from None


def deliver_command(text: str, cfg: paths.Config) -> None:
    """`report_command` with the JSON on stdin: no shell, 60 s limit."""
    if not cfg.report_command:
        raise OutputError("the command output needs report_command in config.toml")
    try:
        r = subprocess.run(
            list(cfg.report_command), input=text, text=True, capture_output=True,
            timeout=COMMAND_LIMIT, cwd="/",
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        raise OutputError(f"report_command ran over {COMMAND_LIMIT:.0f} s") from None
    except OSError as e:
        raise OutputError(f"report_command: {e.strerror}") from None
    if r.returncode != 0:
        # The whole last line: the caller scrubs the error text and cuts it after.
        tail = (r.stderr.strip().splitlines() or [""])[-1]
        raise OutputError(f"report_command exited {r.returncode}" + (f": {tail}" if tail else ""))


def render_json(report: Report) -> str:
    return json.dumps(report.as_dict(), indent=2)


@dataclass(frozen=True)
class Output:
    name: str
    render: Callable[[Report], str]
    deliver: Callable[[str, paths.Config], None]


OUTPUTS: dict[str, Output] = {
    o.name: o
    for o in (
        Output("stdout", render_text, deliver_stdout),
        Output("json", render_json, deliver_stdout),
        Output("slack", lambda r: render_text(r, slack=True), deliver_slack),
        Output("command", render_json, deliver_command),
    )
}
if tuple(OUTPUTS) != paths.REPORT_OUTPUTS:
    raise RuntimeError("report_outputs.OUTPUTS and paths.REPORT_OUTPUTS must list the same names")


def post_failed(reason: str, cfg: paths.Config) -> bool:
    """Post the FAILED line through the slack output when it is configured.
    False: not posted (not configured, or the post failed)."""
    if "slack" not in cfg.report_outputs:
        return False
    try:
        deliver_slack(render_failed(reason, slack=True), cfg)
    except OutputError:
        return False
    return True
