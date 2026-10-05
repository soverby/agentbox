"""Scheduled-run notifications (PLAN §2.7).

At the end of every `schedule _fire` the host posts one status message to a
Slack incoming webhook. The webhook URL is the value of the shared secret that
the host setting `notify_webhook_secret` names. It is read on the host at fire
time and never goes to a box, a file, a log, or argv; error text is scrubbed of
it (secretstore.scrub). A failure here never changes the fire's exit code.

The detail in the message is the last line of the run's transcript. That line
is untrusted box output: control characters are removed, whitespace is
collapsed, the text is capped, and `&`, `<`, `>` are escaped so it cannot make
a Slack mention or link. Nothing else from the transcript is sent.
"""

from __future__ import annotations

import json
import re
import threading
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

from . import paths, secretstore

NOTIFY_TIMEOUT = 10.0  # total seconds for secret read + request
TERMINATED_TIMEOUT = 5.0  # after SIGTERM: launchd kills us 90 s after the signal
LINE_CAP = 300  # characters of box text in a message
TAIL_BYTES = 64 * 1024  # how much of the transcript end is read
REASON_CAP = 200
# agentbox's own last line when it killed a run (cli.run_headless).
KILL_MARK = re.compile(r"\[agentbox: run killed: .*\]")
# CSI and OSC escape sequences (colors, cursor moves, window titles).
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


class NotifyError(Exception):
    pass


# ---------------------------------------------------------------- message
def fmt_duration(sec: float) -> str:
    s = max(0, int(sec))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{s % 3600 // 60:02d}m"


def clean_line(text: str, cap: int = LINE_CAP) -> str:
    """One plain line: escape sequences and control/format characters removed,
    whitespace collapsed, capped at `cap` characters with an ellipsis."""
    s = ANSI.sub("", text)
    s = "".join(
        " " if c.isspace() or unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") else c for c in s
    )
    s = " ".join(s.split())
    return s if len(s) <= cap else s[: cap - 1].rstrip() + "…"


def slack_escape(text: str) -> str:
    """Slack text format: only these three characters need escaping."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def last_line(transcript) -> str:
    """Last non-empty line of the transcript end, cleaned; "" when there is none.
    agentbox's own `[agentbox: run killed: ...]` line is skipped."""
    try:
        with open(transcript, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - TAIL_BYTES))
            data = f.read()
    except (OSError, TypeError):
        return ""
    for raw in reversed(data.decode("utf-8", "replace").splitlines()):
        if KILL_MARK.fullmatch(raw.strip()):
            continue
        if line := clean_line(raw):
            return line
    return ""


def status_head(outcome: str, rc: int, seconds: float, timeout: str | None) -> str:
    """Status word and numbers. `outcome` is what the fire knows (schedule.fire):
    ok, failed (the run ended with a non-zero code of its own), timeout (the CLI
    killed it), terminated (a signal stopped the fire), start_failed (the runner
    raised), not_run (Docker down, preflight), skipped. The bare exit number
    decides nothing: a script may exit 124, 125 or 143 by itself."""
    dur = f"exit {rc}, {fmt_duration(seconds)}"
    if outcome == "ok":
        return f"ok ({dur})"
    if outcome == "timeout":
        return f"TIMEOUT{f' after {timeout}' if timeout else ''} (exit {rc})"
    if outcome == "terminated":
        return f"TERMINATED ({dur})"
    if outcome == "start_failed":
        return f"RUN FAILED ({dur})"
    if outcome == "not_run":
        return f"did not run ({dur})"
    if outcome == "skipped":
        return f"SKIPPED (exit {rc})"
    if outcome == "failed":
        return f"FAILED ({dur})"
    raise ValueError(f"unknown outcome {outcome!r}")


def build_message(
    profile: str,
    name: str,
    *,
    outcome: str,
    rc: int,
    seconds: float,
    timeout: str | None,
    transcript,
    note: str | None,
) -> str:
    """`agentbox <profile>/<job>: <status> (exit N, <time>) — <detail>`.
    detail: the last transcript line when a run happened (`transcript` is its
    path), else `note` (the fire's own message). A timeout needs no `note`:
    the status says it."""
    detail = last_line(transcript) if transcript else ""
    if not detail and note and outcome != "timeout":
        detail = clean_line(note)
    head = f"agentbox {profile}/{name}: {status_head(outcome, rc, seconds, timeout)}"
    return f"{head} — {slack_escape(detail)}" if detail else head


# ---------------------------------------------------------------- webhook
def webhook_problem(url: str) -> str | None:
    """Why `url` is not a usable webhook URL, or None. Never repeats the URL."""
    if not url or any(not 0x20 < ord(c) < 0x7F for c in url):
        return "the webhook URL is empty or has spaces, control or non-ASCII characters"
    try:
        u = urllib.parse.urlsplit(url)
        host, _ = u.hostname, u.port
    except ValueError:
        return "the webhook URL cannot be parsed"
    if u.scheme != "https":
        return "the webhook URL must start with https://"
    if not host:
        return "the webhook URL has no host"
    if u.username is not None or u.password is not None:
        return "the webhook URL must not contain a user name or password"
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follow no redirect. urllib would turn a 301/302/303 POST into a body-less
    GET that looks like a success; returning None makes it an HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post(url: str, text: str, timeout: float) -> None:
    """POST {"text": text} as JSON. https only. Raises NotifyError unless the
    answer is 2xx. The tests replace this function."""
    if msg := webhook_problem(url):
        raise NotifyError(msg)
    req = urllib.request.Request(
        url,
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as r:
            if not 200 <= r.status < 300:
                raise NotifyError(f"HTTP {r.status}")
    except urllib.error.HTTPError as e:
        raise NotifyError(f"HTTP {e.code}") from None  # e.reason or url: not echoed


def read_webhook(cfg, profile: str) -> str:
    name = cfg.notify_webhook_secret
    ref = secretstore.default_ref(cfg, "_shared", name)
    value = secretstore.fetcher(cfg, profile)(ref)
    if value is None:
        raise NotifyError(f"secret {name} is not stored; run `agentbox secret set --shared {name}`")
    return value.strip()


def reason(e: BaseException, url: str | None) -> str:
    """Short error text without the URL (or any piece of it) and without controls."""
    if isinstance(e, urllib.error.URLError):
        text = f"network error: {e.reason}"
    elif isinstance(e, NotifyError | secretstore.SecretError | paths.ConfigError):
        text = str(e)
    else:
        text = f"{type(e).__name__}: {e}"
    return clean_line(secretstore.scrub(text, url), REASON_CAP)


def wanted() -> bool:
    """False only when config.toml loads and notify_webhook_secret is unset.
    A config that does not load counts as wanted: notify_fire reports it."""
    try:
        return paths.load_config().notify_webhook_secret is not None
    except Exception:  # noqa: BLE001
        return True


def notify_fire(
    profile: str,
    name: str,
    *,
    outcome: str,
    rc: int,
    seconds: float,
    timeout: str | None,
    transcript,
    note: str | None,
) -> str | None:
    """Post the end-of-fire message. None: notifications are off (nothing done,
    no HTTP). Else "ok" or "error: <reason>". Never raises. The secret read and
    the request run in a daemon thread with a hard deadline, so a hung keychain
    prompt or DNS lookup cannot hold the fire (or its SIGTERM cleanup) open."""
    try:
        cfg = paths.load_config()
    except Exception as e:  # noqa: BLE001 - a notice must not fail the fire
        return f"error: {reason(e, None)}"
    if cfg.notify_webhook_secret is None:
        return None
    limit = TERMINATED_TIMEOUT if outcome == "terminated" else NOTIFY_TIMEOUT
    out: dict[str, BaseException] = {}

    def work() -> None:
        url = None
        try:
            text = build_message(profile, name, outcome=outcome, rc=rc, seconds=seconds,
                                 timeout=timeout, transcript=transcript, note=note)  # fmt: skip
            url = read_webhook(cfg, profile)
            post(url, text, limit)
        except BaseException as e:  # noqa: BLE001 - reported, never raised
            out["err"] = NotifyError(reason(e, url))

    t = threading.Thread(target=work, name="agentbox-notify", daemon=True)
    try:
        t.start()
        t.join(limit)
    except Exception as e:  # noqa: BLE001 - SIGTERM unwinds as Terminated
        return f"error: {reason(e, None)}"
    if t.is_alive():
        return f"error: no answer within {limit:.0f} s"
    return f"error: {out['err']}" if "err" in out else "ok"
