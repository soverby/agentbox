"""Scheduled-run notifications: message building, webhook post, config key,
delivery guard, failure isolation (PLAN §2.7). No real network: `notify.post`
or the urllib opener is replaced."""

import json
import re
import time
import urllib.error
import urllib.request

import pytest
from agentbox import delivery, notify, paths, secretstore
from agentbox.profile import parse_profile

URL = "https://hooks.slack.com/services/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4"


# ---------------------------------------------------------------- message pieces
def test_fmt_duration():
    assert [notify.fmt_duration(x) for x in (0, 12.9, 59, 60, 305, 3599, 3600, 3725, 90000)] == [
        "0s", "12s", "59s", "1m00s", "5m05s", "59m59s", "1h00m", "1h02m", "25h00m",
    ]  # fmt: skip
    assert notify.fmt_duration(-5) == "0s"


def test_clean_line_strips_controls_and_collapses():
    raw = "a\x00b\x1b[31mred\x1b[0m\t c\x1b]0;title\x07 d\u202eevil\u200b\x9b e\r\n f"
    out = notify.clean_line(raw)
    assert out == "a bred c d evil e f"
    assert "title" not in out and "  " not in out
    assert all(c == " " or c.isprintable() for c in out)


def test_clean_line_cap_and_ellipsis():
    assert notify.clean_line("x" * 300) == "x" * 300
    out = notify.clean_line("x" * 301)
    assert len(out) == 300 and out.endswith("…") and out[:-1] == "x" * 299
    assert notify.clean_line("word " * 200).endswith("…")


def test_slack_escape():
    s = "<!channel> <@U123> <http://evil.example|click> a&b"
    assert notify.slack_escape(s) == (
        "&lt;!channel&gt; &lt;@U123&gt; &lt;http://evil.example|click&gt; a&amp;b"
    )


def test_cap_applies_before_escape():
    """An entity is never cut in half: "<" x 400 is capped first, then escaped."""
    out = notify.slack_escape(notify.clean_line("<" * 400))
    assert out.count("&lt;") == 299 and out.endswith("…") and "&l…" not in out


def write_tr(tmp_path, text):
    f = tmp_path / "transcript.log"
    f.write_bytes(text if isinstance(text, bytes) else text.encode())
    return f


def test_last_line_skips_blank_and_kill_marker(tmp_path):
    f = write_tr(
        tmp_path, "first\n== check: ok\n\n  \n[agentbox: run killed: timeout after 60 s]\n\n"
    )
    assert notify.last_line(f) == "== check: ok"
    assert notify.last_line(write_tr(tmp_path, "")) == ""
    assert notify.last_line(write_tr(tmp_path, "\n \n")) == ""
    assert notify.last_line(write_tr(tmp_path, "[agentbox: run killed: x]\n")) == ""
    assert notify.last_line(tmp_path / "nope.log") == ""
    assert notify.last_line(None) == ""


def test_last_line_only_reads_the_tail_and_survives_bad_utf8(tmp_path):
    big = b"old line\n" * 100_000 + b"final \xff\xfe line\n"
    assert notify.last_line(write_tr(tmp_path, big)) == "final �� line"
    # a progress bar: the last carriage-return segment is the state at the end
    assert notify.last_line(write_tr(tmp_path, "10%\r50%\r100% done\n")) == "100% done"


def msg(**kw):
    a = dict(outcome="ok", rc=0, seconds=12, timeout="1h", transcript=None, note=None)
    a.update(kw)
    return notify.build_message("fx", "eurusd", **a)


def test_build_message_each_outcome(tmp_path):
    tr = write_tr(tmp_path, "x\n== check: ECB date 2026-10-05, series end_date 2026-10-05\n")
    assert msg(transcript=tr) == (
        "agentbox fx/eurusd: ok (exit 0, 12s) — "
        "== check: ECB date 2026-10-05, series end_date 2026-10-05"
    )
    assert msg(outcome="failed", rc=3, transcript=tr).startswith(
        "agentbox fx/eurusd: FAILED (exit 3, 12s) — "
    )
    assert msg(outcome="timeout", rc=124, seconds=3600, transcript=tr).startswith(
        "agentbox fx/eurusd: TIMEOUT after 1h (exit 124) — "
    )
    assert msg(outcome="timeout", rc=124, timeout=None) == "agentbox fx/eurusd: TIMEOUT (exit 124)"
    assert msg(outcome="terminated", rc=143, seconds=5, note="terminated by signal 15") == (
        "agentbox fx/eurusd: TERMINATED (exit 143, 5s) — terminated by signal 15"
    )
    assert msg(outcome="start_failed", rc=125, note="run failed: box start failed") == (
        "agentbox fx/eurusd: RUN FAILED (exit 125, 12s) — run failed: box start failed"
    )
    assert msg(outcome="not_run", rc=69, note="Docker did not come up within 120 s") == (
        "agentbox fx/eurusd: did not run (exit 69, 12s) — Docker did not come up within 120 s"
    )
    assert msg(outcome="not_run", rc=78, note="CLAUDE_CODE_OAUTH_TOKEN is missing").startswith(
        "agentbox fx/eurusd: did not run (exit 78, 12s) — CLAUDE"
    )
    assert msg(outcome="skipped", rc=75, seconds=0, note="another run is active") == (
        "agentbox fx/eurusd: SKIPPED (exit 75) — another run is active"
    )
    with pytest.raises(ValueError):
        msg(outcome="weird")


def test_exit_numbers_alone_decide_nothing(tmp_path):
    """A script that exits 124, 125, 143, 69, 75, or 78 by itself is FAILED."""
    tr = write_tr(tmp_path, "script said no\n")
    for rc in (69, 75, 78, 124, 125, 143):
        assert msg(outcome="failed", rc=rc, transcript=tr) == (
            f"agentbox fx/eurusd: FAILED (exit {rc}, 12s) — script said no"
        )


def test_empty_transcript_and_fallback_to_note(tmp_path):
    empty = write_tr(tmp_path, "")
    assert msg(transcript=empty) == "agentbox fx/eurusd: ok (exit 0, 12s)"
    assert msg(outcome="failed", rc=2, transcript=empty, note="run failed: x").endswith(
        "FAILED (exit 2, 12s) — run failed: x"
    )
    assert msg(transcript=tmp_path / "gone.log") == "agentbox fx/eurusd: ok (exit 0, 12s)"
    # a timeout says it in the status word: the note is not repeated
    assert msg(
        outcome="timeout", rc=124, transcript=empty, note="killed after the timeout (1h)"
    ).endswith("(exit 124)")


def test_kill_marker_is_skipped_but_status_shows_the_kill(tmp_path):
    tr = write_tr(tmp_path, "step 4 of 9\n[agentbox: run killed: timeout after 3600 s]\n")
    out = msg(outcome="timeout", rc=124, seconds=3600, transcript=tr)
    assert out == "agentbox fx/eurusd: TIMEOUT after 1h (exit 124) — step 4 of 9"
    assert "killed" not in out


def test_box_text_cannot_inject_slack_markup(tmp_path):
    evil = "<!channel> <@U1> <http://evil.example|trusted> & \x1b[2J\x07done"
    out = msg(transcript=write_tr(tmp_path, evil + "\n"))
    assert "<" not in out and ">" not in out
    assert out.endswith(
        "&lt;!channel&gt; &lt;@U1&gt; &lt;http://evil.example|trusted&gt; &amp; done"
    )
    # only the last line is used
    out = msg(transcript=write_tr(tmp_path, "SECRET=abc\nline two\n"))
    assert "SECRET" not in out and out.endswith("— line two")


def test_message_detail_is_capped(tmp_path):
    out = msg(transcript=write_tr(tmp_path, "y" * 5000 + "\n"))
    detail = out.split(" — ", 1)[1]
    assert len(detail) == 300 and detail.endswith("…")


# ---------------------------------------------------------------- webhook URL + post
@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.slack.com/services/x",
        "ftp://hooks.slack.com/x",
        "file:///etc/passwd",
        "hooks.slack.com/services/x",
        "https:///nohost",
        "https://user:pw@hooks.slack.com/x",
        "https://hooks.slack.com/x y",
        "https://hooks.slack.com/x\n",
        "https://hooks.slack.com:notaport/x",
        "https://hooks.slack.com/é",
        "",
    ],
)
def test_webhook_problem_refuses(url):
    msg = notify.webhook_problem(url)
    assert msg and (not url or url not in msg)
    with pytest.raises(notify.NotifyError):
        notify.post(url, "t", 1)


def test_webhook_problem_accepts_https():
    assert notify.webhook_problem(URL) is None
    assert notify.webhook_problem("https://example.com:8443/hook?a=b") is None


class FakeResp:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def open(self, req, timeout=None):
        self.calls.append((req, timeout))
        if isinstance(self.result, BaseException):
            raise self.result
        return FakeResp(self.result)


def with_opener(monkeypatch, result):
    op = FakeOpener(result)
    monkeypatch.setattr(urllib.request, "build_opener", lambda *h: op)
    return op


def test_post_sends_json_over_https(monkeypatch):
    op = with_opener(monkeypatch, 200)
    notify.post(URL, "agentbox p/j: ok — é <x>", 10)
    ((req, timeout),) = op.calls
    assert req.full_url == URL and req.get_method() == "POST" and timeout == 10
    assert req.get_header("Content-type") == "application/json"
    assert json.loads(req.data) == {"text": "agentbox p/j: ok — é <x>"}


def test_post_non_2xx_and_http_errors_are_notify_errors_without_the_url(monkeypatch):
    with_opener(monkeypatch, 302)
    with pytest.raises(notify.NotifyError, match="HTTP 302"):
        notify.post(URL, "t", 1)
    err = urllib.error.HTTPError(URL, 500, "Server Error " + URL, None, None)
    with_opener(monkeypatch, err)
    with pytest.raises(notify.NotifyError) as ei:
        notify.post(URL, "t", 1)
    assert str(ei.value) == "HTTP 500"


def test_post_refuses_non_https_before_any_request(monkeypatch):
    op = with_opener(monkeypatch, 200)
    with pytest.raises(notify.NotifyError, match="https://"):
        notify.post("http://hooks.slack.com/services/x", "t", 1)
    assert op.calls == []


def test_no_redirect_is_followed():
    h = notify._NoRedirect()
    req = urllib.request.Request(URL, data=b"{}", method="POST")
    for code in (301, 302, 303, 307, 308):
        for new in ("https://hooks.slack.com/other", "http://evil.example/x"):
            assert h.redirect_request(req, None, code, "Moved", {}, new) is None


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_redirect_is_an_error_not_a_bodyless_get(monkeypatch, code):
    """Real urllib against a loopback server (the https check is lifted for it)."""
    import http.server
    import threading

    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            seen.append(("POST", self.path))
            self.send_response(code)
            self.send_header("Location", "https://hooks.slack.com/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            seen.append(("GET", self.path))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(notify, "webhook_problem", lambda url: None)
    try:
        with pytest.raises(notify.NotifyError) as ei:
            notify.post(f"http://127.0.0.1:{srv.server_port}/hook", "t", 5)
    finally:
        srv.shutdown()
        srv.server_close()
    assert str(ei.value) == f"HTTP {code}" and seen == [("POST", "/hook")]


def test_reason_scrubs_the_url_and_controls():
    e = urllib.error.URLError(f"cannot reach {URL}\x1b[31m!")
    out = notify.reason(e, URL)
    assert "xyzSECRET" not in out and "services/T0AAAAAAA" not in out and "\x1b" not in out
    assert notify.reason(RuntimeError("x" * 500), None).endswith("…")


# ---------------------------------------------------------------- notify_fire
@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv(secretstore.ENV_STORE, str(tmp_path / "store.json"))
    (tmp_path / "cfg").mkdir()
    return tmp_path


def configure(host, store=None, key='notify_webhook_secret = "SLACK_WEBHOOK_URL"\n'):
    (host / "cfg" / "config.toml").write_text(f'secret_backend = "env"\n{key}')
    (host / "store.json").write_text(
        json.dumps({"AGENTBOX__SHARED_SLACK_WEBHOOK_URL": URL} if store is None else store)
    )


def fire_notice(**kw):
    a = dict(outcome="not_run", rc=0, seconds=3, timeout="2h", transcript=None, note="n")
    a.update(kw)
    return notify.notify_fire("p1", "daily", **a)


def forbid(*a, **k):
    raise AssertionError("must not be called")


def test_unset_makes_no_call_and_reads_no_secret(host, monkeypatch):
    monkeypatch.setattr(notify, "post", forbid)
    monkeypatch.setattr(notify, "read_webhook", forbid)
    monkeypatch.setattr(urllib.request, "build_opener", forbid)
    assert fire_notice() is None  # no config.toml
    (host / "cfg" / "config.toml").write_text('secret_backend = "env"\n')
    assert fire_notice() is None


def test_set_posts_once_with_the_stored_url(host, monkeypatch):
    configure(host)
    calls = []
    monkeypatch.setattr(
        notify, "post", lambda url, text, timeout: calls.append((url, text, timeout))
    )
    assert fire_notice(outcome="skipped", rc=75, note="other run active") == "ok"
    assert calls == [(URL, "agentbox p1/daily: SKIPPED (exit 75) — other run active", 10.0)]


@pytest.mark.parametrize(
    "boom",
    [
        notify.NotifyError("HTTP 500"),
        OSError(f"connection reset while posting {URL}"),
        urllib.error.URLError(f"timed out {URL}"),
        RuntimeError(URL),
    ],
)
def test_post_failure_is_returned_not_raised(host, monkeypatch, boom):
    configure(host)

    def bad(url, text, timeout):
        raise boom

    monkeypatch.setattr(notify, "post", bad)
    out = fire_notice()
    assert out.startswith("error: ") and "xyzSECRET" not in out and URL not in out


def test_missing_secret_is_reported(host, monkeypatch):
    configure(host, store={})
    monkeypatch.setattr(notify, "post", forbid)
    out = fire_notice()
    want = "secret SLACK_WEBHOOK_URL is not stored; run `agentbox secret set --shared "
    assert out == f"error: {want}SLACK_WEBHOOK_URL`"


def test_backend_error_is_reported(host, monkeypatch):
    configure(host)
    monkeypatch.setattr(notify, "post", forbid)

    def locked(cfg, profile):
        raise secretstore.SecretError("keychain read of x failed: User interaction is not allowed.")

    monkeypatch.setattr(notify, "read_webhook", locked)
    assert fire_notice() == "error: keychain read of x failed: User interaction is not allowed."


def test_stored_value_that_is_not_https_is_refused(host, monkeypatch):
    configure(
        host, store={"AGENTBOX__SHARED_SLACK_WEBHOOK_URL": "http://hooks.slack.com/x/SECRETTAIL"}
    )
    op = with_opener(monkeypatch, 200)
    out = fire_notice()
    assert out == "error: the webhook URL must start with https://" and op.calls == []


def test_broken_config_is_reported_not_raised(host, monkeypatch):
    (host / "cfg" / "config.toml").write_text("bogus = 1\n")
    monkeypatch.setattr(notify, "post", forbid)
    assert fire_notice().startswith("error: ") and "bogus" in fire_notice()


def test_hung_post_hits_the_deadline(host, monkeypatch):
    configure(host)
    monkeypatch.setattr(notify, "NOTIFY_TIMEOUT", 0.2)
    monkeypatch.setattr(notify, "post", lambda *a: time.sleep(5))
    t0 = time.monotonic()
    assert fire_notice() == "error: no answer within 0 s"
    assert time.monotonic() - t0 < 2


def test_terminated_uses_the_short_deadline(host, monkeypatch):
    configure(host)
    monkeypatch.setattr(notify, "NOTIFY_TIMEOUT", 30)
    monkeypatch.setattr(notify, "TERMINATED_TIMEOUT", 0.2)
    monkeypatch.setattr(notify, "post", lambda *a: time.sleep(5))
    t0 = time.monotonic()
    assert fire_notice(outcome="terminated", rc=143).startswith("error: no answer")
    assert time.monotonic() - t0 < 2


def test_hung_secret_read_hits_the_deadline(host, monkeypatch):
    configure(host)
    monkeypatch.setattr(notify, "NOTIFY_TIMEOUT", 0.2)
    monkeypatch.setattr(notify, "read_webhook", lambda cfg, profile: time.sleep(5))
    assert fire_notice().startswith("error: no answer")


# ---------------------------------------------------------------- config + delivery
def test_config_key(host):
    cfg = host / "cfg" / "config.toml"
    assert paths.load_config().notify_webhook_secret is None
    cfg.write_text('notify_webhook_secret = "SLACK_WEBHOOK_URL"\n')
    assert paths.load_config().notify_webhook_secret == "SLACK_WEBHOOK_URL"
    for bad, match in (
        ('notify_webhook_secret = ""\n', "invalid secret name"),
        ('notify_webhook_secret = "1BAD"\n', "invalid secret name"),
        ('notify_webhook_secret = "has space"\n', "invalid secret name"),
        ('notify_webhook_secret = "AGENTBOX_X"\n', "reserved"),
        ('notify_webhook_secret = "https_proxy"\n', "reserved"),
        ('notify_webhook_secret = "CLAUDE_CODE_OAUTH_TOKEN"\n', "agentbox owns it"),
        ('notify_webhook_secret = "MCP_GATEWAY_TOKEN"\n', "reserved"),
        ('notify_webhook_secret = "AGENTBOX_ROUTER_MASTER_KEY"\n', "reserved"),
        ('notify_webhook_secret = "_OP_SERVICE_ACCOUNT_TOKEN"\n', "reserved"),
        ('notify_webhook_secret = "_MCP_OAUTH_DOCS"\n', "reserved"),
        ("notify_webhook_secret = 1\n", "must be a string"),
        ("notify_webhook_secret = true\n", "must be a string"),
    ):
        cfg.write_text(bad)
        with pytest.raises(paths.ConfigError, match=match):
            paths.load_config()


def test_write_config_keeps_the_key(host):
    paths.write_config({"secret_backend": "env", "notify_webhook_secret": "SLACK_WEBHOOK_URL"})
    assert paths.read_config_values()["notify_webhook_secret"] == "SLACK_WEBHOOK_URL"


def prof(secrets):
    return parse_profile(
        {"box": {"agents": ["claude"]}, "mount": [{"host": "/w/p"}], "secrets": secrets}, "p1"
    )


KC = paths.Config(secret_backend="keychain", notify_webhook_secret="SLACK_WEBHOOK_URL")
ENV = paths.Config(secret_backend="env", notify_webhook_secret="SLACK_WEBHOOK_URL")
OP = paths.Config(secret_backend="op", op_vault="v", notify_webhook_secret="SLACK_WEBHOOK_URL")


@pytest.mark.parametrize(
    "cfg,secrets",
    [
        (KC, {"SLACK_WEBHOOK_URL": "shared"}),
        (KC, {"SLACK_WEBHOOK_URL": {"shared": True, "to": ["agent", "router"]}}),
        (KC, {"HOOK": {"ref": "keychain:agentbox/_shared/SLACK_WEBHOOK_URL"}}),
        (KC, {"HOOK": {"ref": "keychain:agentbox/_shared/SLACK_WEBHOOK_URL", "to": "router"}}),
        (ENV, {"SLACK_WEBHOOK_URL": "shared"}),
        (ENV, {"HOOK": {"ref": "env:AGENTBOX__SHARED_SLACK_WEBHOOK_URL"}}),
        (OP, {"SLACK_WEBHOOK_URL": "shared"}),
        (OP, {"HOOK": {"ref": "op://v/agentbox-_shared/SLACK_WEBHOOK_URL"}}),
        (OP, {"HOOK": {"ref": "op://V/AGENTBOX-_shared/slack_webhook_url"}}),
    ],
)
def test_profile_cannot_deliver_the_webhook_secret(cfg, secrets):
    """Any secret whose resolved ref is the webhook's store item is refused,
    whatever its name, scope, or target. The error names the fix."""
    with pytest.raises(secretstore.SecretError) as ei:
        delivery.collect(prof(secrets), cfg, None, fetch=lambda r: "v")
    msg = str(ei.value)
    assert "notification webhook" in msg and "profile-scope" in msg and "another name" in msg


def test_webhook_guard_allows_other_items_and_the_unset_case():
    ok = [
        (KC, {"SLACK_WEBHOOK_URL": {}}),  # profile scope: item agentbox/p1/SLACK_WEBHOOK_URL
        (KC, {"HOOK": {"ref": "keychain:agentbox/_shared/OTHER"}}),
        (KC, {"HOOK": {"ref": "keychain:agentbox/p1/SLACK_WEBHOOK_URL"}}),
        (KC, {"HOOK": {"ref": "env:AGENTBOX__SHARED_SLACK_WEBHOOK_URL"}}),  # another store
        (KC, {"OTHER": "shared"}),
        (ENV, {"HOOK": {"ref": "keychain:agentbox/_shared/SLACK_WEBHOOK_URL"}}),
        (OP, {"HOOK": {"ref": "op://v/agentbox-p1/SLACK_WEBHOOK_URL"}}),
        (paths.Config(secret_backend="keychain"), {"SLACK_WEBHOOK_URL": "shared"}),  # unset
        (paths.Config(notify_webhook_secret="OTHER_NAME"), {"SLACK_WEBHOOK_URL": "shared"}),
    ]
    for cfg, secrets in ok:
        d = delivery.collect(prof(secrets), cfg, None, fetch=lambda r: "v")
        assert set(d.values) == set(prof(secrets).secrets), (cfg, secrets)


def test_webhook_guard_covers_every_service_filter():
    """Refused even when the secret targets a service that is not being read."""
    p = prof({"HOOK": {"ref": "env:AGENTBOX__SHARED_SLACK_WEBHOOK_URL", "to": "router"}})
    with pytest.raises(secretstore.SecretError):
        delivery.collect(p, ENV, None, {"agent"}, fetch=lambda r: "v")


# ---------------------------------------------------------------- cap order, bounded read
@pytest.mark.parametrize("n", range(270, 305))
def test_cap_is_applied_before_escaping_at_every_alignment(tmp_path, n):
    """`&`, `<`, `>` at the cut: an entity is never split, and the raw text is
    at most 300 characters (so an escape-first order would fail here)."""
    line = "a" * n + "&<>" * 12
    out = msg(transcript=write_tr(tmp_path, line + "\n"))
    detail = out.split(" — ", 1)[1]
    assert not re.search(r"&(?!(amp|lt|gt);)", detail)
    raw = detail.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    assert len(raw) == 300 and raw.endswith("…")
    assert raw[:-1] == line[:299].rstrip()


def test_transcript_read_is_a_bounded_tail(tmp_path, monkeypatch):
    f = tmp_path / "transcript.log"
    f.write_bytes(b"old line\n" * 600_000 + b"the end\n")  # 5.4 MB
    assert f.stat().st_size > 50 * notify.TAIL_BYTES
    read = []
    real_open = open

    class Counting:
        def __init__(self, fh):
            self.fh = fh

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.fh.close()

        def seek(self, *a):
            return self.fh.seek(*a)

        def tell(self):
            return self.fh.tell()

        def read(self, *a):
            data = self.fh.read(*a)
            read.append(len(data))
            return data

    monkeypatch.setattr(notify, "open", lambda *a, **k: Counting(real_open(*a, **k)), raising=False)
    assert notify.last_line(f) == "the end"
    assert read and sum(read) <= notify.TAIL_BYTES
