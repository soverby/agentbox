"""Tests for tools/deliver.py. Run:
uv run --with pytest --with fpdf2==2.8.8 pytest
"""
import importlib.util
import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "tests" / "fixtures" / "sample-brief.md"
TOKEN = "xoxb-test-SECRET-token-123"

spec = importlib.util.spec_from_file_location("deliver", ROOT / "tools" / "deliver.py")
deliver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deliver)


def page_count(pdf: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page(?!s)", pdf))


# ------------------------------------------------------------ rendering


def test_render_sample(tmp_path):
    out = tmp_path / "b.pdf"
    pages = deliver.render_pdf(SAMPLE.read_text(encoding="utf-8"), "2026-09-25", out)
    data = out.read_bytes()
    assert data.startswith(b"%PDF")
    assert pages >= 1 and page_count(data) == pages


def test_render_unicode(tmp_path):
    if deliver.find_dejavu() is None:
        pytest.skip("DejaVu font not installed on this host")
    out = tmp_path / "u.pdf"
    md = "# Überschrift — ☀\n\n- **Zürich** → Kraków, São Paulo, €, 東京\n"
    deliver.render_pdf(md, "2026-09-25", out)
    data = out.read_bytes()
    assert data.startswith(b"%PDF")
    assert b"DejaVu" in data  # embedded Unicode font


def test_render_fallback_without_dejavu(tmp_path, monkeypatch):
    monkeypatch.setattr(deliver, "find_dejavu", lambda: None)
    out = tmp_path / "f.pdf"
    deliver.render_pdf("# Zürich — “quotes” 東京\n\n- a **b** [c](https://x.y)\n", "d", out)
    assert out.read_bytes().startswith(b"%PDF")


def test_inline_segments():
    segs = deliver.inline_segments("a **b** [t](https://u.v/x)")
    assert segs == [("a ", False), ("b", True), (" t (https://u.v/x)", False)]


def test_dry_run_no_network(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SLACK_BOT_TOKEN", TOKEN)
    monkeypatch.setenv("SLACK_TARGET", "U123")
    monkeypatch.setattr(deliver.urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("network in dry run"))
    out = tmp_path / "d.pdf"
    assert deliver.main(["--dry-run", "--out", str(out), str(SAMPLE)]) == 0
    text = capsys.readouterr().out
    assert "conversations.open" in text and TOKEN not in text
    assert out.read_bytes().startswith(b"%PDF")


def test_usage_errors(tmp_path):
    assert deliver.main([str(tmp_path / "missing.md")]) == 2
    assert deliver.main(["--bogus"]) == 2


def test_no_secret_exit4(tmp_path, monkeypatch, capsys):
    for v in ("SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL", "SLACK_TARGET"):
        monkeypatch.delenv(v, raising=False)
    assert deliver.main(["--out", str(tmp_path / "n.pdf"), str(SAMPLE)]) == 4
    assert "SLACK_BOT_TOKEN" in capsys.readouterr().err


def test_render_error_exit3(tmp_path, monkeypatch):
    def boom(*a):
        raise RuntimeError("x")
    monkeypatch.setattr(deliver, "render_pdf", boom)
    assert deliver.main(["--dry-run", str(SAMPLE)]) == 3


# ------------------------------------------------------------ fake Slack


class FakeSlack:
    def __init__(self, fail=None, error="missing_scope"):
        self.error = error
        self.raw = None
        self.calls = []  # (path, auth header, params or byte length)
        self.fail = fail
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                path = self.path
                auth = self.headers.get("Authorization")
                if path.startswith("/services/"):
                    fake.calls.append(("webhook", auth, json.loads(body)))
                    ok = fake.fail != "webhook"
                    self.send_response(200 if ok else 404)
                    self.end_headers()
                    self.wfile.write(b"ok" if ok else b"no_service")
                    return
                if path.startswith("/upload/"):
                    fake.calls.append((path, auth, len(body)))
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK - 1")
                    return
                params = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode()).items()}
                method = path.rsplit("/", 1)[1]
                fake.calls.append((method, auth, params))
                if fake.raw is not None and fake.fail == method:
                    data = fake.raw
                    self.send_response(200)
                    if fake.raw == b"TRUNC":
                        self.send_header("Content-Length", "100")
                        self.end_headers()
                        self.wfile.write(b'{"ok": tr')
                        return
                    self.end_headers()
                    self.wfile.write(data)
                    return
                if fake.fail == method:
                    resp = {"ok": False, "error": fake.error}
                elif method == "chat.postMessage":
                    resp = {"ok": True, "ts": "1.2"}
                elif method == "conversations.open":
                    resp = {"ok": True, "channel": {"id": "D999"}}
                elif method == "files.getUploadURLExternal":
                    resp = {"ok": True, "file_id": "F123",
                            "upload_url": f"{fake.base}/upload/v1/abc"}
                elif method == "files.completeUploadExternal":
                    resp = {"ok": True, "files": [{"id": "F123"}]}
                else:
                    resp = {"ok": False, "error": "unknown_method"}
                data = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def methods(self):
        return [c[0] if not c[0].startswith("/upload/") else "upload" for c in self.calls]


@pytest.fixture
def slack(monkeypatch):
    servers = []

    def make(target="C0123456789", fail=None, token=TOKEN, webhook=None):
        s = FakeSlack(fail)
        servers.append(s)
        for v in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                  "SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL", "SLACK_TARGET"):
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setenv("SLACK_API_BASE", s.base + "/api")
        monkeypatch.setenv("SLACK_HOOKS_BASE", s.base)
        if token:
            monkeypatch.setenv("SLACK_BOT_TOKEN", token)
        if webhook:
            monkeypatch.setenv("SLACK_WEBHOOK_URL", webhook.replace("BASE", s.base))
        if target:
            monkeypatch.setenv("SLACK_TARGET", target)
        return s

    yield make
    for s in servers:
        s.srv.shutdown()


def run(tmp_path):
    return deliver.main(["--out", str(tmp_path / "s.pdf"), str(SAMPLE)])


def test_user_target_opens_dm(slack, tmp_path, capsys):
    s = slack("U0123ABC")
    assert run(tmp_path) == 0
    assert s.methods() == ["conversations.open", "files.getUploadURLExternal",
                           "upload", "files.completeUploadExternal"]
    assert s.calls[0][2] == {"users": "U0123ABC"}
    get = s.calls[1][2]
    size = (tmp_path / "s.pdf").stat().st_size
    assert get["filename"] == "s.pdf" and get["length"] == str(size)
    assert s.calls[2][2] == size and s.calls[2][1] is None  # no token to upload URL
    done = s.calls[3][2]
    assert done["channel_id"] == "D999"
    assert json.loads(done["files"])[0]["id"] == "F123"
    assert done["initial_comment"]
    assert all(c[1] == f"Bearer {TOKEN}" for c in s.calls if not c[0].startswith("/upload/"))
    out = capsys.readouterr()
    assert TOKEN not in out.out + out.err


def test_channel_target_skips_open(slack, tmp_path):
    s = slack("C0456DEF")
    assert run(tmp_path) == 0
    assert s.methods() == ["files.getUploadURLExternal", "upload",
                           "files.completeUploadExternal"]
    assert s.calls[2][2]["channel_id"] == "C0456DEF"


@pytest.mark.parametrize("method", ["conversations.open", "files.getUploadURLExternal",
                                    "files.completeUploadExternal"])
def test_slack_error_exit4(slack, tmp_path, capsys, method):
    slack("U0123ABC", fail=method)
    assert run(tmp_path) == 4
    out = capsys.readouterr()
    assert f"{method}: missing_scope" in out.err
    assert TOKEN not in out.out + out.err


def test_bad_target_exit4(slack, tmp_path, capsys):
    slack("#general")
    assert run(tmp_path) == 4
    assert "SLACK_TARGET" in capsys.readouterr().err


def test_pdf_mode_requires_target(slack, tmp_path, capsys):
    s = slack(None)
    assert run(tmp_path) == 2
    assert "SLACK_TARGET is required" in capsys.readouterr().err
    assert s.calls == []


def test_channel_target_used(slack, tmp_path):
    s = slack("C0123456789")
    assert run(tmp_path) == 0
    assert s.methods()[0] == "files.getUploadURLExternal"
    assert s.calls[2][2]["channel_id"] == "C0123456789"


def test_not_in_channel_hint(slack, tmp_path, capsys):
    s = slack(fail="files.completeUploadExternal")
    s.error = "not_in_channel"
    assert run(tmp_path) == 4
    err = capsys.readouterr().err
    assert "not_in_channel" in err and "/invite" in err


def test_token_wins_over_webhook(slack, tmp_path):
    s = slack(webhook="BASE/services/T0/B0/xyz")
    assert run(tmp_path) == 0
    assert "webhook" not in s.methods()


HOOK_SECRET = "T000/B000/HOOKsecretXYZ"


def test_webhook_mode_payload(slack, tmp_path, capsys):
    s = slack(token=None, webhook=f"BASE/services/{HOOK_SECRET}")
    assert run(tmp_path) == 0
    assert s.methods() == ["webhook"]
    payload = s.calls[0][2]
    assert set(payload) == {"text"}
    text = payload["text"]
    assert text.startswith("*Daily News Brief — 2026-09-25*\n")
    assert "• Summit ends with a draft climate deal — <https://example.com/world/summit-deal|Example Wire>" in text
    assert text.count("\n• ") == 4
    assert "PDF saved in the box" in text and "s.pdf" in text
    assert len(text) <= deliver.WEBHOOK_MAX
    assert (tmp_path / "s.pdf").read_bytes().startswith(b"%PDF")
    out = capsys.readouterr()
    assert HOOK_SECRET not in out.out + out.err


def test_webhook_truncation():
    md = "# Brief 2026-09-25\n\n" + "".join(
        f"### Story {i} " + "x" * 200 + f"\n- **Source:** [Out](https://e.com/{i})\n"
        for i in range(40))
    text = deliver.webhook_text(md, "2026-09-25", "reports/2026-09-25.pdf")
    assert len(text) <= deliver.WEBHOOK_MAX
    assert "more stories in the PDF (message truncated)" in text
    assert text.rstrip().endswith("reports/2026-09-25.pdf_")


def test_webhook_escapes_mrkdwn():
    text = deliver.webhook_text("# A & B <x>\n### C > D\n", "2026-09-25", "p.pdf")
    assert "A &amp; B &lt;x&gt;" in text and "C &gt; D" in text


@pytest.mark.parametrize("url", ["http://hooks.slack.com/services/T/B/x",
                                 "https://evil.example/services/T/B/x",
                                 "https://hooks.slack.com.evil.io/services/T/B/x",
                                 "https://hooks.slack.com/workflows/T/B/x"])
def test_webhook_url_validation(slack, tmp_path, capsys, monkeypatch, url):
    s = slack(token=None, webhook="BASE/services/T/B/placeholder")
    monkeypatch.delenv("SLACK_HOOKS_BASE")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", url)
    assert run(tmp_path) == 4
    out = capsys.readouterr()
    assert "hooks.slack.com/services" in out.err and url not in out.out + out.err
    assert s.calls == []


def test_webhook_production_url_accepted(monkeypatch):
    monkeypatch.delenv("SLACK_HOOKS_BASE", raising=False)
    assert deliver.valid_webhook("https://hooks.slack.com/services/T0/B0/abc")


def test_webhook_error_exit4(slack, tmp_path, capsys):
    slack(token=None, webhook=f"BASE/services/{HOOK_SECRET}", fail="webhook")
    assert run(tmp_path) == 4
    out = capsys.readouterr()
    assert "webhook: HTTP 404 no_service" in out.err
    assert HOOK_SECRET not in out.out + out.err


# ------------------------------------------------------------ round 2


REPORTS = ROOT / "reports"


@pytest.fixture
def report_file():
    made = []

    def make(name, data: bytes):
        p = REPORTS / name
        p.write_bytes(data)
        made.append(p)
        return p

    yield make
    for p in made:
        p.unlink(missing_ok=True)
        p.with_suffix(".pdf").unlink(missing_ok=True)


@pytest.mark.parametrize("path", ["/etc/passwd", "/proc/self/environ",
                                  "reports/../README.md", "tests/fixtures/../../README.md",
                                  "tools/deliver.py"])
def test_brief_path_rejected(path, capsys, monkeypatch):
    monkeypatch.chdir(ROOT)
    assert deliver.main(["--dry-run", path]) == 2
    err = capsys.readouterr().err
    assert ".md" in err or "under reports/" in err


def test_brief_symlink_escape_rejected(report_file, capsys, tmp_path):
    outside = tmp_path / "secret.md"
    outside.write_text("# x\n")
    link = REPORTS / "2026-01-01-link.md"
    link.symlink_to(outside)
    try:
        assert deliver.main(["--dry-run", str(link)]) == 2
    finally:
        link.unlink()
    assert "under reports/" in capsys.readouterr().err


def test_brief_in_reports_ok(report_file, tmp_path):
    p = report_file("2026-01-02.md", SAMPLE.read_bytes())
    assert deliver.main(["--dry-run", "--out", str(tmp_path / "r.pdf"), str(p)]) == 0


def test_non_utf8_brief_exit2(report_file, capsys):
    p = report_file("2026-01-03.md", b"# Brief\n\xff\xfe bad\n")
    assert deliver.main(["--dry-run", str(p)]) == 2
    assert "UTF-8" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL", "SLACK_TARGET"])
@pytest.mark.parametrize("bad", ["xoxb-a b", "xoxb-a\nb", "xoxb-a\x07b", "xoxb-a\tb"])
def test_secret_bad_chars_exit2(slack, tmp_path, capsys, monkeypatch, name, bad):
    s = slack()
    monkeypatch.setenv(name, bad)
    assert run(tmp_path) == 2
    out = capsys.readouterr()
    assert name in out.err and bad.strip() not in out.out + out.err
    assert s.calls == []


def test_failure_notice_webhook(slack, capsys):
    s = slack(token=None, webhook=f"BASE/services/{HOOK_SECRET}")
    reason = "Perigon tools are not available <script>\n\x1b[31m" + "y" * 1000
    assert deliver.main(["--failure", reason]) == 0
    assert s.methods() == ["webhook"]
    text = s.calls[0][2]["text"]
    assert "Daily news brief FAILED" in text and "&lt;script&gt;" in text
    assert "\x1b" not in text and "\n" not in text
    assert len(text) < deliver.FAILURE_MAX + 100
    out = capsys.readouterr()
    assert HOOK_SECRET not in out.out + out.err


def test_failure_notice_bot_redacts(slack, capsys):
    s = slack("U0123ABC")
    assert deliver.main(["--failure", f"boom {TOKEN} end"]) == 0
    assert s.methods() == ["conversations.open", "chat.postMessage"]
    msg = s.calls[1][2]
    assert msg["channel"] == "D999"
    assert TOKEN not in msg["text"] and "[redacted]" in msg["text"]
    out = capsys.readouterr()
    assert TOKEN not in out.out + out.err


def test_failure_notice_channel_and_error(slack, capsys):
    s = slack("C0123456789", fail="chat.postMessage")
    assert deliver.main(["--failure", "x"]) == 4
    assert s.calls[0][2]["channel"] == "C0123456789"
    assert "chat.postMessage: missing_scope" in capsys.readouterr().err


def test_failure_and_brief_exclusive(tmp_path):
    assert deliver.main(["--failure", "x", str(SAMPLE)]) == 2
    assert deliver.main([]) == 2


def test_failure_dry_run_no_network(monkeypatch, capsys):
    monkeypatch.setattr(deliver.urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("network in dry run"))
    assert deliver.main(["--dry-run", "--failure", "no stories"]) == 0
    assert "no stories" in capsys.readouterr().out


@pytest.mark.parametrize("raw,msg", [(b"[1, 2]", "not a JSON object"),
                                     (b'{"ok": true}', "no 'upload_url'"),
                                     (b"not json", "not JSON"),
                                     (b"TRUNC", "IncompleteRead")])
def test_bad_slack_responses_exit4(slack, tmp_path, capsys, raw, msg):
    s = slack("C1", fail="files.getUploadURLExternal")
    s.raw = raw
    assert run(tmp_path) == 4
    out = capsys.readouterr()
    assert msg in out.err and "Traceback" not in out.err and TOKEN not in out.out + out.err


def test_open_missing_channel_exit4(slack, tmp_path, capsys):
    s = slack("U1", fail="conversations.open")
    s.raw = b'{"ok": true, "channel": "D1"}'
    assert run(tmp_path) == 4
    assert "no channel id" in capsys.readouterr().err


def test_unexpected_exception_exit4(slack, tmp_path, capsys, monkeypatch):
    slack("C1")
    def boom(*a):
        raise KeyError(TOKEN)
    monkeypatch.setattr(deliver, "upload", boom)
    assert run(tmp_path) == 4
    out = capsys.readouterr()
    assert "unexpected KeyError" in out.err and TOKEN not in out.out + out.err
