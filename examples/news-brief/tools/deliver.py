# /// script
# requires-python = ">=3.10"
# dependencies = ["fpdf2==2.8.8"]
# ///
"""Render a Markdown news brief to PDF and upload it to Slack.

Usage: uv run tools/deliver.py [--dry-run] [--out PDF] BRIEF.md

Two modes, chosen by the secrets present (neither is ever printed):
  PDF mode      SLACK_BOT_TOKEN set: upload the PDF (files.getUploadURLExternal
                -> POST bytes -> files.completeUploadExternal).
  Webhook mode  only SLACK_WEBHOOK_URL set: render the PDF to disk and POST a
                mrkdwn text summary to the incoming webhook.
SLACK_TARGET: channel ID (C/G/D...) or user ID (U/W... -> DM). Required in
PDF mode; a webhook always posts to its own channel.
SLACK_API_BASE and SLACK_HOOKS_BASE are for tests only.

Exit codes: 0 ok, 2 usage, 3 render error, 4 Slack error.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

EXIT_OK, EXIT_USAGE, EXIT_RENDER, EXIT_SLACK = 0, 2, 3, 4

FONT_DIRS = [
    Path("/usr/share/fonts/truetype/dejavu"),  # Ubuntu fonts-dejavu-core
    Path("/opt/homebrew/share/fonts"),
    Path.home() / "Library/Fonts",
]
DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
LINK_RE = re.compile(r"\[([^\]]+)\]\((\S+?)\)")
TIMEOUT = 60
WEBHOOK_MAX = 3500


class RenderError(Exception):
    pass


class SlackError(Exception):
    pass


# ---------------------------------------------------------------- render


def find_dejavu() -> tuple[Path, Path] | None:
    extra = os.environ.get("DELIVER_FONT_DIR")
    for d in ([Path(extra)] if extra else []) + FONT_DIRS:
        reg, bold = d / "DejaVuSans.ttf", d / "DejaVuSans-Bold.ttf"
        if reg.is_file() and bold.is_file():
            return reg, bold
    return None


def inline_segments(text: str) -> list[tuple[str, bool]]:
    """Split a line into (text, bold) segments. Links become 'text (url)'."""
    text = LINK_RE.sub(lambda m: f"{m.group(1)} ({m.group(2)})", text)
    text = text.replace("`", "")
    parts = text.split("**")
    return [(p, i % 2 == 1) for i, p in enumerate(parts) if p]


def render_pdf(md: str, title_date: str, out: Path) -> int:
    """Render the Markdown subset to out. Return the page count."""
    from fpdf import FPDF

    fonts = find_dejavu()

    class Brief(FPDF):
        def header(self):
            self.set_font(family, "", 8)
            self.set_text_color(110)
            self.cell(0, 6, clean(f"Daily News Brief - {title_date}"), align="L")
            self.ln(8)
            self.set_text_color(0)

        def footer(self):
            self.set_y(-12)
            self.set_font(family, "", 8)
            self.set_text_color(110)
            self.cell(0, 6, f"Page {self.page_no()} / {{nb}}", align="C")
            self.set_text_color(0)

    pdf = Brief(format="A4")
    if fonts:
        pdf.add_font("DejaVu", "", str(fonts[0]))
        pdf.add_font("DejaVu", "B", str(fonts[1]))
        family = "DejaVu"

        def clean(s: str) -> str:
            return s
    else:
        print(
            "warning: DejaVu font not found; using Helvetica (non-Latin-1 characters become '?')",
            file=sys.stderr,
        )
        family = "Helvetica"
        subs = {"—": "-", "–": "-", "‘": "'", "’": "'", "“": '"', "”": '"', "…": "...", "•": "-"}

        def clean(s: str) -> str:
            for k, v in subs.items():
                s = s.replace(k, v)
            return s.encode("latin-1", "replace").decode("latin-1")

    pdf.alias_nb_pages()
    pdf.set_auto_page_break(True, margin=18)
    pdf.set_margins(18, 15, 18)
    pdf.add_page()

    def write_line(text: str, size: float, h: float, base_bold=False):
        pdf.set_font_size(size)
        for seg, bold in inline_segments(text):
            pdf.set_font(family, "B" if (bold or base_bold) else "", size)
            pdf.write(h, clean(seg))
        pdf.ln(h)

    sizes = {1: 18, 2: 14, 3: 12}
    for raw in md.splitlines():
        line = raw.rstrip()
        if not line.strip():
            pdf.ln(2.5)
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            level = len(m.group(1))
            pdf.ln(2 if level > 1 else 0)
            write_line(m.group(2), sizes.get(level, 11), 8 if level == 1 else 7, True)
            pdf.ln(1)
            continue
        if re.match(r"^\s*(-{3,}|\*{3,})\s*$", line):
            y = pdf.get_y() + 2
            pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
            pdf.ln(5)
            continue
        m = re.match(r"^(\s*)[-*+]\s+(.*)$", line)
        if m:
            indent = 4 + 5 * (len(m.group(1)) // 2)
            pdf.set_x(pdf.l_margin + indent)
            pdf.set_font(family, "", 10.5)
            pdf.write(5.5, clean("• "))
            old = pdf.l_margin
            pdf.set_left_margin(old + indent + 4)
            write_line(m.group(2), 10.5, 5.5)
            pdf.set_left_margin(old)
            continue
        write_line(line.strip(), 10.5, 5.5)

    try:
        pdf.output(str(out))
    except Exception as e:  # fpdf raises various types
        raise RenderError(f"cannot write PDF: {e}") from e
    return pdf.pages_count


# ---------------------------------------------------------------- slack


def api_base() -> str:
    return os.environ.get("SLACK_API_BASE", "https://slack.com/api").rstrip("/")


def hooks_base() -> str:
    return os.environ.get("SLACK_HOOKS_BASE", "https://hooks.slack.com").rstrip("/")


def _post(url: str, data: bytes, headers: dict, what: str) -> bytes:
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace").strip()[:200]
        raise SlackError(f"{what}: HTTP {e.code} {detail}".rstrip()) from None
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        raise SlackError(f"{what}: {type(e).__name__}: {e}") from None


def field(body: dict, key: str, what: str):
    v = body.get(key)
    if v in (None, "", {}):
        raise SlackError(f"{what}: response has no {key!r}")
    return v


def slack_call(method: str, token: str, params: dict) -> dict:
    raw = _post(
        f"{api_base()}/{method}",
        urllib.parse.urlencode(params).encode(),
        {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method,
    )
    try:
        body = json.loads(raw.decode())
    except ValueError:
        raise SlackError(f"{method}: response is not JSON") from None
    if not isinstance(body, dict):
        raise SlackError(f"{method}: response is not a JSON object")
    if not body.get("ok"):
        err = body.get("error", "unknown_error")
        hint = {
            "not_in_channel": " (invite the app: /invite @<app> in the channel)",
            "missing_scope": f" (add bot scope {body.get('needed', '?')}, reinstall the app)",
            "channel_not_found": " (check SLACK_TARGET; for a private channel invite the app)",
            "invalid_auth": " (check SLACK_BOT_TOKEN: xoxb-... Bot User OAuth Token)",
        }.get(err, "")
        raise SlackError(f"{method}: {err}{hint}")
    return body


def resolve_channel(token: str, target: str) -> str:
    if target[:1] in ("U", "W"):
        ch = slack_call("conversations.open", token, {"users": target})
        chan = field(ch, "channel", "conversations.open")
        if not isinstance(chan, dict) or not isinstance(chan.get("id"), str):
            raise SlackError("conversations.open: response has no channel id")
        return chan["id"]
    if target[:1] in ("C", "G", "D"):
        return target
    raise SlackError("SLACK_TARGET must be a user ID (U...) or channel ID (C/G/D...)")


def upload(token: str, target: str, pdf: Path, comment: str, title: str) -> str:
    channel = resolve_channel(token, target)
    data = pdf.read_bytes()
    got = slack_call(
        "files.getUploadURLExternal", token, {"filename": pdf.name, "length": str(len(data))}
    )
    url = field(got, "upload_url", "files.getUploadURLExternal")
    file_id = field(got, "file_id", "files.getUploadURLExternal")
    if not isinstance(url, str) or not url.startswith(("https://", "http://")):
        raise SlackError("files.getUploadURLExternal: bad upload_url")
    _post(url, data, {"Content-Type": "application/octet-stream"}, "upload")
    slack_call(
        "files.completeUploadExternal",
        token,
        {
            "files": json.dumps([{"id": file_id, "title": title}]),
            "channel_id": channel,
            "initial_comment": comment,
        },
    )
    return channel


def valid_webhook(url: str) -> bool:
    return url.startswith(hooks_base() + "/services/") and len(url) > len(hooks_base()) + 10


def mrkdwn_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def parse_stories(md: str) -> tuple[str | None, list[dict]]:
    """Return (top line, stories). A story is a '### ' heading with its first source."""
    top, stories = None, []
    for line in md.splitlines():
        s = line.strip()
        if s.startswith("### "):
            stories.append({"headline": s[4:].strip(), "outlet": None, "url": None})
        elif top is None and s.startswith("**Top line:**"):
            top = s[len("**Top line:**") :].strip()
        elif stories and stories[-1]["url"] is None and "Source" in s:
            m = LINK_RE.search(s)
            if m:
                stories[-1]["outlet"], stories[-1]["url"] = m.group(1), m.group(2)
    return top, stories


def webhook_text(md: str, date: str, pdf_path: str, limit: int = WEBHOOK_MAX) -> str:
    title = first_heading(md) or f"Daily News Brief {date}"
    top, stories = parse_stories(md)
    if date not in title:
        title += f" ({date})"
    head = f"*{mrkdwn_escape(title)}*\n"
    if top:
        head += mrkdwn_escape(top.replace("**", "")) + "\n"
    head += "\n"
    tail = f"\n_Full PDF saved in the box: {mrkdwn_escape(pdf_path)}_"
    lines = []
    for st in stories:
        line = f"• {mrkdwn_escape(st['headline'])}"
        if st["url"]:
            line += f" — <{st['url']}|{mrkdwn_escape(st['outlet'] or 'source')}>"
        lines.append(line)
    reserve = len(f"_…{len(lines)} more stories in the PDF (message truncated)_\n")
    body, shown = "", 0
    for line in lines:
        if len(head) + len(body) + len(line) + 1 + reserve + len(tail) > limit:
            break
        body += line + "\n"
        shown += 1
    if shown < len(lines):
        body += f"_…{len(lines) - shown} more stories in the PDF (message truncated)_\n"
    if not lines:
        body = "_No story headings found; see the PDF._\n"
    return head + body + tail


def post_message(token: str, target: str, text: str) -> str:
    channel = resolve_channel(token, target)
    slack_call("chat.postMessage", token, {"channel": channel, "text": text})
    return channel


def post_webhook(url: str, text: str) -> None:
    raw = _post(
        url,
        json.dumps({"text": text}).encode(),
        {"Content-Type": "application/json"},
        "webhook",
    )
    if raw.strip() != b"ok":
        raise SlackError(f"webhook: {raw.decode(errors='replace').strip()[:200]}")


# ---------------------------------------------------------------- main


def first_heading(md: str) -> str | None:
    for line in md.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return None


def redact(msg: str, *secrets: str) -> str:
    for s in secrets:
        if s:
            msg = msg.replace(s, "[redacted]")
    return msg


REPO = Path(__file__).resolve().parents[1]
BRIEF_DIRS = (REPO / "reports", REPO / "tests" / "fixtures")
FAILURE_MAX = 300


class InputError(Exception):
    pass


def check_brief_path(arg: str) -> Path:
    p = Path(os.path.realpath(arg))
    if p.suffix != ".md":
        raise InputError("brief must be a .md file")
    if not any(p.is_relative_to(d.resolve()) for d in BRIEF_DIRS):
        raise InputError("brief must be under reports/ or tests/fixtures/ of this repo")
    if not p.is_file():
        raise InputError(f"brief not found: {arg}")
    return p


def bad_chars(v: str) -> bool:
    return any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in v)


def sanitize_reason(reason: str, *secrets: str) -> str:
    r = redact(reason, *secrets)
    r = "".join(c if c.isprintable() else " " for c in r)
    r = " ".join(r.split())
    if len(r) > FAILURE_MAX:
        r = r[: FAILURE_MAX - 1] + "…"
    return r or "no reason given"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render a brief to PDF; send to Slack.")
    ap.add_argument("brief", nargs="?", help="Markdown brief under reports/, e.g. reports/2026-09-25.md")
    ap.add_argument("--dry-run", action="store_true", help="no network; print what would be sent")
    ap.add_argument("--out", help="PDF path (default: brief path with .pdf)")
    ap.add_argument("--failure", metavar="REASON", help="post a short failure notice instead of a brief")
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return EXIT_OK if e.code == 0 else EXIT_USAGE
    if (args.brief is None) == (args.failure is None):
        print("error: give a brief path or --failure REASON (not both)", file=sys.stderr)
        return EXIT_USAGE

    env = {n: os.environ.get(n, "").strip() for n in ("SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL", "SLACK_TARGET")}
    for n, v in env.items():
        if v and bad_chars(v):
            print(f"error: {n} contains whitespace or control characters; store it again", file=sys.stderr)
            return EXIT_USAGE
    token, webhook = env["SLACK_BOT_TOKEN"], env["SLACK_WEBHOOK_URL"]
    target = env["SLACK_TARGET"]
    if token and not target and not getattr(args, "dry_run", False):
        print("error: SLACK_TARGET is required with SLACK_BOT_TOKEN "
              "(a channel ID C... or a user ID U...)", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run(args, token, webhook, target)
    except InputError as e:
        print(f"error: {redact(str(e), token, webhook)}", file=sys.stderr)
        return EXIT_USAGE
    except RenderError as e:
        print(f"error: render failed: {redact(str(e), token, webhook)}", file=sys.stderr)
        return EXIT_RENDER
    except SlackError as e:
        print(f"error: slack: {redact(str(e), token, webhook)}", file=sys.stderr)
        return EXIT_SLACK
    except Exception as e:  # never show a traceback: it can hold request data
        print(f"error: slack: unexpected {type(e).__name__}: {redact(str(e), token, webhook)}",
              file=sys.stderr)
        return EXIT_SLACK


def send_check(token: str, webhook: str) -> str:
    if token:
        return "pdf"
    if webhook:
        if not valid_webhook(webhook):
            raise SlackError("SLACK_WEBHOOK_URL is not an https://hooks.slack.com/services/... URL")
        return "webhook"
    raise SlackError("no Slack secret: set SLACK_BOT_TOKEN (PDF upload) or SLACK_WEBHOOK_URL (text summary)")


def run(args, token: str, webhook: str, target: str) -> int:
    if args.failure is not None:
        reason = sanitize_reason(args.failure, token, webhook)
        date = datetime.now(timezone.utc).date().isoformat()
        text = f":warning: *Daily news brief FAILED* ({date} UTC): {mrkdwn_escape(reason)}"
        if args.dry_run:
            print(f"dry run: would post failure notice: {text}")
            return EXIT_OK
        mode = send_check(token, webhook)
        if mode == "pdf":
            channel = post_message(token, target, text)
            print(f"posted failure notice to Slack channel {channel}")
        else:
            post_webhook(webhook, text)
            print("posted failure notice to the Slack webhook")
        return EXIT_OK

    src = check_brief_path(args.brief)
    try:
        md = src.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise InputError("brief is not valid UTF-8") from None
    m = DATE_RE.search(src.name) or DATE_RE.search(md)
    date = m.group(1) if m else "undated"
    out = Path(args.out) if args.out else src.with_suffix(".pdf")
    try:
        pages = render_pdf(md, date, out)
        size = out.stat().st_size
    except Exception as e:
        raise RenderError(f"{type(e).__name__}: {e}") from None
    print(f"rendered {out} ({pages} pages, {size} bytes)")

    headline = first_heading(md) or f"Daily News Brief {date}"
    comment = headline if date in headline else f"{headline} ({date})"
    title = f"news-brief-{date}.pdf"
    text = webhook_text(md, date, str(out))

    if args.dry_run:
        mode = "pdf" if token else "webhook" if webhook else None
        print(f"dry run: mode would be {mode or 'none (no Slack secret set)'}")
        kind = "user -> conversations.open" if target[:1] in ("U", "W") else "channel"
        print(f"  pdf mode: target {target} ({kind}); files.getUploadURLExternal -> "
              f"upload_url -> files.completeUploadExternal; title={title} "
              f"length={size}; initial_comment={comment}")
        print(f"  webhook mode: {len(text)} chars of mrkdwn:")
        print("    " + text.replace("\n", "\n    "))
        print(f"  SLACK_BOT_TOKEN: {'set' if token else 'unset'}; "
              f"SLACK_WEBHOOK_URL: {'set' if webhook else 'unset'}")
        return EXIT_OK

    mode = send_check(token, webhook)
    if mode == "pdf":
        channel = upload(token, target, out, comment, title)
        print(f"sent {out.name} to Slack channel {channel}")
    else:
        post_webhook(webhook, text)
        print(f"posted text summary ({len(text)} chars) to the Slack webhook; PDF kept at {out}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
