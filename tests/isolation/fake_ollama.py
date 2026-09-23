#!/usr/bin/env python3
"""Fake Ollama upstream for ollama-gate tests (stdlib only).

Models: llama3.2:latest (local), gpt-oss:120b-cloud (remote_host set),
sneaky:latest (local in /api/tags, remote in /api/show). Every request is
appended as one JSON line to the log (default /tmp/requests.log: method,
path, headers, body) so the harness can check what the gate forwarded.

P5 wire formats, each answering one canned text (`--canned`), streaming when
the request asks for it:
- POST /v1/messages (Anthropic Messages, SSE) — Claude Code
- POST /v1/responses (OpenAI Responses, SSE) — Codex
- POST /v1/chat/completions (OpenAI chat, SSE or JSON) — Pi, LiteLLM upstream
- POST /api/chat, /api/generate (Ollama NDJSON)
Options: --host/--port (default 0.0.0.0:11434), --log, --tls CERT KEY (serve
HTTPS: the router-upstream stub), --bearer TOKEN (401 without
`Authorization: Bearer TOKEN`). Without options the behaviour is the P2 one.
"""

import argparse
import json
import ssl
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OPT = argparse.Namespace(canned=None, log="/tmp/requests.log", bearer=None)

TAGS = {
    "models": [
        {
            "name": "llama3.2:latest",
            "model": "llama3.2:latest",
            "size": 1,
            "digest": "a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72",
            "modified_at": "2026-09-01T00:00:00Z",
        },
        {
            "name": "gpt-oss:120b-cloud",
            "model": "gpt-oss:120b-cloud",
            "size": 1,
            "remote_model": "gpt-oss:120b",
            "remote_host": "https://ollama.com:443",
        },
        {"name": "sneaky:latest", "model": "sneaky:latest", "size": 1},
    ]
}
# The ollama CLI slices digest[:12] in `ollama list`: every entry has one.
for _i, _m in enumerate(TAGS["models"]):
    _m.setdefault("digest", f"{_i + 1:x}" * 64)
    _m.setdefault("modified_at", "2026-09-01T00:00:00Z")

SHOW = {
    "llama3.2:latest": {"modelfile": "", "details": {}},
    "gpt-oss:120b-cloud": {"remote_model": "gpt-oss:120b", "remote_host": "https://ollama.com:443"},
    "sneaky:latest": {"remote_model": "x", "remote_host": "https://ollama.com:443"},
}


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _record(self, body):
        with open(OPT.log, "a") as f:
            f.write(
                json.dumps(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": dict(self.headers.items()),
                        "body": body.decode("utf-8", "replace"),
                    }
                )
                + "\n"
            )

    def _json(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n)

    def _auth_ok(self) -> bool:
        if OPT.bearer is None:
            return True
        if self.headers.get("Authorization") == f"Bearer {OPT.bearer}":
            return True
        self._json({"error": {"message": "bad bearer"}}, 401)
        return False

    def _sse(self, events, done_marker=False):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for name, data in events:
            chunk = (f"event: {name}\n" if name else "") + f"data: {json.dumps(data)}\n\n"
            d = chunk.encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(d), d))
            self.wfile.flush()
        if done_marker:
            d = b"data: [DONE]\n\n"
            self.wfile.write(b"%x\r\n%s\r\n" % (len(d), d))
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _messages(self, req):
        text, model = OPT.canned or "fake answer", req.get("model", "m")
        mid = "msg_" + uuid.uuid4().hex[:12]
        usage = {"input_tokens": 5, "output_tokens": 3}
        msg = {"id": mid, "type": "message", "role": "assistant", "model": model,
               "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
               "stop_sequence": None, "usage": usage}  # fmt: skip
        if not req.get("stream"):
            return self._json(msg)
        u0 = {"input_tokens": 5, "output_tokens": 0}
        start = dict(msg, content=[], stop_reason=None, usage=u0)
        return self._sse([
            ("message_start", {"type": "message_start", "message": start}),
            ("content_block_start", {"type": "content_block_start", "index": 0,
                                     "content_block": {"type": "text", "text": ""}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                     "delta": {"type": "text_delta", "text": text}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta",
                               "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                               "usage": {"output_tokens": 3}}),
            ("message_stop", {"type": "message_stop"}),
        ])  # fmt: skip

    def _responses(self, req):
        text, model = OPT.canned or "fake answer", req.get("model", "m")
        rid, iid = "resp_" + uuid.uuid4().hex[:12], "msg_" + uuid.uuid4().hex[:12]
        part = {"type": "output_text", "text": text, "annotations": []}
        item = {"id": iid, "type": "message", "status": "completed", "role": "assistant",
                "content": [part]}  # fmt: skip
        usage = {"input_tokens": 5, "input_tokens_details": {"cached_tokens": 0},
                 "output_tokens": 3, "output_tokens_details": {"reasoning_tokens": 0},
                 "total_tokens": 8}  # fmt: skip
        base = {"id": rid, "object": "response", "created_at": int(time.time()),
                "model": model, "output": [], "status": "in_progress", "usage": None}  # fmt: skip
        done = dict(base, status="completed", output=[item], usage=usage)
        if not req.get("stream"):
            return self._json(done)
        ev = [
            ("response.created", {"type": "response.created", "response": base}),
            ("response.in_progress", {"type": "response.in_progress", "response": base}),
            ("response.output_item.added", {"type": "response.output_item.added",
             "output_index": 0, "item": dict(item, status="in_progress", content=[])}),
            ("response.content_part.added", {"type": "response.content_part.added",
             "item_id": iid, "output_index": 0, "content_index": 0,
             "part": dict(part, text="")}),
            ("response.output_text.delta", {"type": "response.output_text.delta",
             "item_id": iid, "output_index": 0, "content_index": 0, "delta": text}),
            ("response.output_text.done", {"type": "response.output_text.done",
             "item_id": iid, "output_index": 0, "content_index": 0, "text": text}),
            ("response.content_part.done", {"type": "response.content_part.done",
             "item_id": iid, "output_index": 0, "content_index": 0, "part": part}),
            ("response.output_item.done", {"type": "response.output_item.done",
             "output_index": 0, "item": item}),
            ("response.completed", {"type": "response.completed", "response": done}),
        ]  # fmt: skip
        for i, (_, d) in enumerate(ev):
            d["sequence_number"] = i
        return self._sse(ev)

    def _chat(self, req):
        text, model = OPT.canned or "fake answer", req.get("model", "m")
        cid, now = "chatcmpl-" + uuid.uuid4().hex[:12], int(time.time())
        usage = {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        if not req.get("stream"):
            return self._json({
                "id": cid, "object": "chat.completion", "created": now, "model": model,
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": text}}],
                "usage": usage})  # fmt: skip

        def chunk(delta, finish=None, **kw):
            ch = [{"index": 0, "delta": delta, "finish_reason": finish}]
            return (None, {"id": cid, "object": "chat.completion.chunk", "created": now,
                           "model": model, "choices": ch, **kw})  # fmt: skip

        return self._sse([
            chunk({"role": "assistant", "content": ""}),
            chunk({"content": text}),
            chunk({}, "stop", usage=usage),
        ], done_marker=True)  # fmt: skip

    def do_HEAD(self):  # the ollama CLI sends `HEAD /` before every command
        self._record(b"")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", "17")
        self.end_headers()

    def do_GET(self):
        self._record(b"")
        if self.path.startswith("/v1/") and not self._auth_ok():
            return None
        if self.path == "/api/tags":
            return self._json(TAGS)
        if self.path == "/api/version":
            return self._json({"version": "0.14.2"})
        if self.path == "/api/ps":
            return self._json({"models": []})
        if self.path == "/v1/models":
            return self._json({"object": "list", "data": [{"id": "llama3.2:latest"}]})
        if self.path.startswith("/v1/models/"):
            return self._json({"id": self.path.split("/")[-1], "object": "model"})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        body = self._body()
        self._record(body)
        if not self._auth_ok():
            return None
        path = self.path.split("?", 1)[0]
        if path in ("/v1/messages", "/v1/responses", "/v1/chat/completions", "/chat/completions"):
            try:
                req = json.loads(body or b"{}")
            except ValueError:
                return self._json({"error": "bad json"}, 400)
            if path == "/v1/messages":
                return self._messages(req)
            if path == "/v1/responses":
                return self._responses(req)
            return self._chat(req)
        if self.path == "/api/show":
            name = json.loads(body).get("model") or json.loads(body).get("name")
            if name in SHOW:
                return self._json(SHOW[name])
            return self._json({"error": "not found"}, 404)
        if self.path in ("/api/chat", "/api/generate"):
            # NDJSON stream, 5 parts, 0.3 s apart, no Content-Length (chunked).
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            parts = [OPT.canned, "", "", "", ""] if OPT.canned else [f"part{i}" for i in range(5)]
            for i in range(5):
                line = (
                    json.dumps(
                        {
                            "message": {"role": "assistant", "content": parts[i]},
                            "response": parts[i],
                            "done": i == 4,
                        }
                    )
                    + "\n"
                )
                d = line.encode()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(d), d))
                self.wfile.flush()
                time.sleep(0 if OPT.canned else 0.3)
            self.wfile.write(b"0\r\n\r\n")
            return None
        return self._json({"ok": True, "path": self.path})

    do_DELETE = do_POST


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=11434)
    ap.add_argument("--log", default="/tmp/requests.log")
    ap.add_argument("--canned")
    ap.add_argument("--bearer")
    ap.add_argument("--bearer-file", help="read the bearer from a file (keeps it out of argv)")
    ap.add_argument("--tls", nargs=2, metavar=("CERT", "KEY"))
    a = ap.parse_args()
    OPT.canned, OPT.log, OPT.bearer = a.canned, a.log, a.bearer
    if a.bearer_file:
        with open(a.bearer_file) as f:
            OPT.bearer = f.read().strip()
    srv = ThreadingHTTPServer((a.host, a.port), H)
    if a.tls:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(*a.tls)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
