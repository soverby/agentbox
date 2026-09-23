#!/usr/bin/env python3
"""Fake Ollama upstream for ollama-gate tests (stdlib only).

Models: llama3.2:latest (local), gpt-oss:120b-cloud (remote_host set),
sneaky:latest (local in /api/tags, remote in /api/show). Every request is
appended as one JSON line to /tmp/requests.log (method, path, headers, body)
so the harness can check what the gate forwarded.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TAGS = {
    "models": [
        {"name": "llama3.2:latest", "model": "llama3.2:latest", "size": 1},
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
        with open("/tmp/requests.log", "a") as f:
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

    def do_GET(self):
        self._record(b"")
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
            for i in range(5):
                line = json.dumps({"message": {"content": f"part{i}"}, "done": i == 4}) + "\n"
                d = line.encode()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(d), d))
                self.wfile.flush()
                time.sleep(0.3)
            self.wfile.write(b"0\r\n\r\n")
            return None
        return self._json({"ok": True, "path": self.path})

    do_DELETE = do_POST


ThreadingHTTPServer(("0.0.0.0", 11434), H).serve_forever()
