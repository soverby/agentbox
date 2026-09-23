#!/usr/bin/env python3
"""Minimal MCP streamable-HTTP client (stdlib only) for doctor check 20 and
the P6 smoke. Runs inside the agent (`python3 - <cmd> …` on stdin), so it
honours NO_PROXY like every other in-box client (mcp-gateway is in NO_PROXY).

Commands (one JSON object on stdout):
  code <none|bad|env>          HTTP status of an `initialize` POST
  list                         {"tools": [names]}
  call <name> <json-args>      {"ok": bool, "is_error": bool, "error": str|null, "text": str}
  probe <json-args-for-calls> <name>...   {"list": [...], "calls": {name: result}}

Token: env MCP_GATEWAY_TOKEN (with-secrets exports it). URL: env
MCP_GATEWAY_URL [http://mcp-gateway:8080/mcp].
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

URL = os.environ.get("MCP_GATEWAY_URL", "http://mcp-gateway:8080/mcp")
PROTO = "2025-06-18"


class Session:
    def __init__(self, token: str | None):
        self.token = token
        self.sid: str | None = None
        self.n = 0
        self.opener = urllib.request.build_opener()  # env proxies + NO_PROXY apply

    def post(self, method: str, params: dict | None = None, notify: bool = False):
        body: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notify:
            self.n += 1
            body["id"] = self.n
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTO,
            # Upstreams must never see agent headers (the gateway does not
            # forward them); the P6 stub reports this marker if it arrives.
            "X-Agentbox-Probe": "agent-header",
        }
        if self.token is not None:
            h["Authorization"] = f"Bearer {self.token}"
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        req = urllib.request.Request(URL, json.dumps(body).encode(), h, method="POST")
        try:
            with self.opener.open(req, timeout=60) as r:
                status, ctype, raw = r.status, r.headers.get("Content-Type", ""), r.read()
                self.sid = r.headers.get("Mcp-Session-Id") or self.sid
        except urllib.error.HTTPError as e:
            return e.code, None
        if notify or not raw:
            return status, None
        return status, parse(ctype, raw.decode())

    def initialize(self) -> int:
        st, _ = self.post(
            "initialize",
            {"protocolVersion": PROTO, "capabilities": {},
             "clientInfo": {"name": "agentbox-probe", "version": "1"}},
        )  # fmt: skip
        if st == 200:
            self.post("notifications/initialized", notify=True)
        return st


def parse(ctype: str, text: str) -> dict:
    if "text/event-stream" in ctype:
        msg = None
        for line in text.splitlines():
            if line.startswith("data:"):
                d = json.loads(line[5:].strip())
                if "id" in d:
                    msg = d
        return msg or {}
    return json.loads(text)


def token(mode: str) -> str | None:
    if mode == "none":
        return None
    if mode == "bad":
        return "agentbox-wrong-token-" + "x" * 20
    return os.environ.get("MCP_GATEWAY_TOKEN", "")


def list_tools(s: Session) -> list[str]:
    st, m = s.post("tools/list", {})
    if st != 200 or not m or "result" not in m:
        raise SystemExit(json.dumps({"error": f"tools/list: HTTP {st}: {m}"}))
    return sorted(t["name"] for t in m["result"].get("tools", []))


def call(s: Session, name: str, args: dict) -> dict:
    st, m = s.post("tools/call", {"name": name, "arguments": args})
    if st != 200 or m is None:
        return {"ok": False, "is_error": True, "error": f"HTTP {st}", "text": ""}
    if "error" in m:
        return {"ok": False, "is_error": True, "error": str(m["error"].get("message")), "text": ""}
    res = m.get("result", {})
    text = "".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
    err = bool(res.get("isError"))
    return {"ok": not err, "is_error": err, "error": text if err else None, "text": text}


def main(argv: list[str]) -> int:
    cmd = argv[0]
    if cmd == "code":
        print(json.dumps({"code": Session(token(argv[1])).initialize()}))
        return 0
    s = Session(token("env"))
    st = s.initialize()
    if st != 200:
        print(json.dumps({"error": f"initialize: HTTP {st}"}))
        return 1
    if cmd == "list":
        print(json.dumps({"tools": list_tools(s)}))
    elif cmd == "call":
        print(json.dumps(call(s, argv[1], json.loads(argv[2]))))
    elif cmd == "probe":
        args = json.loads(argv[1])
        out = {"list": list_tools(s), "calls": {n: call(s, n, args) for n in argv[2:]}}
        print(json.dumps(out))
    else:
        print(json.dumps({"error": f"unknown command {cmd}"}))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
