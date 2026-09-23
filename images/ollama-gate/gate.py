#!/usr/bin/env python3
"""agentbox ollama-gate: path- and model-filtering proxy to host Ollama.

PLAN §2.5. Stdlib only. Rules:
- Explicit method + path list; anything else -> 403.
- POST: media type application/json; Transfer-Encoding / Content-Encoding
  rejected; Content-Length required and capped; body parsed with
  object_pairs_hook + parse_constant into a JSON object, else 400.
- Exactly one top-level key that case-insensitively equals "model" (on
  /api/show: "model" or "name", one in total), spelled exactly, value allowed.
- Upstream gets our re-serialized body with a fresh Content-Length.
- HTTP/1.1; upstream read with read1(); responses re-chunked.
- Log: method, path, model, status, byte counts. Never bodies.

Env: GATE_UPSTREAM (default http://host.docker.internal:11434),
GATE_MODELS ("local" or a JSON list of names), GATE_LISTEN (0.0.0.0:11434),
GATE_LOG (/var/log/agentbox/ollama-gate.log), GATE_MAX_BODY (bytes),
GATE_REFRESH (seconds, default 60), GATE_MAX_CONN (default 64).
"""

from __future__ import annotations

import contextlib
import http.client
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass

GET_PATHS = frozenset({"/api/tags", "/api/ps", "/api/version", "/v1/models"})
POST_PATHS = frozenset(
    {
        "/api/chat",
        "/api/generate",
        "/api/embed",
        "/api/embeddings",
        "/api/show",
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/embeddings",
        "/v1/responses",
        "/v1/messages",
    }
)
MODEL_PATH_PREFIX = "/v1/models/"
MODEL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}")
DEFAULT_MAX_BODY = 32 * 1024 * 1024
DEFAULT_MAX_CONN = 64
CLIENT_TIMEOUT = 30
FORWARD_HEADERS = ("accept", "anthropic-version", "anthropic-beta", "openai-beta")
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }
)
SAFE_HEADER_VALUE = re.compile(r"[\x20-\x7e]{0,256}")


class Reject(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def is_cloud_ref(name: str) -> bool:
    """Mirror of Ollama internal/modelref parseSourceSuffix: an explicit
    ':cloud' or ':<tag>-cloud' suffix makes Ollama proxy to ollama.com."""
    raw = name.strip()
    idx = raw.rfind(":")
    if idx < 0:
        return False
    suffix_raw = raw[idx + 1 :].strip()
    suffix = suffix_raw.lower()
    return suffix == "cloud" or ("/" not in suffix_raw and suffix.endswith("-cloud"))


class Policy:
    """Allowed model names = local models (refreshed from upstream, empty
    remote_host in /api/tags and /api/show), intersected with the pinned list
    when the spec is a list. Nothing is allowed before the first refresh."""

    def __init__(self, spec: str | list[str]):
        self.local = spec == "local"
        if not self.local and not (
            isinstance(spec, list) and all(isinstance(m, str) for m in spec)
        ):
            raise ValueError('models must be "local" or a list of names')
        self._lock = threading.Lock()
        self._pinned: frozenset[str] | None = None if self.local else self._expand(spec)
        self._names: frozenset[str] = frozenset()

    @staticmethod
    def _expand(names) -> frozenset[str]:
        out = set()
        for n in names:
            if is_cloud_ref(n) or not MODEL_NAME_RE.fullmatch(n):
                continue
            out.add(n)
            # Ollama resolves "x" to "x:latest"
            if n.endswith(":latest"):
                out.add(n[: -len(":latest")])
            elif ":" not in n.rsplit("/", 1)[-1]:
                out.add(n + ":latest")
        return frozenset(out)

    def set_local(self, names) -> None:
        local = self._expand(names)
        with self._lock:
            self._names = local if self._pinned is None else local & self._pinned

    def names(self) -> frozenset[str]:
        with self._lock:
            return self._names

    def allowed(self, name) -> bool:
        return (
            isinstance(name, str)
            and not is_cloud_ref(name)
            and MODEL_NAME_RE.fullmatch(name) is not None
            and name in self.names()
        )


def local_models(tags: dict, show) -> list[str]:
    """Names from an /api/tags response with an empty remote_host, confirmed
    by /api/show (`show(name) -> dict`) also having an empty remote_host."""
    out = []
    models = tags.get("models") if isinstance(tags, dict) else None
    if not isinstance(models, list):
        raise ValueError("/api/tags: no models list")
    for m in models:
        if not isinstance(m, dict):
            continue
        name = m.get("name") or m.get("model")
        if not isinstance(name, str) or m.get("remote_host") or m.get("remote_model"):
            continue
        if is_cloud_ref(name):
            continue
        info = show(name)
        if not isinstance(info, dict) or info.get("remote_host") or info.get("remote_model"):
            continue
        out.append(name)
    return out


def _reject_constant(c: str):
    raise ValueError(f"invalid JSON constant {c}")


class _Pairs(list):
    pass


def parse_json_object(body: bytes) -> _Pairs:
    """Top-level JSON object as its (key, value) pairs, in order, duplicates kept.
    Nested objects become dicts."""
    try:
        text = body.decode("utf-8")
        obj = json.loads(text, object_pairs_hook=_Pairs, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise Reject(400, f"invalid JSON: {type(e).__name__}") from None
    if not isinstance(obj, _Pairs):
        raise Reject(400, "body must be a JSON object")
    return obj


def _to_plain(v):
    if isinstance(v, _Pairs):
        return {k: _to_plain(x) for k, x in v}
    if isinstance(v, list):
        return [_to_plain(x) for x in v]
    return v


def _is_model_key(k: str, names: tuple[str, ...]) -> bool:
    return k.lower() in names or k.casefold() in names


def check_model(pairs: _Pairs, path: str, policy: Policy) -> str:
    names = ("model", "name") if path == "/api/show" else ("model",)
    hits = [(k, v) for k, v in pairs if _is_model_key(k, names)]
    if len(hits) != 1:
        raise Reject(400, f"need exactly one of {names} (found {len(hits)})")
    k, v = hits[0]
    if k not in names:
        raise Reject(400, f"model key must be spelled {names}")
    if not isinstance(v, str):
        raise Reject(400, "model must be a string")
    if not policy.allowed(v):
        raise Reject(403, "model not allowed")
    return v


@dataclass
class Target:
    method: str
    path: str  # canonical upstream path
    model: str | None = None


def check_target(method: str, target: str, policy: Policy) -> Target:
    """Method + request-target check. Query strings are dropped."""
    if not target.startswith("/"):
        raise Reject(403, "only origin-form request targets")
    path = target.split("?", 1)[0]
    if method == "GET":
        if path in GET_PATHS:
            return Target("GET", path)
        if path.startswith(MODEL_PATH_PREFIX):
            name = urllib.parse.unquote(path[len(MODEL_PATH_PREFIX) :], errors="strict")
            if "/" in name or not policy.allowed(name):
                raise Reject(403, "model not allowed")
            return Target("GET", MODEL_PATH_PREFIX + urllib.parse.quote(name, safe=":"), name)
        raise Reject(403, "path not allowed")
    if method == "POST" and path in POST_PATHS:
        return Target("POST", path)
    raise Reject(403, "method or path not allowed")


def check_post_headers(headers, max_body: int) -> int:
    """Return the Content-Length. `headers`: email.message.Message-like."""
    if headers.get_all("Transfer-Encoding"):
        raise Reject(411, "Transfer-Encoding not allowed")
    if headers.get_all("Content-Encoding"):
        raise Reject(415, "Content-Encoding not allowed")
    cts = headers.get_all("Content-Type") or []
    if len(cts) != 1 or cts[0].split(";", 1)[0].strip().lower() != "application/json":
        raise Reject(415, "Content-Type must be application/json")
    cls = headers.get_all("Content-Length") or []
    if len(cls) != 1 or not re.fullmatch(r"[0-9]{1,12}", cls[0].strip()):
        raise Reject(411, "Content-Length required")
    n = int(cls[0].strip())
    if n > max_body:
        raise Reject(413, "body too large")
    return n


def check_post_body(body: bytes, path: str, policy: Policy) -> tuple[str, bytes]:
    pairs = parse_json_object(body)
    model = check_model(pairs, path, policy)
    try:
        # ensure_ascii: lone surrogates stay escaped instead of failing to encode.
        out = json.dumps(
            _to_plain(pairs), ensure_ascii=True, allow_nan=False, separators=(",", ":")
        ).encode("ascii")
    except (ValueError, RecursionError) as e:
        raise Reject(400, f"invalid JSON: {type(e).__name__}") from None
    return model, out


# --------------------------------------------------------------------------- server


class Gate:
    def __init__(
        self,
        upstream: str,
        policy: Policy,
        log_path: str | None,
        max_body: int = DEFAULT_MAX_BODY,
        timeout: float = 600.0,
    ):
        u = urllib.parse.urlsplit(upstream)
        if u.scheme != "http" or not u.hostname:
            raise ValueError(f"upstream must be http://host:port, got {upstream!r}")
        self.host, self.port = u.hostname, u.port or 80
        self.policy = policy
        self.max_body = max_body
        self.timeout = timeout
        self._refreshed = False
        self._log_lock = threading.Lock()
        self._log_path = log_path
        self._log = open(log_path, "a", buffering=1) if log_path else sys.stderr  # noqa: SIM115

    def conn(self, timeout: float | None = None) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout or self.timeout)

    LOG_MAX = 10 * 1024 * 1024  # rotate at 10 MB, keep one old file (<log>.1)

    def log(self, **rec) -> None:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **rec}
        with self._log_lock:
            if self._log_path and self._log.tell() >= self.LOG_MAX:
                self._log.close()
                os.replace(self._log_path, self._log_path + ".1")
                self._log = open(self._log_path, "a", buffering=1)  # noqa: SIM115
            self._log.write(json.dumps(rec) + "\n")

    def _get_json(self, method: str, path: str, body: dict | None = None):
        c = self.conn(timeout=15)
        try:
            data = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
            hdrs = {"Content-Type": "application/json"} if data is not None else {}
            c.request(method, path, body=data, headers=hdrs)
            r = c.getresponse()
            raw = r.read(8 * 1024 * 1024)
            if r.status != 200:
                raise OSError(f"{path}: HTTP {r.status}")
            return json.loads(raw)
        finally:
            c.close()

    def refresh(self) -> None:
        tags = self._get_json("GET", "/api/tags")
        names = local_models(tags, lambda n: self._get_json("POST", "/api/show", {"model": n}))
        before = self.policy.names()
        self.policy.set_local(names)
        if self.policy.names() != before or not self._refreshed:
            self.log(event="refresh", models=sorted(names))
        self._refreshed = True

    def refresh_loop(self, interval: float) -> None:
        while True:
            try:
                self.refresh()
            except Exception as e:  # keep the last good set
                self.log(event="refresh_error", error=f"{type(e).__name__}: {e}"[:300])
            time.sleep(interval)


def response_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Upstream response headers minus hop-by-hop ones, including every header
    named in the upstream `Connection` header."""
    named = set()
    for k, v in headers:
        if k.lower() == "connection":
            named |= {t.strip().lower() for t in v.split(",") if t.strip()}
    return [(k, v) for k, v in headers if k.lower() not in HOP_BY_HOP | named]


class Server(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer with a cap on concurrent connections (503 when full)."""

    daemon_threads = True

    def __init__(self, addr, handler, max_conn: int = DEFAULT_MAX_CONN):
        self.slots = threading.BoundedSemaphore(max_conn)
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            with contextlib.suppress(OSError):
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def make_handler(gate: Gate):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = CLIENT_TIMEOUT  # idle / slow client socket timeout
        server_version = "ollama-gate"
        sys_version = ""

        def __getattr__(self, name):
            if name.startswith("do_"):
                return self._handle
            raise AttributeError(name)

        def log_message(self, *a):  # replaced by gate.log
            pass

        def _reject(self, status: int, reason: str, model=None, close=False):
            data = json.dumps({"error": reason}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if close:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(data)
            gate.log(
                client=self.client_address[0],
                method=self.command,
                path=self.path[:200],
                model=model,
                status=status,
                bytes_in=0,
                bytes_out=0,
                reason=reason,
            )

        def _handle(self):
            try:
                t = check_target(self.command, self.path, gate.policy)
            except Reject as r:
                return self._reject(r.status, r.reason, close=True)
            body, model = None, t.model
            if t.method == "GET":
                if self.headers.get_all("Transfer-Encoding") or (
                    self.headers.get("Content-Length", "0").strip() not in ("", "0")
                ):
                    return self._reject(400, "GET with body", close=True)
            else:
                try:
                    n = check_post_headers(self.headers, gate.max_body)
                    raw = self.rfile.read(n)
                    if len(raw) != n:
                        return self._reject(400, "short body", close=True)
                    model, body = check_post_body(raw, t.path, gate.policy)
                except Reject as r:
                    return self._reject(r.status, r.reason, close=True)
            self._forward(t, model, body)

        def _forward(self, t: Target, model, body):
            hdrs = {"User-Agent": "agentbox-ollama-gate"}
            for h in FORWARD_HEADERS:
                v = self.headers.get(h)
                if v is not None and SAFE_HEADER_VALUE.fullmatch(v):
                    hdrs[h] = v
            if body is not None:
                hdrs["Content-Type"] = "application/json"
                hdrs["Content-Length"] = str(len(body))
            c = gate.conn()
            sent = 0
            try:
                try:
                    c.request(t.method, t.path, body=body, headers=hdrs)
                    r = c.getresponse()
                except OSError as e:
                    return self._reject(502, f"upstream: {type(e).__name__}", model)
                self.send_response(r.status)
                for k, v in response_headers(r.getheaders()):
                    self.send_header(k, v)
                has_body = r.status not in (204, 304)
                # HTTP/1.0 clients cannot parse chunked: close-delimited body.
                chunked = has_body and self.request_version == "HTTP/1.1"
                if chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                elif has_body:
                    self.send_header("Connection", "close")
                    self.close_connection = True
                self.end_headers()
                while has_body:
                    chunk = r.read1(65536)
                    if not chunk:
                        break
                    sent += len(chunk)
                    if chunked:
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    else:
                        self.wfile.write(chunk)
                    self.wfile.flush()
                if chunked:
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                gate.log(
                    client=self.client_address[0],
                    method=t.method,
                    path=t.path,
                    model=model,
                    status=r.status,
                    bytes_in=len(body) if body else 0,
                    bytes_out=sent,
                )
            except OSError as e:
                self.close_connection = True
                gate.log(
                    client=self.client_address[0],
                    method=t.method,
                    path=t.path,
                    model=model,
                    status="aborted",
                    bytes_in=len(body) if body else 0,
                    bytes_out=sent,
                    reason=type(e).__name__,
                )
            finally:
                c.close()

    return Handler


def main() -> None:
    spec_raw = os.environ.get("GATE_MODELS", "local")
    spec = "local" if spec_raw == "local" else json.loads(spec_raw)
    policy = Policy(spec)
    gate = Gate(
        os.environ.get("GATE_UPSTREAM", "http://host.docker.internal:11434"),
        policy,
        os.environ.get("GATE_LOG", "/var/log/agentbox/ollama-gate.log"),
        int(os.environ.get("GATE_MAX_BODY", DEFAULT_MAX_BODY)),
    )
    # Both modes refresh: list mode allows list ∩ local models.
    threading.Thread(
        target=gate.refresh_loop,
        args=(float(os.environ.get("GATE_REFRESH", "60")),),
        daemon=True,
    ).start()
    host, _, port = os.environ.get("GATE_LISTEN", "0.0.0.0:11434").rpartition(":")
    srv = Server(
        (host, int(port)),
        make_handler(gate),
        int(os.environ.get("GATE_MAX_CONN", DEFAULT_MAX_CONN)),
    )
    gate.log(event="start", upstream=f"{gate.host}:{gate.port}", local=policy.local)
    srv.serve_forever()


if __name__ == "__main__":
    main()
