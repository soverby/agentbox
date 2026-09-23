import email.message
import http.server
import importlib.util
import json
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

_P = Path(__file__).resolve().parents[2] / "images" / "ollama-gate" / "gate.py"
_spec = importlib.util.spec_from_file_location("ollama_gate", _P)
gate = importlib.util.module_from_spec(_spec)
sys.modules["ollama_gate"] = gate
_spec.loader.exec_module(gate)

POL = gate.Policy(["llama3.2:latest", "qwen3:8b", "gpt-oss:20b-cloud", "notlocal:1"])
POL.set_local(["llama3.2:latest", "qwen3:8b", "gpt-oss:20b-cloud", "extra:latest"])


def hdrs(**kv):
    m = email.message.Message()
    for k, v in kv.items():
        m[k.replace("_", "-")] = v
    return m


def post(path, body, pol=POL):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return gate.check_post_body(raw, path, pol)


@pytest.mark.parametrize(
    "name,cloud",
    [
        ("gpt-oss:120b-cloud", True),
        ("gpt-oss:cloud", True),
        ("x:CLOUD ", True),
        ("x:20b-Cloud", True),
        ("llama3", False),
        ("hf.co/a/b:q4", False),
        ("a/b-cloud", False),
    ],
)
def test_is_cloud_ref(name, cloud):
    assert gate.is_cloud_ref(name) is cloud


def test_policy_list():
    assert POL.allowed("llama3.2:latest") and POL.allowed("llama3.2")
    assert POL.allowed("qwen3:8b") and not POL.allowed("qwen3")
    assert not POL.allowed("gpt-oss:20b-cloud")  # cloud never, even if listed
    assert not POL.allowed("LLAMA3.2") and not POL.allowed("llama3.2 ")
    assert not POL.allowed(None) and not POL.allowed(["qwen3:8b"])
    assert not POL.allowed("notlocal:1")  # pinned but not local
    assert not POL.allowed("extra:latest")  # local but not pinned


def test_list_mode_needs_local_set():
    p = gate.Policy(["sneaky:latest", "llama3.2"])
    assert not p.allowed("llama3.2")  # nothing before the first refresh
    tags = {"models": [{"name": "llama3.2:latest"}, {"name": "sneaky:latest"}]}
    show = {"llama3.2:latest": {}, "sneaky:latest": {"remote_host": "https://ollama.com"}}
    p.set_local(gate.local_models(tags, lambda n: show[n]))
    assert p.allowed("llama3.2") and p.allowed("llama3.2:latest")
    assert not p.allowed("sneaky:latest") and not p.allowed("sneaky")


def test_local_models_filter():
    tags = {
        "models": [
            {"name": "llama3.2:latest"},
            {
                "name": "gpt-oss:120b-cloud",
                "remote_host": "https://ollama.com:443",
                "remote_model": "gpt-oss:120b",
            },
            {"name": "sneaky:latest"},  # tags says local, show says remote
            {"name": "x:cloud"},
        ]
    }
    show = {
        "llama3.2:latest": {},
        "sneaky:latest": {"remote_host": "https://ollama.com"},
        "x:cloud": {},
    }
    assert gate.local_models(tags, lambda n: show[n]) == ["llama3.2:latest"]
    p = gate.Policy("local")
    assert not p.allowed("llama3.2:latest")
    p.set_local(["llama3.2:latest"])
    assert p.allowed("llama3.2")


def test_local_models_bad_tags():
    with pytest.raises(ValueError):
        gate.local_models({"nope": 1}, lambda n: {})


@pytest.mark.parametrize(
    "method,path,ok",
    [
        ("GET", "/api/tags", True),
        ("GET", "/api/ps", True),
        ("GET", "/api/version", True),
        ("GET", "/v1/models", True),
        ("GET", "/v1/models/qwen3:8b", True),
        ("GET", "/v1/models/qwen3%3A8b", True),
        ("GET", "/v1/models/evil:1", False),
        ("GET", "/v1/models/a%2Fb", False),
        ("POST", "/api/tags", False),
        ("POST", "/api/chat", True),
        ("POST", "/v1/messages", True),
        ("POST", "/v1/responses", True),
        ("POST", "/api/pull", False),
        ("POST", "/api/push", False),
        ("DELETE", "/api/delete", False),
        ("POST", "/api/copy", False),
        ("POST", "/api/create", False),
        ("POST", "/api/blobs/sha256:x", False),
        ("HEAD", "/api/blobs/sha256:x", False),
        ("POST", "/v1/audio/transcriptions", False),
        ("POST", "/v1/responses/compact", False),
        ("GET", "/", False),
        ("POST", "/api/chat/", False),
        ("POST", "/API/chat", False),
        ("POST", "http://x/api/chat", False),
        ("PUT", "/api/chat", False),
        ("POST", "/api/experimental/web_fetch", False),
        ("POST", "/api/me", False),
    ],
)
def test_targets(method, path, ok):
    if ok:
        gate.check_target(method, path, POL)
    else:
        with pytest.raises(gate.Reject) as r:
            gate.check_target(method, path, POL)
        assert r.value.status == 403


def test_query_dropped():
    assert gate.check_target("GET", "/api/tags?x=1", POL).path == "/api/tags"


def test_headers_ok():
    assert (
        gate.check_post_headers(
            hdrs(Content_Type="application/json; charset=utf-8", Content_Length="10"), 100
        )
        == 10
    )


@pytest.mark.parametrize(
    "h,status",
    [
        ({"Content_Type": "application/json", "Transfer_Encoding": "chunked"}, 411),
        (
            {"Content_Type": "application/json", "Content_Length": "5", "Content_Encoding": "gzip"},
            415,
        ),
        ({"Content_Type": "text/plain", "Content_Length": "5"}, 415),
        ({"Content_Type": "multipart/form-data; boundary=x", "Content_Length": "5"}, 415),
        ({"Content_Type": "application/jsonx", "Content_Length": "5"}, 415),
        ({"Content_Length": "5"}, 415),
        ({"Content_Type": "application/json"}, 411),
        ({"Content_Type": "application/json", "Content_Length": "-1"}, 411),
        ({"Content_Type": "application/json", "Content_Length": "101"}, 413),
        ({"Content_Type": "application/json", "Content_Length": "\u00b2"}, 411),
        ({"Content_Type": "application/json", "Content_Length": "1234567890123"}, 411),
        ({"Content_Type": "application/json", "Content_Length": "+5"}, 411),
    ],
)
def test_headers_rejected(h, status):
    with pytest.raises(gate.Reject) as r:
        gate.check_post_headers(hdrs(**h), 100)
    assert r.value.status == status


def test_body_ok_and_reserialized():
    model, out = post("/api/chat", b'{"model": "qwen3:8b",  "messages": [], "x": {"a":1,"a":2}}')
    assert model == "qwen3:8b"
    assert json.loads(out) == {"model": "qwen3:8b", "messages": [], "x": {"a": 2}}
    assert out == b'{"model":"qwen3:8b","messages":[],"x":{"a":2}}'


def test_show_name_key():
    assert post("/api/show", {"name": "qwen3:8b"})[0] == "qwen3:8b"
    assert post("/api/show", {"model": "qwen3:8b"})[0] == "qwen3:8b"


def test_show_empty_key_dropped():
    """ollama 0.34.3 client: both keys, one exactly "" (counts as absent)."""
    m, out = post("/api/show", {"model": "", "name": "qwen3:8b"})
    assert m == "qwen3:8b" and json.loads(out) == {"name": "qwen3:8b"}
    m, out = post("/api/show", {"model": "qwen3:8b", "name": ""})
    assert m == "qwen3:8b" and json.loads(out) == {"model": "qwen3:8b"}
    # only /api/show; elsewhere "" is just a disallowed model
    with pytest.raises(gate.Reject) as r:
        post("/api/chat", {"model": ""})
    assert r.value.status == 403


@pytest.mark.parametrize(
    "path,body,status",
    [
        ("/api/show", {"model": "", "name": ""}, 400),
        ("/api/show", {"model": "", "name": "evil"}, 403),
        ("/api/show", {"NAME": "", "model": "qwen3:8b"}, 400),
        ("/api/show", {"name": " ", "model": "qwen3:8b"}, 400),
        ("/api/show", {"name": None, "model": "qwen3:8b"}, 400),
        ("/api/chat", {"MODEL": "evil"}, 400),
        ("/api/chat", {"MODEL": "qwen3:8b"}, 400),
        ("/api/chat", {"Model": "qwen3:8b", "model": "qwen3:8b"}, 400),
        ("/api/chat", b'{"model":"qwen3:8b","model":"evil"}', 400),
        ("/api/chat", {"model": "evil"}, 403),
        ("/api/chat", {"model": "gpt-oss:120b-cloud"}, 403),
        ("/api/chat", {"model": "qwen3:8b:cloud"}, 403),
        ("/api/chat", {"model": 1}, 400),
        ("/api/chat", {}, 400),
        ("/api/chat", [{"model": "qwen3:8b"}], 400),
        ("/api/chat", b'{"model":"qwen3:8b","t":NaN}', 400),
        ("/api/chat", b'{"model":"qwen3:8b","t":Infinity}', 400),
        ("/api/chat", b'{"model":"qwen3:8b","t":-Infinity}', 400),
        ("/api/chat", b'\xff{"model":"qwen3:8b"}', 400),
        ("/api/chat", b'{"model":"qwen3:8b"} x', 400),
        ("/api/show", {"name": "qwen3:8b", "model": "evil"}, 400),
        ("/api/show", {"name": "qwen3:8b", "model": "qwen3:8b"}, 400),
        ("/api/show", {"NAME": "qwen3:8b"}, 400),
        ("/api/show", {"name": "evil"}, 403),
        ("/api/chat", {"name": "qwen3:8b"}, 400),
    ],
)
def test_body_rejected(path, body, status):
    with pytest.raises(gate.Reject) as r:
        post(path, body)
    assert r.value.status == status


def test_deep_nesting_rejected():
    with pytest.raises(gate.Reject):
        post("/api/chat", b'{"model":"qwen3:8b","x":' + b"[" * 100000 + b"]" * 100000 + b"}")


def test_lone_surrogate_ok():
    _, out = post("/api/chat", b'{"model":"qwen3:8b","x":"\\ud800"}')
    assert b"\\ud800" in out


def test_response_headers_strip_connection_named():
    h = [
        ("Content-Type", "x"),
        ("Connection", "X-Secret, keep-alive"),
        ("X-Secret", "1"),
        ("Keep-Alive", "t"),
        ("Transfer-Encoding", "chunked"),
        ("X-Ok", "2"),
    ]
    assert gate.response_headers(h) == [("Content-Type", "x"), ("X-Ok", "2")]


# ---- live server tests on loopback (fake upstream in a thread)


class _Up(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    LISTING = {
        "/api/tags": {"models": [{"name": "qwen3:8b"}, {"name": "evil:latest"},
                                 {"name": "gpt-oss:120b-cloud"}, "junk"]},
        "/v1/models": {"object": "list", "data": [{"id": "qwen3:8b"}, {"id": "evil:latest"},
                                                 {"id": "x:cloud"}]},
    }  # fmt: skip

    def do_GET(self):
        if self.path in self.LISTING:
            d = json.dumps(self.LISTING[self.path]).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(d)))
            self.end_headers()
            self.wfile.write(d)
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.send_header("Connection", "X-Hop")
        self.send_header("X-Hop", "secret")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        self.rfile.read(n)
        self.do_GET()


@pytest.fixture
def live(tmp_path):
    up = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Up)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    pol = gate.Policy("local")
    pol.set_local(["qwen3:8b"])
    g = gate.Gate(f"http://127.0.0.1:{up.server_address[1]}", pol, str(tmp_path / "g.log"))
    srv = gate.Server(("127.0.0.1", 0), gate.make_handler(g), max_conn=1)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], tmp_path / "g.log"
    srv.shutdown()
    up.shutdown()


def _raw(port, data, timeout=5):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(data)
    out = b""
    while True:
        try:
            b = s.recv(65536)
        except TimeoutError:
            break
        if not b:
            break
        out += b
    s.close()
    return out


def test_http10_not_chunked(live):
    port, _ = live
    out = _raw(port, b"GET /api/ps HTTP/1.0\r\n\r\n")
    head, _, body = out.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.0 200") or head.startswith(b"HTTP/1.1 200")
    assert b"chunked" not in head.lower() and body == b"ok"
    assert b"x-hop" not in head.lower()


def test_http11_chunked(live):
    port, _ = live
    out = _raw(port, b"GET /api/ps HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    head, _, body = out.partition(b"\r\n\r\n")
    assert b"transfer-encoding: chunked" in head.lower() and body == b"2\r\nok\r\n0\r\n\r\n"


def test_connection_cap_503(live):
    port, _ = live
    hold = socket.create_connection(("127.0.0.1", port))  # takes the only slot
    try:
        time.sleep(0.2)
        # read before sending: the gate answers 503 at accept time and closes
        out = _raw(port, b"")
        assert out.startswith(b"HTTP/1.1 503")
    finally:
        hold.close()
    time.sleep(0.2)
    out = _raw(port, b"GET /api/ps HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert b" 200 " in out.split(b"\r\n")[0] + b" "


def test_client_timeout_is_set():
    assert gate.make_handler(None).timeout == 30


def test_head_root_answered_locally(live):
    port, log = live
    out = _raw(port, b"HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 200")
    assert '"method": "HEAD"' in log.read_text() or '"method":"HEAD"' in log.read_text()


# `HEAD //` is not listed: Python collapses it to `/`, which is answered locally.
@pytest.mark.parametrize("path", [b"/api/tags", b"/api/pull", b"/?x=1"])
def test_head_other_paths_denied(live, path):
    port, _ = live
    out = _raw(port, b"HEAD " + path + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 403")


LISTED = [("/api/tags", "models", [{"name": "qwen3:8b"}]),
          ("/v1/models", "data", [{"id": "qwen3:8b"}])]  # fmt: skip


@pytest.mark.parametrize("path,key,want", LISTED)
def test_listing_filtered_live(live, path, key, want):
    port, _ = live
    out = _raw(port, f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
    head, _, body = out.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200") and b"chunked" not in head.lower()
    assert json.loads(body)[key] == want


def test_filter_listing_list_mode():
    raw = json.dumps({"models": [{"name": "llama3.2:latest"}, {"model": "qwen3:8b"},
                                 {"name": "extra:latest"}, {"name": "notlocal:1"},
                                 {"name": "gpt-oss:20b-cloud"}]}).encode()  # fmt: skip
    out = json.loads(gate.filter_listing("/api/tags", raw, POL))["models"]
    assert out == [{"name": "llama3.2:latest"}, {"model": "qwen3:8b"}]
    for bad in (b"[]", b'{"models": 1}', b"x", b'{"models":[],"t":NaN}'):
        with pytest.raises(ValueError):
            gate.filter_listing("/api/tags", bad, POL)
