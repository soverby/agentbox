"""OAuth upstreams in the gateway (PLAN §2.6, P6b).

The CLI (`agentbox mcp login`, on the host) stores a token set in the secret
backend; `up` delivers it to this container only (/run/secrets/_MCP_OAUTH_<S>).
Here:

- Bearer = the access token. It is refreshed (RFC 6749 §6, with the RFC 8707
  `resource`) when it expires (60 s early) or when the upstream answers 401.
  Refresh goes through squid (HTTPS_PROXY); the token endpoint host is on the
  gateway's allowlist.
- Rotated tokens are kept in the gateway-only volume (/var/lib/mcp-oauth,
  0700, uid 10002), one `<server>.json` (0600) per server. A new login (new
  `login_id` in the delivered set) replaces the volume copy.
- One refresh at a time per server across processes (the server and
  `gateway.py probe` execs): flock on `<server>.lock`, then re-read, so a
  rotated refresh token is never used twice.
- A refused refresh (HTTP 400/401) marks the set `failed`: the upstream then
  reports "re-login needed (agentbox mcp login <p> <s>)" without retrying.
- Tokens are never logged; error text is built here (status + OAuth `error`
  code), never copied from a response.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import json
import os
import re
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

OAUTH_DIR = "/var/lib/mcp-oauth"
VERSION = 1
SKEW = 60
MAX_BODY = 64 * 1024
TIMEOUT = 20.0
ERR_CODE_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
AUTH_METHODS = ("none", "client_secret_post", "client_secret_basic")


class ReloginNeeded(Exception):
    pass


class RefreshError(Exception):
    pass


class TokenSetError(ValueError):
    pass


def iso(t: float | None) -> str | None:
    return None if t is None else datetime.fromtimestamp(t, UTC).isoformat(timespec="seconds")


def _https(u: object, what: str) -> str:
    if not isinstance(u, str) or urlsplit(u).scheme != "https" or not urlsplit(u).hostname:
        raise TokenSetError(f"{what} is not an https URL")
    if "@" in urlsplit(u).netloc or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in u):
        raise TokenSetError(f"{what} is not a plain https URL")
    return u


def parse_token_set(raw: str) -> dict:
    """Validate a delivered token set (JSON). Unknown keys are ignored."""
    try:
        ts = json.loads(raw)
    except ValueError:
        raise TokenSetError("token set is not JSON") from None
    if not isinstance(ts, dict) or ts.get("v") != VERSION:
        raise TokenSetError("token set has an unknown format")
    for k in ("login_id", "client_id"):
        if not isinstance(ts.get(k), str) or not ts[k]:
            raise TokenSetError(f"token set has no {k}")
    _https(ts.get("token_endpoint"), "token_endpoint")
    if ts.get("revocation_endpoint") is not None:
        _https(ts["revocation_endpoint"], "revocation_endpoint")
    if ts.get("auth_method", "none") not in AUTH_METHODS:
        raise TokenSetError("token set has an unknown auth_method")
    if not ts.get("access_token") and not ts.get("refresh_token"):
        raise TokenSetError("token set has neither an access nor a refresh token")
    return ts


def error_code(body: bytes) -> str:
    try:
        e = json.loads(body.decode()).get("error")
    except (ValueError, UnicodeDecodeError, AttributeError):
        return ""
    return e if isinstance(e, str) and ERR_CODE_RE.fullmatch(e) else ""


def httpx_post(url: str, form: dict[str, str], headers: dict[str, str]) -> tuple[int, bytes]:
    """POST a form through the gateway's proxy env; no redirects; capped body."""
    import httpx2

    with (
        httpx2.Client(timeout=TIMEOUT, follow_redirects=False) as c,
        c.stream("POST", url, data=form, headers=headers) as r,
    ):
        body = b""
        for chunk in r.iter_bytes():
            body += chunk
            if len(body) > MAX_BODY:
                raise RefreshError("token endpoint response too large")
        return r.status_code, body


class TokenStore:
    def __init__(self, name: str, raw: str, relogin: str, state_dir: str | Path = OAUTH_DIR,
                 post=None, now=time.time, on_failed=None):  # fmt: skip
        self.name = name
        self.relogin = relogin
        self.backend = parse_token_set(raw)
        self.dir = Path(state_dir)
        self.path = self.dir / f"{name}.json"
        self.lockpath = self.dir / f"{name}.lock"
        self.post = post or httpx_post
        self.now = now
        self.on_failed = on_failed
        self.lock = threading.Lock()

    def secrets(self) -> list[str]:
        """Values to scrub from any text (defence in depth)."""
        out = []
        for ts in (self.backend, self._read() or {}):
            out += [ts.get(k) or "" for k in ("access_token", "refresh_token", "client_secret")]
        return [x for x in out if x]

    # -- volume copy
    def _read(self) -> dict | None:
        try:
            ts = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return None
        return ts if isinstance(ts, dict) else None

    def _write(self, ts: dict) -> None:
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(ts, f, separators=(",", ":"))
        tmp.replace(self.path)

    @contextlib.contextmanager
    def _locked(self):
        with self.lock:
            fd = os.open(self.lockpath, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def _load(self) -> dict:
        """The current set: the volume copy of this login, else the delivered
        set (a new login replaces an old volume copy)."""
        vol = self._read()
        if vol is not None and vol.get("login_id") == self.backend["login_id"]:
            return vol
        ts = dict(self.backend)
        self._write(ts)
        return ts

    def _valid(self, ts: dict) -> bool:
        exp = ts.get("expires_at")
        return bool(ts.get("access_token")) and (exp is None or exp - SKEW > self.now())

    # -- public
    def get_access(self) -> str:
        with self._locked():
            ts = self._load()
            if ts.get("failed"):
                raise ReloginNeeded(self.relogin)
            if self._valid(ts):
                return ts["access_token"]
            return self._refresh(ts)

    def refresh(self, stale: str | None) -> str:
        """After a 401 with `stale`: refresh, unless another process already did."""
        with self._locked():
            ts = self._load()
            if ts.get("failed"):
                raise ReloginNeeded(self.relogin)
            if self._valid(ts) and ts["access_token"] != stale:
                return ts["access_token"]
            return self._refresh(ts)

    def _fail(self, ts: dict, why: str) -> None:
        ts = {**ts, "failed": why, "failed_at": iso(self.now()), "access_token": None}
        self._write(ts)
        if self.on_failed:
            with contextlib.suppress(Exception):
                self.on_failed(self.name, f"re-login needed ({self.relogin})")
        raise ReloginNeeded(self.relogin)

    def _refresh(self, ts: dict) -> str:
        rt = ts.get("refresh_token")
        if not rt:
            self._fail(ts, "no refresh token")
        form = {"grant_type": "refresh_token", "refresh_token": rt}
        if ts.get("resource"):
            form["resource"] = ts["resource"]
        headers = client_auth(ts, form, {"Accept": "application/json"})
        try:
            status, body = self.post(_https(ts["token_endpoint"], "token_endpoint"), form, headers)
        except RefreshError:
            raise
        except Exception as e:  # noqa: BLE001 (network errors: no text from the exception)
            raise RefreshError(f"token endpoint unreachable ({type(e).__name__})") from None
        if status in (400, 401):
            code = error_code(body)
            self._fail(ts, f"refresh refused: HTTP {status}" + (f" {code}" if code else ""))
        if status != 200:
            raise RefreshError(f"token endpoint HTTP {status}")
        try:
            doc = json.loads(body.decode())
        except (ValueError, UnicodeDecodeError):
            raise RefreshError("token endpoint answer is not JSON") from None
        at = doc.get("access_token") if isinstance(doc, dict) else None
        if not isinstance(at, str) or not at:
            raise RefreshError("token endpoint answer has no access_token")
        if str(doc.get("token_type", "")).lower() != "bearer":
            raise RefreshError("token endpoint answer is not a Bearer token")
        exp = doc.get("expires_in")
        new_rt = doc.get("refresh_token")
        ts = {
            **ts,
            "access_token": at,
            "expires_at": int(self.now() + exp) if isinstance(exp, int | float) and exp > 0
            else None,
            "refresh_token": new_rt if isinstance(new_rt, str) and new_rt else rt,
            "last_refresh": iso(self.now()),
            "refreshes": int(ts.get("refreshes") or 0) + 1,
        }  # fmt: skip
        ts.pop("failed", None)
        self._write(ts)
        return at

    def status(self) -> dict:
        """Names and times only (never tokens)."""
        with self._locked():
            ts = self._load()
        exp = ts.get("expires_at")
        out = {
            "login": ts.get("obtained_at"),
            "expires_at": iso(exp),
            "expires_in": None if exp is None else int(exp - self.now()),
            "last_refresh": ts.get("last_refresh"),
            "refreshes": int(ts.get("refreshes") or 0),
            "has_refresh_token": bool(ts.get("refresh_token")),
        }
        if ts.get("failed"):
            out.update(state="needs_login", reason=ts["failed"], failed_at=ts.get("failed_at"))
        elif self._valid(ts) or ts.get("refresh_token"):
            out["state"] = "ok"
        else:
            out["state"] = "needs_login"
            out["reason"] = "access token expired and no refresh token"
        return out

    def logout(self) -> tuple[str, dict]:
        """Best-effort RFC 7009 revocation of the current (newest) refresh and
        access token, then delete the volume copy. Returns (result, the set
        that was current); the caller never logs the set."""
        with self._locked():
            ts = self._read() or dict(self.backend)
            result = "not advertised"
            url = ts.get("revocation_endpoint")
            toks = [(ts.get(k), k) for k in ("refresh_token", "access_token") if ts.get(k)]
            if url and toks:
                bad = []
                for tok, hint in toks:
                    form = {"token": tok, "token_type_hint": hint}
                    headers = client_auth(ts, form, {"Accept": "application/json"})
                    try:
                        status, _ = self.post(_https(url, "revocation_endpoint"), form, headers)
                        if status != 200:
                            bad.append(f"{hint}: HTTP {status}")
                    except Exception as e:  # noqa: BLE001
                        bad.append(f"{hint}: {type(e).__name__}")
                result = "ok" if not bad else "failed (" + "; ".join(bad) + ")"
            elif not toks:
                result = "no token to revoke"
            for p in (self.path, self.lockpath):
                p.unlink(missing_ok=True)
        return result, ts


def client_auth(ts: dict, form: dict[str, str], headers: dict[str, str]) -> dict[str, str]:
    """RFC 6749 §2.3.1 client authentication by the set's auth_method."""
    cid, sec = ts["client_id"], ts.get("client_secret")
    if ts.get("auth_method") == "client_secret_basic" and sec:
        raw = f"{quote(cid, safe='')}:{quote(sec, safe='')}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    else:
        form["client_id"] = cid
        if ts.get("auth_method") == "client_secret_post" and sec:
            form["client_secret"] = sec
    return headers


def remove_volume_copy(name: str, state_dir: str | Path = OAUTH_DIR) -> dict | None:
    """Delete <name>.json (+ lock); return the set it held (None: none)."""
    d = Path(state_dir)
    try:
        ts = json.loads((d / f"{name}.json").read_text())
    except (OSError, ValueError):
        ts = None
    for p in (d / f"{name}.json", d / f"{name}.lock"):
        p.unlink(missing_ok=True)
    return ts if isinstance(ts, dict) else None


def make_auth(store: TokenStore):
    """httpx2.Auth: bearer from the store; one refresh + retry on 401."""
    import asyncio

    import httpx2

    class OAuthUpstream(httpx2.Auth):
        requires_request_body = True

        def sync_auth_flow(self, request):
            request.read()  # the retry re-sends the body
            request.headers["Authorization"] = f"Bearer {store.get_access()}"
            response = yield request
            if response.status_code == 401:
                request.headers["Authorization"] = f"Bearer {store.refresh(None)}"
                yield request

        async def async_auth_flow(self, request):
            await request.aread()
            tok = await asyncio.to_thread(store.get_access)
            request.headers["Authorization"] = f"Bearer {tok}"
            response = yield request
            if response.status_code == 401:
                tok = await asyncio.to_thread(store.refresh, tok)
                request.headers["Authorization"] = f"Bearer {tok}"
                yield request

    return OAuthUpstream()
