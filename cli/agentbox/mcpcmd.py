"""`agentbox mcp login|status|logout` (PLAN §2.3, §2.6, P6b). Host only.

The token set (JSON, mcpoauth.token_set) goes to the profile-scope backend
item `<prefix>/<profile>/_MCP_OAUTH_<SERVER>`; `up` delivers it to
mcp-gateway only. The state dir gets only the token/revocation endpoint
host names (egress allowlist of the gateway), never a token.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from . import box as boxmod
from . import docker, images, mcpgw, mcpoauth, paths, secretstore, term
from .profile import ProfileError, load_profile, oauth_secret_name


class McpCmdError(Exception):
    pass


def out(msg: str) -> None:
    print(term.clean(msg, multiline=True), flush=True)


def _profile(name: str):
    f = paths.profile_file(name)
    if not f.is_file():
        raise McpCmdError(f"no profile {name!r} ({f})")
    try:
        return load_profile(f, name)
    except ProfileError as e:
        raise McpCmdError(f"profile {name} is invalid:\n{e}") from None


def _server(prof, server: str):
    s = prof.mcp_servers.get(server)
    if s is None:
        raise McpCmdError(f"no [mcp.servers.{server}] in profile {prof.name}")
    if s.auth != "oauth":
        raise McpCmdError(f'mcp.servers.{server} does not have auth = "oauth"')
    return s


def token_ref(prof, cfg, server: str) -> str:
    return secretstore.ref_for(prof.secrets[oauth_secret_name(server)], prof.name, cfg)


def store_cap(ref: str) -> int | None:
    return secretstore.KEYCHAIN_MAX if ref.startswith(secretstore.OWNED) else None


def _hosts_file(profile: str) -> Path:
    return paths.state_dir(profile) / mcpgw.OAUTH_HOSTS_FILE


def _update_hosts(profile: str, server: str, rec: dict | None) -> None:
    f = _hosts_file(profile)
    try:
        data = json.loads(f.read_text()) if f.is_file() else {}
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    if rec is None:
        data.pop(server, None)
    else:
        data[server] = rec
    tmp = f.with_name(f".{f.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    tmp.replace(f)


def open_browser(url: str) -> bool:
    exe = "open" if sys.platform == "darwin" else "xdg-open"
    if shutil.which(exe) is None:
        return False
    try:
        subprocess.run([exe, url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15, check=False)  # fmt: skip
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def _running_box(name: str):
    """The Box when it is running, else None (never starts it)."""
    try:
        b = boxmod.load(name)
    except boxmod.BoxError:
        return None
    if not b.compose_file.is_file():
        return None
    try:
        return b if boxmod.is_running(b) else None
    except docker.DockerError:
        return None


def _apply(name: str, why: str) -> None:
    b = _running_box(name)
    if b is None:
        out(f"The box is not running; the next `agentbox up {name}` {why}.")
        return
    out(f"Applying to the running box (`agentbox up {name}`) ...")
    boxmod.up(b, explicit=True)


def login(profile: str, server: str, no_browser: bool = False, timeout: float | None = None,
          redirect_port: int = 0) -> int:  # fmt: skip
    cfg = paths.load_config()
    prof = _profile(profile)
    s = _server(prof, server)
    ref = token_ref(prof, cfg, server)
    if ref.startswith("op://"):
        raise McpCmdError(
            "the op backend is read-only in agentbox, so `mcp login` cannot store the token "
            "set; use the keychain backend for this profile"
        )
    secret = None
    if s.client_secret:
        sref = secretstore.ref_for(prof.secrets[s.client_secret], prof.name, cfg)
        secret = secretstore.fetcher(cfg, prof.name)(sref)
        if secret is None:
            raise McpCmdError(f"client_secret {s.client_secret} ({sref}) is missing: "
                              f"`agentbox secret set {profile} {s.client_secret}`")  # fmt: skip

    def show(url: str) -> None:
        opened = False if no_browser else open_browser(url)
        how = "Your browser opened" if opened else "Open this URL in a browser"
        print(f"{how} to log in to {server}:\n  {term.clean(url)}", flush=True)
        print("Waiting for the authorization response on 127.0.0.1 ...", flush=True)

    lc = mcpoauth.LoginConfig(
        server_url=s.url or "", scopes=s.scopes, client_id=s.client_id, client_secret=secret,
        redirect_port=redirect_port, timeout=timeout or mcpoauth.LOGIN_TIMEOUT,
    )  # fmt: skip
    try:
        ts = mcpoauth.login(lc, show, http=http_client(cfg))
        text, minimal = mcpoauth.fit(ts, store_cap(ref))
    except mcpoauth.OAuthError as e:
        raise McpCmdError(f"mcp login {server}: {e}") from None
    secretstore.set(ref, text)
    _update_hosts(profile, server, {"hosts": mcpoauth.endpoint_hosts(ts), "issuer": ts["issuer"],
                                    "login": ts["obtained_at"]})  # fmt: skip
    exp = ts.get("expires_at")
    when = f"access token expires {iso(exp)}" if exp else "no access token expiry given"
    out(f"{server}: logged in (issuer {ts['issuer']}; scopes {' '.join(ts['scopes']) or '-'}; "
        f"{when}; refresh token {'yes' if ts.get('refresh_token') else 'no'}).")  # fmt: skip
    out(f"Stored at {ref} for mcp-gateway only.")
    if minimal:
        out("The full token set is larger than the keychain limit: only the refresh data is "
            "stored; mcp-gateway gets a fresh access token at start.")  # fmt: skip
    _apply(profile, "delivers it to mcp-gateway")
    return 0


def iso(t: float | None) -> str:
    return datetime.fromtimestamp(t, UTC).isoformat(timespec="seconds") if t else "-"


def _in(sec: float) -> str:
    sec = int(sec)
    if sec <= 0:
        return "expired"
    if sec < 3600:
        return f"{sec // 60}m"
    if sec < 86400:
        return f"{sec // 3600}h{(sec % 3600) // 60:02d}m"
    return f"{sec // 86400}d"


def _gw_json(b, *argv: str) -> dict:
    r = boxmod.dc(b, "exec", "-T", mcpgw.SERVICE, *mcpgw.OAUTH_ARGV, *argv, check=False,
                  timeout=300)  # fmt: skip
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {}


def status(profile: str) -> int:
    cfg = paths.load_config()
    prof = _profile(profile)
    names = [n for n, s in prof.mcp_servers.items() if s.auth == "oauth"]
    if not names:
        out(f'profile {profile} has no auth = "oauth" MCP servers')
        return 0
    b = _running_box(profile)
    probe, gw = {}, {}
    if b is not None:
        try:
            probe = boxmod.gateway_status(b).get("servers", {})
        except boxmod.BoxError as e:
            out(f"(gateway probe failed: {e})")
        gw = _gw_json(b, "oauth-status").get("servers", {})
    bad = 0
    fetch = secretstore.fetcher(cfg, prof.name)
    for n in names:
        hint = f"agentbox mcp login {profile} {n}"
        ref = token_ref(prof, cfg, n)
        ts = mcpoauth.parse_token_set(fetch(ref))
        if ts is None:
            out(f"{n}: needs login (not logged in: {hint})")
            bad += 1
            continue
        if b is None:
            exp = ts.get("expires_at")
            left = f"access token expires in {_in(exp - time.time())} ({iso(exp)})" if exp else (
                "access token fetched at gateway start")  # fmt: skip
            out(f"{n}: logged in {ts.get('obtained_at')}; {left} (box not running: refresh "
                "state unknown)")  # fmt: skip
            continue
        g, p = gw.get(n, {}), probe.get(n, {})
        if g.get("state") != "ok" or p.get("state") == "failed":
            why = g.get("reason") or p.get("reason") or "unknown"
            out(f"{n}: needs login ({hint}): {why}")
            bad += 1
            continue
        exp_in = g.get("expires_in")
        left = (f"access token expires in {_in(exp_in)} ({g.get('expires_at')})"
                if exp_in is not None else "access token without expiry")  # fmt: skip
        refresh = (f"refresh OK (last {g['last_refresh']}, {g.get('refreshes', 0)} total)"
                   if g.get("last_refresh") else "no refresh yet")  # fmt: skip
        up = "connected" if p.get("state") == "connected" else f"probe {p.get('state', '?')}"
        out(f"{n}: logged in {g.get('login')}; {left}; {refresh}; {up}")
    return 1 if bad else 0


def _volume_exists(vol: str) -> bool:
    r = docker.run(["docker", "volume", "inspect", vol], check=False)
    return r.returncode == 0


def http_client(cfg) -> mcpoauth.Http:
    """Test hooks (AGENTBOX_TEST_OAUTH_*) only with the env (test) backend."""
    return mcpoauth.Http(test_hooks=cfg.secret_backend == "env")


REVOKE_HINT = "revoke agentbox's access in the provider's settings (connected apps)"


def current_set(backend: dict | None, volume: dict | None) -> dict | None:
    """The gateway's volume copy is current when it belongs to the stored
    login (it holds the rotated tokens); else the backend set."""
    if volume and (backend is None or volume.get("login_id") == backend.get("login_id")):
        return volume
    return backend


def logout(profile: str, server: str) -> int:
    cfg = paths.load_config()
    prof = _profile(profile)
    _server(prof, server)
    ref = token_ref(prof, cfg, server)
    backend = mcpoauth.parse_token_set(secretstore.fetcher(cfg, prof.name)(ref))
    b = _running_box(profile)
    revoked, removed, volume = "not tried", False, None
    if b is not None:
        res = _gw_json(b, "oauth-logout", server)
        revoked, removed = str(res.get("revoked", "failed (no answer)")), bool(res.get("removed"))
        volume = res.get("current") if isinstance(res.get("current"), dict) else None
    else:
        vol = mcpgw.oauth_volume(profile)
        if _volume_exists(vol):
            volume = _rm_volume_copy(vol, server)
            removed = volume is not None
    cur = current_set(backend, volume)
    if cur is not None and revoked != "ok":
        # the gateway did not revoke (box down, or its request failed): revoke
        # the current tokens from the host
        revoked = mcpoauth.revoke(http_client(cfg), cur)
    elif cur is None and revoked == "not tried":
        revoked = "no token set"
    deleted = secretstore.delete(ref) if backend is not None or secretstore.exists(ref) else False
    _update_hosts(profile, server, None)
    out(f"{server}: backend item {'deleted' if deleted else 'not found'} ({ref}); gateway "
        f"volume copy {'removed' if removed else 'none'}; revocation: {revoked}")  # fmt: skip
    if cur is not None and revoked != "ok":
        out(f"WARNING: the current tokens were NOT revoked ({revoked}); they stay valid until "
            f"they expire: {REVOKE_HINT}.")  # fmt: skip
    _apply(profile, "starts mcp-gateway without it")
    return 0


def _rm_volume_copy(vol: str, server: str) -> dict | None:
    """The box is down: read and delete <server>.json in the volume with the
    gateway image (no network, gateway uid). Returns the removed set (tokens:
    kept in memory for revocation, never printed)."""
    try:
        img = images.sidecar_tag(paths.repo_root(), mcpgw.SERVICE)
    except paths.ConfigError:
        return None
    if docker.run(["docker", "image", "inspect", img], check=False).returncode != 0:
        return None
    code = ("import sys, json, upstream_oauth as u; "
            "print(json.dumps(u.remove_volume_copy(sys.argv[1])))")  # fmt: skip
    r = docker.run(
        ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges:true", "-v", f"{vol}:{mcpgw.OAUTH_DIR}",
         "-w", "/opt/mcp-gateway", "--entrypoint", "python3", img, "-c", code, server],
        check=False,
    )  # fmt: skip
    try:
        ts = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None
    return ts if isinstance(ts, dict) else None
