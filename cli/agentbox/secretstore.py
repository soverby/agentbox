"""Secret backends (PLAN §2.4, §7).

One interface per backend: get(key) -> str | None, set(key, value),
delete(key) -> bool, exists(key) -> bool. Module functions of the same names
take a full ref and dispatch on its scheme:

- `agentbox-keychain:<service>`: internal ref of an agentbox-owned keychain
  item (the default location; account `agentbox`). Stored as
  `agentbox:b64v1:` + base64, so any value without NUL works; raw cap 1,500
  bytes (the `security -i` line limit).
- `keychain:<service>` (explicit profile ref): an item of any account, read
  raw. agentbox does not write or delete these.
- `op://<vault>/<item>/<field>`: 1Password, read-only.
- `env:<VAR>`: tests only.

No secret value is ever placed in a process argv (visible in `ps`): keychain
writes go to `security -i` on stdin; reads print on stdout. Error text is
scrubbed of the value and of any >= 16-char piece of its hex or base64.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from .paths import Config
from .profile import Secret

ACCOUNT = "agentbox"
KEYCHAIN_NOT_FOUND = 44  # errSecItemNotFound exit status of `security`
SERVICE_RE = re.compile(r"[A-Za-z0-9_.@:/+=-]+")
ENV_STORE = "AGENTBOX_TEST_SECRET_STORE"  # env backend file store (tests only)
MAX_VALUE = 64 * 1024
KEYCHAIN_MAX = 1500
B64_PREFIX = "agentbox:b64v1:"
OWNED = "agentbox-keychain:"
OP_SA_NAME = "_OP_SERVICE_ACCOUNT_TOKEN"
SCRUB_MIN = 16


class SecretError(Exception):
    pass


def value_problem(value: str) -> str | None:
    """Any text without NUL, 1 byte to 64 KiB (multi-line is fine)."""
    if not value:
        return "the value is empty"
    if "\x00" in value:
        return "the value contains a NUL byte"
    if len(value.encode()) > MAX_VALUE:
        return "the value is larger than 64 KiB"
    return None


def _run(argv: list[str], *, input: str | None = None, env: dict | None = None):
    try:
        return subprocess.run(argv, input=input, capture_output=True, text=True, env=env)
    except FileNotFoundError:
        raise SecretError(f"{argv[0]}: command not found") from None


def scrub(text: str, value: str | None) -> str:
    """Error text without the value, and without any piece (>= 16 chars) of
    the value, its hex, or its base64 (stored form)."""
    text = text.strip()
    if not value:
        return text[-300:]
    forms = [value, value.encode().hex(), base64.b64encode(value.encode()).decode()]
    grams = {f[i : i + SCRUB_MIN] for f in forms for i in range(len(f) - SCRUB_MIN + 1)}
    mark = [False] * len(text)
    for i in range(len(text) - SCRUB_MIN + 1):
        if text[i : i + SCRUB_MIN] in grams:
            for j in range(i, i + SCRUB_MIN):
                mark[j] = True
    out, i = [], 0
    while i < len(text):
        if mark[i]:
            while i < len(text) and mark[i]:
                i += 1
            out.append("<redacted>")
        else:
            out.append(text[i])
            i += 1
    res = "".join(out)
    if len(value) < SCRUB_MIN:
        res = res.replace(value, "<redacted>")
    return res[-300:]


KEYCHAIN_ONLY_MAC = (
    'the keychain secret backend is macOS-only. On Linux, set secret_backend = "op" '
    "(1Password CLI, with op_vault) in ~/.config/agentbox/config.toml; "
    '"env" is for tests only'
)


def keychain_available() -> bool:
    return sys.platform == "darwin"


class Keychain:
    """macOS keychain generic passwords. owned=True: agentbox items (account
    `agentbox`, base64 envelope). owned=False: explicit refs, any account, raw,
    read-only."""

    name = "keychain"

    def __init__(self, owned: bool = True):
        self.owned = owned

    def _check(self, service: str) -> None:
        if not SERVICE_RE.fullmatch(service):
            raise SecretError(f"keychain service {service!r} has characters agentbox does not use")

    def _mac_only(self) -> None:
        if not keychain_available():
            raise SecretError(KEYCHAIN_ONLY_MAC)

    def _find(self, service: str, show: bool):
        self._check(service)
        self._mac_only()
        argv = ["security", "find-generic-password"]
        if self.owned:
            argv += ["-a", ACCOUNT]
        argv += ["-s", service]
        if show:
            argv.append("-w")
        return _run(argv)

    def get(self, service: str) -> str | None:
        if self.owned and not keychain_available():
            return None  # nothing agentbox-owned can be stored there (set refuses)
        r = self._find(service, True)
        if r.returncode == KEYCHAIN_NOT_FOUND:
            return None
        if r.returncode != 0:
            raise SecretError(f"keychain read of {service} failed: {r.stderr.strip()[-300:]}")
        out = r.stdout[:-1] if r.stdout.endswith("\n") else r.stdout
        if not self.owned and not out.startswith(B64_PREFIX):
            return out  # explicit ref to a non-agentbox item: raw
        if not out.startswith(B64_PREFIX):
            raise SecretError(
                f"keychain item {service} was not written by agentbox; store it again with "
                "`agentbox secret set`"
            )
        try:
            return base64.b64decode(out[len(B64_PREFIX) :], validate=True).decode()
        except (binascii.Error, UnicodeDecodeError):
            raise SecretError(f"keychain item {service} has a damaged value") from None

    def exists(self, service: str) -> bool:
        if self.owned and not keychain_available():
            return False
        r = self._find(service, False)
        if r.returncode == KEYCHAIN_NOT_FOUND:
            return False
        if r.returncode != 0:
            raise SecretError(f"keychain lookup of {service} failed: {r.stderr.strip()[-300:]}")
        return True

    def _owned_only(self, service: str) -> None:
        if not self.owned:
            raise SecretError(
                f"keychain:{service} is an explicit ref; agentbox only reads it (manage it with "
                "Keychain Access or `security`)"
            )

    def set(self, service: str, value: str) -> None:
        self._owned_only(service)
        self._check(service)
        self._mac_only()
        if msg := value_problem(value):
            raise SecretError(msg)
        if len(value.encode()) > KEYCHAIN_MAX:
            raise SecretError(
                f"the value is {len(value.encode())} bytes; the keychain backend holds at most "
                f"{KEYCHAIN_MAX}. Use the op backend (a profile ref op://<vault>/<item>/<field>)."
            )
        stored = B64_PREFIX + base64.b64encode(value.encode()).decode()
        # -U updates an existing item. Command and value reach `security` on stdin
        # only; the base64 alphabet needs no quoting inside "...".
        cmd = f'add-generic-password -U -a {ACCOUNT} -s "{service}" -w "{stored}"\n'
        r = _run(["security", "-i"], input=cmd)
        # `security -i` can exit 0 when the command fails: read back to confirm.
        ok = r.returncode == 0
        if ok:
            try:
                ok = self.get(service) == value
            except SecretError:
                ok = False
        if not ok:
            detail = scrub(r.stderr + r.stdout, value)
            raise SecretError(f"keychain write of {service} failed: {detail}")

    def delete(self, service: str) -> bool:
        self._owned_only(service)
        self._check(service)
        self._mac_only()
        r = _run(["security", "delete-generic-password", "-a", ACCOUNT, "-s", service])
        if r.returncode == KEYCHAIN_NOT_FOUND:
            return False
        if r.returncode != 0:
            raise SecretError(f"keychain delete of {service} failed: {r.stderr.strip()[-300:]}")
        return True


# op's not-found messages (1Password CLI 2.x), as quoted in public reports:
# - item:  `"<item>" isn't an item in the "<vault>" vault.` (matched the same
#   way in github.com/harrisoncramer/ultra cli/resolvers/onepassword and
#   github.com/eblume/blumeops mise-tasks/agent-authkey-sync)
# - field: `item '<vault>/<item>' does not have a field '<field>'`
#   (github.com/studio-b-ai/ops-pipeline/issues/324)
# A missing vault (`isn't a vault in this account`), auth, or network errors
# are hard errors (github.com/getscaf/sfu-fullstack-template/issues/42).
OP_NOT_FOUND = ("isn't an item in the", "does not have a field")


class OnePassword:
    """1Password CLI, read-only (`op item edit` takes values in argv). The
    service-account token, when given, goes only into the op subprocess env."""

    name = "op"

    def __init__(self, sa_token: str | None = None):
        self.sa_token = sa_token

    def get(self, ref: str) -> str | None:
        env = dict(os.environ)
        if self.sa_token:
            env["OP_SERVICE_ACCOUNT_TOKEN"] = self.sa_token
        r = _run(["op", "read", "--no-newline", ref], env=env)
        if r.returncode != 0:
            if any(x in r.stderr for x in OP_NOT_FOUND):
                return None
            raise SecretError(f"op read {ref} failed: {scrub(r.stderr, self.sa_token)}")
        return r.stdout

    def exists(self, ref: str) -> bool:
        return self.get(ref) is not None

    def set(self, ref: str, value: str) -> None:
        raise SecretError(
            f"the op backend is read-only in agentbox; store {ref} with 1Password (app or `op`)"
        )

    def delete(self, ref: str) -> bool:
        raise SecretError(f"the op backend is read-only in agentbox; delete {ref} in 1Password")


class EnvBackend:
    """Tests only. Reads os.environ[VAR]; when AGENTBOX_TEST_SECRET_STORE names a
    JSON file (0600), that file is the store for get/set/delete."""

    name = "env"

    def _store(self) -> Path | None:
        v = os.environ.get(ENV_STORE)
        return Path(v) if v else None

    def _load(self, f: Path) -> dict[str, str]:
        return json.loads(f.read_text()) if f.is_file() else {}

    def get(self, var: str) -> str | None:
        f = self._store()
        if f is not None:
            return self._load(f).get(var)
        return os.environ.get(var)

    def exists(self, var: str) -> bool:
        return self.get(var) is not None

    def set(self, var: str, value: str) -> None:
        if msg := value_problem(value):
            raise SecretError(msg)
        self._write(var, value)

    def delete(self, var: str) -> bool:
        f = self._store()
        if f is None:
            raise SecretError(f"env backend is read-only without {ENV_STORE}")
        if var not in self._load(f):
            return False
        self._write(var, None)
        return True

    def _write(self, var: str, value: str | None) -> None:
        f = self._store()
        if f is None:
            raise SecretError(f"env backend is read-only without {ENV_STORE}")
        data = self._load(f)
        if value is None:
            data.pop(var, None)
        else:
            data[var] = value
        tmp = f.with_name(f".{f.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        tmp.replace(f)


def split_ref(ref: str, sa_token: str | None = None):
    """(backend instance, backend key) for a full ref."""
    if ref.startswith(OWNED):
        return Keychain(owned=True), ref[len(OWNED) :]
    if ref.startswith("keychain:"):
        return Keychain(owned=False), ref[len("keychain:") :]
    if ref.startswith("op://"):
        return OnePassword(sa_token), ref
    if ref.startswith("env:"):
        return EnvBackend(), ref[len("env:") :]
    raise SecretError(f"unknown secret ref scheme: {ref!r}")


def get(ref: str, sa_token: str | None = None) -> str | None:
    b, k = split_ref(ref, sa_token)
    return b.get(k)


def set(ref: str, value: str) -> None:  # noqa: A001 - interface name (PLAN §2.4)
    b, k = split_ref(ref)
    b.set(k, value)


def delete(ref: str) -> bool:
    b, k = split_ref(ref)
    return b.delete(k)


def exists(ref: str, sa_token: str | None = None) -> bool:
    b, k = split_ref(ref, sa_token)
    return b.exists(k)


def _env_var(service: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", service).upper()


def default_ref(cfg: Config, scope: str, name: str) -> str:
    """Ref of a default location. scope: "_shared" or a profile name."""
    service = f"{cfg.secret_prefix}/{scope}/{name}"
    if cfg.secret_backend == "keychain":
        return f"{OWNED}{service}"
    if cfg.secret_backend == "env":
        return f"env:{_env_var(service)}"
    if cfg.secret_backend == "op":
        if not cfg.op_vault:
            raise SecretError('secret_backend = "op" needs op_vault in config.toml')
        return f"op://{cfg.op_vault}/{cfg.secret_prefix}-{scope}/{name}"
    raise SecretError(f"unknown secret_backend {cfg.secret_backend!r}")


def sa_token_ref(cfg: Config, profile: str) -> str:
    """Where the per-profile op service-account token lives: the agentbox
    keychain item <prefix>/<profile>/_OP_SERVICE_ACCOUNT_TOKEN (the env
    backend in tests). Never in op itself."""
    service = f"{cfg.secret_prefix}/{profile}/{OP_SA_NAME}"
    if cfg.secret_backend == "env":
        return f"env:{_env_var(service)}"
    return f"{OWNED}{service}"


def fetcher(cfg: Config, profile: str):
    """get(ref) for one profile: op refs use that profile's service-account
    token when it is stored, else the ambient op session."""
    cache: dict[str, str | None] = {}

    def sa() -> str | None:
        if "t" not in cache:
            cache["t"] = get(sa_token_ref(cfg, profile))
        return cache["t"]

    def fetch(ref: str) -> str | None:
        return get(ref, sa() if ref.startswith("op://") else None)

    return fetch


def ref_for(secret: Secret, profile: str, cfg: Config) -> str:
    """Where a profile secret lives: its explicit ref, or the default location."""
    if secret.scope is None:
        return secret.ref
    if secret.scope not in ("shared", "profile"):
        raise SecretError(f"{secret.name}: unknown scope {secret.scope!r}")
    return default_ref(cfg, "_shared" if secret.scope == "shared" else profile, secret.name)
