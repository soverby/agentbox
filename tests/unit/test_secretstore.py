"""Secret backends with fake `security` / `op` on PATH (argv + stdin recorded).

The key property: no secret value ever appears in the argv of any process.
"""

import base64
import json
import os
import stat
import sys
import textwrap

import pytest
from agentbox import paths, secretstore
from agentbox.profile import Secret

VALUE = "sk-ant-oat01-S3cr3t-marker-value_xyz"

FAKE_SECURITY = r"""
import json, os, shlex, sys
store_f = os.environ["FAKE_STORE"]
log_f = os.environ["FAKE_LOG"]
store = json.load(open(store_f)) if os.path.exists(store_f) else {}
stdin = sys.stdin.read() if "-i" in sys.argv[1:2] else ""
with open(log_f, "a") as f:
    f.write(json.dumps({"argv": sys.argv, "stdin": stdin}) + "\n")
def opt(args, k):
    return args[args.index(k) + 1] if k in args else None
def run(args):
    cmd = args[0]
    svc = opt(args, "-s")
    if cmd == "find-generic-password":
        if svc not in store:
            sys.stderr.write("security: The specified item could not be found in the keychain.\n")
            return 44
        if "-w" in args:
            sys.stdout.write(store[svc] + "\n")
        else:
            sys.stdout.write('keychain: "login.keychain-db"\nclass: "genp"\n')
        return 0
    if cmd == "delete-generic-password":
        if svc not in store:
            return 44
        del store[svc]
        return 0
    if cmd == "add-generic-password":
        if svc in store and "-U" not in args:
            return 45
        hx = opt(args, "-X")
        store[svc] = bytes.fromhex(hx).decode() if hx else opt(args, "-w")
        return 0
    return 2
if sys.argv[1] == "-i":
    rc = 0
    for line in stdin.splitlines():
        rc = run(shlex.split(line))  # security -i: quoted words
    # real `security -i` exits 0 even when a command fails
    rc = 0 if os.environ.get("FAKE_I_RC0") else rc
else:
    rc = run(sys.argv[1:])
json.dump(store, open(store_f, "w"))
sys.exit(rc)
"""

FAKE_OP = r"""
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps({"argv": sys.argv, "stdin": "",
                        "sa": os.environ.get("OP_SERVICE_ACCOUNT_TOKEN")}) + "\n")
sf = os.environ["FAKE_STORE"]
store = json.load(open(sf)) if os.path.exists(sf) else {}
ref = sys.argv[-1]
if sys.argv[1] != "read":
    sys.exit(2)
E = "[ERROR] 2026/09/23 10:00:00 could not read secret '" + ref + "': "
if ref == "op://v/broken/x":
    sys.stderr.write(E + "authentication required\n"); sys.exit(1)
if ref.startswith("op://novault/"):
    sys.stderr.write(E + 'could not get item novault/i: "novault" isn\'t a vault in this '
                     "account. Specify the vault with its ID or name.\n"); sys.exit(1)
if ref == "op://v/item/nofield":
    sys.stderr.write(E + "item 'v/item' does not have a field 'nofield'\n"); sys.exit(1)
if ref not in store:
    sys.stderr.write(E + '"other" isn\'t an item in the "v" vault. Specify the item '
                     "with its UUID, name, or domain.\n"); sys.exit(1)
sys.stdout.write(store[ref]); sys.exit(0)
"""


@pytest.fixture
def fakes(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("security", FAKE_SECURITY), ("op", FAKE_OP)):
        f = bindir / name
        f.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("FAKE_LOG", str(tmp_path / "log.jsonl"))
    # The fake `security` stands in for macOS; simulate darwin so the keychain
    # logic runs on Linux too (non-darwin refusal: test_secret_cli.py).
    monkeypatch.setattr(secretstore, "keychain_available", lambda: True)

    class F:
        def log(self):
            p = tmp_path / "log.jsonl"
            return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

        def store(self, data=None):
            p = tmp_path / "store.json"
            if data is not None:
                p.write_text(json.dumps(data))
            return json.loads(p.read_text()) if p.exists() else {}

    return F()


def b64(v):
    return base64.b64encode(v.encode()).decode()


def no_value_in_argv(log, value):
    for e in log:
        for a in e["argv"]:
            assert value not in a
            assert value.encode().hex() not in a
            assert b64(value) not in a


OWN = "agentbox-keychain:agentbox-test-ab/_shared/CLAUDE_CODE_OAUTH_TOKEN"


def test_keychain_roundtrip_value_never_in_argv(fakes):
    assert secretstore.get(OWN) is None
    assert secretstore.exists(OWN) is False
    secretstore.set(OWN, VALUE)
    assert secretstore.get(OWN) == VALUE
    assert secretstore.exists(OWN) is True
    # stored as the agentbox base64 envelope
    assert fakes.store()["agentbox-test-ab/_shared/CLAUDE_CODE_OAUTH_TOKEN"] == (
        "agentbox:b64v1:" + b64(VALUE)
    )
    secretstore.set(OWN, VALUE + "2")  # update in place (-U)
    assert secretstore.get(OWN) == VALUE + "2"
    assert secretstore.delete(OWN) is True
    assert secretstore.delete(OWN) is False
    log = fakes.log()
    no_value_in_argv(log, VALUE)
    writes = [e for e in log if e["argv"][1:] == ["-i"]]
    assert len(writes) == 2
    assert "-U" in writes[0]["stdin"] and b64(VALUE) in writes[0]["stdin"]
    for e in log:  # owned items: account agentbox, only the requested service
        text = " ".join(e["argv"]) + e["stdin"]
        assert "agentbox-test-ab/_shared/CLAUDE_CODE_OAUTH_TOKEN" in text
        assert "-a agentbox" in text


PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    + "\n".join(["QUJD" * 16] * 12)
    + "\n-----END PRIVATE KEY-----\n"
)


@pytest.mark.parametrize(
    "v", ["a b\"c\\d'e$f`g;h", PEM, '{"k": "v",\n "t": "\\u00e9é"}', "x" * 1500]
)
def test_keychain_any_value_roundtrip(fakes, v):
    ref = "agentbox-keychain:agentbox-test-ab/p/X"
    secretstore.set(ref, v)
    assert secretstore.get(ref) == v
    no_value_in_argv(fakes.log(), v)


def test_keychain_size_cap(fakes):
    with pytest.raises(secretstore.SecretError, match="op backend"):
        secretstore.set("agentbox-keychain:agentbox-test-ab/p/X", "x" * 1501)
    with pytest.raises(secretstore.SecretError, match="op backend"):
        secretstore.set("agentbox-keychain:agentbox-test-ab/p/X", "é" * 751)  # 1,502 bytes
    assert fakes.log() == []


def test_keychain_explicit_ref_raw_any_account_read_only(fakes):
    fakes.store({"other-app/token": "raw-value"})
    assert secretstore.get("keychain:other-app/token") == "raw-value"
    argv = fakes.log()[0]["argv"]
    assert "-a" not in argv and argv[-1] == "-w"
    with pytest.raises(secretstore.SecretError, match="explicit ref"):
        secretstore.set("keychain:other-app/token", "x")
    with pytest.raises(secretstore.SecretError, match="explicit ref"):
        secretstore.delete("keychain:other-app/token")
    # an explicit ref to an item agentbox wrote is decoded
    fakes.store({"agentbox/p/X": "agentbox:b64v1:" + b64("line1\nline2")})
    assert secretstore.get("keychain:agentbox/p/X") == "line1\nline2"
    fakes.store({"other-app/token": "raw-value"})
    # an owned ref whose item lacks the envelope is refused, not used raw
    with pytest.raises(secretstore.SecretError, match="not written by agentbox"):
        secretstore.get("agentbox-keychain:other-app/token")


def test_keychain_failed_write_detected_and_scrubbed(fakes, monkeypatch, tmp_path):
    # `security -i` exits 0 but prints the command (with partial hex / base64
    # pieces of the value) and stores nothing.
    hexv, bv = VALUE.encode().hex(), b64(VALUE)
    (tmp_path / "bin" / "security").write_text(
        f"#!/bin/sh\necho 'error near {hexv[4:40]} and {bv[3:30]} and {VALUE[2:20]}' >&2\nexit 0\n"
    )
    monkeypatch.setattr(secretstore.Keychain, "get", lambda self, s: None)
    with pytest.raises(secretstore.SecretError) as e:
        secretstore.set("agentbox-keychain:agentbox-test-ab/p/X", VALUE)
    msg = str(e.value)
    assert "<redacted>" in msg
    for form in (VALUE, hexv, bv):
        for i in range(len(form) - 15):
            assert form[i : i + 16] not in msg


def test_scrub_keeps_unrelated_text():
    assert secretstore.scrub("plain error", VALUE) == "plain error"
    assert secretstore.scrub("x short y", "short") == "x <redacted> y"


@pytest.mark.parametrize("svc", ['a"b', "a b", "a\nb", "a\\b", ""])
def test_keychain_rejects_odd_service(fakes, svc):
    with pytest.raises(secretstore.SecretError):
        secretstore.set(f"agentbox-keychain:{svc}", VALUE)
    assert fakes.log() == []


@pytest.mark.parametrize("v", ["", "\x00", "a\x00b", "x" * 70000])
def test_value_rules(fakes, v):
    with pytest.raises(secretstore.SecretError):
        secretstore.set("agentbox-keychain:agentbox-test-ab/p/X", v)


def test_keychain_other_error_is_hard(fakes, monkeypatch, tmp_path):
    (tmp_path / "bin" / "security").write_text("#!/bin/sh\necho 'locked' >&2\nexit 51\n")
    with pytest.raises(secretstore.SecretError, match="locked"):
        secretstore.get("agentbox-keychain:agentbox-test-ab/p/X")


def test_op_read(fakes, monkeypatch):
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops_sa_token")
    fakes.store({"op://v/item/field": VALUE})
    assert secretstore.get("op://v/item/field") == VALUE
    assert secretstore.exists("op://v/item/field")
    assert secretstore.get("op://v/other/field") is None  # item not found
    assert secretstore.get("op://v/item/nofield") is None  # field not found
    with pytest.raises(secretstore.SecretError, match="authentication required"):
        secretstore.get("op://v/broken/x")
    with pytest.raises(secretstore.SecretError, match="isn't a vault"):
        secretstore.get("op://novault/i/f")  # a missing vault is a config error
    log = fakes.log()
    assert log[0]["argv"][1:] == ["read", "--no-newline", "op://v/item/field"]
    assert log[0]["sa"] == "ops_sa_token"  # service account token from the environment
    no_value_in_argv(log, VALUE)


def test_op_per_profile_service_account(fakes, monkeypatch, tmp_path):
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "ambient")
    monkeypatch.setenv(secretstore.ENV_STORE, str(tmp_path / "s.json"))
    cfg = paths.Config(secret_backend="env", secret_prefix="agentbox-test-sa")
    fakes.store({"op://v/item/field": VALUE})
    # no per-profile token: the ambient op session
    assert secretstore.fetcher(cfg, "p1")("op://v/item/field") == VALUE
    assert fakes.log()[-1]["sa"] == "ambient"
    secretstore.set(secretstore.sa_token_ref(cfg, "p1"), "ops_profile_token")
    f = secretstore.fetcher(cfg, "p1")
    assert f("op://v/item/field") == VALUE
    assert fakes.log()[-1]["sa"] == "ops_profile_token"  # subprocess env only
    assert os.environ["OP_SERVICE_ACCOUNT_TOKEN"] == "ambient"  # our env unchanged
    no_value_in_argv(fakes.log(), "ops_profile_token")
    kc = paths.Config(secret_prefix="agentbox-test-sa")
    assert secretstore.sa_token_ref(kc, "p1") == (
        "agentbox-keychain:agentbox-test-sa/p1/_OP_SERVICE_ACCOUNT_TOKEN"
    )


def test_op_is_read_only(fakes):
    with pytest.raises(secretstore.SecretError, match="read-only"):
        secretstore.set("op://v/item/field", VALUE)
    with pytest.raises(secretstore.SecretError, match="read-only"):
        secretstore.delete("op://v/item/field")
    assert fakes.log() == []


def test_op_not_installed(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(secretstore.SecretError, match="op: command not found"):
        secretstore.get("op://v/i/f")


def test_env_backend(monkeypatch, tmp_path):
    monkeypatch.setenv("MY_VAR", VALUE)
    monkeypatch.delenv(secretstore.ENV_STORE, raising=False)
    assert secretstore.get("env:MY_VAR") == VALUE
    assert secretstore.get("env:NOPE_X") is None
    with pytest.raises(secretstore.SecretError, match="read-only"):
        secretstore.set("env:MY_VAR", "x")
    store = tmp_path / "s.json"
    monkeypatch.setenv(secretstore.ENV_STORE, str(store))
    secretstore.set("env:A", VALUE)
    assert store.stat().st_mode & 0o777 == 0o600
    assert secretstore.get("env:A") == VALUE and secretstore.get("env:MY_VAR") is None
    assert secretstore.delete("env:A") is True and secretstore.delete("env:A") is False


def test_unknown_scheme():
    with pytest.raises(secretstore.SecretError):
        secretstore.get("file:/etc/passwd")


def test_default_refs_follow_config():
    kc = paths.Config(secret_prefix="agentbox-test-x1")
    assert (
        secretstore.default_ref(kc, "_shared", "GH")
        == "agentbox-keychain:agentbox-test-x1/_shared/GH"
    )
    env = paths.Config(secret_backend="env", secret_prefix="agentbox-test-x1")
    assert secretstore.default_ref(env, "p1", "GH") == "env:AGENTBOX_TEST_X1_P1_GH"
    op = paths.Config(secret_backend="op", op_vault="Dev")
    assert secretstore.default_ref(op, "p1", "GH") == "op://Dev/agentbox-p1/GH"
    with pytest.raises(secretstore.SecretError):
        secretstore.default_ref(paths.Config(secret_backend="op"), "p1", "GH")


def test_ref_for_scopes():
    cfg = paths.Config(secret_prefix="agentbox-test-x1")
    assert (
        secretstore.ref_for(Secret("A", "keychain:agentbox/p/A", ["agent"], "profile"), "p", cfg)
        == "agentbox-keychain:agentbox-test-x1/p/A"
    )
    assert (
        secretstore.ref_for(
            Secret("A", "keychain:agentbox/_shared/A", ["agent"], "shared"), "p", cfg
        )
        == "agentbox-keychain:agentbox-test-x1/_shared/A"
    )
    # explicit refs are used as written
    assert secretstore.ref_for(Secret("A", "op://v/i/f", ["agent"], None), "p", cfg) == "op://v/i/f"


def write_cfg(tmp_path, monkeypatch, text):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text(text)


def test_config_keys(tmp_path, monkeypatch):
    write_cfg(tmp_path, monkeypatch, 'secret_backend = "env"\nsecret_prefix = "agentbox-test-a"\n')
    c = paths.load_config()
    assert (c.secret_backend, c.secret_prefix) == ("env", "agentbox-test-a")
    for bad in ('secret_backend = "vault"\n', 'secret_prefix = "a/b"\n',
                'secret_backend = "op"\n', "secret_backend = 1\n"):  # fmt: skip
        write_cfg(tmp_path, monkeypatch, bad)
        with pytest.raises(paths.ConfigError):
            paths.load_config()
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "new"))
    f = paths.write_config({"secret_backend": "keychain", "subnet_base": "10.213.0.0/16"})
    assert f.stat().st_mode & 0o777 == 0o600
    assert paths.load_config().secret_backend == "keychain"
