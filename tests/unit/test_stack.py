"""Stack secrets (PLAN §2.11, phase s1)."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from agentbox import cli, paths, secretstore, stack

CLI_DIR = str(Path(__file__).resolve().parents[2] / "cli")
V1 = "massive-value-0123456789abcdef"
V2 = "fred-value-fedcba9876543210"
MANIFEST = """
[stack]
name = "finance"
[secrets]
MASSIVE_API_KEY = {}
FRED_API_KEY = { ref = "env:FRED_VAR" }
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("AGENTBOX_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv(secretstore.ENV_STORE, str(tmp_path / "store.json"))
    paths.write_config({"secret_backend": "env", "secret_prefix": "agentbox-test-s"})
    paths.profiles_dir().mkdir(parents=True)
    return tmp_path


@pytest.fixture
def sdir(env):
    d = env / "proj"
    d.mkdir()
    (d / "agentbox-stack.toml").write_text(MANIFEST)
    return d


def store(tmp_path):
    f = tmp_path / "store.json"
    return json.loads(f.read_text()) if f.exists() else {}


def put(tmp_path, **kv):
    (tmp_path / "store.json").write_text(json.dumps({**store(tmp_path), **kv}))


def fill(tmp_path):
    put(tmp_path, AGENTBOX_TEST_S__STACK_FINANCE_MASSIVE_API_KEY=V1, FRED_VAR=V2)


def load(d):
    return stack.load(d, paths.load_config())


def stdin(monkeypatch, text):
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


# ---------------------------------------------------------------- manifest
def test_manifest_parse(sdir):
    st = load(sdir)
    assert st.name == "finance" and st.dir == sdir.resolve() and st.compose_files == []
    assert [(e.name, e.ref, e.explicit) for e in st.entries] == [
        ("FRED_API_KEY", "env:FRED_VAR", True),
        ("MASSIVE_API_KEY", "env:AGENTBOX_TEST_S__STACK_FINANCE_MASSIVE_API_KEY", False),
    ]


def test_default_ref_is_keychain_scope(env):
    cfg = paths.load_config()
    cfg = type(cfg)(**{**cfg.__dict__, "secret_backend": "keychain", "secret_prefix": "agentbox"})
    ref = stack.default_ref(cfg, "finance", "MASSIVE_API_KEY")
    assert ref == "agentbox-keychain:agentbox/_stack/finance/MASSIVE_API_KEY"
    assert secretstore.SERVICE_RE.fullmatch(ref[len(secretstore.OWNED) :])


def test_empty_secrets_valid(env):
    for body in ('[stack]\nname = "x"\n', '[stack]\nname = "x"\n[secrets]\n'):
        (env / "agentbox-stack.toml").write_text(body)
        st = load(env)
        assert st.entries == []


@pytest.mark.parametrize("name", ["", "Finance", "-a", "a_b", "a" * 33, "a/b", "a b", ".x"])
def test_stack_name_rule(env, name):
    (env / "agentbox-stack.toml").write_text(f'[stack]\nname = "{name}"\n')
    with pytest.raises(stack.StackError, match="stack name|stack.name"):
        load(env)


def test_stack_name_accepts_limits(env):
    for n in ("a", "0", "a" * 32, "a-b-1"):
        (env / "agentbox-stack.toml").write_text(f'[stack]\nname = "{n}"\n')
        assert load(env).name == n


@pytest.mark.parametrize(
    "line,msg",
    [
        ("1BAD = {}", "invalid secret name"),
        ("PATH = {}", "reserved"),
        ("AGENTBOX_X = {}", "reserved"),
        ("COMPOSE_FILE = {}", "reserved"),
        ("docker_host = {}", "reserved"),
        ("https_proxy = {}", "reserved"),
        ("GIT_SSH_COMMAND = {}", "reserved"),
        ('X = "shared"', "must be a table"),
        ('X = { ref = "bogus" }', "must be keychain"),
        ("X = { ref = 5 }", "must be keychain"),
        ('X = { ref = "env:A", to = "agent" }', "unknown key"),
    ],
)
def test_secret_validation(env, line, msg):
    (env / "agentbox-stack.toml").write_text(f'[stack]\nname = "x"\n[secrets]\n{line}\n')
    with pytest.raises(stack.StackError, match=msg):
        load(env)


def test_manifest_errors_listed_together(env):
    (env / "agentbox-stack.toml").write_text(
        '[stack]\nname = "BAD"\n[secrets]\nPATH = {}\n9X = {}\n'
    )
    with pytest.raises(stack.StackError) as ei:
        load(env)
    text = str(ei.value)
    assert "stack.name" in text and "secrets.PATH" in text and "secrets.9X" in text


def test_manifest_shape_refusals(env):
    for body in (
        "",
        "[secrets]\nX = {}\n",
        '[stack]\nname = "x"\nextra = 1\n',
        '[stack]\nname = "x"\n[other]\n',
        "not toml [",
    ):
        (env / "agentbox-stack.toml").write_text(body)
        with pytest.raises(stack.StackError):
            load(env)
    with pytest.raises(stack.StackError, match="no agentbox-stack.toml"):
        load(env / "cfg")
    with pytest.raises(stack.StackError, match="not a directory"):
        load(env / "nowhere")


def test_webhook_refusal_by_item_key(env):
    paths.write_config(
        {
            "secret_backend": "env",
            "secret_prefix": "agentbox-test-s",
            "notify_webhook_secret": "HOOK",
        }
    )
    hook = secretstore.default_ref(paths.load_config(), "_shared", "HOOK")
    (env / "agentbox-stack.toml").write_text(
        f'[stack]\nname = "x"\n[secrets]\nSNEAKY = {{ ref = "{hook}" }}\nOK = {{}}\n'
    )
    with pytest.raises(stack.StackError, match="notification webhook"):
        load(env)
    # a stack secret named like the webhook is a different item and stays valid
    (env / "agentbox-stack.toml").write_text('[stack]\nname = "x"\n[secrets]\nHOOK = {}\n')
    assert [e.name for e in load(env).entries] == ["HOOK"]


def test_webhook_refusal_keychain_forms(env):
    paths.write_config(
        {"secret_backend": "keychain", "secret_prefix": "agentbox", "notify_webhook_secret": "HOOK"}
    )
    (env / "agentbox-stack.toml").write_text(
        '[stack]\nname = "x"\n[secrets]\nA = { ref = "keychain:agentbox/_shared/HOOK" }\n'
    )
    with pytest.raises(stack.StackError, match="notification webhook"):
        load(env)


# ---------------------------------------------------------------- compose_files
def test_compose_files(env):
    (env / "compose.yaml").write_text("services: {}\n")
    (env / "compose.secrets.yaml").write_text("services: {}\n")
    (env / "agentbox-stack.toml").write_text(
        '[stack]\nname = "x"\ncompose_files = ["compose.yaml", "compose.secrets.yaml"]\n'
    )
    st = load(env)
    assert st.compose_files == ["compose.yaml", "compose.secrets.yaml"]


@pytest.mark.parametrize(
    "val,msg",
    [
        ('["missing.yaml"]', "no such file"),
        ('["../outside.yaml"]', "not above"),
        ('["/etc/hosts"]', "relative"),
        ("[]", "one or more"),
        ('"compose.yaml"', "one or more"),
        ("[1]", "one or more"),
        ('["sub/../../outside.yaml"]', "not above"),
        ('["."]', "no such file"),
    ],
)
def test_compose_files_refusals(env, val, msg):
    d = env / "proj"
    d.mkdir()
    (env / "outside.yaml").write_text("x: 1\n")
    (d / "agentbox-stack.toml").write_text(f'[stack]\nname = "x"\ncompose_files = {val}\n')
    with pytest.raises(stack.StackError, match=msg):
        load(d)


def test_compose_files_symlink_escape(env):
    d = env / "proj"
    d.mkdir()
    (env / "outside.yaml").write_text("x: 1\n")
    (d / "link.yaml").symlink_to(env / "outside.yaml")
    (d / "agentbox-stack.toml").write_text('[stack]\nname = "x"\ncompose_files = ["link.yaml"]\n')
    with pytest.raises(stack.StackError, match="not above"):
        load(d)


# ---------------------------------------------------------------- secret --stack
def test_secret_set_rm_ls_stack_scope(env, monkeypatch, capsys):
    stdin(monkeypatch, "v-stack\n")
    assert cli.main(["secret", "set", "--stack", "finance", "MASSIVE_API_KEY", "--stdin"]) == 0
    assert store(env) == {"AGENTBOX_TEST_S__STACK_FINANCE_MASSIVE_API_KEY": "v-stack"}
    out = capsys.readouterr()
    assert "v-stack" not in out.out + out.err and "stack finance" in out.out
    put(env, AGENTBOX_TEST_S_P1_OTHER="x", AGENTBOX_TEST_S__STACK_OTHER_Z="y")
    assert cli.main(["secret", "ls", "--stack", "finance"]) == 0
    out = capsys.readouterr().out
    assert "MASSIVE_API_KEY" in out and "present" in out
    assert "OTHER" not in out and "v-stack" not in out
    assert cli.main(["secret", "rm", "--stack", "finance", "MASSIVE_API_KEY"]) == 0
    assert "AGENTBOX_TEST_S__STACK_FINANCE_MASSIVE_API_KEY" not in store(env)
    assert cli.main(["secret", "rm", "--stack", "finance", "MASSIVE_API_KEY"]) == 1


def test_secret_stack_refusals(env, monkeypatch):
    for args in (
        ["secret", "set", "--stack", "finance", "--shared", "X", "--stdin"],
        ["secret", "set", "--stack", "finance", "p1", "X", "--stdin"],
        ["secret", "set", "--stack", "Bad_Name", "X", "--stdin"],
        ["secret", "set", "--stack", "finance", "PATH", "--stdin"],
        ["secret", "set", "--stack", "finance", "AGENTBOX_X", "--stdin"],
        ["secret", "set", "--stack", "finance", "1BAD", "--stdin"],
        ["secret", "rm", "--stack", "finance", "--shared", "X"],
        ["secret", "ls", "--stack", "finance", "--shared"],
        ["secret", "ls", "--stack", "finance", "p1"],
    ):
        stdin(monkeypatch, "v\n")
        assert cli.main(args) == 1, args
    assert store(env) == {}


def test_stack_scope_distinct_from_profile_and_shared(env):
    cfg = paths.load_config()
    refs = {
        stack.default_ref(cfg, "finance", "X"),
        secretstore.default_ref(cfg, "_shared", "X"),
        secretstore.default_ref(cfg, "finance", "X"),
    }
    assert len(refs) == 3


def test_keychain_ls_parses_dump(env, monkeypatch, capsys):
    paths.write_config({"secret_backend": "keychain", "secret_prefix": "agentbox"})
    dump = (
        'keychain: "/x/login.keychain-db"\nclass: "genp"\nattributes:\n'
        '    "acct"<blob>="agentbox"\n    "svce"<blob>="agentbox/_stack/finance/B_KEY"\n'
        'keychain: "/x/login.keychain-db"\nclass: "genp"\nattributes:\n'
        '    "acct"<blob>="agentbox"\n    "svce"<blob>="agentbox/_stack/other/NOPE"\n'
        'keychain: "/x/login.keychain-db"\nclass: "genp"\nattributes:\n'
        '    "acct"<blob>="someone"\n    "svce"<blob>="agentbox/_stack/finance/FOREIGN"\n'
        'keychain: "/x/login.keychain-db"\nclass: "genp"\nattributes:\n'
        '    "acct"<blob>="agentbox"\n    "svce"<blob>="agentbox/_stack/finance/A_KEY"\n'
    )
    monkeypatch.setattr(secretstore, "keychain_available", lambda: True)
    monkeypatch.setattr(
        stack.subprocess, "run", lambda a, **k: subprocess.CompletedProcess(a, 0, dump, "")
    )
    assert cli.main(["secret", "ls", "--stack", "finance"]) == 0
    names = [ln.split()[0] for ln in capsys.readouterr().out.splitlines()[1:]]
    assert names == ["A_KEY", "B_KEY"]


# ---------------------------------------------------------------- stack ls
def test_stack_ls_rows(sdir, env, capsys):
    put(env, FRED_VAR=V2)
    assert cli.main(["stack", "ls", "-C", str(sdir)]) == 0
    out = capsys.readouterr()
    assert V1 not in out.out + out.err and V2 not in out.out + out.err
    rows = {ln.split()[0]: ln.split() for ln in out.out.splitlines()[1:]}
    assert rows["FRED_API_KEY"][1:] == ["env:FRED_VAR", "present"]
    assert rows["MASSIVE_API_KEY"][-1] == "missing"
    assert rows["MASSIVE_API_KEY"][1].endswith("MASSIVE_API_KEY")


def test_stack_ls_cwd_and_no_manifest(sdir, env, monkeypatch, capsys):
    monkeypatch.chdir(sdir)
    assert cli.main(["stack", "ls"]) == 0
    monkeypatch.chdir(env)
    assert cli.main(["stack", "ls"]) == 1
    assert "no agentbox-stack.toml" in capsys.readouterr().err


def test_stack_ls_empty_manifest(env, capsys):
    (env / "agentbox-stack.toml").write_text('[stack]\nname = "x"\n')
    assert cli.main(["stack", "ls", "-C", str(env)]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 1


# ---------------------------------------------------------------- stack run
@pytest.fixture
def execs(monkeypatch):
    calls = []

    def fake(file, argv, env):
        calls.append({"file": file, "argv": list(argv), "env": dict(env), "cwd": os.getcwd()})
        raise SystemExit(0)  # exec never returns

    monkeypatch.setattr(stack.os, "execvpe", fake)
    monkeypatch.chdir(Path.cwd())
    return calls


def run_cli(args):
    try:
        return cli.main(args)
    except SystemExit as e:
        return e.code


def test_run_execs_with_env(sdir, env, execs, monkeypatch):
    fill(env)
    monkeypatch.setenv("KEEP_ME", "inherited")
    monkeypatch.delenv("COMPOSE_FILE", raising=False)
    cwd0 = os.getcwd()
    try:
        argv = ["docker", "compose", "up", "-d"]
        assert run_cli(["stack", "run", "-C", str(sdir), "--", *argv]) == 0
        (c,) = execs
        assert c["argv"] == ["docker", "compose", "up", "-d"] and c["file"] == "docker"
        assert c["cwd"] == str(sdir.resolve())
        e = c["env"]
        assert e["AGENTBOX_SECRET_MASSIVE_API_KEY"] == V1 and e["MASSIVE_API_KEY"] == V1
        assert e["AGENTBOX_SECRET_FRED_API_KEY"] == V2 and e["FRED_API_KEY"] == V2
        assert e["KEEP_ME"] == "inherited"
        assert "COMPOSE_FILE" not in e
        extra = set(e) - set(os.environ)
        assert extra == {
            "AGENTBOX_SECRET_MASSIVE_API_KEY",
            "MASSIVE_API_KEY",
            "AGENTBOX_SECRET_FRED_API_KEY",
            "FRED_API_KEY",
        }
        assert all(V1 not in a and V2 not in a for a in c["argv"])
    finally:
        os.chdir(cwd0)


def test_run_missing_exits_2_and_runs_nothing(sdir, env, execs, capsys):
    put(env, FRED_VAR=V2)  # MASSIVE_API_KEY missing
    assert run_cli(["stack", "run", "-C", str(sdir), "--", "true"]) == 2
    assert execs == []
    out = capsys.readouterr()
    assert "MASSIVE_API_KEY (missing)" in out.err and "FRED_API_KEY" not in out.err
    assert V2 not in out.out + out.err


def test_run_all_missing_lists_all(sdir, env, execs, capsys):
    assert run_cli(["stack", "run", "-C", str(sdir), "--", "true"]) == 2
    err = capsys.readouterr().err
    assert "MASSIVE_API_KEY" in err and "FRED_API_KEY" in err and execs == []


def test_run_unreadable_is_scrubbed(sdir, env, execs, capsys, monkeypatch):
    fill(env)

    def get(ref, sa=None):
        if ref.endswith("FRED_VAR"):
            raise secretstore.SecretError(f"boom containing {V1} and more")
        return V1

    monkeypatch.setattr(secretstore, "get", get)
    assert run_cli(["stack", "run", "-C", str(sdir), "--", "true"]) == 2
    err = capsys.readouterr().err
    assert "FRED_API_KEY (unreadable" in err and V1 not in err and "<redacted>" in err
    assert execs == []


def test_run_no_command(sdir, capsys):
    assert cli.main(["stack", "run", "-C", str(sdir)]) == 1
    assert "needs a command" in capsys.readouterr().err


def test_run_empty_manifest_runs(env, execs):
    (env / "agentbox-stack.toml").write_text('[stack]\nname = "x"\n')
    cwd0 = os.getcwd()
    try:
        assert run_cli(["stack", "run", "-C", str(env), "--", "true"]) == 0
        assert len(execs) == 1
    finally:
        os.chdir(cwd0)


def test_run_sets_compose_file_and_wins(env, execs, monkeypatch):
    (env / "compose.yaml").write_text("services: {}\n")
    (env / "compose.secrets.yaml").write_text("services: {}\n")
    (env / "agentbox-stack.toml").write_text(
        '[stack]\nname = "x"\ncompose_files = ["compose.yaml", "compose.secrets.yaml"]\n'
    )
    monkeypatch.setenv("COMPOSE_FILE", "inherited.yaml")
    cwd0 = os.getcwd()
    try:
        assert run_cli(["stack", "run", "-C", str(env), "--", "true"]) == 0
        assert execs[0]["env"]["COMPOSE_FILE"] == os.pathsep.join(
            ["compose.yaml", "compose.secrets.yaml"]
        )
    finally:
        os.chdir(cwd0)


def test_run_leaves_inherited_compose_file(sdir, env, execs, monkeypatch):
    fill(env)
    monkeypatch.setenv("COMPOSE_FILE", "inherited.yaml")
    cwd0 = os.getcwd()
    try:
        assert run_cli(["stack", "run", "-C", str(sdir), "--", "true"]) == 0
        assert execs[0]["env"]["COMPOSE_FILE"] == "inherited.yaml"
    finally:
        os.chdir(cwd0)


def test_run_keychain_only_on_mac(sdir, env, execs, monkeypatch, capsys):
    paths.write_config({"secret_backend": "keychain", "secret_prefix": "agentbox"})
    monkeypatch.setattr(secretstore, "keychain_available", lambda: False)
    assert run_cli(["stack", "run", "-C", str(sdir), "--", "true"]) == 1
    assert "macOS-only" in capsys.readouterr().err and execs == []


# Real subprocess: exit code passthrough, 127, no value in output.
def agentbox(env_dir, args, **extra):
    e = {
        **os.environ,
        "PYTHONPATH": CLI_DIR,
        "AGENTBOX_CONFIG_HOME": str(env_dir / "cfg"),
        "AGENTBOX_STATE_HOME": str(env_dir / "state"),
        secretstore.ENV_STORE: str(env_dir / "store.json"),
        **extra,
    }
    return subprocess.run(
        [sys.executable, "-m", "agentbox.cli", *args], env=e, capture_output=True, text=True
    )


def test_real_exit_code_127_and_env(sdir, env):
    fill(env)
    code = (
        "import os,sys;"
        "sys.stdout.write(str(os.environ['MASSIVE_API_KEY']==os.environ"
        "['AGENTBOX_SECRET_MASSIVE_API_KEY']) + ' ' + os.getcwd());sys.exit(7)"
    )
    r = agentbox(env, ["stack", "run", "-C", str(sdir), "--", sys.executable, "-c", code])
    assert r.returncode == 7
    assert r.stdout == f"True {sdir.resolve()}"
    assert V1 not in r.stderr
    r = agentbox(env, ["stack", "run", "-C", str(sdir), "--", "agentbox-no-such-cmd"])
    assert r.returncode == 127 and "command not found" in r.stderr
    assert V1 not in r.stdout + r.stderr and V2 not in r.stdout + r.stderr
    (env / "store.json").write_text(json.dumps({"FRED_VAR": V2}))
    r = agentbox(env, ["stack", "run", "-C", str(sdir), "--", sys.executable, "-c", "pass"])
    assert r.returncode == 2 and "MASSIVE_API_KEY" in r.stderr and V2 not in r.stderr
