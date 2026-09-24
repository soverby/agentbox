"""`secret`, `setup`, `login` commands; `up` delivery wiring; doctor 11/17."""

import io
import json
import subprocess

import pytest
from agentbox import box as boxmod
from agentbox import cli, compose, delivery, docker, doctor, images, network, paths, secretstore
from agentbox.profile import parse_profile

PROFILE = """
[box]
agents = ["claude", "codex"]
[[mount]]
host = "/w/p"
[secrets]
GH_TOKEN = "shared"
AGENT_ONLY = {}
EXPL = { ref = "env:EXPLICIT_VAR" }
[mcp.servers.docs]
url = "https://mcp.example.com/mcp"
bearer = "GW_ONLY"
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("AGENTBOX_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv(secretstore.ENV_STORE, str(tmp_path / "store.json"))
    paths.write_config({"secret_backend": "env", "secret_prefix": "agentbox-test-c"})
    paths.profiles_dir().mkdir(parents=True)
    paths.profile_file("p1").write_text(PROFILE)
    return tmp_path


def store(tmp_path):
    f = tmp_path / "store.json"
    return json.loads(f.read_text()) if f.exists() else {}


def stdin(monkeypatch, text):
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


def test_secret_set_scopes(env, monkeypatch, capsys):
    stdin(monkeypatch, "v-profile\n")
    assert cli.main(["secret", "set", "p1", "AGENT_ONLY", "--stdin"]) == 0
    stdin(monkeypatch, "v-shared\n")
    assert cli.main(["secret", "set", "--shared", "GH_TOKEN", "--stdin"]) == 0
    stdin(monkeypatch, "v-expl")
    assert cli.main(["secret", "set", "p1", "EXPL", "--stdin"]) == 0
    s = store(env)
    assert s == {
        "AGENTBOX_TEST_C_P1_AGENT_ONLY": "v-profile",
        "AGENTBOX_TEST_C__SHARED_GH_TOKEN": "v-shared",
        "EXPLICIT_VAR": "v-expl",
    }
    out = capsys.readouterr()
    for v in ("v-profile", "v-shared", "v-expl"):
        assert v not in out.out + out.err


def test_secret_set_refusals(env, monkeypatch, capsys):
    for args in (
        ["secret", "set", "p1", "MCP_GATEWAY_TOKEN", "--stdin"],  # reserved
        ["secret", "set", "--shared", "AGENTBOX_X", "--stdin"],  # reserved
        ["secret", "set", "--shared", "https_proxy", "--stdin"],  # reserved, any case
        ["secret", "set", "p1", "1BAD", "--stdin"],  # name rule
        ["secret", "set", "p1", "GH_TOKEN", "--stdin"],  # shared in profile
        ["secret", "set", "--shared", "p1", "X", "--stdin"],  # both
        ["secret", "set", "nope", "X", "--stdin"],  # no profile
    ):
        stdin(monkeypatch, "v\n")
        assert cli.main(args) == 1, args
    stdin(monkeypatch, "nul\x00byte\n")
    assert cli.main(["secret", "set", "p1", "AGENT_ONLY", "--stdin"]) == 1
    stdin(monkeypatch, "")
    assert cli.main(["secret", "set", "p1", "AGENT_ONLY", "--stdin"]) == 1
    assert store(env) == {}
    assert "reserved" in capsys.readouterr().err


def test_secret_set_prompt_needs_tty(env, monkeypatch):
    stdin(monkeypatch, "v\n")  # StringIO: not a tty
    assert cli.main(["secret", "set", "p1", "AGENT_ONLY"]) == 1
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "hidden-v")
    assert cli.main(["secret", "set", "p1", "AGENT_ONLY"]) == 0
    assert store(env)["AGENTBOX_TEST_C_P1_AGENT_ONLY"] == "hidden-v"


def test_secret_ls_and_rm(env, monkeypatch, capsys):
    stdin(monkeypatch, "marker-value-123\n")
    cli.main(["secret", "set", "p1", "AGENT_ONLY", "--stdin"])
    capsys.readouterr()
    assert cli.main(["secret", "ls", "p1"]) == 0
    out = capsys.readouterr().out
    assert "marker-value-123" not in out
    rows = {line.split()[0]: line.split() for line in out.splitlines()[1:]}
    assert rows["AGENT_ONLY"][1:4] == ["profile", "present", "agent"]
    assert rows["GH_TOKEN"][1:4] == ["shared", "missing", "agent"]
    assert rows["GW_ONLY"][1:4] == ["profile", "missing", "mcp-gateway"]
    assert rows["EXPL"][1] == "ref"
    assert rows["CLAUDE_CODE_OAUTH_TOKEN"][1] == "shared"
    assert rows["MCP_GATEWAY_TOKEN"][1] == "box"
    assert cli.main(["secret", "ls", "--shared"]) == 0
    out = capsys.readouterr().out
    assert "GH_TOKEN" in out and "p1" in out and "CLAUDE_CODE_OAUTH_TOKEN" in out
    assert cli.main(["secret", "rm", "p1", "AGENT_ONLY"]) == 0
    assert cli.main(["secret", "rm", "p1", "AGENT_ONLY"]) == 1
    assert store(env) == {}


def test_setup_token_validation(env, monkeypatch, capsys):
    monkeypatch.setattr(docker, "run", lambda a, **k: subprocess.CompletedProcess(a, 0, "29", ""))
    monkeypatch.setattr(images, "ensure_agent", lambda r: "agentbox/agent:x")
    monkeypatch.setattr(images, "ensure_sidecar", lambda r, s: f"agentbox/{s}:x")
    monkeypatch.setattr(cli, "ollama_note", lambda: "host Ollama: not running")
    stdin(monkeypatch, "not-a-token\n")
    assert cli.main(["setup", "--token-stdin", "--skip-doctor"]) == 1
    tok = "sk-ant-oat01-" + "a" * 90
    stdin(monkeypatch, tok + "\n")
    assert cli.main(["setup", "--token-stdin", "--skip-doctor"]) == 0
    assert store(env)["AGENTBOX_TEST_C__SHARED_CLAUDE_CODE_OAUTH_TOKEN"] == tok
    # idempotent: second run keeps the token and the config
    stdin(monkeypatch, "sk-ant-oat01-other\n")
    assert cli.main(["setup", "--token-stdin", "--skip-doctor"]) == 0
    assert store(env)["AGENTBOX_TEST_C__SHARED_CLAUDE_CODE_OAUTH_TOKEN"] == tok
    assert paths.load_config().secret_backend == "env"  # existing choice kept
    out = capsys.readouterr()
    assert tok not in out.out + out.err


def test_setup_writes_keychain_default(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(docker, "run", lambda a, **k: subprocess.CompletedProcess(a, 0, "29", ""))
    monkeypatch.setattr(images, "ensure_agent", lambda r: "a")
    monkeypatch.setattr(images, "ensure_sidecar", lambda r, s: s)
    monkeypatch.setattr(cli, "ollama_note", lambda: "x")
    assert cli.main(["setup", "--skip-token", "--skip-doctor"]) == 0
    assert paths.load_config().secret_backend == "keychain"


def test_setup_needs_docker(tmp_path, monkeypatch):
    monkeypatch.setattr(docker, "run", lambda a, **k: subprocess.CompletedProcess(a, 1, "", "x"))
    assert cli.main(["setup", "--skip-token", "--skip-doctor"]) == 1


def test_ollama_note(monkeypatch):
    import urllib.request

    class R(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    for v, want in (("0.14.2", "ok"), ("0.13.9", "older"), ("0.20.0-rc1", "ok")):
        body = json.dumps({"version": v}).encode()
        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, _b=body, **k: R(_b))
        assert want in cli.ollama_note()

    def down(*a, **k):
        raise OSError("refused")

    monkeypatch.setattr(urllib.request, "urlopen", down)
    assert "not running" in cli.ollama_note()


def test_login_argv(env, monkeypatch, capsys):
    p = parse_profile({"mount": [{"host": "/w/p"}]}, "p1")
    b = boxmod.Box("p1", p, paths.state_dir("p1"), paths.load_config())
    monkeypatch.setattr(boxmod, "load", lambda n: b)
    monkeypatch.setattr(cli, "is_tty", lambda: True)
    seen = []
    monkeypatch.setattr(cli, "session", lambda box, cmd: seen.append(cmd) or 0)
    assert cli.main(["login", "p1", "codex"]) == 0
    assert cli.main(["login", "p1", "pi"]) == 0
    assert seen == [["codex", "login", "--device-auth"], ["pi"]]
    out = capsys.readouterr().out
    assert "Allow device code login" in out and "/login" in out and "paste" in out
    monkeypatch.setattr(cli, "is_tty", lambda: False)
    assert cli.main(["login", "p1", "codex"]) == 1
    with pytest.raises(SystemExit):
        cli.main(["login", "p1", "claude"])  # argparse choices


# ---------------------------------------------------------------- up wiring
def test_up_passes_values_only_in_compose_env(env, monkeypatch):
    s = {
        "AGENTBOX_TEST_C_P1_AGENT_ONLY": "MARK-agent-only",
        "AGENTBOX_TEST_C_P1_GW_ONLY": "MARK-gw-only",
        "AGENTBOX_TEST_C__SHARED_GH_TOKEN": "MARK-gh",
    }
    (env / "store.json").write_text(json.dumps(s))
    p = parse_profile(__import__("tomllib").loads(PROFILE), "p1")
    ms = [m.__class__(**{**m.__dict__, "host_real": m.host}) for m in p.mounts]
    p = p.__class__(**{**p.__dict__, "mounts": ms})
    b = boxmod.Box("p1", p, paths.state_dir("p1"), paths.load_config())
    monkeypatch.setattr(boxmod.mountstate, "check_and_record", lambda *a: None)
    monkeypatch.setattr(images, "ensure_agent", lambda r: "a")
    monkeypatch.setattr(images, "ensure_sidecar", lambda r, s: s)
    monkeypatch.setattr(docker, "subnets", lambda: [])
    monkeypatch.setattr(network, "verify", lambda *a, **k: None)
    monkeypatch.setattr(boxmod, "wait_ready", lambda b: None)
    monkeypatch.setattr(boxmod, "apply_egress", lambda *a: None)
    monkeypatch.setattr(boxmod, "host_git", lambda k: None)
    calls = []

    def dc(box, *args, **kw):
        calls.append((args, kw))
        return subprocess.CompletedProcess(args, 0, "", "")

    execs = []
    monkeypatch.setattr(boxmod, "dc", dc)
    monkeypatch.setattr(
        boxmod, "exec_in", lambda b, c, **k: execs.append(c) or subprocess.CompletedProcess(c, 0)
    )
    boxmod.up(b)
    up_calls = [(a, k) for a, k in calls if a[0] == "up"]
    assert len(up_calls) == 1
    envd = up_calls[0][1]["env"]
    assert envd["AGENTBOX_SECRET_AGENT_ONLY"] == "MARK-agent-only"
    assert envd["AGENTBOX_SECRET_GH_TOKEN"] == "MARK-gh"
    assert envd["AGENTBOX_SECRET_GW_ONLY"] == "MARK-gw-only"  # P6: the gateway runs
    doc0 = json.loads(b.compose_file.read_text())
    gw = {e["source"]: e for e in doc0["services"]["mcp-gateway"]["secrets"]}
    assert set(gw) == {"GW_ONLY", "MCP_GATEWAY_TOKEN"}
    assert all(e["mode"] == "0444" and "uid" not in e and "gid" not in e for e in gw.values())
    assert "GW_ONLY" not in {e["source"] for e in doc0["services"]["agent"]["secrets"]}
    for a, k in calls:
        assert not any("MARK-" in x for x in a)
        if a[0] != "up":
            assert "env" not in k
    for f in b.state.rglob("*"):
        if f.is_file():
            assert b"MARK-" not in f.read_bytes(), f
    doc = json.loads(b.compose_file.read_text())
    assert doc["services"]["agent"]["labels"][delivery.LABEL]
    assert ["gh", "auth", "setup-git", "--hostname", "github.com"] in execs
    for c in execs:
        assert not any("MARK-" in x for x in c)
    # down rotates the per-box token
    tok = delivery.box_tokens(b.state)["MCP_GATEWAY_TOKEN"]
    boxmod.down(b)
    assert delivery.box_tokens(b.state)["MCP_GATEWAY_TOKEN"] != tok


def test_up_without_gh_token_skips_setup_git(env, monkeypatch, capsys):
    b = boxmod.Box("p1", parse_profile({"mount": [{"host": "/w/p"}]}, "p1"),
                   paths.state_dir("p1"), paths.load_config())  # fmt: skip
    execs = []
    monkeypatch.setattr(boxmod, "host_git", lambda k: None)
    monkeypatch.setattr(
        boxmod, "exec_in", lambda b, c, **k: execs.append(c) or subprocess.CompletedProcess(c, 0)
    )
    boxmod.git_setup(b, ["MCP_GATEWAY_TOKEN"])
    assert not any(c[0] == "gh" for c in execs)


def test_missing_secret_messages(env, capsys):
    p = parse_profile(__import__("tomllib").loads(PROFILE), "p1")
    d = delivery.collect(p, paths.load_config(), None, {"agent"}, fetch=lambda r: None)
    boxmod.secret_problems(d, p)
    err = capsys.readouterr().err
    assert "agentbox setup" in err
    assert "`agentbox secret set --shared GH_TOKEN`" in err
    assert "`agentbox secret set p1 AGENT_ONLY`" in err
    assert "store it at env:EXPLICIT_VAR" in err
    assert "GW_ONLY" not in err  # not needed by a rendered service


# ---------------------------------------------------------------- doctor 11 / 17
def dbox(tmp_path, services=("agent", "egress", "ollama-gate", "mcp-gateway")):
    """mcp-gateway rendered by default (a P6 box) so value checks apply."""
    p = parse_profile(__import__("tomllib").loads(PROFILE), "p1")
    cfg = paths.Config(secret_backend="env", secret_prefix="agentbox-test-c")
    (tmp_path / "compose.json").write_text(json.dumps({"services": dict.fromkeys(services, {})}))
    return boxmod.Box("p1", p, tmp_path, cfg)


VALS = {
    "AGENTBOX_TEST_C_P1_AGENT_ONLY": "A-val",
    "AGENTBOX_TEST_C__SHARED_GH_TOKEN": "GH-val",
    "AGENTBOX_TEST_C_P1_GW_ONLY": "GW-secret-val",
}


def vals(ref):
    return VALS.get(ref.removeprefix("env:"))


def fake_box(monkeypatch, run_secrets, env_pairs, cfg_env=(), perms=None, label=None):
    monkeypatch.setattr(doctor, "agent_container", lambda b: "cid")
    monkeypatch.setattr(boxmod, "running_label", lambda b, s="agent": label)
    monkeypatch.setattr(
        docker, "run", lambda a, **k: subprocess.CompletedProcess(a, 0, json.dumps(list(cfg_env)))
    )
    if perms is None:
        perms = "".join(f"{n} 0 440 r\n" for n in run_secrets)
    out = (
        "\n".join(run_secrets)
        + "\n\0AGENTBOX-PERM\0"
        + perms
        + "\0AGENTBOX-ENV\0"
        + "".join(f"{k}={v}\0" for k, v in env_pairs)
    )
    monkeypatch.setattr(
        boxmod, "exec_in", lambda b, c, **k: subprocess.CompletedProcess(c, 0, out, "")
    )


def test_check_11_pass(tmp_path, monkeypatch):
    b = dbox(tmp_path)
    tok = delivery.box_tokens(tmp_path)["MCP_GATEWAY_TOKEN"]
    names = ["AGENT_ONLY", "GH_TOKEN", "MCP_GATEWAY_TOKEN"]
    fake_box(monkeypatch, names,
             [("AGENT_ONLY", "A-val"), ("GH_TOKEN", "GH-val"), ("MCP_GATEWAY_TOKEN", tok),
              ("PATH", "/usr/bin")])  # fmt: skip
    r = doctor.check_11(b, fetch=vals)
    assert r.status == "PASS", r.detail
    assert "GW-secret-val" not in r.line() and "A-val" not in r.line()


@pytest.mark.parametrize(
    "rs, envp, cfg_env, want",
    [
        (["AGENT_ONLY", "GH_TOKEN", "MCP_GATEWAY_TOKEN", "GW_ONLY"], [], (),
         "not targeted at agent"),
        (["AGENT_ONLY", "MCP_GATEWAY_TOKEN"], [], (), "missing from /run/secrets: GH_TOKEN"),
        (["AGENT_ONLY", "GH_TOKEN", "MCP_GATEWAY_TOKEN"], [("GW_ONLY", "x")], (),
         "sidecar-only secret names"),
        (["AGENT_ONLY", "GH_TOKEN", "MCP_GATEWAY_TOKEN"], [("OTHER", "pre-GW-secret-val")], (),
         "value of sidecar-only secret GW_ONLY"),
        (["AGENT_ONLY", "GH_TOKEN", "MCP_GATEWAY_TOKEN"], [], ("X=GW-secret-val",),
         "value of sidecar-only secret GW_ONLY"),
    ],
)  # fmt: skip
def test_check_11_fail(tmp_path, monkeypatch, rs, envp, cfg_env, want):
    b = dbox(tmp_path)
    tok = delivery.box_tokens(tmp_path)["MCP_GATEWAY_TOKEN"]
    base = [("AGENT_ONLY", "A-val"), ("GH_TOKEN", "GH-val"), ("MCP_GATEWAY_TOKEN", tok)]
    fake_box(monkeypatch, rs, base + envp, cfg_env)
    r = doctor.check_11(b, fetch=vals)
    assert r.status == "FAIL" and want in r.detail
    assert "GW-secret-val" not in r.detail


def test_check_11_p4_box_reads_no_sidecar_value(tmp_path, monkeypatch):
    b = dbox(tmp_path, services=("agent", "egress", "ollama-gate"))
    tok = delivery.box_tokens(tmp_path)["MCP_GATEWAY_TOKEN"]
    names = ["AGENT_ONLY", "GH_TOKEN", "MCP_GATEWAY_TOKEN"]
    base = [("AGENT_ONLY", "A-val"), ("GH_TOKEN", "GH-val"), ("MCP_GATEWAY_TOKEN", tok)]
    fake_box(monkeypatch, names, base)
    asked = []
    r = doctor.check_11(b, fetch=lambda ref: asked.append(ref) or vals(ref))
    assert r.status == "PASS", r.detail
    assert not any("GW_ONLY" in x for x in asked)  # never read from the backend
    # ...but the name is still checked
    fake_box(monkeypatch, names, [("AGENT_ONLY", "A-val"), ("GH_TOKEN", "GH-val"),
                                  ("MCP_GATEWAY_TOKEN", tok), ("GW_ONLY", "x")])  # fmt: skip
    assert "sidecar-only secret names" in doctor.check_11(b, fetch=vals).detail


@pytest.mark.parametrize(
    "perms, want",
    [
        ("AGENT_ONLY 1000 400 w\nGH_TOKEN 0 440 r\nMCP_GATEWAY_TOKEN 0 440 r\n",
         "AGENT_ONLY is owned by the agent"),
        ("AGENT_ONLY 0 666 w\nGH_TOKEN 0 440 r\nMCP_GATEWAY_TOKEN 0 440 r\n",
         "AGENT_ONLY is writable by the agent"),
        ("AGENT_ONLY 0 440 r\nGH_TOKEN 0 440 r\nMCP_GATEWAY_TOKEN 0 440 r\n. dir - w\n",
         "/run/secrets is writable"),
    ],
)  # fmt: skip
def test_check_11_ownership(tmp_path, monkeypatch, perms, want):
    b = dbox(tmp_path)
    tok = delivery.box_tokens(tmp_path)["MCP_GATEWAY_TOKEN"]
    names = ["AGENT_ONLY", "GH_TOKEN", "MCP_GATEWAY_TOKEN"]
    envp = [("AGENT_ONLY", "A-val"), ("GH_TOKEN", "GH-val"), ("MCP_GATEWAY_TOKEN", tok)]
    fake_box(monkeypatch, names, envp, perms=perms)
    r = doctor.check_11(b, fetch=vals)
    assert r.status == "FAIL" and want in r.detail


def test_full_scratch_mode_warns_17_live(tmp_path, monkeypatch):
    b = dbox(tmp_path)
    monkeypatch.setattr(
        doctor, "_full",
        lambda b: [doctor.Result("FAIL", "17 live", "x"), doctor.Result("PASS", "17 env")],
    )  # fmt: skip
    assert [r.status for r in doctor.full(b)] == ["FAIL", "PASS"]
    assert [r.status for r in doctor.full(b, scratch=True)] == ["WARN", "PASS"]
    monkeypatch.setattr(
        doctor, "_full",
        lambda b: [doctor.Result("FAIL", "17 env", "x")],
    )  # fmt: skip
    assert doctor.full(b, scratch=True)[0].status == "FAIL"  # 17 env stays in the gate


def test_classify_claude():
    c = doctor.classify_claude
    assert c(0, "OK") == "ok"
    assert c(1, 'API Error: 401 {"type":"authentication_error","message":"Invalid bearer token"}')
    assert c(1, "Failed to authenticate. API Error: 401") == "rejected"
    assert c(1, "Not logged in · Please run /login") == "no-token"
    assert c(1, "network error") == "other"


def test_check_17(tmp_path):
    b = dbox(tmp_path)
    tokref = "AGENTBOX_TEST_C__SHARED_CLAUDE_CODE_OAUTH_TOKEN"
    runs = []

    def run(ok_env, live):
        def f(box, pre):
            runs.append(pre)
            if pre:
                return ok_env
            return live

        return f

    # invalid env token rejected, no token in backend -> live SKIP
    r = doctor.check_17(b, fetch=lambda ref: None, run=run((1, "API Error: 401"), None))
    assert [(x.check, x.status) for x in r] == [("17 env", "PASS"), ("17 live", "SKIP")]
    assert runs[0] == ["env", f"CLAUDE_CODE_OAUTH_TOKEN={doctor.FAKE_CLAUDE_TOKEN}"]
    # "Not logged in" means the env token was not used -> FAIL
    r = doctor.check_17(b, fetch=lambda ref: None, run=run((1, "Not logged in"), None))
    assert r[0].status == "FAIL"
    # real token present and works
    real = {"env:" + tokref: "sk-ant-oat01-real"}
    r = doctor.check_17(b, fetch=real.get, run=run((1, "401"), (0, "OK")))
    assert [x.status for x in r] == ["PASS", "PASS"]
    # delivered token rejected: FAIL, the token never appears in the detail
    r = doctor.check_17(b, fetch=real.get, run=run((1, "401"), (1, "401 sk-ant-oat01-real")))
    assert r[1].status == "FAIL" and "rejected" in r[1].detail
    assert "agentbox secret set --shared CLAUDE_CODE_OAUTH_TOKEN" in r[1].detail
    assert "sk-ant-oat01-real" not in r[1].detail
    # no claude agent: SKIP both
    p = parse_profile({"box": {"agents": ["pi"]}, "mount": [{"host": "/w/p"}]}, "p1")
    b2 = boxmod.Box("p1", p, tmp_path, b.cfg)
    assert [x.status for x in doctor.check_17(b2)] == ["SKIP", "SKIP"]


def test_compose_render_has_no_secrets_without_delivery(tmp_path):
    # P3 render unchanged: secrets are added only by delivery.apply
    p = dbox(tmp_path).profile
    ms = [m.__class__(**{**m.__dict__, "host_real": m.host}) for m in p.mounts]
    p = p.__class__(**{**p.__dict__, "mounts": ms})
    ctx = compose.Ctx(p, 3, network.DEFAULT_BASE, tmp_path, "a", "e", "g", linux=False)
    assert "secrets" not in compose.render(ctx)


# ---------------------------------------------------------------- round 2
def test_op_sa_token_name(env, monkeypatch):
    stdin(monkeypatch, "ops_tok\n")
    assert cli.main(["secret", "set", "p1", "_OP_SERVICE_ACCOUNT_TOKEN", "--stdin"]) == 0
    assert store(env)["AGENTBOX_TEST_C_P1__OP_SERVICE_ACCOUNT_TOKEN"] == "ops_tok"
    stdin(monkeypatch, "x\n")
    assert cli.main(["secret", "set", "--shared", "_OP_SERVICE_ACCOUNT_TOKEN", "--stdin"]) == 1
    # never a box secret
    from agentbox.profile import ProfileError

    with pytest.raises(ProfileError):
        parse_profile(
            {"mount": [{"host": "/w"}], "secrets": {"_OP_SERVICE_ACCOUNT_TOKEN": {}}}, "p"
        )


def running_box(env, monkeypatch, label, others_hold_lock):
    p = parse_profile(__import__("tomllib").loads(PROFILE), "p1")
    b = boxmod.Box("p1", p, paths.state_dir("p1"), paths.load_config())
    monkeypatch.setattr(boxmod, "running_label", lambda box, s="agent": label)
    monkeypatch.setattr(boxmod, "sessions_active", lambda box: others_hold_lock)
    return b


def docs(new_label="NEW"):
    old = {"services": {"agent": {"labels": {delivery.LABEL: "OLD"},
                                  "secrets": [{"source": "A", "target": "A"}]}},
           "secrets": {"A": {"environment": "AGENTBOX_SECRET_A"}}}  # fmt: skip
    new = {"services": {"agent": {"labels": {delivery.LABEL: new_label},
                                  "secrets": [{"source": "A", "target": "A"},
                                              {"source": "B", "target": "B"}]}},
           "secrets": {"A": {"environment": "AGENTBOX_SECRET_A"},
                       "B": {"environment": "AGENTBOX_SECRET_B"}}}  # fmt: skip
    return old, new


DL = delivery.Delivery(values={"A": "a", "B": "b"})


def test_secret_change_deferred_while_sessions_run(env, monkeypatch):
    b = running_box(env, monkeypatch, "OLD", True)
    old, new = docs()
    assert boxmod.keep_running_secrets(b, new, old, DL) is True
    assert new["services"]["agent"] == old["services"]["agent"]
    assert new["secrets"] == old["secrets"]
    # no other session: recreate (doc unchanged)
    b = running_box(env, monkeypatch, "OLD", False)
    old, new = docs()
    assert boxmod.keep_running_secrets(b, new, old, DL) is False
    assert new["services"]["agent"]["labels"][delivery.LABEL] == "NEW"
    # same label: nothing to defer
    b = running_box(env, monkeypatch, "NEW", True)
    old, new = docs()
    assert boxmod.keep_running_secrets(b, new, old, DL) is False
    # a running name the backend no longer has (removed secret): recreate, never
    # restore a name whose env var would be unset
    b = running_box(env, monkeypatch, "OLD", True)
    old, new = docs()
    removed = delivery.Delivery(values={"B": "b"})
    assert boxmod.keep_running_secrets(b, new, old, removed) is False
    assert new["services"]["agent"]["labels"][delivery.LABEL] == "NEW"


def test_sessions_active_with_real_locks(env):
    import fcntl

    p = parse_profile(__import__("tomllib").loads(PROFILE), "p1")
    b = boxmod.Box("p1", p, paths.state_dir("p1"), paths.load_config())
    with boxmod.session_lock(b):
        assert boxmod.sessions_active(b) is False  # only us
        other = (b.state / "session.lock").open("a")
        fcntl.flock(other, fcntl.LOCK_SH)
        assert boxmod.sessions_active(b) is True
        other.close()
        assert boxmod.sessions_active(b) is False
    assert b.lock_fd is None
    assert boxmod.sessions_active(b) is False


def test_compose_env_skips_names_without_values():
    d = delivery.Delivery(values={"A": "v"}, targets={"A": ["agent"], "B": ["agent"]})
    doc = {"secrets": {"A": {}, "B": {}}}
    assert delivery.compose_env(d, doc) == {"AGENTBOX_SECRET_A": "v"}


def up_env(env, monkeypatch, running, dc_up=None):
    (env / "store.json").write_text(
        json.dumps({"AGENTBOX_TEST_C_P1_AGENT_ONLY": "MARK-SECRET-VALUE-0123456789"})
    )
    p = parse_profile(__import__("tomllib").loads(PROFILE), "p1")
    ms = [m.__class__(**{**m.__dict__, "host_real": m.host}) for m in p.mounts]
    p = p.__class__(**{**p.__dict__, "mounts": ms})
    b = boxmod.Box("p1", p, paths.state_dir("p1"), paths.load_config())
    monkeypatch.setattr(boxmod.mountstate, "check_and_record", lambda *a: None)
    monkeypatch.setattr(images, "ensure_agent", lambda r: "a")
    monkeypatch.setattr(images, "ensure_sidecar", lambda r, s: s)
    monkeypatch.setattr(docker, "subnets", lambda: [])
    monkeypatch.setattr(network, "verify", lambda *a, **k: None)
    monkeypatch.setattr(boxmod, "wait_ready", lambda b: None)
    monkeypatch.setattr(boxmod, "apply_egress", lambda *a: None)
    monkeypatch.setattr(boxmod, "git_setup", lambda *a: None)
    monkeypatch.setattr(boxmod, "is_running", lambda b: running)
    monkeypatch.setattr(boxmod, "keep_running_secrets", lambda *a: False)

    def dc(box, *args, **kw):
        if args[0] == "up" and dc_up:
            dc_up(kw)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(boxmod, "dc", dc)
    return b


def test_missing_warnings_only_on_explicit_or_start(env, monkeypatch, capsys):
    b = up_env(env, monkeypatch, running=True)
    boxmod.up(b)  # a session attaching to a running box: quiet
    assert "missing" not in capsys.readouterr().err
    boxmod.up(b, explicit=True)
    assert "GH_TOKEN" in capsys.readouterr().err
    b = up_env(env, monkeypatch, running=False)
    boxmod.up(b)  # the box starts
    assert "GH_TOKEN" in capsys.readouterr().err


def test_compose_error_is_scrubbed(env, monkeypatch):
    def fail(kw):
        v = kw["env"]["AGENTBOX_SECRET_AGENT_ONLY"]
        raise docker.DockerError(f"docker compose up failed (1): bad {v} and {v[3:25]}")

    b = up_env(env, monkeypatch, running=False, dc_up=fail)
    with pytest.raises(boxmod.BoxError) as e:
        boxmod.up(b)
    assert "MARK-SECRET" not in str(e.value) and "SECRET-VALUE" not in str(e.value)


def test_inherited_secret_env_is_dropped(env, monkeypatch):
    monkeypatch.setenv("AGENTBOX_SECRET_GH_TOKEN", "FROM-USER-SHELL")
    monkeypatch.setenv("AGENTBOX_SECRET_OTHER", "FROM-USER-SHELL")
    seen = {}
    b = up_env(env, monkeypatch, running=False, dc_up=lambda kw: seen.update(kw["env"]))
    boxmod.up(b)
    assert "AGENTBOX_SECRET_OTHER" not in seen
    assert "AGENTBOX_SECRET_GH_TOKEN" not in seen  # GH_TOKEN missing in the backend
    assert seen["AGENTBOX_SECRET_AGENT_ONLY"] == "MARK-SECRET-VALUE-0123456789"


def test_probe_keeps_every_shared_lock(env):
    import fcntl

    p = parse_profile(__import__("tomllib").loads(PROFILE), "p1")
    mk = lambda: boxmod.Box("p1", p, paths.state_dir("p1"), paths.load_config())  # noqa: E731
    run_box, up_box = mk(), mk()
    with boxmod.session_lock(run_box), boxmod.session_lock(up_box):
        assert boxmod.sessions_active(up_box) is True
        assert boxmod.sessions_active(run_box) is True
        # both shared locks are still held: an exclusive try must fail
        with (up_box.state / "session.lock").open("a") as g, pytest.raises(BlockingIOError):
            fcntl.flock(g, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_stop_if_idle_waits_for_up_and_sees_its_session(env, monkeypatch):
    """run-vs-up: while `up` (holding up.lock) attaches a new session, run's
    stop-if-idle blocks; afterwards it sees the session and keeps the box."""
    import threading

    p = parse_profile(__import__("tomllib").loads(PROFILE), "p1")
    mk = lambda: boxmod.Box("p1", p, paths.state_dir("p1"), paths.load_config())  # noqa: E731
    run_box, sess_box = mk(), mk()
    downs = []
    monkeypatch.setattr(boxmod, "down_locked", lambda b, volumes=False: downs.append(1))
    monkeypatch.setattr(boxmod, "other_processes", lambda b: [])
    result = {}
    with boxmod.session_lock(run_box):
        upcm = boxmod.up_lock(sess_box)
        upcm.__enter__()  # an `up` in progress for a new session
        t = threading.Thread(target=lambda: result.setdefault("why", boxmod.stop_if_idle(run_box)))
        t.start()
        t.join(0.5)
        assert t.is_alive() and not downs  # blocked on up.lock
        new_session = boxmod.session_lock(sess_box)
        new_session.__enter__()  # the session starts before up releases
        upcm.__exit__(None, None, None)
        t.join(5)
        assert not t.is_alive()
        assert result["why"] == "another agentbox session uses the box" and not downs
        new_session.__exit__(None, None, None)
        assert boxmod.stop_if_idle(run_box) is None and downs == [1]  # now idle


def test_stop_if_idle_kills_leftovers_unless_pinned(env, monkeypatch):
    p = parse_profile(__import__("tomllib").loads(PROFILE), "p1")
    b = boxmod.Box("p1", p, paths.state_dir("p1"), paths.load_config())
    b.state.mkdir(parents=True, exist_ok=True)
    downs = []
    monkeypatch.setattr(boxmod, "down_locked", lambda b, volumes=False: downs.append(1))
    procs = [f"sh -c loop{i}" for i in range(5)]
    monkeypatch.setattr(boxmod, "other_processes", lambda b: procs)
    note: list[str] = []
    with boxmod.session_lock(b):  # the run's own session does not count
        assert boxmod.stop_if_idle(b, note) is None
    assert downs == [1]
    assert note == ["killed leftover processes (sh -c loop0, sh -c loop1, sh -c loop2, ...)"]
    boxmod.pin(b)
    note.clear()
    assert boxmod.stop_if_idle(b, note) == boxmod.PINNED and downs == [1] and not note


def test_check_11_deferred(tmp_path, monkeypatch):
    b = dbox(tmp_path)
    tok = delivery.box_tokens(tmp_path)["MCP_GATEWAY_TOKEN"]
    # running set = the old one (no AGENT_ONLY yet); a session is active
    names = ["GH_TOKEN", "MCP_GATEWAY_TOKEN"]
    envp = [("GH_TOKEN", "GH-val"), ("MCP_GATEWAY_TOKEN", tok)]
    monkeypatch.setattr(boxmod, "sessions_active", lambda b: True)
    fake_box(monkeypatch, names, envp, label="OLD-LABEL")
    r = doctor.check_11(b, fetch=vals)
    assert r.status == "PASS" and "secret change deferred: sessions active" in r.detail
    # ownership is still enforced during a deferral
    fake_box(monkeypatch, names, envp, label="OLD-LABEL",
             perms="GH_TOKEN 1000 440 w\nMCP_GATEWAY_TOKEN 0 444 r\n")  # fmt: skip
    assert doctor.check_11(b, fetch=vals).status == "FAIL"
    # ...and sidecar names
    fake_box(monkeypatch, names, [*envp, ("GW_ONLY", "x")], label="OLD-LABEL")
    assert "sidecar-only" in doctor.check_11(b, fetch=vals).detail
    # no session: the same mismatch is a FAIL
    monkeypatch.setattr(boxmod, "sessions_active", lambda b: False)
    fake_box(monkeypatch, names, envp, label="OLD-LABEL")
    assert "missing from /run/secrets: AGENT_ONLY" in doctor.check_11(b, fetch=vals).detail


@pytest.mark.parametrize(
    "out, scratch_status",
    [
        ("API Error: 429 rate_limit_error", "WARN"),
        ("API Error: 529 overloaded_error", "WARN"),
        ("fetch failed: ECONNRESET", "WARN"),
        ("Not logged in · Please run /login", "FAIL"),
    ],
)
def test_scratch_17_env(tmp_path, out, scratch_status):
    b = dbox(tmp_path)

    def run(box, pre):
        return (1, out) if pre else (0, "OK")

    r = doctor.check_17(b, fetch=lambda ref: None, run=run)
    assert r[0].status == "FAIL"
    orig = doctor._full
    try:
        doctor._full = lambda box: r
        assert doctor.full(b, scratch=True)[0].status == scratch_status
    finally:
        doctor._full = orig
    ok = doctor.check_17(b, fetch=lambda ref: None, run=lambda box, pre: (0, "OK"))
    assert ok[0].kind == "ok" and ok[0].status == "FAIL"  # success with a fake token


def test_setup_linux_never_writes_keychain(tmp_path, monkeypatch, capsys):
    """P8: simulated Linux host, no backend configured -> clear stop, no config."""
    import sys

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "cfg"))
    calls = []
    monkeypatch.setattr(docker, "run", lambda a, **k: calls.append(a))
    assert cli.main(["setup", "--skip-token", "--skip-doctor"]) == 1
    err = capsys.readouterr().err
    assert "keychain secret backend is macOS-only" in err and 'secret_backend = "op"' in err
    assert not paths.config_file().exists() and calls == []  # stops before Docker/builds
    paths.write_config({"secret_backend": "keychain"})
    assert cli.main(["setup", "--skip-token", "--skip-doctor"]) == 1
    assert "macOS-only" in capsys.readouterr().err


def test_setup_linux_with_env_backend(tmp_path, monkeypatch):
    import sys

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "cfg"))
    paths.write_config({"secret_backend": "env"})
    monkeypatch.setattr(docker, "run", lambda a, **k: subprocess.CompletedProcess(a, 0, "29", ""))
    monkeypatch.setattr(images, "ensure_agent", lambda r: "a")
    monkeypatch.setattr(images, "ensure_sidecar", lambda r, s: s)
    monkeypatch.setattr(cli, "ollama_note", lambda: "x")
    assert cli.main(["setup", "--skip-token", "--skip-doctor"]) == 0
    assert paths.load_config().secret_backend == "env"


def test_keychain_on_linux_clear_error(tmp_path, monkeypatch, capsys):
    import sys

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("AGENTBOX_STATE_HOME", str(tmp_path / "state"))
    paths.write_config({"secret_backend": "keychain"})
    paths.profiles_dir().mkdir(parents=True)
    paths.profile_file("p1").write_text(PROFILE)
    ran = []
    monkeypatch.setattr(secretstore, "_run", lambda *a, **k: ran.append(a))
    monkeypatch.setattr("sys.stdin", io.StringIO("v\n"))
    assert cli.main(["secret", "set", "p1", "AGENT_ONLY", "--stdin"]) != 0
    assert "keychain secret backend is macOS-only" in capsys.readouterr().err
    assert secretstore.get("agentbox-keychain:agentbox/p1/AGENT_ONLY") is None  # owned: absent
    with pytest.raises(secretstore.SecretError, match="macOS-only"):
        secretstore.get("keychain:some/item")
    assert ran == []  # `security` never called


def test_mcp_login_keychain_on_linux(tmp_path, monkeypatch):
    import sys

    from agentbox import mcpcmd

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("AGENTBOX_STATE_HOME", str(tmp_path / "state"))
    paths.write_config({"secret_backend": "keychain"})
    paths.profiles_dir().mkdir(parents=True)
    paths.profile_file("p1").write_text(
        PROFILE + '\n[mcp.servers.od]\nurl = "https://mcp2.example.com/mcp"\nauth = "oauth"\n'
    )
    monkeypatch.setattr(mcpcmd.mcpoauth, "login", lambda *a, **k: pytest.fail("flow ran"))
    with pytest.raises(mcpcmd.McpCmdError, match="macOS-only"):
        mcpcmd.login("p1", "od")
