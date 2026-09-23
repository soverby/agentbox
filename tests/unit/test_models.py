"""P5 model routing (PLAN §2.5): `--model` parsing, launch argv/env per agent
and route kind, router config, egress ACLs, delivery of the router key."""

import json
import os
import subprocess

import pytest
from agentbox import compose, delivery, egress, launch, network, paths, router, secretstore
from agentbox.profile import ProfileError, parse_profile

REMOTE = {
    "qwen": {"api_base": "https://ws--vllm.modal.run/v1", "key": "MODAL_API_KEY",
             "model": "Qwen/Qwen3-Coder", "provider": "vllm"},
    "gpt": {"api_base": "https://api.example.com/v1", "key": "EX_KEY"},
    "open": {"api_base": "https://open.example.org/v1"},
}  # fmt: skip
KEY_VALUE = "sk-remote-VALUE-must-not-leak"
MASTER_VALUE = "sk-master-VALUE-must-not-leak"
BYPASS = "--dangerously-bypass-approvals-and-sandbox"


def prof(remote=None, ollama="local", agents=("claude", "codex", "pi"), **extra):
    doc = {
        "box": {"agents": list(agents)},
        "mount": [{"host": "/work/proj", "mode": "rw"}],
        "models": {"ollama": ollama, **({"remote": remote} if remote else {})},
        **extra,
    }
    p = parse_profile(doc, "p1")
    ms = [m.__class__(**{**m.__dict__, "host_real": m.host}) for m in p.mounts]
    return p.__class__(**{**p.__dict__, "mounts": ms})


def ctx(p, tmp_path):
    return compose.Ctx(p, 7, network.DEFAULT_BASE, tmp_path, "a", "e", "g", "gw", "rt",
                       linux=False)  # fmt: skip


# ---------------------------------------------------------------- --model
def test_parse_model_kinds():
    p = prof(REMOTE)
    assert launch.parse_model(p, None) is None
    assert launch.parse_model(p, "ollama/qwen3:8b") == launch.ModelRoute("ollama", "qwen3:8b")
    assert launch.parse_model(p, "remote/qwen") == launch.ModelRoute("remote", "qwen")
    assert launch.parse_model(p, "sonnet") == launch.ModelRoute("native", "sonnet")
    assert launch.parse_model(p, "gpt-5.1-codex") == launch.ModelRoute("native", "gpt-5.1-codex")


@pytest.mark.parametrize("spec", ["remote/nope", "remote/", "ollama/", "ollama/-x",
                                  "ollama/gpt-oss:120b-cloud", "ollama/x:CLOUD", "-rm",
                                  "--dangerously", "a b", "x;y", ""])  # fmt: skip
def test_parse_model_refused(spec):
    with pytest.raises(launch.ResolveError):
        launch.parse_model(prof(REMOTE), spec)


def test_missing_remote_is_a_hard_error_with_names():
    with pytest.raises(launch.ResolveError, match=r"no \[models.remote.nope\].*gpt, open, qwen"):
        launch.parse_model(prof(REMOTE), "remote/nope")


def test_ollama_list_restricts_models():
    p = prof(ollama=["llama3.2", "qwen3:8b"])
    assert launch.parse_model(p, "ollama/llama3.2:latest").model == "llama3.2:latest"
    assert launch.parse_model(p, "ollama/qwen3:8b").model == "qwen3:8b"
    with pytest.raises(launch.ResolveError, match="not in"):
        launch.parse_model(p, "ollama/mistral")


# ---------------------------------------------------------------- launch
def L(agent, spec, headless=False, args=(), p=None):  # noqa: N802
    p = p or prof(REMOTE)
    return launch.agent_launch(
        p, agent, list(args), headless, launch.parse_model(p, spec) if spec else None
    )


@pytest.mark.parametrize("agent", ["claude", "codex", "pi"])
@pytest.mark.parametrize("headless", [False, True])
def test_no_model_is_unchanged(agent, headless):
    p = prof(REMOTE)
    ln = L(agent, None, headless, ["x"] if not headless else [])
    assert ln.env == {}
    assert ln.argv == launch.agent_argv(p, agent, ["x"] if not headless else [], headless)


def test_claude_ollama():
    ln = L("claude", "ollama/qwen3:8b", headless=True)
    assert ln.env["ANTHROPIC_BASE_URL"] == "http://ollama-gate:11434"
    assert ln.env["ANTHROPIC_AUTH_TOKEN"] == "ollama"
    assert all(ln.env[k] == "qwen3:8b" for k in launch.CLAUDE_MODEL_ENVS)
    assert ln.argv[:4] == ["sh", "-c", launch.CLAUDE_SHIM["ollama"], launch.SHIM_NAME]
    assert "unset CLAUDE_CODE_OAUTH_TOKEN" in ln.argv[2]
    assert ln.argv[4:] == ["claude", "--dangerously-skip-permissions", "-p",
                           "--model", "qwen3:8b"]  # fmt: skip


def test_claude_remote_key_by_name_only():
    ln = L("claude", "remote/qwen", args=["--version"])
    assert ln.env["ANTHROPIC_BASE_URL"] == "http://router:4000"
    assert "ANTHROPIC_AUTH_TOKEN" not in ln.env  # set from the delivered secret in the box
    assert ln.argv[:2] == ["sh", "-c"]
    assert "ANTHROPIC_AUTH_TOKEN=$AGENTBOX_ROUTER_MASTER_KEY" in ln.argv[2]
    assert "unset CLAUDE_CODE_OAUTH_TOKEN" in ln.argv[2]
    assert ln.argv[4:] == ["claude", "--dangerously-skip-permissions", "--model", "qwen",
                           "--version"]  # fmt: skip


def test_claude_native():
    ln = L("claude", "opus")
    assert ln.env == {} and ln.argv == ["claude", "--dangerously-skip-permissions",
                                        "--model", "opus"]  # fmt: skip


def test_codex_ollama_overrides():
    ln = L("codex", "ollama/qwen3:8b", headless=True)
    assert ln.env == {}
    a = ln.argv
    assert a[:2] == ["codex", "exec"] and a[-2:] == ["--skip-git-repo-check", "-"]
    i = a.index(BYPASS)
    ov = a[a.index("mcp_servers.agentbox.enabled=true") + 1 : i]
    assert ov == [
        "-c", 'model_provider="agentbox_ollama"',
        "-c", 'model_providers.agentbox_ollama.name="agentbox ollama"',
        "-c", 'model_providers.agentbox_ollama.base_url="http://ollama-gate:11434/v1"',
        "-c", 'model_providers.agentbox_ollama.wire_api="responses"',
        "-c", 'model="qwen3:8b"',
    ]  # fmt: skip


def test_codex_remote_env_key():
    ln = L("codex", "remote/gpt", args=["hi"])
    a = ln.argv
    assert "-c" in a and 'model_providers.agentbox_router.env_key="AGENTBOX_ROUTER_MASTER_KEY"' in a
    assert 'model_providers.agentbox_router.base_url="http://router:4000/v1"' in a
    assert 'model_providers.agentbox_router.wire_api="responses"' in a
    assert 'model="gpt"' in a and a[-1] == "hi" and a.index(BYPASS) < a.index("hi")


def test_codex_native_before_exec_dash():
    a = L("codex", "gpt-5.1-codex", headless=True).argv
    assert a[-1] == "-" and a[a.index("--model") + 1] == "gpt-5.1-codex"


def test_pi_routes():
    ln = L("pi", "ollama/qwen3:8b", headless=True)
    assert ln.env == {"AGENTBOX_MODEL_ROUTE": "ollama", "AGENTBOX_MODEL_ID": "qwen3:8b"}
    assert ln.argv == ["pi", "-p", "--provider", "agentbox-ollama", "--model", "qwen3:8b"]
    ln = L("pi", "remote/qwen")
    assert ln.env == {"AGENTBOX_MODEL_ROUTE": "remote", "AGENTBOX_MODEL_ID": "qwen"}
    assert ln.argv == ["pi", "--provider", "agentbox-router", "--model", "qwen"]
    assert L("pi", "anthropic/claude-sonnet-5").argv == [
        "pi", "--model", "anthropic/claude-sonnet-5",
    ]  # fmt: skip


@pytest.mark.parametrize("agent", ["claude", "codex", "pi"])
@pytest.mark.parametrize("spec", ["ollama/qwen3:8b", "remote/qwen", "remote/gpt", "sonnet"])
def test_no_secret_value_or_ref_in_argv_or_env(agent, spec):
    ln = L(agent, spec, headless=True)
    blob = json.dumps([ln.argv, ln.env])
    for bad in (KEY_VALUE, MASTER_VALUE, "MODAL_API_KEY", "EX_KEY", "os.environ/"):
        assert bad not in blob
    ex = launch.exec_argv("proj", "/f.json", "/w", ln.argv, False, ln.env)
    assert ex[ex.index("agent") + 1] == launch.WITH_SECRETS
    for k, v in ln.env.items():
        assert ex[ex.index(f"{k}={v}") - 1] == "-e"


def test_claude_shim_exports_key_without_argv(tmp_path):
    """The shim, run by a real sh: the key reaches the child env by name, the
    subscription token is gone, and argv holds no value."""
    out = tmp_path / "out"
    script = (
        f'printf "%s\\n" "$ANTHROPIC_AUTH_TOKEN" "${{CLAUDE_CODE_OAUTH_TOKEN-unset}}" "$*" > {out}'
    )
    env = {"PATH": os.environ["PATH"], "AGENTBOX_ROUTER_MASTER_KEY": MASTER_VALUE,
           "CLAUDE_CODE_OAUTH_TOKEN": "oauth-x"}  # fmt: skip
    argv = ["sh", "-c", launch.CLAUDE_SHIM["remote"], launch.SHIM_NAME, "sh", "-c", script]
    assert MASTER_VALUE not in " ".join(argv)
    subprocess.run(argv, env=env, check=True)
    assert out.read_text().splitlines()[:2] == [MASTER_VALUE, "unset"]
    r = subprocess.run(argv, env={"PATH": os.environ["PATH"]}, capture_output=True, text=True)
    assert r.returncode == 1 and "no router key" in r.stderr


# ---------------------------------------------------------------- profile
def test_profile_remote_model_and_provider():
    p = prof(REMOTE)
    q, g = p.models.remote["qwen"], p.models.remote["gpt"]
    assert (q.model, q.provider) == ("Qwen/Qwen3-Coder", "vllm")
    assert (g.model, g.provider) == ("gpt", "openai")


@pytest.mark.parametrize("bad", [{"provider": "azure"}, {"model": "-x"}, {"model": "a b"}])
def test_profile_remote_bad_fields(bad):
    with pytest.raises(ProfileError):
        prof({"m": {"api_base": "https://x.io/v1", **bad}})


# ---------------------------------------------------------------- router config
def test_router_config_render():
    cfg = router.config(prof(REMOTE))
    gs = cfg["general_settings"]
    assert gs["allowed_routes"] == [
        "/v1/messages", "/v1/messages/count_tokens", "/v1/responses", "/v1/chat/completions",
        "/chat/completions", "/v1/models", "/models", "/health/liveliness",
    ]  # fmt: skip
    assert gs["master_key"] == "os.environ/AGENTBOX_ROUTER_MASTER_KEY"
    assert gs["store_model_in_db"] is False
    assert gs["forward_client_headers_to_llm_api"] is False
    assert cfg["litellm_settings"]["callbacks"] == ["agentbox_guard.guard"]
    assert "database_url" not in json.dumps(cfg).lower()
    ml = {m["model_name"]: m["litellm_params"] for m in cfg["model_list"]}
    assert ml["qwen"] == {"model": "hosted_vllm/Qwen/Qwen3-Coder",
                          "api_base": "https://ws--vllm.modal.run/v1",
                          "api_key": "os.environ/MODAL_API_KEY",
                          "use_chat_completions_api": True}  # fmt: skip
    assert ml["gpt"]["model"] == "openai/gpt" and ml["gpt"]["api_key"] == "os.environ/EX_KEY"
    assert ml["open"]["api_key"] == router.NO_KEY
    # YAML is a superset of JSON: the rendered text is valid JSON
    assert json.loads(router.config_text(prof(REMOTE))) == cfg


@pytest.mark.parametrize("url", ["http://x.io/v1", "https://x.io:8443/v1", "https://localhost/v1",
                                 "https://host.docker.internal/v1", "https://10.0.0.1/v1",
                                 "https://127.0.0.1/v1"])  # fmt: skip
def test_router_refuses_unreachable_api_base(url):
    with pytest.raises(router.RouterError):
        router.check(prof({"m": {"api_base": url}}))


# ---------------------------------------------------------------- compose + egress
def test_router_only_with_remote_models(tmp_path):
    assert "router" not in compose.render(ctx(prof(), tmp_path))["services"]
    doc = compose.render(ctx(prof(REMOTE), tmp_path))
    r = doc["services"]["router"]
    assert r["image"] == "rt"
    assert r["networks"] == {"internal": {"ipv4_address": "10.213.7.11"}}
    assert r["cap_drop"] == ["ALL"] and r["security_opt"] == ["no-new-privileges:true"]
    assert r["mem_limit"] and r["pids_limit"] and "read_only" not in r
    assert r["environment"]["NO_PROXY"] == "localhost,127.0.0.1"
    assert r["environment"]["no_proxy"] == "localhost,127.0.0.1"
    assert r["environment"]["HTTPS_PROXY"] == "http://egress:3128"
    assert r["environment"]["DISABLE_ADMIN_UI"] == "True"
    assert r["healthcheck"]["test"][0] == "CMD"
    assert r["volumes"] == [f"{tmp_path}/router:/etc/router:ro"]
    assert "user" not in r  # the image's uid 65534


def test_egress_router_acl(tmp_path):
    c = ctx(prof(REMOTE), tmp_path)
    clients = compose.egress_clients(c, ["github.com"])
    rt = next(x for x in clients if x.name == "router")
    assert rt.ip == "10.213.7.11"
    assert rt.domains == ["api.example.com", "open.example.org", "ws--vllm.modal.run"]
    files = egress.render("strict", clients, partial=True)
    assert files["router.allow"].split() == rt.domains
    conf = files["squid.conf"]
    assert "acl src_router src 10.213.7.11/32" in conf
    assert "http_access allow src_router allow_router" in conf
    # the private-range deny and the CONNECT-443 rule come before every allow
    lines = conf.splitlines()
    assert lines.index("http_access deny private_dst") < lines.index(
        "http_access allow src_router allow_router"
    )
    assert lines.index("http_access deny CONNECT !conn_ports") < lines.index(
        "http_access allow src_router allow_router"
    )
    none = compose.egress_clients(ctx(prof(), tmp_path), ["github.com"])
    assert [x.name for x in none] == ["agent", "mcp-gateway"]


# ---------------------------------------------------------------- delivery
CFG = paths.Config(secret_backend="env", secret_prefix="agentbox-test-m")


def _fetch(p):
    vals = {secretstore.ref_for(s, p.name, CFG): KEY_VALUE for s in p.secrets.values()}
    return vals.get


def test_router_key_delivery(tmp_path):
    p = prof(REMOTE, secrets={"MODAL_API_KEY": {}, "EX_KEY": {}})
    doc = compose.render(ctx(p, tmp_path))
    d = delivery.collect(p, CFG, tmp_path, set(doc["services"]), fetch=_fetch(p))
    delivery.apply(doc, d, b"k" * 32)
    agent = [e["target"] for e in doc["services"]["agent"].get("secrets", [])]
    rt = [e["target"] for e in doc["services"]["router"]["secrets"]]
    assert "AGENTBOX_ROUTER_MASTER_KEY" in agent
    assert "MODAL_API_KEY" not in agent and "EX_KEY" not in agent  # T4
    assert rt == ["AGENTBOX_ROUTER_MASTER_KEY", "EX_KEY", "MODAL_API_KEY"]
    gw = [e["target"] for e in doc["services"]["mcp-gateway"].get("secrets", [])]
    assert "AGENTBOX_ROUTER_MASTER_KEY" not in gw
    text = json.dumps(doc)
    assert KEY_VALUE not in text and d.values["AGENTBOX_ROUTER_MASTER_KEY"] not in text
    env = delivery.compose_env(d, doc)
    assert env["AGENTBOX_SECRET_AGENTBOX_ROUTER_MASTER_KEY"].startswith("sk-")


def test_no_router_no_router_key(tmp_path):
    p = prof()
    doc = compose.render(ctx(p, tmp_path))
    d = delivery.collect(p, CFG, tmp_path, set(doc["services"]), fetch=lambda r: None)
    assert "AGENTBOX_ROUTER_MASTER_KEY" not in d.values
    assert "AGENTBOX_ROUTER_MASTER_KEY" not in d.targets
    # also with every target service asked for (the default)
    d = delivery.collect(p, CFG, tmp_path, fetch=lambda r: None)
    assert "AGENTBOX_ROUTER_MASTER_KEY" not in d.values
