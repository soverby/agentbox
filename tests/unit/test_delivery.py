"""Delivery render: secrets block, env var names, target filter, HMAC label,
per-box tokens (PLAN §2.4)."""

import hashlib
import json

import pytest
from agentbox import compose, delivery, network, paths, secretstore
from agentbox.profile import parse_profile

CFG = paths.Config(secret_backend="env", secret_prefix="agentbox-test-u")


def profile(extra=None):
    doc = {
        "box": {"agents": ["claude", "codex"]},
        "mount": [{"host": "/w/p"}],
        "secrets": {
            "GH_TOKEN": "shared",
            "AGENT_ONLY": {},
            "BOTH": {"to": ["agent", "mcp-gateway"]},
        },
        "models": {"remote": {"m": {"api_base": "https://x.example/v1", "key": "ROUTER_KEY"}}},
        "mcp": {"servers": {"docs": {"url": "https://mcp.example.com/mcp", "bearer": "GW_ONLY"}}},
    }
    doc.update(extra or {})
    p = parse_profile(doc, "p1")
    ms = [m.__class__(**{**m.__dict__, "host_real": m.host}) for m in p.mounts]
    return p.__class__(**{**p.__dict__, "mounts": ms})


def store_for(p, missing=()):
    vals = {}
    for s in p.secrets.values():
        if s.name not in missing:
            vals[secretstore.ref_for(s, p.name, CFG)] = f"val-{s.name}"
    return vals.get


def ctx(p, tmp_path):
    return compose.Ctx(
        profile=p, n=7, base=network.DEFAULT_BASE, state=tmp_path,
        agent_image="a", egress_image="e", gate_image="g", linux=False,
    )  # fmt: skip


def test_collect_only_needed_services(tmp_path):
    p = profile()
    fetched = []

    def fetch(ref):
        fetched.append(ref)
        return store_for(p)(ref)

    d = delivery.collect(p, CFG, tmp_path, {"agent", "egress", "ollama-gate"}, fetch=fetch)
    assert sorted(d.values) == [
        "AGENT_ONLY", "BOTH", "CLAUDE_CODE_OAUTH_TOKEN", "GH_TOKEN", "MCP_GATEWAY_TOKEN",
    ]  # fmt: skip
    # sidecar-only secrets are never read when their service is not rendered
    assert not any("ROUTER_KEY" in r or "GW_ONLY" in r for r in fetched)
    assert d.targets["GW_ONLY"] == ["mcp-gateway"] and d.targets["ROUTER_KEY"] == ["router"]


def test_render_names_only_and_target_filter(tmp_path):
    p = profile()
    d = delivery.collect(p, CFG, tmp_path, fetch=store_for(p))
    doc = compose.render(ctx(p, tmp_path))
    doc["services"]["mcp-gateway"] = {"image": "gw"}  # P6 stub, render level only
    delivery.apply(doc, d, b"k" * 32)
    agent = doc["services"]["agent"]
    names = [e["target"] for e in agent["secrets"]]
    # P5: the profile has [models.remote.*], so the router runs and the agent
    # gets the per-box router master key (never the remote key).
    assert names == sorted(["AGENT_ONLY", "BOTH", "CLAUDE_CODE_OAUTH_TOKEN", "GH_TOKEN",
                            "MCP_GATEWAY_TOKEN", "AGENTBOX_ROUTER_MASTER_KEY"])  # fmt: skip
    # no uid/gid (they make Compose chown to the container user): root:root 0444
    assert all(e["mode"] == "0444" and "uid" not in e and "gid" not in e for e in agent["secrets"])
    gw = [e["target"] for e in doc["services"]["mcp-gateway"]["secrets"]]
    assert gw == ["BOTH", "GW_ONLY", "MCP_GATEWAY_TOKEN"]
    rt = doc["services"]["router"]["secrets"]
    assert [e["target"] for e in rt] == ["AGENTBOX_ROUTER_MASTER_KEY", "ROUTER_KEY"]
    assert all(e["mode"] == "0444" and "uid" not in e for e in rt)
    assert "secrets" not in doc["services"]["egress"]
    assert "secrets" not in doc["services"]["ollama-gate"]
    for n, spec in doc["secrets"].items():
        assert spec == {"environment": f"AGENTBOX_SECRET_{n}"}
    text = json.dumps(doc)
    for v in d.values.values():
        assert v not in text
    env = delivery.compose_env(d, doc)
    assert set(env) == {f"AGENTBOX_SECRET_{n}" for n in doc["secrets"]}
    assert env["AGENTBOX_SECRET_GW_ONLY"] == "val-GW_ONLY"


def test_missing_and_claude_hint(tmp_path):
    p = profile()
    fetch = store_for(p, missing=("CLAUDE_CODE_OAUTH_TOKEN", "GH_TOKEN"))
    d = delivery.collect(p, CFG, tmp_path, {"agent"}, fetch=fetch)
    assert sorted(m.name for m in d.missing) == ["CLAUDE_CODE_OAUTH_TOKEN", "GH_TOKEN"]
    assert "agentbox setup" in delivery.claude_hint(d, p)
    doc = compose.render(ctx(p, tmp_path))
    delivery.apply(doc, d, b"k" * 32)
    assert "GH_TOKEN" not in [e["target"] for e in doc["services"]["agent"]["secrets"]]
    d2 = delivery.collect(p, CFG, tmp_path, {"agent"}, fetch=store_for(p))
    assert delivery.claude_hint(d2, p) is None


def test_bad_backend_value_is_hard_error(tmp_path):
    p = profile()
    with pytest.raises(secretstore.SecretError, match="AGENT_ONLY"):
        delivery.collect(p, CFG, tmp_path, fetch=lambda r: "a\x00b" if "AGENT_ONLY" in r else "v")


def test_label_is_hmac_not_plain_hash(tmp_path):
    key = delivery.hmac_key(tmp_path)
    assert len(key) == 32 and (tmp_path / delivery.KEY_FILE).stat().st_mode & 0o777 == 0o600
    assert delivery.hmac_key(tmp_path) == key  # stable
    a = delivery.label(key, {"A": "v1", "B": "v2"})
    assert a == delivery.label(key, {"B": "v2", "A": "v1"})
    assert a != delivery.label(key, {"A": "v1", "B": "v3"})  # value change
    assert a != delivery.label(key, {"A": "v1"})  # set change
    assert a != delivery.label(b"x" * 32, {"A": "v1", "B": "v2"})  # key matters
    assert delivery.label(key, {"AB": "c"}) != delivery.label(key, {"A": "Bc"})  # framing
    for v in ("v1", "v2"):
        assert hashlib.sha256(v.encode()).hexdigest() != a


def test_changed_secret_changes_only_its_service_label(tmp_path):
    p = profile()
    base = store_for(p)
    key = b"k" * 32

    def labels(fetch):
        d = delivery.collect(p, CFG, tmp_path, fetch=fetch)
        doc = compose.render(ctx(p, tmp_path))
        doc["services"]["mcp-gateway"] = {"image": "gw"}
        delivery.apply(doc, d, key)
        return {s: v.get("labels", {}).get(delivery.LABEL) for s, v in doc["services"].items()}

    before = labels(base)
    after = labels(lambda r: "changed" if r.endswith("AGENT_ONLY") else base(r))
    assert before["agent"] != after["agent"]
    assert before["mcp-gateway"] == after["mcp-gateway"]
    assert before["egress"] is None and after["egress"] is None


def test_box_tokens_made_once_and_rotated(tmp_path):
    t1 = delivery.box_tokens(tmp_path)
    f = tmp_path / delivery.TOKENS_FILE
    assert f.stat().st_mode & 0o777 == 0o600
    assert set(t1) == {"MCP_GATEWAY_TOKEN", "AGENTBOX_ROUTER_MASTER_KEY"}
    assert len(t1["MCP_GATEWAY_TOKEN"]) >= 40
    rk = t1["AGENTBOX_ROUTER_MASTER_KEY"]
    assert rk.startswith("sk-") and len(rk) >= 43  # LiteLLM wants an sk- master key
    assert delivery.box_tokens(tmp_path) == t1
    delivery.rotate_box_tokens(tmp_path)
    t2 = delivery.box_tokens(tmp_path)
    assert t2["MCP_GATEWAY_TOKEN"] != t1["MCP_GATEWAY_TOKEN"]
    assert t2["AGENTBOX_ROUTER_MASTER_KEY"] != rk  # rotated at down
    f.write_text("garbage")
    assert delivery.box_tokens(tmp_path)["MCP_GATEWAY_TOKEN"] not in (
        t1["MCP_GATEWAY_TOKEN"], t2["MCP_GATEWAY_TOKEN"],
    )  # fmt: skip


def test_router_master_key_name_is_reserved():
    from agentbox.profile import secret_name_problem

    assert secret_name_problem(delivery.ROUTER_MASTER_KEY)
    assert secret_name_problem(delivery.MCP_GATEWAY_TOKEN)


def test_render_escapes_dollars(tmp_path):
    p = profile({"mount": [{"host": "/w/${AGENTBOX_SECRET_GH_TOKEN}/$HOME"}]})
    doc = compose.render(ctx(p, tmp_path))
    a = doc["services"]["agent"]
    assert a["working_dir"] == "/w/$${AGENTBOX_SECRET_GH_TOKEN}/$$HOME"
    assert a["volumes"][1]["source"] == "/w/$${AGENTBOX_SECRET_GH_TOKEN}/$$HOME"

    def strings(v):
        if isinstance(v, str):
            yield v
        elif isinstance(v, dict):
            for x in v.values():
                yield from strings(x)
        elif isinstance(v, list):
            for x in v:
                yield from strings(x)

    for x in strings(doc):  # no unescaped `$` anywhere
        assert "$" not in x.replace("$$", "")
