"""MCP gateway wiring (PLAN §2.2, §2.4, §2.6): service, egress ACLs, delivery
targets, Codex / Pi config merge, doctor parsers."""

import json
import tomllib

import pytest
from agentbox import compose, delivery, doctor_mcp, egress, mcpgw, network
from agentbox.profile import parse_profile

SERVERS = {
    "docs": {"url": "https://mcp.example.com/mcp", "bearer": "DOCS_TOK", "tools": ["search"]},
    "hostsrv": {"url": "http://host.docker.internal:8765/mcp", "bearer": "HOST_TOK"},
    "hsse": {"url": "http://host.docker.internal:9000/sse"},
    "t": {"command": ["uvx", "mcp-server-time==1"], "tools": ["get_current_time"]},
    "py": {"command": ["python3", "-m", "srv"]},
}


def prof(servers=None, **extra):
    d = {"mount": [{"host": "/work/a", "mode": "rw"}], "secrets": {"GH_TOKEN": "shared"}}
    if servers is not None:
        d["mcp"] = {"servers": servers}
    d.update(extra)
    p = parse_profile(d, "demo")
    mounts = [m.__class__(**{**m.__dict__, "host_real": m.host}) for m in p.mounts]
    return p.__class__(**{**p.__dict__, "mounts": mounts})


def ctx(tmp_path, p):
    return compose.Ctx(p, 7, network.DEFAULT_BASE, tmp_path, "a", "e", "g", gateway_image="gw:1")


def test_gateway_config_names_only():
    cfg = mcpgw.gateway_config(prof(SERVERS))
    assert cfg["servers"]["docs"] == {"url": "https://mcp.example.com/mcp", "command": None,
                                      "bearer_env": "DOCS_TOK", "tools": ["search"]}  # fmt: skip
    assert cfg["servers"]["hostsrv"]["tools"] is None
    assert cfg["servers"]["t"]["command"] == ["uvx", "mcp-server-time==1"]
    assert mcpgw.config_text(prof({})) == '{\n "servers": {}\n}\n'


def test_egress_domains_and_ports():
    p = prof(SERVERS)
    assert mcpgw.egress_domains(p) == ["files.pythonhosted.org", "mcp.example.com", "pypi.org"]
    assert mcpgw.host_ports(p) == [8765, 9000]
    p0 = prof({"x": {"url": "http://host.docker.internal/mcp"}})
    assert mcpgw.host_ports(p0) == [80] and mcpgw.egress_domains(p0) == []
    assert mcpgw.egress_domains(prof({"py": SERVERS["py"]})) == []  # no uvx: no PyPI
    npx = {"command": ["npx", "-y", "@modelcontextprotocol/server-memory@1"]}
    assert mcpgw.egress_domains(prof({"n": npx})) == ["registry.npmjs.org"]
    assert mcpgw.egress_domains(prof({"n": {"command": ["node", "/x.js"]}})) == []
    mcpgw.check(prof({"n": npx}))


@pytest.mark.parametrize(
    "server, msg",
    [
        ({"url": "https://host.docker.internal:8765/mcp"}, "must use http://"),
        ({"url": "http://localhost:8765/mcp"}, "not reachable"),
        ({"url": "http://127.0.0.1:8765/mcp"}, "not reachable"),
        ({"url": "http://mcp.example.com/mcp"}, "must use https://"),
        ({"url": "https://mcp.example.com:8443/mcp"}, "port 443"),
        ({"url": "https://10.0.0.1/mcp"}, "10.0.0.1"),
        ({"command": ["pnpm", "dlx", "srv"]}, "not in the mcp-gateway image"),
        ({"command": ["/usr/bin/bunx", "x"]}, "not in the mcp-gateway image"),
        ({"url": "https://mcp.example.com/mcp", "auth": "oauth"}, "P6b"),
    ],
)
def test_check_rejects(server, msg):
    with pytest.raises(mcpgw.McpError, match=msg):
        mcpgw.check(prof({"s": server}))


def test_namespace_clash_rejected():
    with pytest.raises(mcpgw.McpError, match="clash"):
        mcpgw.check(prof({"a": SERVERS["py"], "a_b": SERVERS["py"]}))
    mcpgw.check(prof({"a": SERVERS["py"], "ab": SERVERS["py"]}))


def test_service_render(tmp_path):
    p = prof(SERVERS)
    doc = compose.render(ctx(tmp_path, p))
    g = doc["services"]["mcp-gateway"]
    assert g["image"] == "gw:1"
    assert g["networks"] == {"internal": {"ipv4_address": "10.213.7.12"}}  # internal only
    assert g["cap_drop"] == ["ALL"] and g["security_opt"] == ["no-new-privileges:true"]
    assert g["mem_limit"] and g["pids_limit"] and g["init"] is True
    assert "read_only" not in g  # Compose: env-source secrets need a writable rootfs
    for bad in ("privileged", "cap_add", "network_mode", "ports", "extra_hosts", "user"):
        assert bad not in g
    env = g["environment"]
    assert env["HTTPS_PROXY"] == env["HTTP_PROXY"] == "http://egress:3128"
    assert env["NO_PROXY"] == env["no_proxy"] == "localhost,127.0.0.1"
    assert g["volumes"] == [f"{tmp_path}/mcp-gateway:/etc/mcp-gateway:ro",
                            f"{tmp_path}/logs/mcp:/var/log/mcp"]  # fmt: skip
    assert g["tmpfs"] == ["/tmp:uid=10002,gid=10002,mode=0700,exec"]
    lab = g["labels"][mcpgw.CONFIG_LABEL]
    doc2 = compose.render(ctx(tmp_path, prof({"docs": SERVERS["docs"]})))
    assert doc2["services"]["mcp-gateway"]["labels"][mcpgw.CONFIG_LABEL] != lab
    assert "DOCS_TOK" not in json.dumps(g)  # names only via secrets, added by delivery


def test_gateway_runs_without_servers(tmp_path):
    doc = compose.render(ctx(tmp_path, prof()))
    assert "mcp-gateway" in doc["services"]


def test_egress_acl_gateway(tmp_path):
    p = prof(SERVERS)
    c = ctx(tmp_path, p)
    clients = compose.egress_clients(c, ["api.anthropic.com"])
    files = egress.render("strict", clients, host_mcp_ports=mcpgw.host_ports(p), partial=True)
    assert files["mcp-gateway.allow"] == "files.pythonhosted.org\nmcp.example.com\npypi.org\n"
    assert "mcp.example.com" not in files["agent.allow"]
    conf = files["squid.conf"]
    assert "acl src_mcp-gateway src 10.213.7.12/32" in conf
    assert "acl host_mcp_ports port 8765 9000" in conf
    rule = "http_access allow src_mcp-gateway !CONNECT host_dom host_mcp_ports"
    lines = conf.splitlines()
    assert lines.index(rule) < lines.index("http_access deny internal_dom")
    assert lines.index(rule) < lines.index("http_access deny private_dst")
    assert "http_access allow src_mcp-gateway allow_mcp-gateway" in conf
    # no host ports: no rule
    files = egress.render("strict", compose.egress_clients(ctx(tmp_path, prof()), ["a.com"]),
                          host_mcp_ports=[], partial=True)  # fmt: skip
    assert "host_mcp_ports" not in files["squid.conf"]
    assert files["mcp-gateway.allow"] == ""


def test_delivery_targets_gateway(tmp_path):
    p = prof(SERVERS, secrets={"DOCS_TOK": {}, "HOST_TOK": {}, "GH_TOKEN": "shared"})
    vals = {"DOCS_TOK": "d", "HOST_TOK": "h", "GH_TOKEN": "g"}
    from agentbox import paths

    fetch = lambda ref: vals.get(ref.split("/")[-1])  # noqa: E731
    d = delivery.collect(p, paths.Config(), tmp_path, fetch=fetch)
    assert d.names_for("mcp-gateway") == ["DOCS_TOK", "HOST_TOK", "MCP_GATEWAY_TOKEN"]
    assert d.names_for("agent") == ["GH_TOKEN", "MCP_GATEWAY_TOKEN"]
    doc = compose.render(ctx(tmp_path, p))
    delivery.apply(doc, d, b"k" * 32)
    gw = doc["services"]["mcp-gateway"]["secrets"]
    assert [e["source"] for e in gw] == ["DOCS_TOK", "HOST_TOK", "MCP_GATEWAY_TOKEN"]
    assert all(e["mode"] == "0444" and set(e) == {"source", "target", "mode"} for e in gw)
    agent = {e["source"] for e in doc["services"]["agent"]["secrets"]}
    assert agent == {"GH_TOKEN", "MCP_GATEWAY_TOKEN"}


# --- Codex / Pi config merge ---


def test_codex_mcp_overrides_match_gateway():
    from agentbox import launch

    ov = launch.CODEX_MCP_OVERRIDES
    assert ov[::2] == ("-c",) * 3
    got = dict(x.split("=", 1) for x in ov[1::2])
    parsed = {k.removeprefix("mcp_servers.agentbox."): tomllib.loads(f"v = {v}")["v"]
              for k, v in got.items()}  # fmt: skip
    assert parsed == mcpgw.CODEX_MCP
    assert set(ov) <= set(launch.CODEX_OVERRIDES)


def test_pi_managed_config_matches_image():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "images" / "agent"
    doc = json.loads((root / "pi-mcp.json").read_text())
    assert doc == {"mcpServers": {"agentbox": mcpgw.PI_ENTRY}}
    wrapper = (root / "pi-wrapper").read_text()
    assert f"MCP_CONFIG={mcpgw.PI_MCP_FILE}\n" in wrapper
    assert '--extension "$ADAPTER" --mcp-config "$MCP_CONFIG"' in wrapper
    assert "\nPI_MCP_CONFIG_MODE=exclusive\nexport PI_MCP_CONFIG_MODE\n" in wrapper
    assert not hasattr(mcpgw, "merge_pi")


# --- doctor parsers ---


def test_parse_claude_mcp_list():
    out = (
        "Checking MCP server health…\n\n"
        "agentbox: http://mcp-gateway:8080/mcp (HTTP) - ✔ Connected\n"
    )
    assert doctor_mcp.parse_claude_mcp_list(out) == {
        "agentbox": "http://mcp-gateway:8080/mcp (HTTP) - ✔ Connected"
    }
    two = out + "other: npx srv - ✗ Failed to connect\n"
    assert list(doctor_mcp.parse_claude_mcp_list(two)) == ["agentbox", "other"]


def test_codex_features_parse():
    text = "apps   stable   false\nremote_plugin  stable  false\nplugins stable true\n"
    assert doctor_mcp.features(text) == {"apps": "false", "remote_plugin": "false",
                                         "plugins": "true"}  # fmt: skip


def test_connectors_proxy_denied_every_mode(tmp_path):
    for mode in ("strict", "open"):
        p = prof(SERVERS)
        clients = compose.egress_clients(ctx(tmp_path, p), ["mcp-proxy.anthropic.com"])
        files = egress.render(mode, clients, host_mcp_ports=[8765], partial=True)
        lines = files["squid.conf"].splitlines()
        assert "acl denied_dom dstdomain -n .mcp-proxy.anthropic.com" in lines
        deny = lines.index("http_access deny denied_dom")
        allows = [i for i, x in enumerate(lines) if x.startswith("http_access allow")]
        assert allows and deny < min(allows), mode  # before every allow, incl. open mode


def test_failed_upstreams():
    st = {"servers": {"a": {"state": "connected", "tools": 1},
                      "b": {"state": "failed", "reason": "timeout"}}}  # fmt: skip
    assert doctor_mcp.failed_upstreams(st) == ["b (timeout)"]


def test_gateway_node_pin_matches_agent():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    env = dict(
        x.split("=", 1)
        for x in (root / "images/agent/versions.env").read_text().splitlines()
        if x and not x.startswith("#")
    )
    df = (root / "images/mcp-gateway/Dockerfile").read_text()
    assert f"ARG NODE_VERSION={env['NODE_VERSION']}\n" in df
    assert f"ARG NODE_SHA256={env['NODE_SHA256']}\n" in df
    assert f'"$(node --version)" = "v{env["NODE_VERSION"]}"' in df


def test_host_rule_only_host_docker_internal(tmp_path):
    p = prof(SERVERS)
    files = egress.render("strict", compose.egress_clients(ctx(tmp_path, p), ["a.com"]),
                          host_mcp_ports=[8765], partial=True)  # fmt: skip
    lines = files["squid.conf"].splitlines()
    assert "acl host_dom dstdomain -n host.docker.internal" in lines
    assert "acl internal_dom dstdomain -n host.docker.internal gateway.docker.internal" in lines
    allow = lines.index("http_access allow src_mcp-gateway !CONNECT host_dom host_mcp_ports")
    assert allow < lines.index("http_access deny internal_dom")
