"""Compose rendering (PLAN §2, §2.1, §2.2, §2.5)."""

import json

import pytest
from agentbox import compose, network
from agentbox.profile import parse_profile

SECRET_WORDS = ("secret", "token", "password", "GH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")


def ctx(tmp_path, linux=False, **doc):
    d = {"mount": [{"host": "/work/a", "mode": "rw"}, {"host": "/work/b", "path": "/src/b"}]}
    d.update(doc)
    d.setdefault("secrets", {"GH_TOKEN": "shared"})
    p = parse_profile(d, "demo")
    # host_real is filled by host checks; simulate them.
    mounts = [m.__class__(**{**m.__dict__, "host_real": m.host}) for m in p.mounts]
    p = p.__class__(**{**p.__dict__, "mounts": mounts})
    return compose.Ctx(p, 7, network.DEFAULT_BASE, tmp_path, "agentbox/agent:latest",
                       "agentbox/egress:h1", "agentbox/ollama-gate:h2", linux=linux)  # fmt: skip


def test_agent_hardening(tmp_path):
    doc = compose.render(ctx(tmp_path, box={"resources": {"cpus": 2, "memory": "4g"}}))
    a = doc["services"]["agent"]
    assert a["user"] == "1000:1000"
    assert a["cap_drop"] == ["ALL"]
    assert a["security_opt"] == ["no-new-privileges:true"]
    assert a["init"] is True
    assert a["command"] == ["sleep", "infinity"]
    assert a["pids_limit"] == compose.DEFAULT_PIDS
    assert a["mem_limit"] == 4 * 1024**3 and a["cpus"] == 2
    for bad in ("privileged", "cap_add", "network_mode", "pid", "ipc", "devices", "read_only"):
        assert bad not in a
    s = json.dumps(doc)
    assert "docker.sock" not in s


def test_agent_network_and_env(tmp_path):
    doc = compose.render(ctx(tmp_path))
    a = doc["services"]["agent"]
    assert a["networks"] == {"internal": {"ipv4_address": "10.213.7.10"}}
    env = a["environment"]
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        assert env[k] == "http://egress:3128"
    no = "router,mcp-gateway,ollama-gate,localhost,127.0.0.1"
    assert env["NO_PROXY"] == env["no_proxy"] == no
    assert env["OLLAMA_HOST"] == "http://ollama-gate:11434"
    nets = doc["networks"]
    assert nets["internal"] == {"internal": True, "ipam": {"config": [{"subnet": "10.213.7.0/24"}]}}
    assert nets["external"] == {}


def test_mounts_and_home(tmp_path):
    doc = compose.render(ctx(tmp_path))
    vols = doc["services"]["agent"]["volumes"]
    assert vols[0] == {"type": "volume", "source": "home", "target": "/home/agent"}
    assert vols[1] == {
        "type": "bind", "source": "/work/a", "target": "/work/a", "read_only": False,
        "bind": {"create_host_path": False},
    }  # fmt: skip
    assert vols[2]["target"] == "/src/b" and vols[2]["read_only"] is True
    assert doc["volumes"] == {"home": {"name": "agentbox-demo-home"}}
    assert doc["name"] == "agentbox-demo"
    assert doc["services"]["agent"]["working_dir"] == "/work/a"


def test_unvalidated_mount_refused(tmp_path):
    c = ctx(tmp_path)
    m = c.profile.mounts[0].__class__(**{**c.profile.mounts[0].__dict__, "host_real": ""})
    c.profile = c.profile.__class__(**{**c.profile.__dict__, "mounts": [m]})
    with pytest.raises(ValueError, match="not validated"):
        compose.render(c)


def test_sidecars(tmp_path):
    doc = compose.render(ctx(tmp_path, models={"ollama": ["llama3.2:latest"]}))
    e, g = doc["services"]["egress"], doc["services"]["ollama-gate"]
    for s in (e, g):
        assert s["cap_drop"] == ["ALL"] and s["read_only"] is True
        assert s["security_opt"] == ["no-new-privileges:true"]
        assert set(s["networks"]) == {"internal", "external"}
        assert "extra_hosts" not in s
    assert e["networks"]["internal"]["ipv4_address"] == "10.213.7.2"
    assert g["networks"]["internal"]["ipv4_address"] == "10.213.7.13"
    assert e["volumes"] == [
        f"{tmp_path}/egress:/etc/squid/agentbox:ro",
        f"{tmp_path}/logs/egress:/var/log/agentbox",
    ]
    assert g["volumes"] == [f"{tmp_path}/logs/gate:/var/log/agentbox"]
    assert g["environment"]["GATE_MODELS"] == '["llama3.2:latest"]'
    assert g["environment"]["GATE_UPSTREAM"] == "http://host.docker.internal:11434"
    assert set(doc["services"]) == {"agent", "egress", "ollama-gate"}  # no router/gateway in P3


def test_linux_extra_hosts(tmp_path):
    doc = compose.render(ctx(tmp_path, linux=True))
    for s in ("egress", "ollama-gate"):
        assert doc["services"][s]["extra_hosts"] == ["host.docker.internal:host-gateway"]
    assert "extra_hosts" not in doc["services"]["agent"]


def test_no_secrets_in_render(tmp_path):
    doc = compose.render(ctx(tmp_path))
    s = json.dumps(doc).replace(str(tmp_path), "<state>")
    assert "secrets" not in doc
    for w in SECRET_WORDS:
        assert w.lower() not in s.lower()


def test_egress_clients_agent_only(tmp_path):
    c = compose.egress_clients(ctx(tmp_path), ["example.com"])
    assert [(x.name, x.ip) for x in c] == [("agent", "10.213.7.10")]


def test_write_json_mode(tmp_path):
    f = tmp_path / "compose.json"
    compose.write_json(f, {"a": 1})
    assert json.loads(f.read_text()) == {"a": 1}
    assert f.stat().st_mode & 0o777 == 0o600


def test_egress_tmpfs_label_and_defaults(tmp_path):
    c = ctx(tmp_path)
    c.egress_config_hash = "abc"
    doc = compose.render(c)
    e = doc["services"]["egress"]
    tm = [x.split(":")[0] for x in e["tmpfs"]]
    assert {"/var/log/squid", "/var/spool/squid", "/run/squid", "/tmp"} == set(tm)
    assert e["labels"] == {"agentbox.egress-config": "abc"}
    a = doc["services"]["agent"]
    assert a["cpus"] == 4 and a["mem_limit"] == 8 * 1024**3  # defaults, no [box] resources


def test_config_hash():
    assert compose.config_hash({"a": "1", "b": "2"}) == compose.config_hash({"b": "2", "a": "1"})
    assert compose.config_hash({"a": "1"}) != compose.config_hash({"a": "2"})
