import json
import os
import re
import subprocess
import sys
import tomllib

import pytest
from agentbox import __version__
from agentbox.cli import main
from agentbox.profile import (
    ProfileError,
    hostname_problem,
    load_profile,
    merge_domains,
    parse_profile,
)
from agentbox.template import render_default_profile
from conftest import ROOT

MIN = {"mount": [{"host": "/work/proj"}]}


def parse(doc, name="p1"):
    return parse_profile(doc, name)


def problems(doc, name="p1"):
    with pytest.raises(ProfileError) as e:
        parse_profile(doc, name)
    return dict(e.value.problems)


def with_(**sections):
    return {**MIN, **sections}


# --- defaults ---------------------------------------------------------------


def test_minimal_defaults():
    p = parse(MIN)
    assert p.box.agents == ["claude", "codex", "pi"]
    assert p.box.web_tools is True
    assert p.box.packages == []
    assert p.network.mode == "strict"
    assert p.network.presets == ["anthropic", "openai", "github", "dev"]
    assert p.network.allow == [] and p.network.allow_http is False
    assert p.models.ollama == "local" and p.models.remote == {}
    assert p.mcp_servers == {}
    m = p.mounts[0]
    assert (m.mode, m.path, m.allow_dotpath) == ("ro", "/work/proj", False)


def test_mount_path_expands_tilde():
    p = parse({"mount": [{"host": "~/Projects/foo"}]})
    assert p.mounts[0].path == os.path.expanduser("~/Projects/foo")
    assert p.mounts[0].host == "~/Projects/foo"


def test_mount_path_override_and_mode():
    p = parse(
        {"mount": [{"host": "/srv/a", "path": "/work/a", "mode": "rw", "allow_dotpath": True}]}
    )
    assert (p.mounts[0].path, p.mounts[0].mode, p.mounts[0].allow_dotpath) == (
        "/work/a",
        "rw",
        True,
    )


def test_mount_hook_called(monkeypatch):
    # P3: the host check runs only with host_checks=True (the CLI always sets it).
    seen = []
    monkeypatch.setattr(
        "agentbox.profile.check_mount_host", lambda h, dot=False, **kw: seen.append((h, dot)) or h
    )
    parse({"mount": [{"host": "/srv/a"}, {"host": "/srv/b"}]})
    assert seen == []
    parse_profile({"mount": [{"host": "/srv/a"}, {"host": "/srv/b", "allow_dotpath": True}]},
                  "p1", host_checks=True)  # fmt: skip
    assert seen == [("/srv/a", False), ("/srv/b", True)]


# --- structural errors ------------------------------------------------------


def test_unknown_keys_reported_with_path():
    doc = {
        "bogus": 1,
        "box": {"agent": ["claude"], "resources": {"gpu": 1}},
        "mount": [{"host": "/srv/a", "ro": True}],
        "network": {"mode": "strict", "deny": []},
        "models": {"remote": {"r": {"api_base": "https://x.io", "token": "T"}}},
        "mcp": {"servers": {"s": {"url": "https://x.io", "headers": {}}}, "other": 1},
        "secrets": {"A": {"scope": "x"}},
    }
    ps = problems(doc)
    for key in [
        "bogus",
        "box.agent",
        "box.resources.gpu",
        "mount[0].ro",
        "network.deny",
        "models.remote.r.token",
        "mcp.servers.s.headers",
        "mcp.other",
        "secrets.A.scope",
    ]:
        assert ps.get(key) == "unknown key", key


def test_all_problems_collected():
    ps = problems({"network": {"mode": "x"}, "box": {"web_tools": "yes"}})
    assert set(ps) == {"mount", "network.mode", "box.web_tools"}


def test_mount_required():
    assert "mount" in problems({})
    assert "mount" in problems({"mount": {"host": "/srv/a"}})
    assert problems({"mount": [{"mode": "rw"}]}) == {"mount[0].host": "is required"}


@pytest.mark.parametrize(
    "doc,key",
    [
        ({"mount": [{"host": "/srv/a", "mode": "rx"}]}, "mount[0].mode"),
        ({"mount": [{"host": 1}]}, "mount[0].host"),
        ({"mount": [{"host": "/srv/a", "path": "rel"}]}, "mount[0].path"),
        ({"mount": [{"host": "/srv/a", "allow_dotpath": "yes"}]}, "mount[0].allow_dotpath"),
        (with_(network={"mode": "closed"}), "network.mode"),
        (with_(network={"allow_http": 1}), "network.allow_http"),
        (with_(network={"presets": "dev"}), "network.presets"),
        (with_(network={"presets": ["../x"]}), "network.presets[0]"),
        (with_(box={"agents": ["claude", "gemini"]}), "box.agents[1]"),
        (with_(box={"agents": ["pi", "pi"]}), "box.agents"),
        (with_(box={"agents": []}), "box.agents"),
        (with_(box={"web_tools": 0}), "box.web_tools"),
        (with_(box={"packages": ["ffmpeg; rm"]}), "box.packages[0]"),
        (with_(box={"packages": [1]}), "box.packages[0]"),
        (with_(box={"resources": {"cpus": 0}}), "box.resources.cpus"),
        (with_(box={"resources": {"cpus": True}}), "box.resources.cpus"),
        (with_(box={"resources": {"memory": 8}}), "box.resources.memory"),
        (with_(box={"resources": {"memory": "8GB"}}), "box.resources.memory"),
        (with_(box={"resources": "big"}), "box.resources"),
        (with_(box=[]), "box"),
    ],
)
def test_invalid_values(doc, key):
    assert key in problems(doc)


def test_resources_ok():
    r = parse(with_(box={"resources": {"cpus": 1.5, "memory": "512m"}})).box.resources
    assert (r.cpus, r.memory) == (1.5, "512m")


def test_agents_subset():
    assert parse(with_(box={"agents": ["codex"]})).box.agents == ["codex"]


# --- profile name -----------------------------------------------------------


@pytest.mark.parametrize("name", ["a", "foo", "foo-bar", "0x", "a" * 31])
def test_name_ok(name):
    assert parse(MIN, name).name == name


@pytest.mark.parametrize("name", ["", "-a", "Foo", "a_b", "a.b", "a" * 32, "_shared"])
def test_name_bad(name):
    assert "<name>" in problems(MIN, name)


# --- network.allow ----------------------------------------------------------


@pytest.mark.parametrize("h", ["example.com", ".example.com", "a-b.example.co.uk", "x1.io"])
def test_allow_ok(h):
    assert hostname_problem(h) is None
    assert parse(with_(network={"allow": [h]})).network.allow == [h]


@pytest.mark.parametrize(
    "h",
    [
        "1.2.3.4",
        "::1",
        "[::1]",
        "example.com:443",
        "https://example.com",
        "*.example.com",
        "ex*.com",
        "example.com/path",
        "",
        "..example.com",
        "-bad.com",
        "localhost.",
        "localhost",
        "x.localhost",
        "nas.local",
        "db.internal",
        "router.home.arpa",
        "box.localdomain",
        "a.123",
        "a.0x1f",
        "0x7f.0x0.0x0.0x1",
        "2130706433",
        "under_score.com",
        "com",
        " example.com",
    ],
)
def test_allow_bad(h):
    assert hostname_problem(h) is not None
    assert "network.allow[0]" in problems(with_(network={"allow": [h]}))


def test_open_mode():
    assert parse(with_(network={"mode": "open"})).network.mode == "open"


# --- secrets ----------------------------------------------------------------


def secrets(doc, name="p1"):
    return {k: (s.ref, s.to) for k, s in parse(doc, name).secrets.items()}


def test_implicit_claude_token():
    assert secrets(MIN)["CLAUDE_CODE_OAUTH_TOKEN"] == (
        "keychain:agentbox/_shared/CLAUDE_CODE_OAUTH_TOKEN",
        ["agent"],
    )
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in secrets(with_(box={"agents": ["codex"]}))


def test_explicit_claude_token_kept():
    doc = with_(secrets={"CLAUDE_CODE_OAUTH_TOKEN": {}})
    assert (
        secrets(doc)["CLAUDE_CODE_OAUTH_TOKEN"][0] == "keychain:agentbox/p1/CLAUDE_CODE_OAUTH_TOKEN"
    )


def test_secret_forms():
    s = secrets(
        with_(
            secrets={
                "GH_TOKEN": "shared",
                "A": {},
                "B": {"ref": "op://vault/item/field"},
                "C": {"shared": True, "to": "agent"},
            }
        ),
        "foo",
    )
    assert s["GH_TOKEN"] == ("keychain:agentbox/_shared/GH_TOKEN", ["agent"])
    assert s["A"] == ("keychain:agentbox/foo/A", ["agent"])
    assert s["B"] == ("op://vault/item/field", ["agent"])
    assert s["C"] == ("keychain:agentbox/_shared/C", ["agent"])


@pytest.mark.parametrize(
    "value,key",
    [
        ("profile", "secrets.X"),
        (1, "secrets.X"),
        ({"to": "egress"}, "secrets.X.to"),
        ({"ref": 5}, "secrets.X.ref"),
        ({"ref": "op://a/b/c", "shared": True}, "secrets.X"),
        ({"shared": "yes"}, "secrets.X.shared"),
    ],
)
def test_secret_bad(value, key):
    assert key in problems(with_(secrets={"X": value}))


def test_secret_bad_name():
    assert "secrets.1BAD" in problems(with_(secrets={"1BAD": "shared"}))


REMOTE = {"remote": {"m": {"api_base": "https://x.modal.run/v1", "key": "MODAL_API_KEY"}}}
MCP = {"servers": {"d": {"url": "https://mcp.x.com/mcp", "bearer": "DOCS"}}}


def test_target_inference_implicit():
    s = secrets(with_(models=REMOTE, mcp=MCP))
    assert s["MODAL_API_KEY"] == ("keychain:agentbox/p1/MODAL_API_KEY", ["router"])
    assert s["DOCS"] == ("keychain:agentbox/p1/DOCS", ["mcp-gateway"])


def test_target_inference_declared():
    s = secrets(with_(models=REMOTE, mcp=MCP, secrets={"MODAL_API_KEY": "shared", "DOCS": {}}))
    assert s["MODAL_API_KEY"] == ("keychain:agentbox/_shared/MODAL_API_KEY", ["agent", "router"])
    assert s["DOCS"][1] == ["mcp-gateway"]


def test_explicit_to_list_and_string():
    s = secrets(with_(secrets={"X": {"to": "router"}, "Y": {"to": ["router", "agent"]}}))
    assert s["X"][1] == ["router"]
    assert s["Y"][1] == ["agent", "router"]


def test_inference_adds_to_explicit():
    s = secrets(with_(mcp=MCP, secrets={"DOCS": {"to": "agent"}}))
    assert s["DOCS"][1] == ["agent", "mcp-gateway"]


def test_same_secret_router_and_gateway():
    mcp = {"servers": {"d": {"url": "https://mcp.x.com/mcp", "bearer": "MODAL_API_KEY"}}}
    assert secrets(with_(models=REMOTE, mcp=mcp))["MODAL_API_KEY"][1] == ["mcp-gateway", "router"]


@pytest.mark.parametrize("to", [[], 1, ["agent", "egress"], "Agent", [1]])
def test_to_bad(to):
    assert "secrets.X.to" in problems(with_(secrets={"X": {"to": to}}))


@pytest.mark.parametrize(
    "name",
    [
        "MCP_GATEWAY_TOKEN", "AGENTBOX_X", "AGENTBOX_", "PATH", "HOME", "USER", "SHELL",
        "LD_PRELOAD", "HTTPS_PROXY", "http_proxy", "No_Proxy", "ALL_PROXY", "NODE_OPTIONS",
        "PYTHONPATH", "PYTHON",
    ],
)  # fmt: skip
def test_reserved_secret_names(name):
    assert f"secrets.{name}" in problems(with_(secrets={name: "shared"}))
    remote = {"remote": {"m": {"api_base": "https://x.io", "key": name}}}
    assert "models.remote.m.key" in problems(with_(models=remote))
    mcp = {"servers": {"d": {"url": "https://x.io", "bearer": name}}}
    assert "mcp.servers.d.bearer" in problems(with_(mcp=mcp))


@pytest.mark.parametrize("name", ["path", "home", "PATHX", "MY_HOME", "PROXY", "USERNAME"])
def test_not_reserved(name):
    assert name in secrets(with_(secrets={name: {}}))


def test_claude_token_not_key_or_bearer():
    remote = {"remote": {"m": {"api_base": "https://x.io", "key": "CLAUDE_CODE_OAUTH_TOKEN"}}}
    assert "models.remote.m.key" in problems(with_(models=remote))
    mcp = {"servers": {"d": {"url": "https://x.io", "bearer": "CLAUDE_CODE_OAUTH_TOKEN"}}}
    assert "mcp.servers.d.bearer" in problems(with_(mcp=mcp))


@pytest.mark.parametrize(
    "ref", ["keychain:svc", "keychain:agentbox/p/X", "op://v/i/f", "env:MY_VAR", "env:_X1"]
)
def test_ref_ok(ref):
    assert secrets(with_(secrets={"X": {"ref": ref}}))["X"][0] == ref


@pytest.mark.parametrize(
    "ref",
    [
        "", "keychain:", "keychain: x", "op://v/i", "op://v/i/f/g", "op:///i/f", "env:",
        "env:1X", "env:A-B", "file:/etc/passwd", "vault:x", "KEYCHAIN:x", "keychain:x\n",
    ],
)  # fmt: skip
def test_ref_bad(ref):
    assert "secrets.X.ref" in problems(with_(secrets={"X": {"ref": ref}}))


# --- models -----------------------------------------------------------------


def test_ollama_list():
    assert parse(with_(models={"ollama": ["a:1", "b"]})).models.ollama == ["a:1", "b"]


@pytest.mark.parametrize("val", ["all", 1, ["a", 2], {"x": 1}])
def test_ollama_bad(val):
    assert any(k.startswith("models.ollama") for k in problems(with_(models={"ollama": val})))


def test_remote_ok():
    r = parse(with_(models=REMOTE)).models.remote["m"]
    assert (r.api_base, r.key) == ("https://x.modal.run/v1", "MODAL_API_KEY")


@pytest.mark.parametrize(
    "remote,key",
    [
        ({"m": {}}, "models.remote.m.api_base"),
        ({"m": {"api_base": "ftp://x"}}, "models.remote.m.api_base"),
        ({"m": {"api_base": "https://x.io", "key": "bad-name"}}, "models.remote.m.key"),
        ({"m": "https://x.io"}, "models.remote.m"),
    ],
)
def test_remote_bad(remote, key):
    assert key in problems(with_(models={"remote": remote}))


# --- mcp --------------------------------------------------------------------


def test_mcp_kinds():
    p = parse(
        with_(
            mcp={
                "servers": {
                    "a": {"url": "https://a.io/mcp", "bearer": "A_TOKEN", "tools": ["x"]},
                    "b": {"url": "https://b.io/mcp", "auth": "oauth"},
                    "c": {"command": ["npx", "srv"]},
                }
            }
        )
    )
    s = p.mcp_servers
    assert (s["a"].bearer, s["a"].tools) == ("A_TOKEN", ["x"])
    assert s["b"].auth == "oauth" and s["b"].bearer is None
    assert s["c"].command == ["npx", "srv"] and s["c"].url is None and s["c"].tools is None


@pytest.mark.parametrize(
    "srv,key",
    [
        ({}, "mcp.servers.s"),
        ({"url": "https://a.io", "command": ["x"]}, "mcp.servers.s"),
        ({"url": "https://a.io", "bearer": "T", "auth": "oauth"}, "mcp.servers.s"),
        ({"url": "https://a.io", "auth": "basic"}, "mcp.servers.s.auth"),
        ({"url": "a.io"}, "mcp.servers.s.url"),
        ({"command": "npx srv"}, "mcp.servers.s.command"),
        ({"command": []}, "mcp.servers.s.command"),
        ({"command": ["x"], "bearer": "T"}, "mcp.servers.s"),
        ({"url": "https://a.io", "tools": "x"}, "mcp.servers.s.tools"),
        ({"url": "https://a.io", "bearer": "bad-name"}, "mcp.servers.s.bearer"),
    ],
)
def test_mcp_bad(srv, key):
    assert key in problems(with_(mcp={"servers": {"s": srv}}))


# --- files, template, CLI ---------------------------------------------------


def test_example_validates():
    p = load_profile(ROOT / "profiles" / "example.toml")
    assert p.name == "example"
    assert len(p.mcp_servers) == 3 and "qwen-modal" in p.models.remote
    assert {t for s in p.secrets.values() for t in s.to} == {"agent", "router", "mcp-gateway"}


def test_load_bad_toml(tmp_path):
    f = tmp_path / "x.toml"
    f.write_text("[box\n")
    with pytest.raises(ProfileError):
        load_profile(f)


def plan_template():
    text = (ROOT / "docs" / "PLAN.md").read_text()
    m = re.search(
        r"what `agentbox init foo --mount ~/Projects/foo` writes:\n\n```toml\n(.*?)```", text, re.S
    )
    assert m, "PLAN.md §2.3 default profile block not found; update the test regex or the plan"
    return m.group(1)


def test_template_matches_plan_exactly():
    assert render_default_profile("foo", "~/Projects/foo", None, False) == plan_template()


@pytest.mark.parametrize("open_mode", [False, True])
def test_template_round_trip(open_mode):
    text = render_default_profile("foo", "~/Projects/foo", ["claude", "pi"], open_mode)
    p = parse_profile(tomllib.loads(text), "foo")
    assert p.network.mode == ("open" if open_mode else "strict")
    assert p.box.agents == ["claude", "pi"]
    assert p.mounts[0].mode == "rw"
    assert p.secrets["GH_TOKEN"].ref == "keychain:agentbox/_shared/GH_TOKEN"
    assert "CLAUDE_CODE_OAUTH_TOKEN" in p.secrets


def test_template_escapes_mount():
    text = render_default_profile("foo", '/srv/a "b"\\c', None, False)
    assert parse_profile(tomllib.loads(text), "foo").mounts[0].host == '/srv/a "b"\\c'


def test_cli_validate_ok(capsys):
    assert main(["validate", str(ROOT / "profiles" / "example.toml")]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["name"] == "example"


def test_cli_validate_errors(tmp_path, capsys):
    f = tmp_path / "bad.toml"
    f.write_text('[network]\nmode = "x"\n')
    assert main(["validate", str(f)]) == 1
    err = capsys.readouterr().err
    assert "error: network.mode:" in err and "error: mount:" in err


def test_cli_version():
    r = subprocess.run(
        [sys.executable, "-m", "agentbox.cli", "--version"],
        capture_output=True,
        text=True,
        cwd=ROOT / "cli",
    )
    assert r.returncode == 0 and r.stdout.strip() == f"agentbox {__version__}"


# --- round 2 additions -------------------------------------------------------


def test_skip_permissions():
    assert parse(MIN).box.skip_permissions is True
    assert parse(with_(box={"skip_permissions": False})).box.skip_permissions is False
    assert "box.skip_permissions" in problems(with_(box={"skip_permissions": "no"}))


def test_skip_permissions_not_in_template():
    assert "skip_permissions" not in render_default_profile("foo", "~/p", None, False)


def test_allow_normalised():
    allow = ["Example.COM", "example.com", ".Foo.io", "a.foo.io", ".x.foo.io", "foo.io", "b.io"]
    assert parse(with_(network={"allow": allow})).network.allow == [
        "example.com",
        ".foo.io",
        "b.io",
    ]


def test_merge_domains_helper():
    assert merge_domains(["a.com", ".b.com"], ["A.com", "x.b.com", "b.com", "xb.com"]) == [
        "a.com",
        ".b.com",
        "xb.com",
    ]


def test_idn_message():
    msg = problems(with_(network={"allow": ["bücher.de"]}))["network.allow[0]"]
    assert "use punycode (xn--" in msg
    assert parse(with_(network={"allow": ["xn--bcher-kva.de"]})).network.allow == [
        "xn--bcher-kva.de"
    ]


def test_mcp_url_host_docker_internal():
    s = {"servers": {"h": {"url": "http://host.docker.internal:8765/mcp"}}}
    assert parse(with_(mcp=s)).mcp_servers["h"].url == "http://host.docker.internal:8765/mcp"


# Each (document, key path) sets one pattern-checked value with a trailing newline.
TRAILING_NL = [
    (with_(box={"packages": ["ffmpeg\n"]}), "box.packages[0]"),
    (with_(box={"resources": {"memory": "8g\n"}}), "box.resources.memory"),
    (with_(network={"presets": ["dev\n"]}), "network.presets[0]"),
    (with_(network={"allow": ["example.com\n"]}), "network.allow[0]"),
    (with_(secrets={"GH_TOKEN\n": "shared"}), "secrets.GH_TOKEN\n"),
    (with_(secrets={"X": {"ref": "op://v/i/f\n"}}), "secrets.X.ref"),
    (with_(secrets={"X": {"ref": "env:X\n"}}), "secrets.X.ref"),
    (with_(models={"remote": {"m\n": {"api_base": "https://x.io"}}}), "models.remote.m\n"),
    (with_(models={"remote": {"m": {"api_base": "https://x.io\n"}}}), "models.remote.m.api_base"),
    (
        with_(models={"remote": {"m": {"api_base": "https://x.io", "key": "K\n"}}}),
        "models.remote.m.key",
    ),
    (with_(mcp={"servers": {"s\n": {"url": "https://x.io"}}}), "mcp.servers.s\n"),
    (with_(mcp={"servers": {"s": {"url": "https://x.io/\n"}}}), "mcp.servers.s.url"),
    (
        with_(mcp={"servers": {"s": {"url": "https://x.io", "bearer": "B\n"}}}),
        "mcp.servers.s.bearer",
    ),
    ({"mount": [{"host": "/srv/a", "path": "/work/a\n"}]}, "mount[0].path"),
]


@pytest.mark.parametrize("doc,key", TRAILING_NL)
def test_trailing_newline_rejected(doc, key):
    assert key in problems(doc)


def test_trailing_newline_profile_name():
    assert "<name>" in problems(MIN, "foo\n")


def test_trailing_newline_label():
    assert hostname_problem("example.com\n") is not None


def test_load_non_utf8(tmp_path, capsys):
    f = tmp_path / "bin.toml"
    f.write_bytes(b'[box]\nagents = ["\xff"]\n')
    with pytest.raises(ProfileError):
        load_profile(f)
    assert main(["validate", str(f)]) == 1
    assert "not valid UTF-8" in capsys.readouterr().err


@pytest.mark.parametrize(
    "path,ok",
    [
        ("/work/a", "/work/a"),
        ("/work//a/./b/", "/work/a/b"),
        ("/srv", "/srv"),
        ("/home/sean/x", "/home/sean/x"),
        ("/library", None),
        ("/libx", None),
        ("/lib64/x", None),
        ("/", None),
        ("/work/../etc", None),
        ("/work/a:b", None),
        ("/work/a,b", None),
        ("/usr/local/x", None),
        ("/etc", None),
        ("/tmp/x", None),
        ("/home/agent", None),
        ("/home/agent/p", None),
        ("/home/agents", "/home/agents"),
        ("/proc", None),
        ("/sys/x", None),
        ("/dev", None),
        ("/run/secrets", None),
        ("/var/x", None),
        ("/root", None),
        ("/boot", None),
        ("/opt/x", None),
        ("/bin", None),
        ("/sbin", None),
        ("//etc", None),
    ],
)
def test_container_path(path, ok):
    doc = {"mount": [{"host": "/srv/h", "path": path}]}
    if ok:
        assert parse(doc).mounts[0].path == ok
    else:
        assert "mount[0].path" in problems(doc)


def test_container_path_error_on_host_when_defaulted():
    assert "mount[0].host" in problems({"mount": [{"host": "/etc/x"}]})
    assert "mount[0].host" in problems({"mount": [{"host": "relative/dir"}]})


def test_duplicate_container_paths():
    doc = {"mount": [{"host": "/srv/a"}, {"host": "/srv/b", "path": "/srv/a/"}]}
    assert "mount[1].path" in problems(doc)


@pytest.mark.parametrize("cpus", [float("nan"), float("inf"), -1, 0])
def test_cpus_bad(cpus):
    assert "box.resources.cpus" in problems(with_(box={"resources": {"cpus": cpus}}))


@pytest.mark.parametrize("mem,ok", [("64m", True), ("8G", True), ("65536k", True), ("1g", True),
                                     ("63m", False), ("65535k", False), ("512", False),
                                     ("0g", False), ("8gb", False)])  # fmt: skip
def test_memory(mem, ok):
    doc = with_(box={"resources": {"memory": mem}})
    if ok:
        assert parse(doc).box.resources.memory == mem
    else:
        assert "box.resources.memory" in problems(doc)


def test_mcp_tools_empty_and_dup():
    ps = problems(with_(mcp={"servers": {"s": {"url": "https://x.io", "tools": []}}}))
    assert "omit `tools`" in ps["mcp.servers.s.tools"]
    ps = problems(with_(mcp={"servers": {"s": {"url": "https://x.io", "tools": ["a", "a"]}}}))
    assert "mcp.servers.s.tools" in ps


@pytest.mark.parametrize("name", ["-x", "a b", ".x", "a/b"])
def test_remote_model_name(name):
    remote = {"remote": {name: {"api_base": "https://x.io"}}}
    assert f"models.remote.{name}" in problems(with_(models=remote))


# --- round 3 additions -------------------------------------------------------


def test_shared_shorthand_is_explicit_agent():
    mcp = {"servers": {"gh": {"url": "https://api.githubcopilot.com/mcp", "bearer": "GH_TOKEN"}}}
    s = secrets(with_(mcp=mcp, secrets={"GH_TOKEN": "shared"}))
    assert s["GH_TOKEN"] == ("keychain:agentbox/_shared/GH_TOKEN", ["agent", "mcp-gateway"])


def test_table_without_to_goes_only_to_sidecar():
    mcp = {"servers": {"d": {"url": "https://x.io", "bearer": "X"}}}
    assert secrets(with_(mcp=mcp, secrets={"X": {"ref": "op://v/i/f"}}))["X"][1] == ["mcp-gateway"]
    assert secrets(with_(mcp=mcp, secrets={"X": {"shared": True}}))["X"][1] == ["mcp-gateway"]


@pytest.mark.parametrize("val", ["shared", {}, {"to": "agent"}, {"ref": "env:T"}])
def test_claude_token_declared_ok(val):
    assert secrets(with_(secrets={"CLAUDE_CODE_OAUTH_TOKEN": val}))["CLAUDE_CODE_OAUTH_TOKEN"][
        1
    ] == ["agent"]


@pytest.mark.parametrize("to", ["router", ["agent", "mcp-gateway"]])
def test_claude_token_declared_bad(to):
    ps = problems(with_(secrets={"CLAUDE_CODE_OAUTH_TOKEN": {"to": to}}))
    assert "secrets.CLAUDE_CODE_OAUTH_TOKEN" in ps


@pytest.mark.parametrize(
    "name",
    [
        "NPM_CONFIG_REGISTRY", "npm_config_registry", "Npm_Config_X", "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN", "OLLAMA_HOST", "DISABLE_AUTOUPDATER", "DISABLE_UPDATES",
        "ENABLE_CLAUDEAI_MCP_SERVERS", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    ],
)  # fmt: skip
def test_reserved_round3(name):
    assert f"secrets.{name}" in problems(with_(secrets={name: "shared"}))


@pytest.mark.parametrize("name", ["anthropic_base_url", "ANTHROPIC_API_KEY", "OLLAMA_HOSTS"])
def test_not_reserved_round3(name):
    assert name in secrets(with_(secrets={name: {}}))


CONTROL = [
    ({"mount": [{"host": "/srv/a\tb"}]}, "mount[0].host"),
    ({"mount": [{"host": "/srv/a", "path": "/work/\x7f"}]}, "mount[0].path"),
    (with_(secrets={"X": {"ref": "keychain:a\x01b"}}), "secrets.X.ref"),
    (with_(mcp={"servers": {"s": {"command": ["npx", "a\x00"]}}}), "mcp.servers.s.command[1]"),
    (with_(mcp={"servers": {"s": {"url": "https://x.io/\r"}}}), "mcp.servers.s.url"),
    (with_(models={"ollama": ["qwen3\x1b"]}), "models.ollama[0]"),
]


@pytest.mark.parametrize("doc,key", CONTROL)
def test_control_chars_rejected(doc, key):
    assert key in problems(doc)


@pytest.mark.parametrize(
    "doc,key",
    [
        (with_(models={"ollama": [""]}), "models.ollama[0]"),
        (
            with_(mcp={"servers": {"s": {"url": "https://x.io", "tools": [""]}}}),
            "mcp.servers.s.tools[0]",
        ),
        (with_(mcp={"servers": {"s": {"command": [""]}}}), "mcp.servers.s.command[0]"),
        (with_(box={"packages": [""]}), "box.packages[0]"),
        (with_(network={"presets": [""]}), "network.presets[0]"),
        (with_(network={"allow": [""]}), "network.allow[0]"),
    ],
)
def test_empty_list_items_rejected(doc, key):
    assert key in problems(doc)


@pytest.mark.parametrize(
    "m",
    [
        "qwen3",
        "qwen3-coder:30b",
        "gpt-oss:20b",
        "hf.co/org/model:Q4_K_M",
        "llama3.2",
        "hf.co/unsloth/Qwen3-Coder-GGUF:Q4_K_M",
    ],
)
def test_ollama_names_ok(m):
    assert parse(with_(models={"ollama": [m]})).models.ollama == [m]


@pytest.mark.parametrize("m", ["-x", "a:b:c", "a:", "a b", ":tag", "a:t@g", "qwen3\n"])
def test_ollama_names_bad(m):
    assert "models.ollama[0]" in problems(with_(models={"ollama": [m]}))


@pytest.mark.parametrize("t", ["a b", "a/b", "x" * 129, "tool\n", "a:b"])
def test_tool_names_bad(t):
    ps = problems(with_(mcp={"servers": {"s": {"url": "https://x.io", "tools": [t]}}}))
    assert "mcp.servers.s.tools[0]" in ps


def test_tool_names_ok():
    tools = ["search", "read_file", "a.b-c", "x" * 128]
    assert (
        parse(with_(mcp={"servers": {"s": {"url": "https://x.io", "tools": tools}}}))
        .mcp_servers["s"]
        .tools
        == tools
    )


@pytest.mark.parametrize(
    "u", ["https://user:pass@x.io/mcp", "https://user@x.io", "http://a@host.docker.internal:1/"]
)
def test_url_userinfo_rejected(u):
    assert "mcp.servers.s.url" in problems(with_(mcp={"servers": {"s": {"url": u}}}))
    remote = {"remote": {"m": {"api_base": u}}}
    assert "models.remote.m.api_base" in problems(with_(models=remote))


def test_url_at_in_path_ok():
    u = "https://x.io/mcp/@scope/pkg"
    assert parse(with_(mcp={"servers": {"s": {"url": u}}})).mcp_servers["s"].url == u


@pytest.mark.parametrize("path", ["/home", "/home/", "//home"])
def test_home_reserved(path):
    msg = problems({"mount": [{"host": "/srv/a", "path": path}]})["mount[0].path"]
    assert "set `path` to mount it elsewhere" in msg


def test_home_user_ok():
    assert (
        parse({"mount": [{"host": "/srv/a", "path": "/home/sean"}]}).mounts[0].path == "/home/sean"
    )


def test_reserved_hint_on_host():
    msg = problems({"mount": [{"host": "/etc/x"}]})["mount[0].host"]
    assert "set `path` to mount it elsewhere" in msg
