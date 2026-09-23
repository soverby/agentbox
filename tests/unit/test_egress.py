import re

import pytest
from agentbox import egress as e


def clients(agent=("example.com",), router=(), gw=("mcp.example.org",)):
    return [
        e.Client("agent", "10.213.1.10", list(agent)),
        e.Client("router", "10.213.1.11", list(router)),
        e.Client("mcp-gateway", "10.213.1.12", list(gw)),
    ]


def access_lines(conf):
    return [x for x in conf.splitlines() if x.startswith("http_access")]


def test_strict_files_and_order():
    f = e.render("strict", clients(agent=["a.com", ".a.com", "B.org"]), host_mcp_ports=[8765, 9000])
    assert f["agent.allow"] == ".a.com\nb.org\n"  # overlap removed (squid FATALs on it)
    assert f["router.allow"] == ""
    assert f["mcp-gateway.allow"] == "mcp.example.org\n"
    c = f["squid.conf"]
    pairs = (("10.213.1.10", "agent"), ("10.213.1.11", "router"), ("10.213.1.12", "mcp-gateway"))
    for ip, n in pairs:
        assert f"acl src_{n} src {ip}/32" in c
        assert f'acl allow_{n} dstdomain -n "{e.CONF_DIR}/{n}.allow"' in c
    assert "acl host_mcp_ports port 8765 9000" in c
    assert "acl conn_ports port 443\n" in c
    acc = access_lines(c)
    assert acc[0] == "http_access deny manager"
    assert acc[1] == "http_access deny ip_literal"
    gw = acc.index("http_access allow src_mcp-gateway !CONNECT host_dom host_mcp_ports")
    assert gw < acc.index("http_access deny private_dst")
    assert gw < acc.index("http_access deny host_dom")
    allow_agent = acc.index("http_access allow src_agent allow_agent")
    assert acc.index("http_access deny private_dst") < allow_agent
    assert "http_access deny !CONNECT" in acc
    assert acc[-1] == "http_access deny all"
    assert "cache deny all" in c
    assert f"access_log stdio:{e.ACCESS_LOG} agentbox" in c
    assert f"logformat agentbox {e.LOGFORMAT}" in c
    assert e.LOGFORMAT.endswith('"%#{User-Agent}>h"')


def test_private_ranges_present():
    c = e.render("strict", clients())["squid.conf"]
    line = next(x for x in c.splitlines() if x.startswith("acl private_dst dst"))
    for r in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::/96",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "2002::/16",
        "100::/64",
        "2001::/32",
        "2001:db8::/32",
        "64:ff9b:1::/48",
        "fec0::/10",
    ):
        assert f" {r}" in line
    # squid reads ::ffff:0:0/96 as all IPv4; must never be listed
    assert "::ffff:0:0/96" not in line
    assert " ::1" not in line  # covered by ::/96; squid warns on the overlap


def test_open_mode_agent_any():
    f = e.render("open", clients(agent=["x.com"]))
    assert f["agent.allow"] == ""
    acc = access_lines(f["squid.conf"])
    assert "http_access allow src_agent" in acc
    assert "acl allow_agent" not in f["squid.conf"]
    # always-deny rules still precede it
    assert acc.index("http_access deny private_dst") < acc.index("http_access allow src_agent")
    assert acc.index("http_access deny ip_literal") < acc.index("http_access allow src_agent")


def test_no_mcp_ports_no_gateway_rule():
    c = e.render("strict", clients())["squid.conf"]
    assert "host_mcp_ports" not in c


def test_allow_http():
    c = e.render("strict", clients(), allow_http=True)["squid.conf"]
    assert "acl conn_ports port 443 80" in c
    assert "acl plain_ports port 80" in c
    assert "http_access deny !CONNECT !plain_ports" in c


@pytest.mark.parametrize(
    "host",
    [
        "1.1.1.1",
        "1.1.1.1.",
        "2130706433",
        "0x7f000001",
        "0x7f.1",
        "127.1",
        "[::1]",
        "::1",
        "[fe80::1%eth0]",
        "2001:db8::1",
    ],
)
def test_ip_literal_regex_matches(host):
    assert any(re.search(r, host, re.I) for r in e.IP_LITERAL_RES)


@pytest.mark.parametrize(
    "host", ["example.com", "1.1.1.1.nip.io", "0x.dev", "api.github.com", "a1.b2", "123.example"]
)
def test_ip_literal_regex_not_domains(host):
    assert not any(re.search(r, host, re.I) for r in e.IP_LITERAL_RES)


def test_errors():
    with pytest.raises(e.EgressError):
        e.render("lax", clients())
    with pytest.raises(e.EgressError):
        e.render("strict", clients()[:2])
    with pytest.raises(e.EgressError):
        e.render("strict", clients(agent=["1.2.3.4"]))
    with pytest.raises(e.EgressError):
        e.render("strict", clients(), host_mcp_ports=[0])
    with pytest.raises(e.EgressError):
        e.render("strict", clients(), host_mcp_ports=[True])
    bad = clients()
    bad[1] = e.Client("router", "10.213.1.10", [])
    with pytest.raises(e.EgressError, match="distinct"):
        e.render("strict", bad)


def test_write_atomic(tmp_path):
    f = e.render("strict", clients())
    e.write(tmp_path, f)
    assert (tmp_path / "squid.conf").read_text() == f["squid.conf"]
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]
