import ipaddress

import pytest
from agentbox import network as net


def test_first_allocation_and_stable(tmp_path):
    assert net.allocate(tmp_path, "a") == 1
    assert net.allocate(tmp_path, "a") == 1
    assert (tmp_path / "a" / "subnet").read_text() == "1\n"
    assert net.allocate(tmp_path, "b") == 2


def test_reuse_freed(tmp_path):
    for p in "abc":
        net.allocate(tmp_path, p)
    net.release(tmp_path, "b")
    assert net.allocate(tmp_path, "d") == 2
    assert net.allocate(tmp_path, "e") == 4
    net.release(tmp_path, "b")  # idempotent


def test_in_use_skipped(tmp_path):
    assert net.allocate(tmp_path, "a", in_use=["10.213.1.0/24", "10.213.2.128/25"]) == 3
    assert net.allocate(tmp_path, "b", in_use=["10.213.0.0/22"]) == 4
    assert net.allocate(tmp_path, "c", in_use=["10.214.5.0/24"], base="10.214.0.0/16") == 1


def test_in_use_covering_all(tmp_path):
    with pytest.raises(net.NetworkError, match="no free"):
        net.allocate(tmp_path, "a", in_use=["10.0.0.0/8"])


def test_colliding_indexes_pure():
    assert net.colliding_indexes([]) == set()
    assert net.colliding_indexes(["172.17.0.0/16", "fd00::/64"]) == set()
    assert net.colliding_indexes(["10.213.7.5/32"]) == {7}
    with pytest.raises(net.NetworkError):
        net.colliding_indexes(["bogus"])


def test_verify():
    net.verify(3, ["10.213.4.0/24"])
    with pytest.raises(net.NetworkError, match="overlaps"):
        net.verify(4, ["10.213.4.0/24"])


def test_exhaustion(tmp_path):
    for i in range(254):
        assert net.allocate(tmp_path, f"p{i}") == i + 1
    with pytest.raises(net.NetworkError, match="no free subnet"):
        net.allocate(tmp_path, "overflow")
    net.release(tmp_path, "p99")
    assert net.allocate(tmp_path, "overflow") == 100


def test_corrupt_state_is_error(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "subnet").write_text("300\n")
    with pytest.raises(net.NetworkError):
        net.allocate(tmp_path, "b")


def test_duplicate_state_is_error(tmp_path):
    for p in "ab":
        (tmp_path / p).mkdir()
        (tmp_path / p / "subnet").write_text("5\n")
    with pytest.raises(net.NetworkError, match="used by"):
        net.allocate(tmp_path, "c")


def test_subnet_and_ips():
    assert str(net.subnet_for(7)) == "10.213.7.0/24"
    assert str(net.subnet_for(7, "10.99.0.0/16")) == "10.99.7.0/24"
    ips = net.fixed_ips(7)
    assert ips == {
        "egress": "10.213.7.2",
        "agent": "10.213.7.10",
        "router": "10.213.7.11",
        "mcp-gateway": "10.213.7.12",
        "ollama-gate": "10.213.7.13",
    }
    assert len(set(ips.values())) == len(ips)
    assert all(ipaddress.ip_address(v) in net.subnet_for(7) for v in ips.values())
    assert net.gateway_ip(7) == "10.213.7.1"


@pytest.mark.parametrize("n", [0, 255, -1])
def test_index_range(n):
    with pytest.raises(net.NetworkError):
        net.subnet_for(n)


@pytest.mark.parametrize("base", ["10.213.0.0/24", "8.8.0.0/16", "10.213.1.0/16", "nope"])
def test_bad_base(base):
    with pytest.raises(net.NetworkError):
        net.parse_base(base)


def test_verify_excludes_own_project():
    in_use = [("agentbox-foo", "10.213.4.0/24"), ("other", "172.20.0.0/16"), "10.213.9.0/24"]
    net.verify(4, in_use, exclude_project="agentbox-foo")  # re-up of a running box
    with pytest.raises(net.NetworkError):
        net.verify(4, in_use)
    with pytest.raises(net.NetworkError):
        net.verify(4, in_use, exclude_project="agentbox-bar")
    with pytest.raises(net.NetworkError):  # plain strings are never excluded
        net.verify(9, in_use, exclude_project="agentbox-foo")


def test_in_use_pairs_and_bad_entry(tmp_path):
    assert net.allocate(tmp_path, "a", in_use=[("x", "10.213.1.0/24")]) == 2
    with pytest.raises(net.NetworkError):
        net.colliding_indexes([("x",)])
