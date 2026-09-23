"""Doctor helpers: result parsing, test-domain choice, check 10 logic."""

import json
import subprocess

import pytest
from agentbox import box as boxmod
from agentbox import docker, doctor, paths
from agentbox.profile import parse_profile


def test_parse_lines():
    out = (
        "noise\nPASS 1\nFAIL 2: CONNECT x -> 200 (want 403)\n"
        "SKIP 19: mode is strict\nPASS 13 (router)\n"
    )
    r = doctor.parse_lines(out)
    assert [(x.status, x.check, x.detail) for x in r] == [
        ("PASS", "1", ""),
        ("FAIL", "2", "CONNECT x -> 200 (want 403)"),
        ("SKIP", "19", "mode is strict"),
        ("PASS", "13 (router)", ""),
    ]


def test_pick_domains():
    al = [".pypi.org", "github.com", "api.anthropic.com"]
    assert doctor.pick_allowed("strict", al) == "github.com"
    assert doctor.pick_allowed("strict", [".x.org", "a.x.net"]) == "a.x.net"
    assert doctor.pick_allowed("open", []) == "example.com"
    assert doctor.pick_denied(al) == "example.org"
    assert doctor.pick_denied(["example.org", ".example.net"]) == "iana.org"
    with pytest.raises(boxmod.BoxError):
        doctor.pick_allowed("strict", [".only.wild"])


def test_ptr_pair():
    one = ("1.1.1.1", "one.one.one.one", True)
    assert doctor.ptr_pair("open", [], "example.com") == one
    assert doctor.ptr_pair("strict", ["one.one.one.one"], "x") == one
    res = lambda h: "9.9.9.9"  # noqa: E731
    # PTR not allowlisted: live IP-literal case, PTR case relies on config check
    got = doctor.ptr_pair("strict", ["github.com"], "github.com", res, ptr=lambda ip: "x.aws.com")
    assert got == ("9.9.9.9", "github.com", False)
    # PTR covered by an allowlist entry: live PTR case
    got = doctor.ptr_pair(
        "strict", [".github.com"], "github.com", res, ptr=lambda ip: "lb-9.iad.github.com"
    )
    assert got == ("9.9.9.9", "lb-9.iad.github.com", True)

    def fail(h):
        raise OSError

    assert doctor.ptr_pair("strict", ["github.com"], "github.com", resolve=fail) is None


def test_windows(tmp_path):
    doctor.record_window(tmp_path, 100.0, 110.0, "agentbox-doctor/a")
    doctor.record_window(tmp_path, 200.0, 201.0, "agentbox-doctor/b")
    (tmp_path / doctor.WINDOWS_FILE).write_text(
        (tmp_path / doctor.WINDOWS_FILE).read_text() + "garbage\n[1, 2]\n"
    )
    assert doctor.load_windows(tmp_path) == [
        (98.0, 112.0, "agentbox-doctor/a"),
        (198.0, 203.0, "agentbox-doctor/b"),
    ]
    ua = doctor.new_ua()
    assert ua.startswith("agentbox-doctor/") and ua != doctor.new_ua()


def test_check_config(tmp_path, monkeypatch):
    b = make_box(tmp_path, [{"host": "/w/a", "mode": "rw"}])
    (tmp_path / "subnet").write_text("5\n")
    monkeypatch.setattr(boxmod, "agent_domains", lambda p: ["example.com"])
    want = boxmod.render_egress(b, boxmod.ctx_for(b, 5))
    live = dict(want)

    def dc(box, *args, **kw):
        if args[3] == "ls":
            return cp("\n".join(live) + "\n")
        return cp(live.get(args[4].rsplit("/", 1)[1], ""))

    monkeypatch.setattr(boxmod, "dc", dc)
    assert doctor.check_config(b) == []
    # negative control: the running conf lost `-n` and `deny ip_literal`
    live["squid.conf"] = (
        want["squid.conf"].replace(" -n ", " ").replace("http_access deny ip_literal\n", "")
    )
    assert doctor.check_config(b) == [
        "running egress squid.conf differs from the CLI render (run `agentbox up` to restore it)"
    ]
    live["extra.allow"] = ""
    assert "!= render" in doctor.check_config(b)[0]


def make_box(tmp_path, mounts):
    p = parse_profile({"mount": mounts}, "demo")
    ms = [m.__class__(**{**m.__dict__, "host_real": m.host}) for m in p.mounts]
    p = p.__class__(**{**p.__dict__, "mounts": ms})
    return boxmod.Box("demo", p, tmp_path, paths.Config())


def cp(stdout="", rc=0):
    return subprocess.CompletedProcess([], rc, stdout, "")


def fake(monkeypatch, mounts_json, mountinfo, write_rc):
    monkeypatch.setattr(doctor, "agent_container", lambda b: "cid")
    monkeypatch.setattr(docker, "run", lambda args, **kw: cp(json.dumps(mounts_json)))

    def exec_in(b, cmd, **kw):
        if cmd[0] == "awk":
            return cp(mountinfo)
        return cp(rc=write_rc(cmd[-1]))

    monkeypatch.setattr(boxmod, "exec_in", exec_in)


HOME = {"Type": "volume", "Name": "agentbox-demo-home", "Destination": "/home/agent", "RW": True}
MI = "/\n/proc\n/dev/pts\n/home/agent\n/etc/hosts\n/usr/sbin/docker-init\n/w/a\n/w/b\n"


def test_check_10_pass(tmp_path, monkeypatch):
    b = make_box(tmp_path, [{"host": "/w/a", "mode": "rw"}, {"host": "/w/b"}])
    mounts = [
        HOME,
        {"Type": "bind", "Source": "/w/a", "Destination": "/w/a", "RW": True},
        {"Type": "bind", "Source": "/w/b", "Destination": "/w/b", "RW": False},
    ]
    fake(monkeypatch, mounts, MI, lambda c: 1 if "/w/b/" in c else 0)
    r = doctor.check_10(b, ci=False)
    assert r.status == "PASS", r.detail


def test_check_10_failures(tmp_path, monkeypatch):
    b = make_box(tmp_path, [{"host": "/w/a", "mode": "rw"}, {"host": "/w/b"}])
    mounts = [
        HOME,
        {"Type": "bind", "Source": "/w/a", "Destination": "/w/a", "RW": True},
        {"Type": "bind", "Source": "/w/b", "Destination": "/w/b", "RW": True},  # ro expected
        {"Type": "bind", "Source": "/Users/me/.ssh", "Destination": "/x", "RW": False},
    ]
    fake(monkeypatch, mounts, MI + "/x\n", lambda c: 0)  # ro mount accepts writes
    r = doctor.check_10(b, ci=False)
    assert r.status == "FAIL"
    for s in ("RW=True but mode ro", "undeclared mount /Users/me/.ssh", "in-box mount point /x",
              "ro mount /w/b accepted a write"):  # fmt: skip
        assert s in r.detail
