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


# ---------------------------------------------------------------- check 22 (PLAN §2.8)
def cfg22(tmp_path, monkeypatch, text="", installed=None):
    from agentbox import schedule

    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text(text)
    monkeypatch.setattr(schedule, "report_installed", lambda: installed)


def test_check_22_skips_with_the_plan_text(tmp_path, monkeypatch):
    cfg22(tmp_path, monkeypatch)
    r = doctor.check_22()
    assert (r.status, r.check) == ("SKIP", "22-report")
    assert r.detail == "no report_investigator and no report job installed"
    assert r.line() == "SKIP 22-report: no report_investigator and no report job installed"


def test_check_22_investigator_safety_check(tmp_path, monkeypatch):
    from agentbox import fleet

    cfg22(tmp_path, monkeypatch, 'report_investigator = "inv"\n')
    monkeypatch.setattr(fleet, "investigator_problems", lambda name: [])
    r = doctor.check_22()
    assert r.status == "PASS" and "inv passes the safety check" in r.detail
    monkeypatch.setattr(
        fleet,
        "investigator_problems",
        lambda name: ["the mount /x is not empty", "[mcp.servers] must be empty"],
    )
    r = doctor.check_22()
    assert r.status == "FAIL" and r.check == "22-report"
    assert (
        "investigator profile inv: the mount /x is not empty; [mcp.servers] must be empty"
        in r.detail
    )


@pytest.mark.parametrize(
    "state,status,text",
    [("loaded", "PASS", "report job loaded"), ("in crontab", "PASS", "report job in crontab"),
     ("not loaded", "FAIL", "installed but not loaded"), ("unknown", "FAIL", "state unknown")],
)  # fmt: skip
def test_check_22_report_job_state(tmp_path, monkeypatch, state, status, text):
    cfg22(tmp_path, monkeypatch, installed=state)
    r = doctor.check_22()
    assert r.status == status and text in r.detail


def test_check_22_with_both(tmp_path, monkeypatch):
    from agentbox import fleet

    cfg22(tmp_path, monkeypatch, 'report_investigator = "inv"\n', installed="loaded")
    monkeypatch.setattr(fleet, "investigator_problems", lambda name: [])
    r = doctor.check_22()
    assert r.status == "PASS" and "safety check" in r.detail and "report job loaded" in r.detail


def test_check_22_bad_config_is_a_fail_not_a_crash(tmp_path, monkeypatch):
    cfg22(tmp_path, monkeypatch, "bogus = 1\n")
    r = doctor.check_22()
    assert r.status == "FAIL" and "unknown key" in r.detail


def test_check_22_sorts_after_21():
    res = [doctor.Result("PASS", "22-report"), doctor.Result("PASS", "21 router-health"),
           doctor.Result("PASS", "3")]  # fmt: skip
    got = sorted(res, key=lambda x: (doctor._num(x.check), x.check))
    assert [x.check for x in got] == ["3", "21 router-health", "22-report"]


def test_doctor_command_runs_check_22_once(tmp_path, monkeypatch, capsys):
    from agentbox import cli

    calls = {"22": 0}
    b = make_box(tmp_path, [{"host": "/w/a", "mode": "rw"}])
    monkeypatch.setattr(boxmod, "load", lambda name: b)
    monkeypatch.setattr(boxmod, "is_running", lambda box: True)
    monkeypatch.setattr(doctor, "full", lambda box, scratch=False: [doctor.Result("PASS", "1")])

    def c22():
        calls["22"] += 1
        return doctor.Result(
            "SKIP", "22-report", "no report_investigator and no report job installed"
        )

    monkeypatch.setattr(doctor, "check_22", c22)
    assert cli.main(["doctor", "demo"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert calls["22"] == 1 and out[-1].startswith("SKIP 22-report")
    # a failing 22 makes doctor exit 1
    monkeypatch.setattr(doctor, "check_22", lambda: doctor.Result("FAIL", "22-report", "x"))
    assert cli.main(["doctor", "demo"]) == 1
