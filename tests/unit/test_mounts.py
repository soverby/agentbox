"""Mount validation (PLAN §2.3, T1): realpath, missing, denylist, dot-paths."""

import os
import sys

import pytest
from agentbox.profile import MountError, ProfileError, check_mount_host, parse_profile


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "Users" / "me"
    for d in ("Projects/foo/src", ".ssh/keys", "Library/Keychains", ".config/x", ".hidden/p"):
        (h / d).mkdir(parents=True)
    (h / ".gitconfig").write_text("")
    return str(h)


def chk(host, home, dot=False, ci=False, system=False):
    # tmp_path lives under /private on macOS (itself denied), so the
    # home-relative tests use a test system list: "/" and the fake /Users.
    deny = None if system else (("/", os.path.dirname(home)), ())
    return check_mount_host(host, dot, home=home, case_insensitive=ci, system_deny=deny)


def test_ok_and_realpath(home):
    assert chk("~/Projects/foo", home) == os.path.realpath(f"{home}/Projects/foo")
    assert chk(f"{home}/Projects/foo/", home) == os.path.realpath(f"{home}/Projects/foo")


def test_dotdot_resolves_before_check(home):
    assert chk(f"{home}/Projects/foo/src/..", home).endswith("/Projects/foo")
    with pytest.raises(MountError, match="denied path"):
        chk(f"{home}/Projects/../.ssh", home)
    with pytest.raises(MountError, match="never mountable"):
        chk(f"{home}/Projects/..", home)


def test_symlink_into_ssh_refused(home):
    link = f"{home}/Projects/foo/keys"
    os.symlink(f"{home}/.ssh/keys", link)
    with pytest.raises(MountError, match=r"\.ssh"):
        chk(link, home)
    os.symlink(f"{home}", f"{home}/Projects/homelink")
    with pytest.raises(MountError, match="never mountable"):
        chk(f"{home}/Projects/homelink/", home)


def test_missing_refused(home):
    with pytest.raises(MountError, match="does not exist"):
        chk("~/Projects/nope", home)


def test_relative_and_tilde_user_refused(home):
    with pytest.raises(MountError, match="absolute"):
        chk("Projects/foo", home)
    with pytest.raises(MountError, match="~user"):
        chk("~root/x", home)


@pytest.mark.parametrize("sub", [".ssh", ".ssh/keys", "Library", "Library/Keychains", ".config/x"])
def test_denylist_equal_and_descendant(home, sub):
    with pytest.raises(MountError):
        chk(f"{home}/{sub}", home)


def test_denylist_file_entry(home):
    with pytest.raises(MountError, match="gitconfig"):
        chk(f"{home}/.gitconfig", home, dot=True)


def test_ancestor_of_denied_refused(home):
    with pytest.raises(MountError, match="never mountable"):
        chk(home, home)
    with pytest.raises(MountError):
        chk(os.path.dirname(home), home)  # ancestor of $HOME/.ssh


@pytest.mark.parametrize(
    "p",
    ["/", "/etc", "/private", "/var", "/tmp", "/usr/../etc", "/run", "/proc", "/dev", "/root",
     "/home"],
)  # fmt: skip
def test_system_paths(home, p):
    if not os.path.exists(p):
        pytest.skip(f"{p} missing on this host")
    with pytest.raises(MountError):
        chk(p, home, system=True)


def test_system_descendants(home):
    for p in ("/etc/hosts", "/var/tmp", "/private/tmp"):
        if os.path.exists(p):
            with pytest.raises(MountError):
                chk(p, home, system=True)


def test_dotpath_needs_opt_in(home):
    with pytest.raises(MountError, match="allow_dotpath"):
        chk(f"{home}/.hidden/p", home)
    assert chk(f"{home}/.hidden/p", home, dot=True).endswith(".hidden/p")
    # the denylist still wins with the opt-in
    with pytest.raises(MountError):
        chk(f"{home}/.ssh", home, dot=True)


def test_case_variants_case_insensitive(home):
    # On APFS /Users/me/.SSH is ~/.ssh. Simulate: the case-variant path exists.
    variant = home.replace("/me", "/ME")
    os.makedirs(f"{variant}/.SSH", exist_ok=True)
    with pytest.raises(MountError):
        chk(f"{variant}/.SSH", home, dot=True, ci=True)
    os.makedirs(f"{home}/LIBRARY/x", exist_ok=True)
    with pytest.raises(MountError, match="(?i)library"):
        chk(f"{home}/LIBRARY/x", home, ci=True)
    assert chk(f"{home}/LIBRARY/x", home, ci=False)  # case-sensitive host: a different dir


def test_real_denylist_under_private(tmp_path):
    # Real lists: a temp dir (under /private/var on macOS) is refused.
    if os.path.realpath(tmp_path).startswith("/private/"):
        with pytest.raises(MountError, match="/private"):
            check_mount_host(str(tmp_path))


def test_parse_profile_host_checks(home, monkeypatch):
    monkeypatch.setenv("HOME", home)
    import agentbox.profile as prof

    real_check = prof.check_mount_host
    monkeypatch.setattr(
        prof,
        "check_mount_host",
        lambda h, dot=False, **kw: real_check(h, dot, home=home, system_deny=((), ()), **kw),
    )
    doc = {"mount": [{"host": "~/Projects/foo"}]}
    p = parse_profile(doc, "p1", host_checks=True)
    real = os.path.realpath(f"{home}/Projects/foo")
    assert (p.mounts[0].host_real, p.mounts[0].path) == (real, real)
    with pytest.raises(ProfileError) as e:
        parse_profile({"mount": [{"host": "~/.ssh"}]}, "p1", host_checks=True)
    assert e.value.problems[0][0] == "mount[0].host"


def test_agentbox_repo_refused(home):
    """PLAN §2.3: the repo the CLI runs from: equal, ancestor, descendant."""
    repo = f"{home}/Projects/foo"
    deny = (("/", os.path.dirname(home)), ())
    for p, ok in ((repo, False), (f"{repo}/src", False), (f"{home}/Projects", False),
                  (f"{home}/.config/x", None)):  # fmt: skip
        if ok is None:
            continue
        with pytest.raises(MountError, match="agentbox repo .*runs from that code on the host"):
            check_mount_host(p, home=home, case_insensitive=False, system_deny=deny,
                             repo_roots=(os.path.realpath(repo),))  # fmt: skip
    os.makedirs(f"{home}/Other")
    assert check_mount_host(f"{home}/Other", home=home, case_insensitive=False,
                            system_deny=deny, repo_roots=(os.path.realpath(repo),))  # fmt: skip


def test_real_repo_is_in_default_denylist():
    from agentbox import profile

    here = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
    assert here in profile.agentbox_repos()
    with pytest.raises(MountError, match="agentbox repo"):
        check_mount_host(os.path.join(here, "cli"))


def test_agentbox_repo_read_only_allowed(home):
    """A read-only mount of the repo or a parent of it is allowed: the agent
    can read the code, not change what runs on the host."""
    repo = f"{home}/Projects/foo"
    deny = (("/", os.path.dirname(home)), ())
    for p in (repo, f"{repo}/src", f"{home}/Projects"):
        assert check_mount_host(p, home=home, case_insensitive=False, system_deny=deny,
                                repo_roots=(os.path.realpath(repo),), writable=False)  # fmt: skip


def test_profile_ro_parent_of_repo_ok_rw_refused():
    here = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
    parent = os.path.dirname(here)
    ro = parse_profile({"mount": [{"host": parent, "mode": "ro", "path": "/w/p"}]}, "p1",
                       host_checks=True)  # fmt: skip
    assert ro.mounts[0].mode == "ro"
    with pytest.raises(ProfileError, match="agentbox repo"):
        parse_profile({"mount": [{"host": parent, "mode": "rw", "path": "/w/p"}]}, "p1",
                      host_checks=True)  # fmt: skip


def test_host_code_paths_refused_rw_only(home):
    """Interpreter/venv/PYTHONPATH (equal, ancestor, descendant): rw refused, ro allowed."""
    deny = (("/", os.path.dirname(home)), ())
    venv = f"{home}/Projects/foo"
    kw = dict(home=home, case_insensitive=False, system_deny=deny, repo_roots=(),
              code_paths=(os.path.realpath(venv),))  # fmt: skip
    for p in (venv, f"{venv}/src", f"{home}/Projects"):
        with pytest.raises(MountError, match="change what runs on the host"):
            check_mount_host(p, **kw)
        assert check_mount_host(p, writable=False, **kw)
    os.makedirs(f"{home}/Other")
    assert check_mount_host(f"{home}/Other", **kw)


def test_default_code_paths_include_interpreter(monkeypatch, tmp_path):

    from agentbox import profile

    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    code = profile.host_code_paths(("/nonexistent/x",))
    assert os.path.realpath(sys.prefix) in code
    assert os.path.realpath(sys.executable) in code
    assert os.path.realpath(tmp_path) in code
    assert "/nonexistent/x" not in code
    assert profile.code_path_conflict(os.path.dirname(os.path.realpath(sys.prefix)), code, False)


def test_rw_deny_system_and_tool_dirs(home):
    """P8: /usr, /opt, /Applications and the docker/git dirs: rw refused
    (equal, ancestor, descendant), ro allowed."""
    deny = (("/", os.path.dirname(home)), ())
    tools = f"{home}/Projects/foo/src"
    kw = dict(home=home, case_insensitive=False, system_deny=deny, repo_roots=(),
              code_paths=(), rw_deny=(os.path.realpath(tools),))  # fmt: skip
    for p in (tools, f"{home}/Projects/foo", f"{home}/Projects"):
        with pytest.raises(MountError, match="docker/git"):
            check_mount_host(p, **kw)
        assert check_mount_host(p, writable=False, **kw)
    os.makedirs(f"{tools}/deeper")
    with pytest.raises(MountError, match="docker/git"):
        check_mount_host(f"{tools}/deeper", **kw)
    os.makedirs(f"{home}/Other")
    assert check_mount_host(f"{home}/Other", **kw)


def test_rw_deny_defaults(monkeypatch, tmp_path):
    from agentbox import profile

    bindir = tmp_path / "bin"
    real = tmp_path / "cellar" / "git" / "bin"
    real.mkdir(parents=True)
    bindir.mkdir()
    (real / "git").write_text("#!/bin/sh\n")
    (real / "git").chmod(0o755)
    os.symlink(real / "git", bindir / "git")
    monkeypatch.setenv("PATH", str(bindir))
    d = profile.rw_deny_paths()
    assert {"/usr", "/opt", "/Applications"} <= set(d)
    assert str(bindir) in d and os.path.realpath(real) in d
    with pytest.raises(MountError, match="docker/git"):
        check_mount_host("/usr/local", writable=True)
    assert check_mount_host("/usr/local", writable=False) == os.path.realpath("/usr/local")
