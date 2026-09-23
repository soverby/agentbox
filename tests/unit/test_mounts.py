"""Mount validation (PLAN §2.3, T1): realpath, missing, denylist, dot-paths."""

import os

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


@pytest.mark.parametrize("p", ["/", "/etc", "/private", "/var", "/tmp", "/usr/../etc"])
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
        lambda h, dot=False: real_check(h, dot, home=home, system_deny=((), ())),
    )
    doc = {"mount": [{"host": "~/Projects/foo"}]}
    p = parse_profile(doc, "p1", host_checks=True)
    real = os.path.realpath(f"{home}/Projects/foo")
    assert (p.mounts[0].host_real, p.mounts[0].path) == (real, real)
    with pytest.raises(ProfileError) as e:
        parse_profile({"mount": [{"host": "~/.ssh"}]}, "p1", host_checks=True)
    assert e.value.problems[0][0] == "mount[0].host"
