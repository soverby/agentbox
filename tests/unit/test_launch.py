"""Launch argv, working dir mapping, profile resolution (PLAN §2.3)."""

import os

import pytest
from agentbox import launch
from agentbox.profile import parse_profile


def prof(mounts=None, **box):
    mounts = mounts or [{"host": "/work/proj", "mode": "rw"}]
    return parse_profile({"box": box, "mount": mounts}, "p1")


def test_claude_default_and_flags():
    assert launch.agent_argv(prof(), "claude", ["--version"]) == [
        "claude", "--dangerously-skip-permissions", "--version",
    ]  # fmt: skip
    p = prof(skip_permissions=False, web_tools=False)
    assert launch.agent_argv(p, "claude", []) == [
        "claude", "--disallowedTools", "WebFetch", "WebSearch",
    ]  # fmt: skip
    assert launch.agent_argv(prof(), "claude", [], headless=True) == [
        "claude", "--dangerously-skip-permissions", "-p",
    ]  # fmt: skip


def test_codex_overrides_every_launch():
    over = [
        "-c", "features.apps=false", "-c", "features.remote_plugin=false",
        "-c", "apps._default.enabled=false",
    ]  # fmt: skip
    bypass = "--dangerously-bypass-approvals-and-sandbox"
    assert launch.agent_argv(prof(), "codex", ["x"]) == ["codex", *over, bypass, "x"]
    assert launch.agent_argv(prof(), "codex", [], headless=True) == [
        "codex", "exec", *over, bypass, "--skip-git-repo-check", "-",
    ]  # fmt: skip
    p = prof(web_tools=False)
    assert launch.agent_argv(p, "codex", []) == [
        "codex", *over, bypass, "-c", "web_search=disabled",
    ]  # fmt: skip
    # skip_permissions is Claude-only; Codex always bypasses its own sandbox
    assert bypass in launch.agent_argv(prof(skip_permissions=False), "codex", [])


def test_pi():
    assert launch.agent_argv(prof(), "pi", ["--help"]) == ["pi", "--help"]
    assert launch.agent_argv(prof(), "pi", [], headless=True) == ["pi", "-p"]


def test_agent_not_in_profile():
    with pytest.raises(launch.ResolveError, match="not in"):
        launch.agent_argv(prof(agents=["claude"]), "codex", [])


def test_exec_argv_never_login_shell():
    a = launch.exec_argv("agentbox-p1", "/s/compose.json", "/w", ["bash"], tty=True)
    assert a == [
        "docker", "compose", "-p", "agentbox-p1", "-f", "/s/compose.json", "exec",
        "-w", "/w", "agent", "/usr/local/bin/with-secrets", "bash",
    ]  # fmt: skip
    assert "-l" not in a and "--login" not in a
    b = launch.exec_argv("agentbox-p1", "/s/c.json", "/w", ["pwd"], tty=False)
    assert b[b.index("exec") + 1] == "-T"


def test_workdir_mapping(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    (a / "sub" / "deep").mkdir(parents=True)
    b.mkdir()
    p = prof(
        [
            {"host": str(a), "path": "/src/a", "mode": "rw"},
            {"host": str(b), "path": "/src/b"},
        ]
    )
    ci = False
    assert launch.container_workdir(p, str(a), ci) == "/src/a"
    assert launch.container_workdir(p, str(a / "sub" / "deep"), ci) == "/src/a/sub/deep"
    assert launch.container_workdir(p, str(b), ci) == "/src/b"
    assert launch.container_workdir(p, str(tmp_path), ci) == "/src/a"  # outside: first mount
    # a sibling with a shared prefix is not "inside"
    (tmp_path / "ab").mkdir()
    assert launch.container_workdir(p, str(tmp_path / "ab"), ci) == "/src/a"
    assert launch.mount_for(p, str(tmp_path / "ab"), ci) is None


def test_workdir_nested_mounts_deepest_wins(tmp_path):
    (tmp_path / "x" / "y").mkdir(parents=True)
    p = prof(
        [
            {"host": str(tmp_path / "x"), "path": "/x"},
            {"host": str(tmp_path / "x" / "y"), "path": "/other"},
        ]
    )
    assert launch.container_workdir(p, str(tmp_path / "x" / "y"), False) == "/other"


def test_workdir_through_symlink(tmp_path):
    (tmp_path / "real" / "d").mkdir(parents=True)
    os.symlink(tmp_path / "real", tmp_path / "link")
    p = prof([{"host": str(tmp_path / "real"), "path": "/r"}])
    assert launch.container_workdir(p, str(tmp_path / "link" / "d"), False) == "/r/d"


def test_workdir_case_insensitive(tmp_path):
    (tmp_path / "Proj" / "src").mkdir(parents=True)
    p = prof([{"host": str(tmp_path / "Proj"), "path": "/p"}])
    hit = launch.mount_for(p, str(tmp_path / "Proj" / "src"), ci=True)
    assert hit is not None and hit[1] == "src"


def write_profile(d, name, host):
    (d / f"{name}.toml").write_text(f'[[mount]]\nhost = "{host}"\n')


def test_resolve_profile(tmp_path):
    pdir = tmp_path / "profiles"
    pdir.mkdir()
    (tmp_path / "w1" / "s").mkdir(parents=True)
    (tmp_path / "w2").mkdir()
    write_profile(pdir, "one", tmp_path / "w1")
    write_profile(pdir, "two", tmp_path / "w2")
    assert launch.resolve_profile(pdir, str(tmp_path / "w1" / "s"), ci=False) == "one"
    with pytest.raises(launch.ResolveError, match="Profiles: one, two"):
        launch.resolve_profile(pdir, str(tmp_path), ci=False)
    write_profile(pdir, "three", tmp_path / "w1")
    with pytest.raises(launch.ResolveError, match="several profiles.*one, three"):
        launch.resolve_profile(pdir, str(tmp_path / "w1"), ci=False)
    (pdir / "bad.toml").write_text("not toml [")
    with pytest.raises(launch.ResolveError, match="invalid, skipped: bad"):
        launch.resolve_profile(pdir, str(tmp_path / "w1"), ci=False)


def test_resolve_no_profiles(tmp_path):
    with pytest.raises(launch.ResolveError, match="agentbox init"):
        launch.resolve_profile(tmp_path / "none", str(tmp_path))
