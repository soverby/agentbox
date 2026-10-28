"""`agentbox update`: version lookup parsing, versions.env edit, apply rollback."""

import json
import shutil

import pytest
from agentbox import docker, images, update
from conftest import ROOT
from fakedocker import FakeDocker

ENV = "# c\nA=1\n# d\nB=x@sha256:1\n"


def test_read_write_env():
    assert update.read_env(ENV) == {"A": "1", "B": "x@sha256:1"}
    assert update.write_env(ENV, {"A": "2"}) == "# c\nA=2\n# d\nB=x@sha256:1\n"
    with pytest.raises(update.UpdateError):
        update.write_env(ENV, {"C": "1"})


def test_real_versions_env_parses():
    env = update.read_env((ROOT / "images/agent/versions.env").read_text())
    for k in ("CLAUDE_CODE_VERSION", "NODE_VERSION", "PYTHON_VERSION", "UBUNTU_IMAGE",
              "PYTHON_LINE", "PYTHON_LINE_EOL"):  # fmt: skip
        assert k in env


def test_apt_latest():
    txt = (
        "Package: claude-code\nVersion: 2.1.236-1\nDescription: x\n continued\n\n"
        "Package: other\nVersion: 9.9.9\n\n"
        "Package: claude-code\nVersion: 2.1.267-1\n"
    )
    assert update.apt_latest(txt, "claude-code") == "2.1.267-1"
    with pytest.raises(update.UpdateError):
        update.apt_latest(txt, "gh")


def test_node_python_gh():
    idx = [{"version": "v25.1.0"}, {"version": "v24.22.0"}, {"version": "v24.21.0"}]
    assert update.node_latest(idx, "24") == "24.22.0"
    rel = [
        {"name": "Python 3.15.0rc1", "pre_release": True},
        {"name": "Python 3.15.0", "pre_release": False},
        {"name": "Python 3.14.7", "pre_release": False},
        {"name": "Python 3.13.9", "pre_release": False},
        {"name": "Python 3.14.10", "pre_release": False},
    ]
    assert update.python_latest(rel, "3.14") == "3.14.10"  # the line filter, not the newest
    d = {"tag_name": "v0.35.0", "assets": [{"name": "a.tar", "digest": "sha256:ab"}]}
    assert update.gh_release("o/r", "a.tar", fetch=lambda url: d) == ("0.35.0", "ab")
    with pytest.raises(update.UpdateError):
        update.gh_release("o/r", "b.tar", fetch=lambda url: d)


def test_table():
    rows = update.table({"A": "1", "CLAUDE_KEY_FPR": "F"}, {"A": "2"})
    assert [(r.key, r.status) for r in rows] == [("A", "newer"), ("CLAUDE_KEY_FPR", "manual")]
    out = update.format_table(rows)
    assert "A" in out and "1 -> 2" in out


@pytest.fixture
def repo(tmp_path):
    for f in ("images/agent/versions.env", "images/agent/pi-mcp-adapter/package.json",
              "images/agent/pi-mcp-adapter/package-lock.json"):  # fmt: skip
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / f, tmp_path / f)
    return tmp_path


def fake_docker(monkeypatch, calls, latest_id="sha256:prev"):
    monkeypatch.setattr(docker, "image_id", lambda ref: latest_id)

    def run(args, **kw):
        calls.append(args)

    monkeypatch.setattr(docker, "run", run)


@pytest.mark.parametrize("fail_at", ["build", "doctor", "relock"])
def test_apply_rollback_on_injected_failure(repo, monkeypatch, fail_at):
    calls = []
    fake_docker(monkeypatch, calls)
    env_f = repo / "images/agent/versions.env"
    lock = repo / "images/agent/pi-mcp-adapter/package-lock.json"
    pkg = repo / "images/agent/pi-mcp-adapter/package.json"
    before = (env_f.read_text(), lock.read_bytes(), pkg.read_bytes())

    def build():
        if fail_at == "build":
            raise RuntimeError("injected build failure")

    def relock():
        lock.write_text("{}")
        if fail_at == "relock":
            raise RuntimeError("injected relock failure")

    ok = update.apply(
        repo,
        {"CODEX_VERSION": "9.9.9", "PI_MCP_ADAPTER_VERSION": "9.0.0"},
        build,
        lambda: fail_at != "doctor",
        relock,
    )
    assert ok is False
    assert (env_f.read_text(), lock.read_bytes(), pkg.read_bytes()) == before
    assert calls == [["docker", "tag", "sha256:prev", "agentbox/agent:latest"]]


def test_apply_success_keeps_new(repo, monkeypatch):
    calls = []
    fake_docker(monkeypatch, calls)
    steps = []
    ok = update.apply(
        repo,
        {"CODEX_VERSION": "9.9.9", "PI_MCP_ADAPTER_VERSION": "9.0.0"},
        lambda: steps.append("build"),
        lambda: steps.append("doctor") or True,
        lambda: steps.append("relock"),
    )
    assert ok and steps == ["relock", "build", "doctor"] and calls == []
    env = update.read_env((repo / "images/agent/versions.env").read_text())
    assert env["CODEX_VERSION"] == "9.9.9"
    pkg = json.loads((repo / "images/agent/pi-mcp-adapter/package.json").read_text())
    assert pkg["dependencies"]["pi-mcp-adapter"] == "9.0.0"


def test_apply_nothing_to_do(repo, monkeypatch):
    fake_docker(monkeypatch, [])
    cur = update.read_env((repo / "images/agent/versions.env").read_text())

    def boom():
        raise AssertionError("must not build")

    assert update.apply(repo, {"CODEX_VERSION": cur["CODEX_VERSION"]}, boom, boom)


def test_apply_rollback_on_keyboard_interrupt(repo, monkeypatch):
    calls = []
    fake_docker(monkeypatch, calls)
    env_f = repo / "images/agent/versions.env"
    before = env_f.read_text()

    def build():
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        update.apply(repo, {"CODEX_VERSION": "9.9.9"}, build, lambda: True)
    assert env_f.read_text() == before
    assert calls == [["docker", "tag", "sha256:prev", "agentbox/agent:latest"]]


def test_lookup_failure_marks_only_its_keys(monkeypatch):
    import urllib.error

    def fetch_json(url):
        if "api.github.com" in url:
            raise urllib.error.HTTPError(url, 403, "rate limit exceeded", {}, None)
        if "nodejs.org" in url:
            return [{"version": "v24.9.9"}]
        if "npmjs" in url:
            return {"version": "1.0.0"}
        return [{"name": "Python 3.14.9", "pre_release": False}]

    def fetch(url):
        if "SHASUMS" in url:
            return f"{'a' * 64}  node-v24.9.9-linux-x64.tar.xz\n".encode()
        return b"Package: claude-code\nVersion: 2.1.300-1\n\nPackage: gh\nVersion: 2.200.0\n"

    class R:
        stdout = '{"digest": "sha256:abc"}'

    monkeypatch.setattr(update.docker, "run", lambda *a, **k: R())
    out = update.lookup({"NODE_VERSION": "24.1.0"}, fetch_json, fetch)
    assert out["OLLAMA_VERSION"].startswith(update.FAILED)
    assert out["OLLAMA_SHA256"].startswith(update.FAILED)
    assert out["UV_VERSION"].startswith(update.FAILED)
    assert out["NODE_VERSION"] == "24.9.9" and out["NODE_SHA256"] == "a" * 64
    assert out["CLAUDE_CODE_VERSION"] == "2.1.300-1"
    rows = {r.key: r for r in update.table({"OLLAMA_VERSION": "1", "NODE_VERSION": "1"}, out)}
    assert rows["OLLAMA_VERSION"].status == "failed"
    assert "rate limit" in update.format_table(list(rows.values()))


def test_github_token_only_for_api_github(monkeypatch):
    seen = []

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"{}"

    monkeypatch.setattr(update, "_GH_TOKEN", ["tok123"])
    monkeypatch.setattr(
        update.urllib.request, "urlopen", lambda req, timeout: seen.append(req) or Resp()
    )
    update._get("https://api.github.com/repos/x/y/releases/latest")
    update._get("https://registry.npmjs.org/x/latest")
    assert seen[0].get_header("Authorization") == "Bearer tok123"
    assert seen[1].get_header("Authorization") is None


PAYLOAD = "9.9.9\nCLAUDE_KEY_FPR=ATTACKERFPR\x1b]0;PWN\x07"


def test_lookup_rejects_injected_values(monkeypatch):
    """P8: the reviewer's payload in a looked-up version (npm, apt, image)."""

    def fetch_json(url):
        if "api.github.com" in url:
            return {"tag_name": "v1.2.3", "assets": [
                {"name": "ollama-linux-amd64.tar.zst", "digest": "sha256:" + "A" * 64},
                {"name": "uv-x86_64-unknown-linux-gnu.tar.gz", "digest": "sha256:" + "b" * 64},
            ]}  # fmt: skip
        if "nodejs.org" in url:
            return [{"version": "v24." + PAYLOAD}]
        if "npmjs" in url:
            return {"version": PAYLOAD}
        return [{"name": "Python 3.14.9", "pre_release": False}]

    def fetch(url):  # apt stanzas are line-based: the part after \n is another field
        return f"Package: claude-code\nVersion: {PAYLOAD.replace(chr(10), ' ')}\n".encode()

    class R:
        stdout = '{"digest": "sha256:' + "c" * 64 + '\\n"}'

    monkeypatch.setattr(update.docker, "run", lambda *a, **k: R())
    cur = {
        "NODE_VERSION": "24.1.0",
        "PYTHON_LINE": "3.14",
        "UBUNTU_IMAGE": "ubuntu:24.04@sha256:" + "0" * 64,
    }
    out = update.lookup(cur, fetch_json, fetch)
    for k in ("CODEX_VERSION", "PI_VERSION", "CLAUDE_CODE_VERSION", "NODE_VERSION",
              "NODE_SHA256", "OLLAMA_VERSION", "OLLAMA_SHA256", "UBUNTU_IMAGE"):  # fmt: skip
        assert out[k].startswith(update.FAILED), k
    assert out["UV_VERSION"] == "1.2.3" and out["UV_SHA256"] == "b" * 64
    assert out["PYTHON_VERSION"] == "3.14.9"
    rows = update.table({k: "1" for k in out}, out)
    txt = update.format_table(rows)
    assert "\x1b" not in txt and "\x07" not in txt
    # a failure reason that carries the payload is shown escaped, on one line per pin
    rows = [update.Row("X_VERSION", "1", f"{update.FAILED}: {PAYLOAD})")]
    txt = update.format_table(rows)
    assert "\x1b" not in txt and len(txt.splitlines()) == 2 and "\\x1b" in txt


def test_write_env_refuses_injection():
    text = "CODEX_VERSION=1.0.0\nCLAUDE_KEY_FPR=31DD\n"
    for bad in (PAYLOAD, "1.0\n", "1.0=x", "1 0", "1.0\r"):
        with pytest.raises(update.UpdateError, match="invalid value"):
            update.write_env(text, {"CODEX_VERSION": bad})
    with pytest.raises(update.UpdateError, match="invalid value"):
        update.write_env("NODE_SHA256=x\n", {"NODE_SHA256": "g" * 64})
    assert update.write_env(text, {"CODEX_VERSION": "1.1.0"}) == text.replace("1.0.0", "1.1.0")


def test_value_problem_kinds():
    assert update.value_problem("CODEX_VERSION", "0.156.1") is None
    assert update.value_problem("CLAUDE_CODE_VERSION", "2.1.267-1") is None
    assert update.value_problem("X_VERSION", "1:2.3~rc1+b@x") is None
    assert update.value_problem("X_VERSION", "v" * 81)
    assert update.value_problem("X_SHA256", "a" * 64) is None
    assert update.value_problem("X_SHA256", "a" * 63)
    img = "ubuntu:24.04@sha256:" + "0" * 64
    assert update.value_problem("UBUNTU_IMAGE", img) is None
    assert update.value_problem("UBUNTU_IMAGE", "ubuntu@sha256:" + "0" * 64)
    assert update.value_problem("UBUNTU_IMAGE", img + "\n")


# ---------------------------------------------------------------- Python line (PLAN §2.9)
def test_value_problem_python_pins():
    for ok in ("3.14", "3.9", "3.100"):
        assert update.value_problem("PYTHON_LINE", ok) is None
    for bad in ("3", "3.14.1", "4.0", "3.x", "3.14\n", " 3.14", "3.", "03.14"):
        assert update.value_problem("PYTHON_LINE", bad), bad
    for ok in ("2030-10", "2026-01", "2099-12"):
        assert update.value_problem("PYTHON_LINE_EOL", ok) is None
    for bad in ("2030-13", "2030-00", "2030-1", "2030-10-01", "30-10", "2030/10", "2030-10\n"):
        assert update.value_problem("PYTHON_LINE_EOL", bad), bad
    assert update.value_problem("PYTHON_VERSION", "3.14.8") is None
    for bad in ("3.14", "3.14.8rc1", "3.14.x", "3.14.8\n", "v3.14.8", "3.14.8.1"):
        assert update.value_problem("PYTHON_VERSION", bad), bad
    env = {"PYTHON_LINE": "3.14"}
    assert update.value_problem("PYTHON_VERSION", "3.14.9", env) is None
    assert "PYTHON_LINE 3.14" in update.value_problem("PYTHON_VERSION", "3.15.0", env)
    assert update.value_problem("PYTHON_VERSION", "3.140.1", env)  # 3.14 is not a prefix of 3.140
    assert update.value_problem("PYTHON_LINE", 3.14)  # not a string


def test_write_env_checks_the_version_against_the_line_it_lands_with():
    text = "PYTHON_LINE=3.14\nPYTHON_LINE_EOL=2030-10\nPYTHON_VERSION=3.14.8\n"
    with pytest.raises(update.UpdateError, match="invalid value"):
        update.write_env(text, {"PYTHON_VERSION": "3.15.0"})
    new = update.write_env(
        text, {"PYTHON_LINE": "3.15", "PYTHON_VERSION": "3.15.0", "PYTHON_LINE_EOL": "2031-10"}
    )
    assert new == "PYTHON_LINE=3.15\nPYTHON_LINE_EOL=2031-10\nPYTHON_VERSION=3.15.0\n"
    with pytest.raises(update.UpdateError, match="invalid value"):
        update.write_env(text, {"PYTHON_LINE_EOL": "2031-13"})


RELS = [
    {"name": "Python 3.15.0", "pre_release": False},
    {"name": "Python 3.15.1rc1", "pre_release": True},
    {"name": "Python 3.14.10", "pre_release": False},
    {"name": "Python 3.14.9", "pre_release": False},
    {"name": "Python 3.14.11", "pre_release": True},  # a pre-release is never the target
    {"name": "Python 3.13.12", "pre_release": False},
    {"name": "Python 3.14 documentation", "pre_release": False},
]


def test_python_latest_filters_to_the_line():
    assert update.python_latest(RELS, "3.14") == "3.14.10"
    assert update.python_latest(RELS, "3.15") == "3.15.0"
    assert update.python_latest(RELS, "3.13") == "3.13.12"
    for line in ("3.16", "3.1", "3.140"):  # "3.1" must not match 3.14.x
        with pytest.raises(update.UpdateError, match="no final CPython"):
            update.python_latest(RELS, line)


def test_python_new_line_is_the_next_line_with_a_final_dot_zero():
    assert update.python_new_line(RELS, "3.14") == "3.15"
    pre = [{"name": "Python 3.15.0rc2", "pre_release": True}, *RELS[2:]]
    assert update.python_new_line(pre, "3.14") is None
    only_patch = [{"name": "Python 3.15.1", "pre_release": False}, *RELS[2:]]
    assert update.python_new_line(only_patch, "3.14") is None  # needs the final 3.15.0
    assert update.python_new_line(RELS, "3.15") is None  # 3.16.0 is not out
    with pytest.raises(update.UpdateError):
        update.python_new_line(RELS, "3.x")


def test_lookup_python_follows_the_line_and_needs_it(monkeypatch):
    def fetch_json(url):
        if "python.org" in url:
            return RELS
        raise OSError("offline")

    class R:
        stdout = '{"digest": "sha256:abc"}'

    monkeypatch.setattr(update.docker, "run", lambda *a, **k: R())
    seen: list = []
    out = update.lookup({"PYTHON_LINE": "3.14"}, fetch_json, lambda u: b"", releases_out=seen)
    assert out["PYTHON_VERSION"] == "3.14.10" and seen == RELS
    out = update.lookup({}, fetch_json, lambda u: b"")  # no PYTHON_LINE: no default
    assert out["PYTHON_VERSION"].startswith(update.FAILED)
    assert "PYTHON_LINE" in out["PYTHON_VERSION"]
    # the line and its end date are never looked up: they show as manual
    rows = update.table({"PYTHON_LINE": "3.14", "PYTHON_LINE_EOL": "2030-10"}, out)
    assert [r.status for r in rows] == ["manual", "manual"]


def test_apply_rollback_keeps_other_edits_to_versions_env(repo, monkeypatch):
    calls = []
    fake_docker(monkeypatch, calls)
    env_f = repo / "images/agent/versions.env"
    original = update.read_env(env_f.read_text())["PYTHON_VERSION"]
    before = env_f.read_text()

    def build():
        # someone edits another pin while the build runs
        env_f.write_text(env_f.read_text().replace("PI_VERSION=", "PI_VERSION=9", 1))
        raise RuntimeError("injected build failure")

    info: dict = {}
    ok = update.apply(repo, {"CODEX_VERSION": "9.9.9", "PYTHON_VERSION": "3.14.99"}, build,
                      lambda: True, info=info)  # fmt: skip
    assert ok is False
    after = update.read_env(env_f.read_text())
    assert after["CODEX_VERSION"] == update.read_env(before)["CODEX_VERSION"]  # restored
    assert after["PYTHON_VERSION"] == original  # restored
    assert after["PI_VERSION"] == "9" + update.read_env(before)["PI_VERSION"]  # the edit stays
    assert info["step"] == "build" and "injected build failure" in info["error"]
    assert calls == [["docker", "tag", "sha256:prev", "agentbox/agent:latest"]]


@pytest.mark.parametrize("stop,step", [("check", "check"), ("doctor", "doctor")])
def test_apply_reports_the_step_that_failed(repo, monkeypatch, stop, step):
    fake_docker(monkeypatch, [])

    def check():
        if stop == "check":
            raise update.UpdateError("lock check failed")

    info: dict = {}
    ok = update.apply(repo, {"CODEX_VERSION": "9.9.9"}, lambda: None, lambda: stop != "doctor",
                      check=check, info=info)  # fmt: skip
    assert ok is False and info["step"] == step


def test_apply_check_runs_between_build_and_doctor(repo, monkeypatch):
    fake_docker(monkeypatch, [])
    steps = []
    ok = update.apply(
        repo,
        {"CODEX_VERSION": "9.9.9"},
        lambda: steps.append("build"),
        lambda: steps.append("doctor") or True,
        check=lambda: steps.append("check"),
    )
    assert ok and steps == ["build", "check", "doctor"]


def test_apply_write_failure_is_step_write_and_rolls_back(repo, monkeypatch):
    fake_docker(monkeypatch, [])
    monkeypatch.setattr(update, "write_env", lambda text, new: (_ for _ in ()).throw(
        update.UpdateError("refusing to write an invalid value for X")))  # fmt: skip
    info: dict = {}
    assert update.apply(repo, {"CODEX_VERSION": "9.9.9"}, lambda: None, lambda: True,
                        info=info) is False  # fmt: skip
    assert info["step"] == "write" and "refusing" in info["error"]


# ---------------------------------------------------------------- the candidate tag (PLAN §2.10)
@pytest.fixture
def full_repo(tmp_path):
    """A repo copy with every agent build input, so `images.agent_hash` works."""
    for f in ("images/agent/versions.env", *(f"images/agent/{x}" for x in images.AGENT_INPUTS)):
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / f, tmp_path / f)
    return tmp_path


def good_and_candidate(monkeypatch, repo, *, same_image=False):
    """A fake daemon with the last good image (latest + its hash tag). Returns it and a
    `build` that, like build.sh, tags the new hash and moves latest to the new image."""
    d = FakeDocker()
    monkeypatch.setattr(docker, "run", d.run)
    good_tag = f"{images.AGENT_REPO}:{images.agent_hash(repo)}"
    d.image(1, [good_tag, images.AGENT_LATEST], 5)
    box = {}

    def build():
        box["tag"] = f"{images.AGENT_REPO}:{images.agent_hash(repo)}"  # the new inputs
        new = d.tags[good_tag] if same_image else d.image(2, [], 6)
        d.tags[box["tag"]] = new
        d.tags[images.AGENT_LATEST] = new

    return d, good_tag, box, build


def test_rollback_removes_only_the_candidate_tag_and_keeps_the_previous_hash_tag(
    full_repo, monkeypatch
):
    d, good_tag, box, build = good_and_candidate(monkeypatch, full_repo)
    ok = update.apply(full_repo, {"CODEX_VERSION": "9.9.9"}, build, lambda: False)
    assert ok is False
    assert d.tags[images.AGENT_LATEST] == d.tags[good_tag]  # latest is the last good image
    assert box["tag"] not in d.tags and good_tag in d.tags  # only the candidate tag went
    rm = [c for c in d.calls if c[:3] == ["docker", "image", "rm"]]
    assert rm == [["docker", "image", "rm", box["tag"]]]  # no -f, one tag
    tag_at = d.calls.index(["docker", "tag", d.tags[good_tag], images.AGENT_LATEST])
    assert d.calls.index(rm[0]) > tag_at  # after latest is re-tagged


def test_the_candidate_is_computed_after_the_build_from_the_new_inputs(full_repo, monkeypatch):
    d, good_tag, box, build = good_and_candidate(monkeypatch, full_repo)
    update.apply(full_repo, {"CODEX_VERSION": "9.9.9"}, build, lambda: False)
    assert box["tag"] != good_tag  # the hash changed with versions.env


def test_a_failure_before_the_build_returns_has_no_candidate(full_repo, monkeypatch):
    d, good_tag, box, build = good_and_candidate(monkeypatch, full_repo)

    def failing_build():
        build()  # tagged, then failed: still no candidate (the plan: before the build returns)
        raise RuntimeError("build died")

    assert update.apply(full_repo, {"CODEX_VERSION": "9.9.9"}, failing_build, lambda: True) is False
    assert not [c for c in d.calls if c[:3] == ["docker", "image", "rm"]]


def test_the_candidate_is_kept_when_it_is_the_previous_image(full_repo, monkeypatch):
    d, good_tag, box, build = good_and_candidate(monkeypatch, full_repo, same_image=True)
    update.apply(full_repo, {"CODEX_VERSION": "9.9.9"}, build, lambda: False)
    assert not [c for c in d.calls if c[:3] == ["docker", "image", "rm"]]
    assert box["tag"] in d.tags and good_tag in d.tags


def test_a_refused_candidate_removal_does_not_fail_the_rollback(full_repo, monkeypatch):
    d, good_tag, box, build = good_and_candidate(monkeypatch, full_repo)
    d.fail["image rm"] = (1, "conflict: image is being used by a container")
    info: dict = {}
    assert (
        update.apply(full_repo, {"CODEX_VERSION": "9.9.9"}, build, lambda: False, info=info)
        is False
    )
    assert info["step"] == "doctor" and "doctor failed" in info["error"]
    assert d.tags[images.AGENT_LATEST] == d.tags[good_tag]


def test_a_success_removes_nothing(full_repo, monkeypatch):
    d, good_tag, box, build = good_and_candidate(monkeypatch, full_repo)
    assert update.apply(full_repo, {"CODEX_VERSION": "9.9.9"}, build, lambda: True)
    assert not [c for c in d.calls if c[:3] == ["docker", "image", "rm"]]
