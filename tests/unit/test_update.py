"""`agentbox update`: version lookup parsing, versions.env edit, apply rollback."""

import json
import shutil

import pytest
from agentbox import docker, update
from conftest import ROOT

ENV = "# c\nA=1\n# d\nB=x@sha256:1\n"


def test_read_write_env():
    assert update.read_env(ENV) == {"A": "1", "B": "x@sha256:1"}
    assert update.write_env(ENV, {"A": "2"}) == "# c\nA=2\n# d\nB=x@sha256:1\n"
    with pytest.raises(update.UpdateError):
        update.write_env(ENV, {"C": "1"})


def test_real_versions_env_parses():
    env = update.read_env((ROOT / "images/agent/versions.env").read_text())
    for k in ("CLAUDE_CODE_VERSION", "NODE_VERSION", "PYTHON_VERSION", "UBUNTU_IMAGE"):
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
        {"name": "Python 3.14.7", "pre_release": False},
        {"name": "Python 3.13.9", "pre_release": False},
        {"name": "Python 3.14.10", "pre_release": False},
    ]
    assert update.python_latest(rel) == "3.14.10"
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
