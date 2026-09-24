"""Image tags: agent hash mirrors build.sh; derived packages image."""

import re
import shutil
import subprocess

from agentbox import images
from conftest import ROOT

# build.sh uses `shasum -a 256`; slim Linux images may only ship coreutils'
# sha256sum, which prints the same digest.
SHA256 = "shasum -a 256" if shutil.which("shasum") else "sha256sum"


def test_agent_inputs_match_build_sh():
    text = (ROOT / "images/agent/build.sh").read_text()
    m = re.search(r"inputs=\(([^)]*)\)", text)
    assert tuple(m.group(1).split()) == images.AGENT_INPUTS


def test_agent_hash_equals_build_sh():
    d = ROOT / "images/agent"
    script = (
        "set -e; cd " + str(d) + "; inputs=(" + " ".join(images.AGENT_INPUTS) + "); "
        'for f in "${inputs[@]}"; do printf \'%s\\0\' "$f"; cat "$f"; printf \'\\0\'; done'
        " | " + SHA256 + " | cut -c1-12"
    )
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == images.agent_hash(ROOT)


def test_pkgs_tag_order_independent():
    a = images.pkgs_tag("sha256:1", ["ffmpeg", "tree"])
    assert a == images.pkgs_tag("sha256:1", ["tree", "ffmpeg", "tree"])
    assert a != images.pkgs_tag("sha256:2", ["ffmpeg", "tree"])
    assert re.fullmatch(r"agentbox/agent-pkgs:[0-9a-f]{12}", a)


def test_pkgs_dockerfile():
    df = images.pkgs_dockerfile("agentbox/agent:base-x", ["tree", "ffmpeg"])
    lines = df.splitlines()
    assert lines[0] == "FROM agentbox/agent:base-x"
    assert lines[1] == "USER root"
    assert "apt-get install -y --no-install-recommends ffmpeg tree" in df
    assert "-u HTTPS_PROXY" in df and "-u http_proxy" in df
    assert "-perm /6000" in df  # setuid bits from packages removed (doctor 16)
    assert "USER agent" in lines


def test_dir_hash_ignores_pycache(tmp_path):
    (tmp_path / "a.py").write_text("x")
    h = images.dir_hash(tmp_path)
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "a.pyc").write_text("y")
    assert images.dir_hash(tmp_path) == h
    (tmp_path / "a.py").write_text("z")
    assert images.dir_hash(tmp_path) != h


def test_ensure_agent_retags_latest(monkeypatch):
    from agentbox import docker

    want = f"agentbox/agent:{images.agent_hash(ROOT)}"
    ids = {want: "sha256:new", "agentbox/agent:latest": "sha256:old"}
    calls = []
    monkeypatch.setattr(docker, "image_id", ids.get)
    monkeypatch.setattr(docker, "run", lambda a, **k: calls.append(a))
    monkeypatch.setattr(images, "build_agent", lambda r: calls.append("BUILD"))
    assert images.ensure_agent(ROOT) == "agentbox/agent:latest"
    assert calls == [["docker", "tag", want, "agentbox/agent:latest"]]
    calls.clear()
    ids["agentbox/agent:latest"] = "sha256:new"
    images.ensure_agent(ROOT)
    assert calls == []
