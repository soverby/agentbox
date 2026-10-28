"""Python line and patch updates (PLAN §2.9): uv probe, result classification,
Slack posts and their dedupe, the lock check, the update lock and its interlock,
the daily host job. Network and Docker are faked."""

import hashlib
import io
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest
from agentbox import box as boxmod
from agentbox import cli, docker, images, notify, pyupdate, schedule, updatelock
from agentbox import update as upd
from conftest import ROOT
from fakedocker import FakeDocker

HOOK = "https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/hookSECRETVALUE0123456789"
IMG = "sha256:" + "ab" * 32  # agentbox/agent:latest after a build
SHORT = "abababababab"
PREFIX = "🐍 agentbox: "


def rels(*versions, pre=()):
    return [{"name": f"Python {v}", "pre_release": False} for v in versions] + [
        {"name": f"Python {v}", "pre_release": True} for v in pre
    ]


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Isolated roots and a repo copy; Docker faked; a fake Slack; the clock set by `w.at`."""
    cfg, state, la = tmp_path / "cfg", tmp_path / "state", tmp_path / "la"
    for k, v in (("CONFIG_HOME", cfg), ("STATE_HOME", state), ("LAUNCHAGENTS_DIR", la)):
        monkeypatch.setenv(f"AGENTBOX_{k}", str(v))
    monkeypatch.setenv("AGENTBOX_LAUNCHD_PREFIX", "com.agentbox-unit")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    repo = tmp_path / "repo"
    for f in (
        "images/agent/build.sh",
        *(f"images/agent/{x}" for x in images.AGENT_INPUTS),
    ):
        (repo / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / f, repo / f)
    # The tests assume this baseline, not whatever the live pins are today.
    env = repo / "images/agent/versions.env"
    env.write_text(upd.write_env(env.read_text(), {
        "PYTHON_LINE": "3.14", "PYTHON_VERSION": "3.14.8", "PYTHON_LINE_EOL": "2030-10",
        "UV_VERSION": "0.13.6",
    }))  # fmt: skip
    monkeypatch.setenv("AGENTBOX_REPO", str(repo))
    (cfg / "profiles").mkdir(parents=True)
    sysbin = tmp_path / "sysbin"  # job_env needs a `docker` on PATH
    sysbin.mkdir()
    (sysbin / "docker").write_text("#!/bin/sh\nexit 0\n")
    (sysbin / "docker").chmod(0o755)
    monkeypatch.setenv("PATH", os.environ["PATH"] + os.pathsep + str(sysbin))

    w = SimpleNamespace(tmp=tmp_path, cfg=cfg, state=state, la=la, repo=repo, runs=[],
                        images={images.AGENT_LATEST: IMG}, at="2026-10-28T05:00:00+01:00",
                        posts=[])  # fmt: skip
    # The fake daemon (PLAN §2.10 prune): one current agent image, nothing to remove.
    w.fake = FakeDocker(w.runs)
    w.fake.image(0xAB, [images.AGENT_LATEST, f"{images.AGENT_REPO}:{images.agent_hash(repo)}"])
    monkeypatch.setattr(docker, "run", w.fake.run)
    monkeypatch.setattr(docker, "image_id", lambda ref: w.images.get(ref))
    monkeypatch.setattr(schedule, "now_iso", lambda: w.at)
    # Slack: the secret in the env-backend store; notify.post records instead of using the network.
    (cfg / "config.toml").write_text(
        'secret_backend = "env"\nnotify_webhook_secret = "SLACK_WEBHOOK_URL"\n'
    )
    store = tmp_path / "store.json"
    store.write_text(json.dumps({"AGENTBOX__SHARED_SLACK_WEBHOOK_URL": HOOK}))
    monkeypatch.setenv("AGENTBOX_TEST_SECRET_STORE", str(store))
    w.post_error = None

    def post(url, text, timeout):
        if w.post_error:
            raise notify.NotifyError(w.post_error)
        w.posts.append(text)

    monkeypatch.setattr(notify, "post", post)
    return w


def env_of(w):
    return upd.read_env((w.repo / "images/agent/versions.env").read_text())


def set_env(w, **kv):
    f = w.repo / "images/agent/versions.env"
    f.write_text(upd.write_env(f.read_text(), kv))


def last(w):
    return json.loads((updatelock.update_dir() / "last.json").read_text())


def history(w):
    f = updatelock.update_dir() / "history.jsonl"
    return [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []


def resolves(monkeypatch, result):
    """pyupdate.resolve returns `result`, or raises it when it is an exception."""

    def fake(env, target, uv=None):
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(pyupdate, "resolve", fake)


def run_patch(w, releases, build=None, doctor=None, ready=True):
    return pyupdate.patch(
        w.repo,
        build=build or (lambda: None),
        doctor=doctor or (lambda failed: True),
        fetch_json=lambda url: releases,
        docker_ready=lambda: ready,
    )


def failing(exc):
    def f(*a, **k):
        raise exc

    return f


# ---------------------------------------------------------------- probe
def test_probe_parsing_json_list_and_empty():
    assert pyupdate.parse_probe('[{"version": "3.14.9", "key": "x"}]', "3.14.9") is True
    assert pyupdate.parse_probe("[]", "3.14.9") is False  # unknown version: absent, rc 0
    assert pyupdate.parse_probe('[{"version": "3.14.8"}]', "3.14.9") is False
    assert pyupdate.parse_probe('[{"version": "3.14.90"}]', "3.14.9") is False  # equal, not prefix
    assert pyupdate.parse_probe('[{"nope": 1}, 7, "x"]', "3.14.9") is False
    for bad in ("", "3.14.9\n", '{"version": "3.14.9"}', "null"):
        with pytest.raises(upd.UpdateError):
            pyupdate.parse_probe(bad, "3.14.9")


def test_probe_image_runs_uv_offline_in_the_image(world, monkeypatch):
    seen = []

    def run(args, **kw):
        seen.append((args, kw))
        return subprocess.CompletedProcess(args, 0, '[{"version": "3.14.9"}]', "")

    monkeypatch.setattr(docker, "run", run)
    assert pyupdate.probe_image(images.AGENT_LATEST, "3.14.9") is True
    args, kw = seen[0]
    assert args[:3] == ["docker", "run", "--rm"] and args[args.index("--network") + 1] == "none"
    i = args.index(images.AGENT_LATEST)
    assert args[i + 1 :] == ["uv", "python", "list", "--all-versions", "--only-downloads",
                             "--output-format", "json", "cpython@3.14.9"]  # fmt: skip
    assert "-v" not in args and kw["timeout"] == pyupdate.PROBE_LIMIT


def test_probe_nonzero_exit_is_an_error_not_absent(world, monkeypatch):
    monkeypatch.setattr(
        docker, "run", lambda args, **kw: subprocess.CompletedProcess(args, 2, "", "boom\n")
    )
    with pytest.raises(upd.UpdateError, match=r"exit 2.*boom"):
        pyupdate.probe_image(images.AGENT_LATEST, "3.14.9")


def test_probe_tarball_mounts_uv_read_only_with_no_network(world, monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(
        docker, "run",
        lambda args, **kw: seen.append(args) or subprocess.CompletedProcess(args, 0, "[]", ""),
    )  # fmt: skip
    ubuntu = "ubuntu:24.04@sha256:" + "0" * 64
    assert pyupdate.probe_tarball(ubuntu, tmp_path, "3.14.9") is False
    a = seen[0]
    assert a[a.index("--network") + 1] == "none" and "--cap-drop" in a
    assert a[a.index("-v") + 1] == f"{tmp_path}:/uvbin:ro"
    assert a[a.index("-e") + 1] == "HOME=/nonexistent"
    i = a.index(ubuntu)
    assert a[i + 1 :] == ["/uvbin/uv", "python", "list", "--all-versions", "--only-downloads",
                          "--output-format", "json", "cpython@3.14.9"]  # fmt: skip


def uv_tarball(payload=b"#!uv\n", names=("uv-x86_64-unknown-linux-gnu/uv",)):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in names:
            ti = tarfile.TarInfo(name)
            ti.size = len(payload)
            tf.addfile(ti, io.BytesIO(payload))
    return buf.getvalue()


def test_download_uv_checks_the_sha256_and_writes_one_file(tmp_path):
    data = uv_tarball(
        b"UVBINARY", ("uv-x86_64-unknown-linux-gnu/uvx", "uv-x86_64-unknown-linux-gnu/uv")
    )
    sha = hashlib.sha256(data).hexdigest()
    urls = []
    dest = tmp_path / "d"
    dest.mkdir()
    out = pyupdate.download_uv("0.13.7", sha, dest, fetch=lambda u: urls.append(u) or data)
    assert urls == [
        "https://github.com/astral-sh/uv/releases/download/0.13.7/uv-x86_64-unknown-linux-gnu.tar.gz"
    ]
    assert out == dest / "uv" and out.read_bytes() == b"UVBINARY"
    assert out.stat().st_mode & 0o777 == 0o755 and sorted(p.name for p in dest.iterdir()) == ["uv"]
    with pytest.raises(upd.UpdateError, match="does not match its sha256"):
        pyupdate.download_uv("0.13.7", "0" * 64, dest, fetch=lambda u: data)
    with pytest.raises(upd.UpdateError, match="UV_VERSION"):
        pyupdate.download_uv("0.13.7/../x\n", sha, dest, fetch=lambda u: data)
    none = uv_tarball(names=("uv-x86_64-unknown-linux-gnu/uvx",))
    with pytest.raises(upd.UpdateError, match="no usable uv binary"):
        pyupdate.download_uv("0.13.7", hashlib.sha256(none).hexdigest(), dest, fetch=lambda u: none)


# ---------------------------------------------------------------- resolve (uv coupling)
@pytest.fixture
def probes(world, monkeypatch):
    """probe_image / probe_tarball / download_uv / latest_uv faked. `p.image` and
    `p.tar` map a target to found; `p.calls` lists what ran, in order."""
    p = SimpleNamespace(image=True, tar=True, calls=[], latest=("0.13.7", "f" * 64))
    ubuntu = env_of(world)["UBUNTU_IMAGE"]

    def probe_image(ref, target):
        p.calls.append(("image", ref, target))
        return p.image

    def probe_tarball(image, d, target):
        assert image == ubuntu  # the pinned Ubuntu image
        p.calls.append(("tarball", target))
        return p.tar

    monkeypatch.setattr(pyupdate, "probe_image", probe_image)
    monkeypatch.setattr(pyupdate, "probe_tarball", probe_tarball)
    monkeypatch.setattr(pyupdate, "download_uv",
                        lambda v, s, d, fetch=None: p.calls.append(("download", v, s)))  # fmt: skip
    monkeypatch.setattr(pyupdate, "latest_uv", lambda: p.latest)
    return p


def test_resolve_pinned_uv_in_the_current_image_is_enough(world, probes):
    res = pyupdate.resolve(env_of(world), "3.14.9")
    assert res.uv is None
    assert probes.calls == [("image", "agentbox/agent:latest", "3.14.9")]


def test_resolve_without_an_image_probes_the_pinned_tarball(world, probes):
    world.images.clear()
    env = env_of(world)
    assert pyupdate.resolve(env, "3.14.9").uv is None
    assert probes.calls == [("download", env["UV_VERSION"], env["UV_SHA256"]),
                            ("tarball", "3.14.9")]  # fmt: skip


def test_resolve_falls_back_to_the_latest_uv(world, probes):
    probes.image = False
    res = pyupdate.resolve(env_of(world), "3.14.9")
    assert res.uv == ("0.13.7", "f" * 64)
    assert probes.calls == [("image", "agentbox/agent:latest", "3.14.9"),
                            ("download", "0.13.7", "f" * 64), ("tarball", "3.14.9")]  # fmt: skip


def test_resolve_not_installable_when_no_uv_has_it(world, probes):
    probes.image = probes.tar = False
    with pytest.raises(pyupdate.NotInstallable, match="uv has no build of Python 3.14.9"):
        pyupdate.resolve(env_of(world), "3.14.9")


@pytest.mark.parametrize(
    "boom",
    [upd.UpdateError("astral-sh/uv: asset missing"),
     urllib.error.URLError("offline"),
     docker.DockerError("docker: command not found"),
     tarfile.ReadError("bad tar")],
)  # fmt: skip
def test_resolve_failure_before_a_write_is_lookup_failed(world, probes, monkeypatch, boom):
    probes.image = False
    monkeypatch.setattr(pyupdate, "latest_uv", failing(boom))
    with pytest.raises(pyupdate.LookupFailed):
        pyupdate.resolve(env_of(world), "3.14.9")
    probes.calls.clear()
    monkeypatch.setattr(pyupdate, "latest_uv", lambda: probes.latest)
    monkeypatch.setattr(pyupdate, "download_uv", failing(boom))  # download or checksum failure
    with pytest.raises(pyupdate.LookupFailed):
        pyupdate.resolve(env_of(world), "3.14.9")


def test_resolve_given_uv_probes_only_that_one(world, probes):
    probes.image = False  # would fail; must not be asked
    res = pyupdate.resolve(env_of(world), "3.14.9", uv=("0.13.8", "e" * 64))
    assert res.uv == ("0.13.8", "e" * 64)
    assert [c[0] for c in probes.calls] == ["download", "tarball"]


def test_resolve_pin_full_update_keeps_python_when_uv_has_no_build(world, probes, capsys):
    probes.image = probes.tar = False
    cur = env_of(world)
    latest = {"PYTHON_VERSION": "3.14.99", "UV_VERSION": "0.13.7", "UV_SHA256": "f" * 64}
    pyupdate.resolve_pin(cur, latest)
    assert latest["PYTHON_VERSION"] == cur["PYTHON_VERSION"]
    assert "PYTHON_VERSION stays 3.14.8" in capsys.readouterr().out
    # a newer uv in the lookup is the one probed
    probes.tar, probes.calls = True, []
    latest = {"PYTHON_VERSION": "3.14.99", "UV_VERSION": "0.13.7", "UV_SHA256": "f" * 64}
    pyupdate.resolve_pin(cur, latest)
    assert latest["PYTHON_VERSION"] == "3.14.99"
    assert probes.calls == [("download", "0.13.7", "f" * 64), ("tarball", "3.14.99")]
    # nothing newer: nothing probed
    probes.calls.clear()
    pyupdate.resolve_pin(cur, {"PYTHON_VERSION": cur["PYTHON_VERSION"]})
    pyupdate.resolve_pin(cur, {"PYTHON_VERSION": f"{upd.FAILED}: x)"})
    assert probes.calls == []


def test_resolve_pin_probe_failure_marks_only_python_failed(world, probes, monkeypatch):
    monkeypatch.setattr(pyupdate, "probe_image", failing(docker.DockerError("no docker")))
    latest = {"PYTHON_VERSION": "3.14.99", "CODEX_VERSION": "9.9.9"}
    pyupdate.resolve_pin(env_of(world), latest)
    assert latest["PYTHON_VERSION"].startswith(upd.FAILED) and latest["CODEX_VERSION"] == "9.9.9"


# ---------------------------------------------------------------- patch: classification
def test_current_posts_nothing_and_writes_the_record(world, monkeypatch):
    resolves(monkeypatch, AssertionError("must not probe"))
    rec = run_patch(world, rels("3.14.8", "3.13.9"))
    assert rec["result"] == "current" and rec["python_to"] == "3.14.8"
    assert world.posts == [] and rec["notify"] is None and rec["reported"] == []
    assert last(world) == rec and history(world) == [rec]
    assert (updatelock.update_dir().stat().st_mode & 0o777) == 0o700
    assert set(rec) == {"start", "end", "result", "step", "python_from", "python_to", "uv_from",
                        "uv_to", "image", "derived_warnings", "prune", "message",
                        "notify", "reported"}  # fmt: skip
    assert env_of(world)["PYTHON_VERSION"] == "3.14.8"


def test_never_a_downgrade(world, monkeypatch):
    resolves(monkeypatch, AssertionError("must not probe"))
    set_env(world, PYTHON_VERSION="3.14.9")
    rec = run_patch(world, rels("3.14.8", "3.14.7"))
    assert rec["result"] == "current" and rec["python_to"] == "3.14.9"


def test_applied_writes_builds_checks_and_posts(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    steps = []
    rec = run_patch(
        world,
        rels("3.14.9", "3.14.8", "3.15.0rc1"),
        build=lambda: steps.append(("build", env_of(world)["PYTHON_VERSION"])),
        doctor=lambda failed: steps.append(("doctor",)) or True,
    )
    assert steps == [("build", "3.14.9"), ("doctor",)]  # the pin is written before the build
    assert env_of(world)["PYTHON_VERSION"] == "3.14.9"
    assert rec["result"] == "applied" and rec["python_from"] == "3.14.8"
    assert rec["python_to"] == "3.14.9" and rec["uv_to"] is None and rec["image"] == IMG
    assert world.posts == [
        f"{PREFIX}Python 3.14.8 -> 3.14.9 applied; new image {SHORT}. Commit and release the pins."
    ]
    assert rec["notify"] == "ok" and len(rec["reported"]) == 1
    assert last(world) == rec and history(world) == [rec]
    assert env_of(world)["UV_VERSION"] == "0.13.6"


def test_applied_with_a_newer_uv_writes_the_uv_pins_too(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(("0.13.7", "c" * 64)))
    rec = run_patch(world, rels("3.14.9"))
    env = env_of(world)
    assert (env["UV_VERSION"], env["UV_SHA256"], env["PYTHON_VERSION"]) == (
        "0.13.7", "c" * 64, "3.14.9")  # fmt: skip
    assert rec["uv_from"] == "0.13.6" and rec["uv_to"] == "0.13.7"
    assert world.posts == [
        f"{PREFIX}Python 3.14.8 -> 3.14.9 applied (uv 0.13.6 -> 0.13.7); "
        f"new image {SHORT}. Commit and release the pins."
    ]


def profile_with_packages(w, name, packages):
    (w.cfg / "profiles" / f"{name}.toml").write_text(
        f'[[mount]]\nhost = "{w.tmp}"\n\n[box]\npackages = {json.dumps(packages)}\n'
    )


def test_applied_builds_derived_images_and_a_failure_is_a_warning(world, monkeypatch, capsys):
    resolves(monkeypatch, pyupdate.Resolution(None))
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False, **kw: h)
    profile_with_packages(world, "media", ["ffmpeg"])
    profile_with_packages(world, "docs", ["pandoc"])
    profile_with_packages(world, "plain", [])
    built = []

    def ensure_pkgs(base, packages):
        built.append((base, packages))
        if packages == ["pandoc"]:
            raise docker.DockerError("apt failed")
        return "tag"

    monkeypatch.setattr(images, "ensure_pkgs", ensure_pkgs)
    rec = run_patch(world, rels("3.14.9"))
    assert sorted(built) == [("agentbox/agent:latest", ["ffmpeg"]),
                             ("agentbox/agent:latest", ["pandoc"])]  # fmt: skip
    assert rec["result"] == "applied" and rec["derived_warnings"] == ["docs"]  # no rollback
    assert env_of(world)["PYTHON_VERSION"] == "3.14.9"
    assert world.posts == [
        f"{PREFIX}Python 3.14.8 -> 3.14.9 applied; new image {SHORT}; "
        "derived image failed: docs. Commit and release the pins."
    ]
    assert "derived image failed for: docs" in capsys.readouterr().out


def test_not_installable_changes_nothing_and_posts_once_per_target(world, monkeypatch):
    resolves(monkeypatch, pyupdate.NotInstallable("uv has no build of Python 3.14.9 yet"))
    before = (world.repo / "images/agent/versions.env").read_text()

    def boom():
        raise AssertionError("must not build")

    rec = run_patch(world, rels("3.14.9"), build=boom)
    assert rec["result"] == "not_installable" and rec["python_to"] == "3.14.9"
    assert (world.repo / "images/agent/versions.env").read_text() == before
    text = f"{PREFIX}Python 3.14.9 is out; uv has no build yet. Retrying daily."
    assert world.posts == [text]
    run_patch(world, rels("3.14.9"), build=boom)  # next day: same target, no post
    assert world.posts == [text]
    run_patch(world, rels("3.14.10", "3.14.9"), build=boom)  # a new target posts again
    assert world.posts == [text, text.replace("3.14.9", "3.14.10")]


def test_lookup_failed_python_org_down(world, monkeypatch):
    resolves(monkeypatch, AssertionError("must not probe"))
    rec = pyupdate.patch(world.repo, build=lambda: None, doctor=lambda f: True,
                         fetch_json=failing(urllib.error.URLError("offline")))  # fmt: skip
    assert rec["result"] == "lookup_failed" and "offline" in rec["message"]
    assert rec["python_to"] is None and world.posts == []  # silent on day 1


def test_lookup_failed_no_release_in_the_line(world, monkeypatch):
    rec = run_patch(world, rels("3.15.0", "3.13.9"))
    assert rec["result"] == "lookup_failed" and "no final CPython 3.14 release" in rec["message"]


def test_lookup_failed_uv_lookup_writes_nothing(world, monkeypatch):
    resolves(monkeypatch, pyupdate.LookupFailed("astral-sh/uv: asset missing"))
    before = (world.repo / "images/agent/versions.env").read_text()
    rec = run_patch(world, rels("3.14.9"))
    assert rec["result"] == "lookup_failed" and rec["message"] == "astral-sh/uv: asset missing"
    assert (world.repo / "images/agent/versions.env").read_text() == before


def test_lookup_failed_when_docker_does_not_come_up(world, monkeypatch):
    resolves(monkeypatch, AssertionError("must not probe"))
    rec = run_patch(world, rels("3.14.9"), ready=False)
    assert rec["result"] == "lookup_failed" and rec["message"] == "Docker did not come up"


def test_failed_build_rolls_back_and_posts(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(("0.13.7", "c" * 64)))
    before = (world.repo / "images/agent/versions.env").read_text()

    def build():
        raise docker.DockerError("bash build.sh failed (1): E: Unable to locate package abc1234def")

    rec = run_patch(world, rels("3.14.9"), build=build)
    assert rec["result"] == "failed" and rec["step"] == "build"
    assert (world.repo / "images/agent/versions.env").read_text() == before  # pins restored
    assert ["docker", "tag", IMG, "agentbox/agent:latest"] in world.runs  # image tag restored
    assert world.posts == [
        f"{PREFIX}Python 3.14.9 update FAILED at build, kept 3.14.8: "
        "bash build.sh failed (1): E: Unable to locate package abc1234def"
    ]
    assert rec["image"] is None and rec["python_to"] == "3.14.9"


def test_failed_doctor_names_the_check(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    before = (world.repo / "images/agent/versions.env").read_text()

    def doctor(failed):
        failed.extend(["10", "16"])
        return False

    rec = run_patch(world, rels("3.14.9"), doctor=doctor)
    assert rec["result"] == "failed" and rec["step"] == "doctor 10"
    assert (world.repo / "images/agent/versions.env").read_text() == before
    assert world.posts[0].startswith(
        f"{PREFIX}Python 3.14.9 update FAILED at doctor 10, kept 3.14.8: "
    )
    assert rec["message"] == "doctor failed on the new image"


def test_failed_write_is_step_write(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    monkeypatch.setattr(upd, "write_env", failing(upd.UpdateError("refusing to write")))
    rec = run_patch(world, rels("3.14.9"))
    assert rec["result"] == "failed" and rec["step"] == "write"
    assert "FAILED at write" in world.posts[0]


def test_failed_text_is_one_clean_escaped_line(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))

    def build():
        raise upd.UpdateError("<!channel> a & b\x1b[31m\nsecond line " + "x" * 400)

    run_patch(world, rels("3.14.9"), build=build)
    [text] = world.posts
    assert "\n" not in text and "\x1b" not in text and "<!channel>" not in text
    assert "&lt;!channel&gt; a &amp; b" in text and "second line" not in text
    assert len(text) < 400


def test_failed_post_never_contains_the_webhook(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    run_patch(world, rels("3.14.9"), build=failing(upd.UpdateError(f"cannot reach {HOOK}")))
    [text] = world.posts
    assert HOOK not in text and "hookSECRETVALUE" not in text


# ---------------------------------------------------------------- patch: post rules
def day(w, text):
    w.at = f"{text}T05:00:00+01:00"


def test_applied_posts_every_time(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    run_patch(world, rels("3.14.9"))
    day(world, "2026-10-29")
    set_env(world, PYTHON_VERSION="3.14.8")
    run_patch(world, rels("3.14.9"))
    assert [t.split(" applied")[0] for t in world.posts] == [PREFIX + "Python 3.14.8 -> 3.14.9"] * 2


def test_failed_posts_once_per_normalized_key(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))

    def build_with(reason):
        return failing(upd.UpdateError(reason))

    r = rels("3.14.9")
    run_patch(world, r, build=build_with("bash build.sh failed (1): layer abcdef123456 gone 17"))
    # same target, step and reason except for hex ids and digits: no second post
    day(world, "2026-10-29")
    run_patch(world, r, build=build_with("bash build.sh failed (2): layer 0123456789ab gone 4"))
    assert len(world.posts) == 1
    # another reason: posts
    day(world, "2026-10-30")
    run_patch(world, r, build=build_with("network is down"))
    assert len(world.posts) == 2
    # another step: posts
    day(world, "2026-10-31")
    run_patch(world, r, doctor=lambda failed: failed.append("5") or False)
    assert len(world.posts) == 3 and "FAILED at doctor 5" in world.posts[2]
    # another target: posts
    day(world, "2026-11-01")
    run_patch(world, rels("3.14.10", "3.14.9"), build=build_with("network is down"))
    assert len(world.posts) == 4 and "Python 3.14.10 update FAILED" in world.posts[3]
    # the same failure again: still silent
    day(world, "2026-11-02")
    run_patch(world, rels("3.14.10", "3.14.9"), build=build_with("network is down"))
    assert len(world.posts) == 4


def test_normalize_reason():
    n = pyupdate.normalize_reason
    assert n("failed (1): layer abcdef123456 gone 17\nmore") == "failed (N): layer <id> gone N"
    assert n("sha256:" + "ab" * 32) == "shaN:<id>"  # the digits of "sha256" go too
    assert n("") == "" and n("  \n") == ""


def test_lookup_failed_posts_on_day_3_then_every_7th_day(world, monkeypatch):
    resolves(monkeypatch, AssertionError("must not probe"))
    boom = failing(urllib.error.URLError("python.org down"))
    posted_on = []
    for n in range(1, 25):  # 2026-11-01 ... 2026-11-24
        day(world, f"2026-11-{n:02d}")
        before = len(world.posts)
        pyupdate.patch(world.repo, build=lambda: None, doctor=lambda f: True, fetch_json=boom)
        if len(world.posts) > before:
            posted_on.append(n)
    assert posted_on == [3, 10, 17, 24]
    assert world.posts[0] == (
        f"{PREFIX}Python check has failed for 3 days: <urlopen error python.org down>".replace(
            "<", "&lt;"
        ).replace(">", "&gt;")
    )
    assert "failed for 10 days" in world.posts[1]


def test_lookup_failed_streak_resets_after_a_good_run(world, monkeypatch):
    resolves(monkeypatch, AssertionError("must not probe"))
    boom = failing(urllib.error.URLError("down"))

    def go(n, fetch):
        day(world, f"2026-11-{n:02d}")
        pyupdate.patch(world.repo, build=lambda: None, doctor=lambda f: True, fetch_json=fetch)

    go(1, boom)
    go(2, boom)
    go(3, lambda url: rels("3.14.8"))  # current: the streak is over
    go(4, boom)
    go(5, boom)
    assert world.posts == []
    go(6, boom)  # the third day of the new streak
    assert len(world.posts) == 1 and "failed for 3 days" in world.posts[0]


def test_lookup_failed_same_day_reruns_do_not_count_as_days(world, monkeypatch):
    boom = failing(urllib.error.URLError("down"))
    for _ in range(5):
        pyupdate.patch(world.repo, build=lambda: None, doctor=lambda f: True, fetch_json=boom)
    assert world.posts == []


def test_new_line_posts_once(world, monkeypatch):
    r = rels("3.14.8", "3.15.0")
    run_patch(world, r)
    text = (
        f"{PREFIX}Python 3.15 is out; the box stays on 3.14 (agentbox update --python-line 3.15)."
    )
    assert world.posts == [text]
    day(world, "2026-10-29")
    run_patch(world, r)
    assert world.posts == [text]  # once per line
    run_patch(world, rels("3.14.8", "3.15.0", "3.16.0"))
    assert world.posts == [text]  # only 3.(N+1) is announced
    run_patch(world, rels("3.14.8", pre=("3.15.0",)))
    assert world.posts == [text]


def test_new_line_not_announced_for_a_pre_release(world):
    run_patch(world, rels("3.14.8", pre=("3.15.0rc1",)))
    assert world.posts == []


def test_eol_posts_monthly_in_the_last_6_months(world):
    set_env(world, PYTHON_LINE_EOL="2027-03")
    text = (
        f"{PREFIX}Python 3.14 security support ends 2027-03. "
        "Plan a line change (agentbox update --python-line)."
    )
    ended = (
        f"{PREFIX}Python 3.14 security support ended 2027-03. "
        "Change the line now (agentbox update --python-line)."
    )
    posted = {}
    for d in ("2026-08-31", "2026-09-05", "2026-09-20", "2026-10-01", "2026-12-15", "2027-02-28",
              "2027-03-02", "2027-04-01", "2027-04-20", "2027-05-02", "2028-01-03"):  # fmt: skip
        day(world, d)
        before = len(world.posts)
        run_patch(world, rels("3.14.8"))
        posted[d] = len(world.posts) - before
    assert posted == {
        "2026-08-31": 0,  # 7 months before
        "2026-09-05": 1,  # 6 months before: the first run of the month posts
        "2026-09-20": 0,  # same month
        "2026-10-01": 1,
        "2026-12-15": 1,
        "2027-02-28": 1,  # 1 month before
        "2027-03-02": 1,  # the end month itself: "ends", once
        "2027-04-01": 1,  # after that month: "ended", on the first run of each month
        "2027-04-20": 0,  # same month
        "2027-05-02": 1,
        "2028-01-03": 1,  # and so on, while the line stays
    }
    assert set(world.posts) == {text, ended}
    assert world.posts[-3:] == [ended] * 3 and world.posts.count(text) == 5


def test_eol_and_new_line_post_in_one_run_after_the_result_post(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    set_env(world, PYTHON_LINE_EOL="2027-03")
    rec = run_patch(world, rels("3.14.9", "3.15.0"))
    assert [t.removeprefix(PREFIX).split(";")[0].split(" (")[0] for t in world.posts] == [
        "Python 3.14.8 -> 3.14.9 applied",
        "Python 3.15 is out",
        "Python 3.14 security support ends 2027-03. Plan a line change",
    ]  # the result first, then the new line, then end of support
    assert len(rec["reported"]) == 3 and rec["notify"] == "ok"


def test_a_failed_post_is_retried_and_not_marked_reported(world, monkeypatch):
    resolves(monkeypatch, pyupdate.NotInstallable("x"))
    world.post_error = "HTTP 500"
    rec = run_patch(world, rels("3.14.9"))
    assert rec["notify"] == "error: HTTP 500" and rec["reported"] == [] and world.posts == []
    assert rec["result"] == "not_installable"  # a failed post changes nothing else
    world.post_error = None
    day(world, "2026-10-29")
    rec = run_patch(world, rels("3.14.9"))
    assert rec["notify"] == "ok" and len(world.posts) == 1 and len(rec["reported"]) == 1


def test_no_webhook_no_post_but_the_record_has_the_result(world, monkeypatch):
    (world.cfg / "config.toml").write_text("")
    resolves(monkeypatch, pyupdate.Resolution(None))
    rec = run_patch(world, rels("3.14.9", "3.15.0"))
    assert rec["result"] == "applied" and rec["notify"] is None and rec["reported"] == []
    assert world.posts == [] and last(world)["result"] == "applied"


def test_a_bad_config_does_not_fail_the_update(world, monkeypatch):
    (world.cfg / "config.toml").write_text("bogus = 1\n")
    resolves(monkeypatch, pyupdate.Resolution(None))
    rec = run_patch(world, rels("3.14.9"))
    assert rec["result"] == "applied" and rec["notify"].startswith("error: ")
    assert "unknown key" in rec["notify"]


def test_post_goes_through_the_host_webhook_with_the_job_deadline(world, monkeypatch):
    seen = []
    monkeypatch.setattr(notify, "post", lambda url, text, timeout: seen.append((url, timeout)))
    resolves(monkeypatch, pyupdate.Resolution(None))
    run_patch(world, rels("3.14.9"))
    assert seen == [(HOOK, notify.NOTIFY_TIMEOUT)]


def test_history_dedupe_survives_unreadable_lines(world, monkeypatch):
    resolves(monkeypatch, pyupdate.NotInstallable("x"))
    run_patch(world, rels("3.14.9"))
    f = updatelock.update_dir() / "history.jsonl"
    f.write_text("not json\n[1]\n" + f.read_text())
    run_patch(world, rels("3.14.9"))
    assert len(world.posts) == 1


# ---------------------------------------------------------------- the command: exit codes
@pytest.fixture
def cmd(world, monkeypatch):
    """`agentbox update ...` with python.org, uv, build, doctor and Docker Desktop faked."""
    c = SimpleNamespace(releases=rels("3.14.9", "3.14.8"), doctor_ok=True, build_calls=0,
                        docker_ready=True, doctor_failed=[])  # fmt: skip
    monkeypatch.setattr(upd, "_get", lambda url: json.dumps(c.releases).encode())

    def build():
        c.build_calls += 1

    monkeypatch.setattr(cli, "update_build", lambda repo: build)

    def scratch(failed=None):
        if failed is not None:
            failed.extend(c.doctor_failed)
        return c.doctor_ok

    monkeypatch.setattr(cli, "scratch_doctor", scratch)
    monkeypatch.setattr(schedule, "ensure_docker", lambda *a, **k: c.docker_ready)
    resolves(monkeypatch, pyupdate.Resolution(None))
    return c


def raw_lock(f):
    """Hold the update lock from outside the holder flag (as another process would)."""
    import fcntl

    fh = open(f, "a")  # noqa: SIM115 - closed by the caller
    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fh


def test_exit_codes_per_result(world, cmd, monkeypatch, capsys):
    # current -> 0
    cmd.releases = rels("3.14.8")
    assert cli.main(["update", "--python-patch"]) == 0
    assert last(world)["result"] == "current"
    assert "Python 3.14.8 is current." in capsys.readouterr().out
    # applied -> 0
    cmd.releases = rels("3.14.9", "3.14.8")
    assert cli.main(["update", "--python-patch"]) == 0
    assert last(world)["result"] == "applied" and cmd.build_calls == 1
    # not installable -> 0
    set_env(world, PYTHON_VERSION="3.14.8")
    resolves(monkeypatch, pyupdate.NotInstallable("uv has no build of Python 3.14.9 yet"))
    assert cli.main(["update", "--python-patch"]) == 0
    assert last(world)["result"] == "not_installable"
    # lookup failed -> 0
    resolves(monkeypatch, pyupdate.LookupFailed("uv: down"))
    assert cli.main(["update", "--python-patch"]) == 0
    assert last(world)["result"] == "lookup_failed"
    # failed -> 1
    resolves(monkeypatch, pyupdate.Resolution(None))
    cmd.doctor_ok, cmd.doctor_failed = False, ["10"]
    assert cli.main(["update", "--python-patch"]) == 1
    rec = last(world)
    assert rec["result"] == "failed" and rec["step"] == "doctor 10"
    assert env_of(world)["PYTHON_VERSION"] == "3.14.8"
    assert [r["result"] for r in history(world)] == [
        "current", "applied", "not_installable", "lookup_failed", "failed"]  # fmt: skip


def test_the_update_holds_the_lock_and_releases_it(world, cmd, monkeypatch):
    seen = []
    cmd.releases = rels("3.14.9")
    orig = cli.update_patch

    def spy(repo):
        seen.append((updatelock.holder(), updatelock.lock_file().exists()))
        return orig(repo)

    monkeypatch.setattr(cli, "update_patch", spy)
    assert cli.main(["update", "--python-patch"]) == 0
    assert seen == [(True, True)] and updatelock.holder() is False and not updatelock.busy()


def test_a_second_update_exits_75_with_one_line(world, cmd, capsys):
    held = raw_lock(updatelock.update_dir() / "update.lock")
    try:
        for argv in (
            ["update", "--python-patch"],
            ["update"],
            ["update", "--python-line", "3.15", "--eol", "2031-10"],
        ):
            assert cli.main(argv) == 75
            err = capsys.readouterr().err
            assert err == "agentbox: another update is running; retry in a few minutes\n"
        assert cmd.build_calls == 0 and history(world) == []
    finally:
        held.close()


@pytest.mark.parametrize(
    "argv,msg",
    [
        (["--python-patch", "--python-line", "3.15", "--eol", "2031-10"], "cannot be combined"),
        (["--install"], "need --python-patch"),
        (["--uninstall"], "need --python-patch"),
        (["--python-patch", "--install", "--uninstall"], "cannot be combined"),
        (["--python-patch", "--at", "07:00"], "--at works only with --install"),
        (["--eol", "2031-10"], "--eol works only with --python-line"),
        (["--python-line", "3.15"], "needs --eol"),
        (["--force"], "--force works only with --python-line"),
        (["--python-patch", "--force"], "--force works only with --python-line"),
        (["--check", "--python-patch"], "--check cannot be combined"),
    ],
)
def test_option_errors(world, cmd, capsys, argv, msg):
    assert cli.main(["update", *argv]) == 1
    assert msg in capsys.readouterr().err
    assert history(world) == [] and cmd.build_calls == 0


def test_docker_not_ready_is_a_lookup_failure(world, cmd):
    cmd.docker_ready = False
    assert cli.main(["update", "--python-patch"]) == 0
    assert last(world)["result"] == "lookup_failed" and cmd.build_calls == 0


def test_stop_signal_rolls_back_and_releases_the_lock(world, cmd, monkeypatch):
    import signal

    cmd.releases = rels("3.14.9")
    before = (world.repo / "images/agent/versions.env").read_text()
    old = signal.getsignal(signal.SIGTERM)

    def build():
        os.kill(os.getpid(), signal.SIGTERM)  # launchd stops the job
        time.sleep(1)

    monkeypatch.setattr(cli, "update_build", lambda repo: build)
    assert cli.main(["update", "--python-patch"]) == 130
    assert (world.repo / "images/agent/versions.env").read_text() == before
    assert signal.getsignal(signal.SIGTERM) == old and not updatelock.busy()
    assert ["docker", "tag", IMG, "agentbox/agent:latest"] in world.runs


def test_update_check_prints_the_new_line_and_eol_notices(world, monkeypatch, capsys):
    set_env(world, PYTHON_LINE_EOL=f"{date.today().year + 1:04d}-01")

    def lookup(current, fetch_json=None, fetch=None, releases_out=None):
        releases_out[:] = rels("3.14.9", "3.15.0")
        return {"PYTHON_VERSION": "3.14.9"}

    monkeypatch.setattr(upd, "lookup", lookup)
    assert cli.main(["update", "--check"]) == 0
    out = capsys.readouterr().out
    assert "PYTHON_VERSION" in out and "3.14.8 -> 3.14.9" in out
    assert "Python 3.15 is out; the box stays on 3.14 (agentbox update --python-line 3.15)." in out
    set_env(world, PYTHON_LINE_EOL="2099-10")
    assert cli.main(["update", "--check"]) == 0
    assert "security support ends" not in capsys.readouterr().out  # more than 6 months away


def test_check_takes_no_lock_and_changes_nothing(world, monkeypatch):
    held = raw_lock(updatelock.update_dir() / "update.lock")
    try:
        monkeypatch.setattr(upd, "lookup", lambda current, **kw: {})
        assert cli.main(["update", "--check"]) == 0
    finally:
        held.close()


def test_full_update_python_follows_the_line_and_takes_the_lock(world, monkeypatch):
    seen = {}
    monkeypatch.setattr(upd, "lookup", lambda current, **kw: {"PYTHON_VERSION": "3.14.9"})
    resolves(monkeypatch, pyupdate.Resolution(None))

    def apply(repo, latest, build, doctor, relock=None, **kw):
        seen.update(latest=latest, holder=updatelock.holder())
        return True

    monkeypatch.setattr(upd, "apply", apply)
    assert cli.main(["update"]) == 0
    assert seen == {"latest": {"PYTHON_VERSION": "3.14.9"}, "holder": True}


# ---------------------------------------------------------------- the daily host job
@pytest.fixture
def launchctl(world, monkeypatch):
    calls, loaded = [], set()

    def label_of(plist):
        return plistlib.loads(Path(plist).read_bytes())["Label"]

    def fake(*a):
        calls.append(a)
        label = a[1].rsplit("/", 1)[-1] if len(a) > 1 else ""
        if a[0] == "print":
            return subprocess.CompletedProcess(a, 0 if label in loaded else 1, "", "")
        if a[0] == "bootstrap":
            loaded.add(label_of(a[2]))
        if a[0] == "bootout":
            loaded.discard(label)
        return subprocess.CompletedProcess(a, 0, "", "")

    monkeypatch.setattr(schedule, "is_macos", lambda: True)
    monkeypatch.setattr(schedule, "launchctl", fake)
    return SimpleNamespace(calls=calls, loaded=loaded)


@pytest.fixture
def crontab(world, monkeypatch):
    monkeypatch.setattr(schedule, "is_macos", lambda: False)
    box = {"text": "0 1 * * * echo mine\n"}
    monkeypatch.setattr(schedule, "crontab_read", lambda: box["text"])
    monkeypatch.setattr(schedule, "crontab_write", lambda t: box.update(text=t))
    monkeypatch.setattr(schedule, "launchctl", lambda *a: pytest.fail("launchctl on Linux"))
    return box


def test_install_launchd_job(world, launchctl, capsys):
    assert cli.main(["update", "--python-patch", "--install"]) == 0
    plist = world.la / "com.agentbox-unit._update.plist"
    d = plistlib.loads(plist.read_bytes())
    assert d["Label"] == "com.agentbox-unit._update"
    assert d["ProgramArguments"][-2:] == ["update", "--python-patch"]
    assert os.path.isabs(d["ProgramArguments"][0])
    assert d["StartCalendarInterval"] == [{"Minute": 0, "Hour": 5}]  # default 05:00
    udir = world.state / "_update"
    assert d["StandardOutPath"] == str(udir / "launchd.out")
    assert d["StandardErrorPath"] == str(udir / "launchd.err")
    assert udir.stat().st_mode & 0o777 == 0o700
    assert {"PATH", "HOME"} <= set(d["EnvironmentVariables"])
    assert d["RunAtLoad"] is False
    assert "com.agentbox-unit._update" in launchctl.loaded
    assert schedule.update_installed() == "loaded" and schedule.report_installed() is None
    out = capsys.readouterr()
    assert "daily at 05:00" in out.out
    assert "notify_webhook_secret" not in out.err  # the fixture has one
    # the profile jobs do not see it
    assert schedule.list_jobs() == [] and not (udir / "schedules").exists()


def test_install_at_replaces_and_warns_without_a_webhook(world, launchctl, capsys):
    (world.cfg / "config.toml").write_text("")
    assert cli.main(["update", "--python-patch", "--install", "--at", "06:15"]) == 0
    assert "notify_webhook_secret is not set" in capsys.readouterr().err
    assert cli.main(["update", "--python-patch", "--install", "--at", "7:05"]) == 0
    plist = world.la / "com.agentbox-unit._update.plist"
    assert plistlib.loads(plist.read_bytes())["StartCalendarInterval"] == [{"Minute": 5, "Hour": 7}]
    assert [c[0] for c in launchctl.calls].count("bootout") == 1
    for bad in ("25:00", "9", "ab"):
        assert cli.main(["update", "--python-patch", "--install", "--at", bad]) == 1
        assert "HH:MM" in capsys.readouterr().err
    assert plistlib.loads(plist.read_bytes())["StartCalendarInterval"] == [{"Minute": 5, "Hour": 7}]


def test_uninstall_launchd_job(world, launchctl, capsys):
    assert cli.main(["update", "--python-patch", "--install"]) == 0
    plist = world.la / "com.agentbox-unit._update.plist"
    assert cli.main(["schedule", "report", "--install"]) == 0  # the report job stays
    capsys.readouterr()
    assert cli.main(["update", "--python-patch", "--uninstall"]) == 0
    assert not plist.exists() and "com.agentbox-unit._update" not in launchctl.loaded
    assert "com.agentbox-unit._report" in launchctl.loaded
    assert ("bootout", f"gui/{os.getuid()}/com.agentbox-unit._update") in launchctl.calls
    assert "Python patch update job removed" in capsys.readouterr().out
    assert (world.state / "_update").is_dir()  # its files stay
    assert cli.main(["update", "--python-patch", "--uninstall"]) == 0
    assert "no Python patch update job installed" in capsys.readouterr().out


def test_install_and_uninstall_in_the_crontab(world, crontab, capsys):
    assert cli.main(["update", "--python-patch", "--install"]) == 0
    text = crontab["text"]
    assert text.startswith("0 1 * * * echo mine\n# agentbox:_update\n0 5 * * * cd / && ")
    udir = world.state / "_update"
    line = text.splitlines()[-1]
    tail = f"update --python-patch </dev/null >>{udir / 'launchd.out'} 2>>{udir / 'launchd.err'}"
    assert line.endswith(tail)
    assert schedule.update_installed() == "in crontab" and schedule.report_installed() is None
    assert cli.main(["schedule", "report", "--install"]) == 0
    assert cli.main(["update", "--python-patch", "--install", "--at", "10:00"]) == 0
    assert crontab["text"].count("# agentbox:_update") == 1 and "0 10 * * *" in crontab["text"]
    assert crontab["text"].count("# agentbox:_report") == 1
    assert cli.main(["update", "--python-patch", "--uninstall"]) == 0
    assert "# agentbox:_update" not in crontab["text"] and "# agentbox:_report" in crontab["text"]
    assert schedule.update_installed() is None
    assert cli.main(["update", "--python-patch", "--uninstall"]) == 0
    assert "no Python patch update job installed" in capsys.readouterr().out


def test_update_job_states_on_macos(world, launchctl):
    assert schedule.update_installed() is None
    assert cli.main(["update", "--python-patch", "--install"]) == 0
    assert schedule.update_installed() == "loaded"
    launchctl.loaded.clear()
    assert schedule.update_installed() == "not loaded"  # the plist is there, the job is not loaded


def test_report_job_helpers_still_use_their_own_label_and_tag(world):
    assert schedule.report_label() == "com.agentbox-unit._report"
    assert schedule.report_tag() == "# agentbox:_report"
    assert schedule.host_label("_update") == "com.agentbox-unit._update"
    assert schedule.host_tag("_update") == "# agentbox:_update"


# ---------------------------------------------------------------- line change and the lock check
def run_line(w, line="3.15", eol="2031-10", releases=None, lock=None, **kw):
    return pyupdate.change_line(
        w.repo,
        line,
        eol,
        build=kw.get("build", lambda: None),
        doctor=kw.get("doctor", lambda failed: True),
        force=kw.get("force", False),
        fetch_json=lambda url: releases if releases is not None else rels("3.15.0", "3.14.9"),
        lock=lock or (lambda prev, cand, force: True),
    )


def test_line_change_writes_line_eol_and_version_then_checks_then_doctors(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    steps = []
    rec = run_line(
        world,
        build=lambda: steps.append(("build", env_of(world)["PYTHON_LINE"])),
        doctor=lambda failed: steps.append(("doctor",)) or True,
        lock=lambda prev, cand, force: steps.append(("lock", prev, cand, force)) or True,
    )
    env = env_of(world)
    assert (env["PYTHON_LINE"], env["PYTHON_LINE_EOL"], env["PYTHON_VERSION"]) == (
        "3.15", "2031-10", "3.15.0")  # fmt: skip
    assert steps == [("build", "3.15"), ("lock", IMG, "agentbox/agent:latest", False),
                     ("doctor",)]  # fmt: skip
    assert rec["result"] == "applied" and rec["python_from"] == "3.14.8"
    assert world.posts == [
        f"{PREFIX}Python line 3.14 -> 3.15 (3.14.8 -> 3.15.0) applied; new image {SHORT}. "
        "Commit and release the pins."
    ]
    assert history(world) == [rec]


def test_line_change_lock_failure_rolls_back_everything(world, monkeypatch, capsys):
    resolves(monkeypatch, pyupdate.Resolution(("0.13.7", "c" * 64)))
    before = (world.repo / "images/agent/versions.env").read_text()

    def lock(prev, cand, force):
        print("lock check: 1 project(s) fail")
        raise upd.UpdateError("lock check failed: a project would not install")

    def doctor(failed):
        raise AssertionError("doctor must not run")

    rec = run_line(world, lock=lock, doctor=doctor)
    assert rec["result"] == "failed" and rec["step"] == "check"
    assert (world.repo / "images/agent/versions.env").read_text() == before
    assert ["docker", "tag", IMG, "agentbox/agent:latest"] in world.runs
    assert world.posts == [
        f"{PREFIX}Python 3.15.0 update FAILED at check, kept 3.14.8: "
        "lock check failed: a project would not install"
    ]  # a failed line change posts too, once per (target, step, reason)
    run_line(world, lock=lock, doctor=doctor)
    assert len(world.posts) == 1


def test_line_change_passes_force_to_the_check(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    seen = []
    run_line(world, force=True, lock=lambda p, c, force: seen.append(force) or True)
    assert seen == [True]


def test_line_change_needs_a_uv_that_can_install_it_and_writes_nothing(world, monkeypatch):
    before = (world.repo / "images/agent/versions.env").read_text()
    for exc, text in (
        (pyupdate.NotInstallable("uv has no build of Python 3.15.0 yet"), "uv has no build"),
        (pyupdate.LookupFailed("uv: down"), "uv: down"),
    ):
        resolves(monkeypatch, exc)
        with pytest.raises(upd.UpdateError, match=text):
            run_line(world, build=lambda: pytest.fail("must not build"))
        assert (world.repo / "images/agent/versions.env").read_text() == before
    assert history(world) == []


@pytest.mark.parametrize(
    "line,eol,releases,msg",
    [
        ("3.14", "2031-10", None, "already 3.14"),
        ("3.x", "2031-10", None, "--python-line"),
        ("3.15", "2031-13", None, "--eol"),
        ("3.16", "2031-10", None, "no final CPython 3.16 release"),
    ],
)
def test_line_change_refusals(world, monkeypatch, line, eol, releases, msg):
    resolves(monkeypatch, AssertionError("must not probe"))
    with pytest.raises(upd.UpdateError, match=msg):
        run_line(world, line, eol, releases)


def test_line_change_through_the_cli(world, cmd, monkeypatch, capsys):
    cmd.releases = rels("3.15.0", "3.14.9")
    seen = []

    def lock_check(prev, cand, force=False, scan=None, run=None):
        seen.append((prev, cand, force, updatelock.holder()))
        return True

    monkeypatch.setattr(pyupdate, "lock_check", lock_check)
    monkeypatch.setattr(
        pyupdate, "change_line", _wrap_change_line(pyupdate.change_line, lock_check)
    )
    assert cli.main(["update", "--python-line", "3.15", "--eol", "2031-10", "--force"]) == 0
    assert seen == [(IMG, "agentbox/agent:latest", True, True)]
    assert env_of(world)["PYTHON_LINE"] == "3.15" and last(world)["result"] == "applied"


def _wrap_change_line(orig, lock_check):
    def wrapped(*a, **kw):
        return orig(*a, lock=lock_check, **kw)

    return wrapped


def mount_tree(root: Path):
    """uv.lock at depth 0, 1, 2 (found); 3, in a dot-dir, behind symlinks (not found)."""
    for d in ("", "a", "a/b", "a/b/c", ".hidden", "plain", "linked-target"):
        (root / d).mkdir(parents=True, exist_ok=True)
        (root / d / "uv.lock").write_text("version = 1\n")
    (root / "symlock").mkdir()
    (root / "symlock" / "uv.lock").symlink_to(root / "uv.lock")  # a symlinked lock
    (root / "dirlock").mkdir()
    (root / "dirlock" / "uv.lock").mkdir()  # not a regular file
    (root / "linkdir").symlink_to(root / "linked-target")  # a symlinked directory
    (root / "a" / ".venv").mkdir()
    (root / "a" / ".venv" / "uv.lock").write_text("x")


def test_scan_mount_finds_regular_locks_at_depth_0_to_2_only(tmp_path):
    mount_tree(tmp_path)
    found = sorted(p.relative_to(tmp_path).as_posix() for p in pyupdate.scan_mount(tmp_path))
    assert found == [".", "a", "a/b", "linked-target", "plain"]


def test_scan_profiles_covers_every_mount_of_every_profile(world, monkeypatch):
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False, **kw: h)
    one, two = world.tmp / "one", world.tmp / "two"
    for d in (one, two):
        d.mkdir()
        (d / "uv.lock").write_text("x")
    (one / "sub").mkdir()
    (one / "sub" / "uv.lock").write_text("x")
    (world.cfg / "profiles" / "a.toml").write_text(f'[[mount]]\nhost = "{one}"\n')
    (world.cfg / "profiles" / "b.toml").write_text(
        f'[[mount]]\nhost = "{one}"\nmode = "ro"\n\n[[mount]]\nhost = "{two}"\nmode = "ro"\n'
    )
    (world.cfg / "profiles" / "bad.toml").write_text("not = [valid\n")
    scan = pyupdate.scan_profiles()
    assert scan.projects == {one: ["a", "b"], one / "sub": ["a", "b"], two: ["b"]}
    assert scan.skipped == ["bad"]


MARK1 = "marked as `--no-build` but has no binary distribution"
NO_BIN = (
    "error: Distribution `numpy==2.4.0 @ registry+https://pypi.org/simple` can't be installed "
    f"because it is {MARK1}\n"
)
INCOMPAT = (
    "error: The requested interpreter resolved to Python 3.15.0, which is incompatible with the "
    "project's Python requirement: `>=3.8, <3.15`\n"
)


def fake_run(table):
    """run(image, project) -> (rc, output) from {image: (rc, output)}; records calls."""
    calls = []

    def run(image, project):
        calls.append((image, project))
        return table[image]

    run.calls = calls
    return run


def one(current, cand, **table):
    run = fake_run({"cur": current, "cand": cand})
    return pyupdate.check_one("cur", "cand", Path("/w/p"), ["demo"], run), run


def test_lock_fails_when_the_candidate_has_no_wheel_and_the_current_passes():
    r, run = one((0, ""), (2, NO_BIN))
    assert (r.status, r.detail) == ("fail", f"package numpy==2.4.0: {MARK1.replace('`', '')}")
    assert run.calls == [("cand", Path("/w/p")), ("cur", Path("/w/p"))]  # each lock runs twice


def test_lock_fails_on_an_incompatible_python_requirement():
    r, _ = one((0, ""), (2, INCOMPAT))
    assert r.status == "fail" and "incompatible with the project's Python requirement" in r.detail
    r, _ = one((0, ""), (2, INCOMPAT.replace("'", "\u2019")))  # a typographic apostrophe
    assert r.status == "fail"


def test_lock_passes_when_the_candidate_passes():
    r, _ = one((2, NO_BIN), (0, ""))  # the current image fails, the new one is better
    assert r.status == "ok"
    r, _ = one((0, ""), (0, ""))
    assert r.status == "ok" and r.detail == ""


@pytest.mark.parametrize(
    "cur,cand,why",
    [
        ((2, NO_BIN), (2, NO_BIN), "the current image fails too"),
        ((0, ""), (2, "error: Failed to fetch: https://pypi.org/simple/x/\n"), "Failed to fetch"),
        ((0, ""), (124, ""), "no output"),  # a timeout
        ((0, ""), (1, "something odd\nsecond\n"), "something odd"),
    ],
)
def test_every_other_failure_is_undecided_and_not_blocking(cur, cand, why):
    r, _ = one(cur, cand)
    assert r.status == "undecided" and why in r.detail


def test_lock_without_a_current_image_is_undecided():
    run = fake_run({"cand": (2, NO_BIN)})
    r = pyupdate.check_one(None, "cand", Path("/w/p"), ["demo"], run)
    assert r.status == "undecided" and "no current image to compare" in r.detail
    assert run.calls == [("cand", Path("/w/p"))]


def test_lock_in_a_path_docker_cannot_mount_is_undecided():
    run = fake_run({})
    r = pyupdate.check_one("cur", "cand", Path("/w/a:b"), ["demo"], run)
    assert r.status == "undecided" and run.calls == []


def test_lock_check_prints_each_project_and_blocks_only_on_a_failure(capsys):
    scan = pyupdate.Scan({Path("/w/ok"): ["a"], Path("/w/bad"): ["a", "b"], Path("/w/odd"): ["b"]},
                         ["broken"])  # fmt: skip
    table = {
        "/w/ok": ((0, ""), (0, "")),
        "/w/bad": ((0, ""), (2, NO_BIN)),
        "/w/odd": ((0, ""), (1, "error: Failed to fetch\n")),
    }

    def run(image, project):
        cur, cand = table[str(project)]
        return cur if image == "cur" else cand

    assert pyupdate.lock_check("cur", "cand", False, scan, run) is False
    out = capsys.readouterr().out
    assert "profile broken does not load" in out and "3 uv.lock project(s)" in out
    assert "ok        /w/ok (profile a)" in out
    assert "FAIL      /w/bad (profile a, b): package numpy==2.4.0" in out
    assert "undecided /w/odd (profile b): error: Failed to fetch" in out
    assert "1 project(s) fail on the new Python; rolling back" in out
    assert pyupdate.lock_check("cur", "cand", True, scan, run) is True  # --force
    assert "--force: going on" in capsys.readouterr().out
    undecided_only = pyupdate.Scan({Path("/w/odd"): ["b"]})
    assert pyupdate.lock_check("cur", "cand", False, undecided_only, run) is True


def test_run_lock_is_a_plain_offline_read_only_container(world, monkeypatch):
    seen = []

    def run(args, **kw):
        seen.append((args, kw))
        return subprocess.CompletedProcess(args, 2, "out\n", "err\n")

    monkeypatch.setattr(docker, "run", run)
    rc, out = pyupdate.run_lock("sha256:img", Path("/w/p"))
    args, kw = seen[0]
    assert (rc, out) == (2, "err\nout\n") and kw["timeout"] == 120
    assert args[:3] == ["docker", "run", "--rm"] and args[args.index("--network") + 1] == "none"
    assert args[args.index("--user") + 1] == "agent"
    assert args[args.index("-v") + 1] == "/w/p:/project:ro"
    assert args[args.index("-w") + 1] == "/project"
    envs = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
    assert envs == [
        "UV_OFFLINE=1",
        "UV_CACHE_DIR=/tmp/uv-cache",
        "UV_PROJECT_ENVIRONMENT=/tmp/venv",
    ]
    i = args.index("sha256:img")
    assert args[i + 1 :] == ["uv", "sync", "--frozen", "--no-build", "--dry-run", "--python",
                             "/usr/local/bin/python"]  # fmt: skip
    for forbidden in (
        "--privileged",
        "--cap-add",
        "--network=host",
        "--env-file",
        "--volumes-from",
    ):
        assert forbidden not in args
    assert len(seen) == 1  # no timeout: nothing to clean up


def test_run_lock_removes_the_container_after_a_timeout(world, monkeypatch):
    seen = []

    def run(args, **kw):
        seen.append(args)
        return subprocess.CompletedProcess(args, 124 if args[1] == "run" else 0, "", "")

    monkeypatch.setattr(docker, "run", run)
    rc, _ = pyupdate.run_lock("img", Path("/w/p"))
    name = seen[0][seen[0].index("--name") + 1]
    assert rc == 124 and seen[1] == ["docker", "rm", "-f", name]


# ---------------------------------------------------------------- the interlock
@pytest.fixture
def box_world(world, monkeypatch):
    """A profile `demo` and a box whose start stops at the first step after the interlock."""
    from agentbox import mountstate

    monkeypatch.setattr(
        "agentbox.profile.check_mount_host", lambda h, d=False, **kw: os.path.realpath(h)
    )
    mnt = world.tmp / "mnt"
    mnt.mkdir()
    (world.cfg / "profiles" / "demo.toml").write_text(f'[[mount]]\nhost = "{mnt}"\n')

    class Reached(Exception):
        pass

    reached = []

    def check_and_record(*a, **k):
        reached.append("started")
        raise Reached("past the interlock")

    monkeypatch.setattr(mountstate, "check_and_record", check_and_record)
    monkeypatch.setattr(boxmod, "is_running", lambda b: False)
    monkeypatch.setattr(
        images, "ensure_agent", lambda repo: pytest.fail("an image was built under an update")
    )
    return SimpleNamespace(reached=reached, Reached=Reached, mnt=mnt)


MSG = "agentbox: an update is running; retry in a few minutes\n"


@pytest.fixture
def held(world):
    fh = raw_lock(updatelock.update_dir() / "update.lock")
    yield fh
    fh.close()


@pytest.mark.parametrize(
    "argv",
    [["up", "demo"], ["shell", "demo"], ["claude", "demo"], ["doctor", "demo"]],
)
def test_commands_that_start_a_box_exit_75_while_an_update_runs(
    world, box_world, held, capsys, argv
):
    assert cli.main(argv) == 75
    assert capsys.readouterr().err == MSG
    assert box_world.reached == []


def test_run_exits_75_too(world, box_world, held, capsys):
    prompt = world.tmp / "p.md"
    prompt.write_text("hi\n")
    assert cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(prompt)]) == 75
    assert capsys.readouterr().err == MSG and box_world.reached == []


def test_the_box_starts_when_no_update_runs(world, box_world):
    with pytest.raises(box_world.Reached):  # past the interlock, into the start
        boxmod.up(boxmod.load("demo"))
    assert box_world.reached == ["started"]


def test_a_second_process_sees_the_lock_and_the_holder_does_not(world):
    probe = (
        "import sys; sys.path.insert(0, sys.argv[1]);"
        "from agentbox import updatelock; print(updatelock.busy())"
    )
    cmd = [sys.executable, "-c", probe, str(ROOT / "cli")]
    env = {**os.environ, "AGENTBOX_STATE_HOME": str(world.state)}

    def other_process():
        return subprocess.run(cmd, env=env, capture_output=True, text=True).stdout.strip()

    assert updatelock.busy() is False and other_process() == "False"  # no lock file yet
    with updatelock.hold():
        assert updatelock.holder() is True
        assert updatelock.busy() is False  # the holder passes
        updatelock.check()
        assert other_process() == "True"  # a fire, another CLI process, a shell: never
        with pytest.raises(updatelock.UpdateBusy), updatelock.hold():  # one holder at a time
            pass
    assert updatelock.holder() is False and other_process() == "False"


def test_no_environment_variable_carries_the_holder_state(world, monkeypatch):
    held_fh = raw_lock(updatelock.update_dir() / "update.lock")
    try:
        for k, v in os.environ.items():
            monkeypatch.setenv(k, v)
        for name in ("AGENTBOX_UPDATE_HOLDER", "AGENTBOX_UPDATE", "AGENTBOX_UPDATING"):
            monkeypatch.setenv(name, "1")
        assert updatelock.busy() is True
        with pytest.raises(updatelock.UpdateBusy, match="an update is running"):
            updatelock.check()
    finally:
        held_fh.close()


@pytest.fixture
def fixed_lock(world, monkeypatch):
    """The scratch doctor swaps AGENTBOX_STATE_HOME; pin the lock path so that only
    the holder flag, not the swap, decides whether the interlock passes."""
    f = updatelock.update_dir() / "update.lock"
    monkeypatch.setattr(updatelock, "lock_file", lambda: f)
    return f


def test_scratch_doctor_starts_its_box_while_the_lock_is_held(world, box_world, fixed_lock, capsys):
    failed: list[str] = []
    with updatelock.hold():
        assert updatelock.lock_file().exists()
        ok = cli.scratch_doctor(failed)
    assert ok is False and box_world.reached == ["started"]  # it got past the interlock
    assert failed == ["scratch-box"]
    assert "past the interlock" in capsys.readouterr().err


def test_scratch_doctor_without_the_holder_is_stopped_by_the_lock(
    world, box_world, fixed_lock, capsys
):
    held_fh = raw_lock(fixed_lock)  # another process holds it
    try:
        assert cli.scratch_doctor() is False
    finally:
        held_fh.close()
    assert box_world.reached == [] and "an update is running" in capsys.readouterr().err


# ---------------------------------------------------------------- the fire waits, then does not run
def make_job(w, profile="p1", name="daily"):
    prog, extra = schedule.program_args(argv0="")
    jd = schedule.job_dir(profile, name)
    jd.mkdir(parents=True, exist_ok=True)
    label = schedule.label_for(profile, name)
    job = {
        "profile": profile, "name": name, "agent": "claude", "model": None,
        "schedule": schedule.Spec(every=60).as_json(), "dir": str(jd), "label": label,
        "plist": str(schedule.launchagents_dir() / f"{label}.plist"),
        "argv": schedule.fire_argv(prog, profile, name), "env": schedule.job_env(extra),
    }  # fmt: skip
    (jd / "job.json").write_text(json.dumps(job))
    (jd / "prompt.md").write_text("hello\n")
    return job


def ok_preflight(profile, agent, model=None, code=()):
    return None, []


def test_fire_waits_for_the_update_and_then_runs(world, monkeypatch):
    monkeypatch.setattr(schedule, "docker_up", lambda: True)
    job = make_job(world)
    held = raw_lock(updatelock.update_dir() / "update.lock")
    threading_release = __import__("threading").Timer(0.3, held.close)
    threading_release.start()
    ran = []
    t0 = time.monotonic()
    rc = schedule.fire("p1", "daily", lambda *a: ran.append(1) or (0, world.tmp), ok_preflight,
                       update_wait=5, update_poll=0.05)  # fmt: skip
    threading_release.join()
    assert rc == 0 and ran == [1] and 0.2 < time.monotonic() - t0 < 4
    last_rec = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last_rec["status"] == "ok"


def test_fire_records_not_run_after_the_wait(world, monkeypatch, capsys):
    monkeypatch.setattr(schedule, "docker_up", lambda: True)
    job = make_job(world)
    (world.cfg / "config.toml").write_text(
        'secret_backend = "env"\nnotify_webhook_secret = "SLACK_WEBHOOK_URL"\n'
    )
    held = raw_lock(updatelock.update_dir() / "update.lock")
    try:
        t0 = time.monotonic()
        rc = schedule.fire("p1", "daily", lambda *a: pytest.fail("must not run"), ok_preflight,
                           update_wait=0.4, update_poll=0.05)  # fmt: skip
        assert 0.35 < time.monotonic() - t0 < 4
    finally:
        held.close()
    assert rc == schedule.RC_DOCKER_DOWN == 69
    rec = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert rec["status"] == "failed" and rec["exit_code"] == 69
    assert rec["message"] == "update in progress"
    assert world.posts == ["agentbox p1/daily: did not run (exit 69, 0s) — update in progress"]
    assert "update in progress" in capsys.readouterr().err


def test_the_fire_defaults_are_15_minutes_polled_every_10_seconds():
    assert schedule.UPDATE_WAIT == 900 and schedule.UPDATE_POLL == 10
    import inspect

    sig = inspect.signature(schedule.fire).parameters
    assert sig["update_wait"].default is None and sig["update_poll"].default == 10


def test_fire_does_not_wait_without_an_update(world, monkeypatch):
    monkeypatch.setattr(schedule, "docker_up", lambda: True)
    make_job(world)
    monkeypatch.setattr(time, "sleep", lambda s: pytest.fail("must not wait"))
    assert schedule.fire("p1", "daily", lambda *a: (0, world.tmp), ok_preflight) == 0


# ---------------------------------------------------------------- pickup: image outdated
def test_images_outdated_compares_the_running_container_with_the_current_image(world, monkeypatch):
    h = images.agent_hash(ROOT)
    world.images[f"{images.AGENT_REPO}:{h}"] = "sha256:new"
    running = {"id": "sha256:old"}
    monkeypatch.setattr(docker, "container_image_id", lambda project: running["id"])
    assert images.outdated(ROOT, "agentbox-demo", []) is True
    running["id"] = "sha256:new"
    assert images.outdated(ROOT, "agentbox-demo", []) is False
    # a derived image: the container must run it, not the base
    pk = images.pkgs_tag("sha256:new", ["ffmpeg"])
    assert images.outdated(ROOT, "agentbox-demo", ["ffmpeg"]) is True  # not built yet
    world.images[pk] = "sha256:derived"
    assert images.outdated(ROOT, "agentbox-demo", ["ffmpeg"]) is True  # runs the base
    running["id"] = "sha256:derived"
    assert images.outdated(ROOT, "agentbox-demo", ["ffmpeg"]) is False
    running["id"] = None  # no running container: nothing to mark
    assert images.outdated(ROOT, "agentbox-demo", []) is False
    monkeypatch.setattr(docker, "container_image_id", failing(docker.DockerError("down")))
    assert images.outdated(ROOT, "agentbox-demo", []) is False


def test_container_image_id_asks_docker_for_the_agent_service(monkeypatch):
    seen = []

    def run(args, **kw):
        seen.append(args)
        return subprocess.CompletedProcess(
            args, 0, "abc123\n" if args[1] == "ps" else "sha256:i\n", ""
        )

    monkeypatch.setattr(docker, "run", run)
    assert docker.container_image_id("agentbox-demo") == "sha256:i"
    assert "label=com.docker.compose.project=agentbox-demo" in seen[0]
    assert "label=com.docker.compose.service=agent" in seen[0] and seen[1][-1] == "abc123"
    monkeypatch.setattr(
        docker, "run", lambda args, **kw: subprocess.CompletedProcess(args, 0, "", "")
    )
    assert docker.container_image_id("agentbox-demo") is None


def test_ls_marks_a_running_box_with_an_old_image(world, monkeypatch, capsys):
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False, **kw: h)
    for name in ("old", "new", "off"):
        (world.cfg / "profiles" / f"{name}.toml").write_text(
            f'[[mount]]\nhost = "{world.tmp}/{name}"\n'
        )
    projects = {"agentbox-old": ["agent"], "agentbox-new": ["agent"]}
    monkeypatch.setattr(
        docker, "running_projects", lambda prefix="agentbox-", timeout=None: projects
    )
    monkeypatch.setattr(
        images, "outdated", lambda repo, project, packages: project == "agentbox-old"
    )
    assert cli.main(["ls"]) == 0
    rows = {line.split()[0]: line for line in capsys.readouterr().out.splitlines()}
    assert rows["old"].endswith("image outdated") and "running" in rows["old"]
    assert "image outdated" not in rows["new"] and "running" in rows["new"]
    assert "image outdated" not in rows["off"] and "stopped" in rows["off"]


def test_ls_does_not_ask_docker_about_a_stopped_box(world, monkeypatch, capsys):
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False, **kw: h)
    (world.cfg / "profiles" / "off.toml").write_text(f'[[mount]]\nhost = "{world.tmp}/off"\n')
    monkeypatch.setattr(docker, "running_projects", lambda prefix="agentbox-", timeout=None: {})
    monkeypatch.setattr(images, "outdated", lambda *a: pytest.fail("asked for a stopped box"))
    assert cli.main(["ls"]) == 0


def test_up_says_image_outdated_and_how_to_recreate(world, monkeypatch, capsys):
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False, **kw: h)
    (world.cfg / "profiles" / "demo.toml").write_text(f'[[mount]]\nhost = "{world.tmp}/demo"\n')
    monkeypatch.setattr(cli, "ensure_up", lambda b, *a, **k: None)
    monkeypatch.setattr(boxmod, "pin", lambda b: None)
    monkeypatch.setattr(boxmod, "session_lock", lambda b: __import__("contextlib").nullcontext())
    box = SimpleNamespace(packages=[])
    fake = SimpleNamespace(name="demo", project="agentbox-demo", profile=SimpleNamespace(box=box))
    monkeypatch.setattr(boxmod, "load", lambda name: fake)
    monkeypatch.setattr(images, "outdated", lambda repo, project, packages: True)
    assert cli.main(["up", "demo"]) == 0
    out = capsys.readouterr().out
    assert "demo: image outdated" in out
    assert "`agentbox down demo`, then `agentbox up demo`" in out
    monkeypatch.setattr(images, "outdated", lambda repo, project, packages: False)
    assert cli.main(["up", "demo"]) == 0
    assert "image outdated" not in capsys.readouterr().out


# ---------------------------------------------------------------- pins and image build
def test_versions_env_has_the_python_pins_with_sources():
    text = (ROOT / "images/agent/versions.env").read_text()
    env = upd.read_env(text)
    assert env["PYTHON_LINE"] == "3.14" and env["PYTHON_LINE_EOL"] == "2030-10"
    assert env["PYTHON_VERSION"].startswith(env["PYTHON_LINE"] + ".")  # the daily job moves it
    for k in ("PYTHON_LINE", "PYTHON_LINE_EOL", "PYTHON_VERSION"):
        assert upd.value_problem(k, env[k], env) is None
        prev = text.splitlines()[text.splitlines().index(f"{k}={env[k]}") - 1]
        assert prev.startswith("# "), f"{k} needs a source comment"
    assert "pep-0745" in text


def test_build_passes_every_versions_env_line_as_a_build_arg():
    sh = (ROOT / "images/agent/build.sh").read_text()
    assert '--build-arg "$line"' in sh and "versions.env" in sh  # no per-key list to extend
    df = (ROOT / "images/agent/Dockerfile").read_text()
    final = df[df.index("\nFROM ${UBUNTU_IMAGE}\n") :]
    for arg in ("PYTHON_LINE", "PYTHON_LINE_EOL", "PYTHON_VERSION"):
        assert f"\nARG {arg}\n" in final


def run_dockerfile_check(line, version):
    import re

    df = (ROOT / "images/agent/Dockerfile").read_text()
    m = re.search(r'RUN (case "\$\{PYTHON_VERSION\}".*?esac)', df, re.S)
    assert m, "the Dockerfile must fail the build when PYTHON_VERSION is not in PYTHON_LINE"
    snippet = m.group(1).replace("\\\n", " ")
    env = {"PATH": os.environ["PATH"], "PYTHON_VERSION": version}
    if line is not None:
        env["PYTHON_LINE"] = line
    r = subprocess.run(["bash", "-euo", "pipefail", "-c", snippet], env=env, capture_output=True,
                       text=True)  # fmt: skip
    return r.returncode, r.stderr


def test_dockerfile_fails_when_the_version_is_not_in_the_line():
    assert run_dockerfile_check("3.14", "3.14.8")[0] == 0
    assert run_dockerfile_check("3.15", "3.15.0")[0] == 0
    for line, version in (("3.14", "3.15.0"), ("3.15", "3.14.8"), ("3.1", "3.14.8"),
                          ("3.14", "3.140.1"), ("3.14", "3.14"), ("3.14", "")):  # fmt: skip
        rc, err = run_dockerfile_check(line, version)
        assert rc == 1 and "FATAL" in err, (line, version)
    rc, err = run_dockerfile_check(None, "3.14.8")  # PYTHON_LINE unset
    assert rc != 0


def test_dockerfile_python_install_comes_after_the_check():
    df = (ROOT / "images/agent/Dockerfile").read_text()
    assert df.index("FATAL: PYTHON_VERSION") < df.index("uv python install")
    for line in df.splitlines():
        assert "3.15" not in line or line.lstrip().startswith("#")  # no hard-coded line


def test_a_fire_that_waited_out_an_update_is_not_reported_as_docker_down():
    from datetime import datetime

    from agentbox import fleet

    start = datetime.now().astimezone()
    cause = fleet.row_cause("docker_down", {"message": "update in progress"}, start)
    assert cause == "update in progress"
    docker_msg = {"message": "Docker did not come up within 120 s; the job did not run."}
    assert fleet.row_cause("docker_down", docker_msg, start) == "Docker did not come up"
    assert fleet.row_cause("docker_down", {"message": None}, start) == "Docker did not come up"


def test_a_failure_after_the_doctor_pass_cannot_undo_the_update(world, monkeypatch, capsys):
    resolves(monkeypatch, pyupdate.Resolution(None))
    monkeypatch.setattr(pyupdate, "profiles_with_packages", failing(OSError("disk")))
    rec = run_patch(world, rels("3.14.9"))
    assert rec["result"] == "applied" and env_of(world)["PYTHON_VERSION"] == "3.14.9"
    assert "warning: after the update: disk" in capsys.readouterr().out


# ---------------------------------------------------------------- review round 1
def test_every_probe_container_disables_the_uv_cache(world, monkeypatch, tmp_path):
    seen = []

    def run(args, **kw):
        seen.append(args)
        return subprocess.CompletedProcess(args, 0, "[]", "")

    monkeypatch.setattr(docker, "run", run)
    pyupdate.probe_image(images.AGENT_LATEST, "3.14.9")
    pyupdate.probe_tarball("ubuntu:24.04@sha256:" + "0" * 64, tmp_path, "3.14.9")
    assert len(seen) == 2
    for args in seen:
        pairs = [(args[i], args[i + 1]) for i in range(len(args) - 1)]
        assert ("-e", "UV_NO_CACHE=1") in pairs, args  # no HOME to put a cache in


def test_a_lock_taken_after_the_preflight_makes_the_fire_wait_and_record_not_run(
    world, monkeypatch
):
    monkeypatch.setattr(schedule, "docker_up", lambda: True)
    job = make_job(world)
    held = []

    def preflight(profile, agent, model=None, code=()):
        held.append(raw_lock(updatelock.update_dir() / "update.lock"))  # the update starts now
        return None, []

    def runner(*a):
        updatelock.check()  # box._up
        pytest.fail("the box must not start")

    try:
        rc = schedule.fire("p1", "daily", runner, preflight, update_wait=0.4, update_poll=0.05)
    finally:
        for h in held:
            h.close()
    assert rc == 69
    rec = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert rec["exit_code"] == 69 and rec["message"] == "update in progress"
    assert rec["run_dir"] is None
    assert world.posts == ["agentbox p1/daily: did not run (exit 69, 0s) — update in progress"]


def test_a_lock_that_frees_during_the_second_wait_lets_the_fire_run(world, monkeypatch):
    import threading

    monkeypatch.setattr(schedule, "docker_up", lambda: True)
    job = make_job(world)
    held = []
    calls = []

    def preflight(profile, agent, model=None, code=()):
        held.append(raw_lock(updatelock.update_dir() / "update.lock"))
        threading.Timer(0.3, held[0].close).start()
        return None, []

    def runner(*a):
        calls.append(1)
        updatelock.check()
        return 0, world.tmp

    rc = schedule.fire("p1", "daily", runner, preflight, update_wait=5, update_poll=0.05)
    assert rc == 0 and len(calls) == 2  # busy once, then the box started
    assert json.loads((Path(job["dir"]) / "last.json").read_text())["status"] == "ok"


def test_the_wait_budget_is_shared_by_both_waits(world, monkeypatch):
    monkeypatch.setattr(schedule, "docker_up", lambda: True)
    make_job(world)
    held = raw_lock(updatelock.update_dir() / "update.lock")
    t0 = time.monotonic()
    try:
        rc = schedule.fire("p1", "daily", lambda *a: updatelock.check(), ok_preflight,
                           update_wait=0.5, update_poll=0.05)  # fmt: skip
    finally:
        held.close()
    assert rc == 69 and time.monotonic() - t0 < 1.5  # 0.5 s once, not once per wait


def test_sched_runner_lets_update_busy_through_unwrapped(world, monkeypatch):
    def load(name):
        raise updatelock.UpdateBusy(updatelock.BUSY_MSG)

    monkeypatch.setattr(boxmod, "load", load)
    with pytest.raises(updatelock.UpdateBusy):
        cli.sched_runner("demo", "claude", "/p.md", None)
    monkeypatch.setattr(boxmod, "load", failing(boxmod.BoxError("other")))
    with pytest.raises(cli.RunFailed):  # every other failure is still wrapped
        cli.sched_runner("demo", "claude", "/p.md", None)


def test_busy_probes_share_the_lock_and_do_not_block_hold(world):
    import fcntl

    f = updatelock.update_dir() / "update.lock"
    f.touch()
    with f.open("rb") as other_probe:  # a probe in flight in another process
        fcntl.flock(other_probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
        assert updatelock.busy() is False  # an exclusive probe would say True here
    with updatelock.hold():
        pass
    with updatelock.hold():  # and a probe that ended leaves nothing behind
        assert updatelock.holder()
    assert updatelock.busy() is False
    held = raw_lock(f)
    try:
        assert updatelock.busy() is True  # a real holder still shows
    finally:
        held.close()


def test_hold_waits_out_a_probe_in_flight_but_not_a_holder(world, monkeypatch):
    import fcntl
    import threading

    monkeypatch.setattr(updatelock, "HOLD_PAUSE", 0.05)
    f = updatelock.update_dir() / "update.lock"
    f.touch()
    probe = f.open("rb")
    fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
    threading.Timer(0.12, probe.close).start()  # the probe ends during the retries
    with updatelock.hold():
        assert updatelock.holder()
    held = raw_lock(f)
    try:
        with pytest.raises(updatelock.UpdateBusy), updatelock.hold():
            pass
    finally:
        held.close()


def test_a_stop_during_after_apply_still_writes_the_record_and_posts(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    monkeypatch.setattr(pyupdate, "after_apply", failing(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        run_patch(world, rels("3.14.9"))
    assert last(world)["result"] == "applied" and history(world)[-1]["result"] == "applied"
    assert world.posts == [
        f"{PREFIX}Python 3.14.8 -> 3.14.9 applied; new image ?. Commit and release the pins."
    ]
    world.posts.clear()
    monkeypatch.setattr(pyupdate, "after_apply", failing(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        run_line(world)
    assert last(world)["result"] == "applied" and "Python line 3.14 -> 3.15" in world.posts[0]


# ---------------------------------------------------------------- image pruning (PLAN §2.10)
GB = 10**9
BUILDER = ["docker", "builder", "prune", "--force", "--filter", "until=24h"]


def stale_images(w, n=2, size=GB):
    """`n` superseded agent images (older than the current one and one previous)."""
    w.fake.image(0x02, ["agentbox/agent:" + "0" * 11 + "2"], 3, size)  # the previous generation
    for k in range(n):
        w.fake.image(0x10 + k, [f"agentbox/agent:{0x10 + k:012x}"], 2, size)


def rm_ran(w):
    return [r for r in w.runs if r[:3] == ["docker", "image", "rm"]]


def prune_file(w):
    return updatelock.update_dir() / "prune.json"


def test_applied_prunes_after_the_derived_builds_and_records_it(world, monkeypatch, capsys):
    resolves(monkeypatch, pyupdate.Resolution(None))
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False, **kw: h)
    profile_with_packages(world, "media", ["ffmpeg"])
    stale_images(world, n=2, size=2 * GB)
    monkeypatch.setattr(
        images, "ensure_pkgs", lambda base, packages: world.runs.append(["derived"])
    )
    rec = run_patch(world, rels("3.14.9"))
    assert world.runs.index(["derived"]) < world.runs.index(BUILDER)
    assert rec["result"] == "applied"
    pr = rec["prune"]
    assert pr["end"] == world.at and len(pr["images"]) == 2 and pr["freed_bytes"] == 4 * GB
    assert pr["after"]["images"] == 3 * GB and pr["error"] is None and pr["kept_busy"] == []
    assert last(world) == rec and history(world) == [rec]
    assert not prune_file(world).exists()  # a patch prune is in the record, not in prune.json
    assert world.posts == [
        f"{PREFIX}Python 3.14.8 -> 3.14.9 applied; new image {SHORT}; freed 4.0 GB. "
        "Commit and release the pins."
    ]
    out = capsys.readouterr().out
    assert "pruned 2 images, freed 4.0 GB (images 3.0 GB, build cache 0.0 GB now)" in out
    assert out.index("pruned 2 images") < out.index("applied; new image")
    assert "images that nothing uses" not in out and "docker image rm" not in out


def test_the_applied_post_has_no_suffix_below_a_tenth_of_a_gigabyte(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    stale_images(world, n=1, size=50_000_000)
    run_patch(world, rels("3.14.9"))
    assert world.posts == [
        f"{PREFIX}Python 3.14.8 -> 3.14.9 applied; new image {SHORT}. Commit and release the pins."
    ]


def test_the_applied_post_has_no_suffix_when_freed_is_unknown(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    stale_images(world, n=1)
    world.fake.fail["df"] = (1, "no")
    rec = run_patch(world, rels("3.14.9"))
    assert rec["prune"]["freed_bytes"] is None and "freed" not in world.posts[0]


def test_the_suffix_follows_the_derived_warning(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False, **kw: h)
    profile_with_packages(world, "docs", ["pandoc"])
    monkeypatch.setattr(images, "ensure_pkgs", failing(docker.DockerError("apt failed")))
    stale_images(world, n=1, size=2 * GB)
    run_patch(world, rels("3.14.9"))
    assert world.posts == [
        f"{PREFIX}Python 3.14.8 -> 3.14.9 applied; new image {SHORT}; "
        "derived image failed: docs; freed 2.0 GB. Commit and release the pins."
    ]


@pytest.mark.parametrize("why", ["current", "not_installable", "lookup_uv", "lookup_python_org"])
def test_every_patch_run_that_changes_nothing_prunes_too(world, monkeypatch, why):
    stale_images(world, n=2)
    boom = lambda: pytest.fail("must not build")  # noqa: E731
    if why == "current":
        rec = run_patch(world, rels("3.14.8"), build=boom)
    elif why == "lookup_python_org":
        rec = pyupdate.patch(world.repo, build=boom, doctor=lambda f: True,
                             fetch_json=failing(urllib.error.URLError("offline")))  # fmt: skip
    else:
        resolves(monkeypatch, pyupdate.NotInstallable("x") if why == "not_installable"
                 else pyupdate.LookupFailed("uv: down"))  # fmt: skip
        rec = run_patch(world, rels("3.14.9"), build=boom)
    assert rec["result"] == ("lookup_failed" if why.startswith("lookup") else why)
    assert len(rec["prune"]["images"]) == 2 and BUILDER in world.runs
    assert last(world)["prune"] == rec["prune"] and history(world)[-1]["prune"] == rec["prune"]
    assert not prune_file(world).exists()


def test_a_failed_update_does_not_prune(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    stale_images(world, n=2)

    def build():
        raise docker.DockerError("build failed")

    rec = run_patch(world, rels("3.14.9"), build=build)
    assert rec["result"] == "failed" and rec["prune"] is None
    assert rm_ran(world) == [] and BUILDER not in world.runs
    assert not any(r[:3] == ["docker", "system", "df"] for r in world.runs)


def test_a_failed_doctor_does_not_prune_either(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    stale_images(world, n=2)
    rec = run_patch(world, rels("3.14.9"), doctor=lambda failed: False)
    assert rec["result"] == "failed" and rec["prune"] is None and BUILDER not in world.runs


def test_docker_not_up_does_not_prune(world, monkeypatch):
    stale_images(world, n=2)
    rec = run_patch(world, rels("3.14.9"), ready=False)
    assert rec["result"] == "lookup_failed" and rec["prune"] is None and world.runs == []


def test_a_prune_error_changes_neither_the_result_nor_the_post(world, monkeypatch, capsys):
    resolves(monkeypatch, pyupdate.Resolution(None))
    stale_images(world, n=2)
    world.fake.fail["ps -a"] = (1, "Cannot connect to the Docker daemon")
    rec = run_patch(world, rels("3.14.9"))
    assert rec["result"] == "applied" and env_of(world)["PYTHON_VERSION"] == "3.14.9"
    assert "docker ps -a failed" in rec["prune"]["error"] and rec["prune"]["images"] == []
    assert rm_ran(world) == []
    assert world.posts == [
        f"{PREFIX}Python 3.14.8 -> 3.14.9 applied; new image {SHORT}. Commit and release the pins."
    ]
    assert "prune failed: docker ps -a failed" in capsys.readouterr().out


def test_an_unexpected_prune_crash_does_not_fail_the_update(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    monkeypatch.setattr(pyupdate.prune, "run", failing(RuntimeError("bug")))
    rec = run_patch(world, rels("3.14.9"))
    assert rec["result"] == "applied" and "RuntimeError: bug" in rec["prune"]["error"]


def test_a_stop_during_the_prune_still_writes_the_record_and_posts(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    monkeypatch.setattr(pyupdate.prune, "run", failing(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        run_patch(world, rels("3.14.9"))
    assert last(world)["result"] == "applied" and len(world.posts) == 1


def test_a_line_change_prunes_into_prune_json_and_posts_the_freed_space(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    stale_images(world, n=2, size=2 * GB)
    rec = run_line(world)
    assert rec["result"] == "applied" and rec["prune"] is None  # not in last.json
    assert last(world)["prune"] is None and history(world)[-1]["prune"] is None
    f = prune_file(world)
    assert (f.stat().st_mode & 0o777) == 0o600
    data = json.loads(f.read_text())
    assert data["freed_bytes"] == 4 * GB and len(data["images"]) == 2
    assert set(data) == {"end", "removed", "images", "kept_busy", "freed_bytes", "after", "error"}
    assert world.posts == [
        f"{PREFIX}Python line 3.14 -> 3.15 (3.14.8 -> 3.15.0) applied; new image {SHORT}; "
        "freed 4.0 GB. Commit and release the pins."
    ]


def test_a_failed_line_change_does_not_prune(world, monkeypatch):
    resolves(monkeypatch, pyupdate.Resolution(None))
    stale_images(world, n=2)
    rec = run_line(world, doctor=lambda failed: False)
    assert (
        rec["result"] == "failed" and not prune_file(world).exists() and BUILDER not in world.runs
    )


# ---------------------------------------------------------------- the commands
def test_full_update_prunes_after_an_apply_and_writes_prune_json(world, monkeypatch, capsys):
    stale_images(world, n=2)
    monkeypatch.setattr(upd, "lookup", lambda current, **kw: {"CODEX_VERSION": "9.9.9"})
    monkeypatch.setattr(cli, "update_build", lambda repo: lambda: None)
    monkeypatch.setattr(cli, "scratch_doctor", lambda failed=None: True)
    assert cli.main(["update"]) == 0
    data = json.loads(prune_file(world).read_text())
    assert len(data["images"]) == 2 and (prune_file(world).stat().st_mode & 0o777) == 0o600
    assert "pruned 2 images, freed 2.0 GB" in capsys.readouterr().out
    assert not (updatelock.update_dir() / "last.json").exists()  # patch readers see nothing new


def test_full_update_that_fails_does_not_prune(world, monkeypatch):
    stale_images(world, n=2)
    monkeypatch.setattr(upd, "lookup", lambda current, **kw: {"CODEX_VERSION": "9.9.9"})
    monkeypatch.setattr(cli, "update_build", lambda repo: lambda: None)
    monkeypatch.setattr(cli, "scratch_doctor", lambda failed=None: False)
    assert cli.main(["update"]) == 1
    assert not prune_file(world).exists() and BUILDER not in world.runs


def test_full_update_with_nothing_to_apply_still_prunes(world, monkeypatch):
    stale_images(world, n=2)
    monkeypatch.setattr(upd, "lookup", lambda current, **kw: {})
    assert cli.main(["update"]) == 0
    assert prune_file(world).exists() and BUILDER in world.runs


def test_full_update_prune_error_keeps_exit_0(world, monkeypatch, capsys):
    stale_images(world, n=2)
    world.fake.fail["image ls"] = (1, "down")
    monkeypatch.setattr(upd, "lookup", lambda current, **kw: {"CODEX_VERSION": "9.9.9"})
    monkeypatch.setattr(cli, "update_build", lambda repo: lambda: None)
    monkeypatch.setattr(cli, "scratch_doctor", lambda failed=None: True)
    assert cli.main(["update"]) == 0
    assert "docker image ls failed" in json.loads(prune_file(world).read_text())["error"]


def test_the_daily_job_exit_code_ignores_a_prune_error(world, cmd):
    world.fake.fail["ps -a"] = (1, "down")
    cmd.releases = rels("3.14.9")
    assert cli.main(["update", "--python-patch"]) == 0
    assert last(world)["result"] == "applied" and last(world)["prune"]["error"]


def test_update_prune_removes_and_writes_prune_json(world, capsys):
    stale_images(world, n=2)
    assert cli.main(["update", "--prune"]) == 0
    out = capsys.readouterr().out
    assert "pruned 2 images, freed 2.0 GB" in out
    assert len(json.loads(prune_file(world).read_text())["images"]) == 2
    assert not (updatelock.update_dir() / "last.json").exists() and world.posts == []


def test_update_prune_holds_the_lock_and_exits_75_when_busy(world, monkeypatch, capsys):
    stale_images(world, n=2)
    seen = []
    real = world.fake.run

    def spy(args, **kw):
        seen.append(updatelock.holder())
        return real(args, **kw)

    monkeypatch.setattr(docker, "run", spy)
    assert cli.main(["update", "--prune"]) == 0
    assert seen and all(seen)
    held = raw_lock(updatelock.update_dir() / "update.lock")
    try:
        before = list(world.runs)
        assert cli.main(["update", "--prune"]) == 75
        assert "another update is running" in capsys.readouterr().err
        assert world.runs == before  # nothing ran
    finally:
        held.close()


def test_update_prune_exits_1_on_an_error(world, capsys):
    world.fake.fail["ps -a"] = (1, "Cannot connect")
    assert cli.main(["update", "--prune"]) == 1
    assert "prune failed: docker ps -a failed" in capsys.readouterr().out
    assert "docker ps -a failed" in json.loads(prune_file(world).read_text())["error"]


def test_update_prune_dry_run_lists_tags_removes_nothing_and_takes_no_lock(world, capsys):
    stale_images(world, n=1)
    before = dict(world.fake.tags)
    held = raw_lock(updatelock.update_dir() / "update.lock")
    try:
        assert cli.main(["update", "--prune", "--dry-run"]) == 0
    finally:
        held.close()
    out = capsys.readouterr().out
    assert "would remove 1 image (1 tags):" in out and f"  agentbox/agent:{0x10:012x}" in out
    assert world.fake.tags == before and rm_ran(world) == [] and BUILDER not in world.runs
    assert not prune_file(world).exists()


def test_update_prune_dry_run_with_an_error_exits_1(world):
    world.fake.fail["image ls"] = (1, "down")
    assert cli.main(["update", "--prune", "--dry-run"]) == 1


@pytest.mark.parametrize(
    "argv,msg",
    [
        (["--dry-run"], "--dry-run works only with --prune"),
        (["--check", "--dry-run"], "--dry-run works only with --prune"),
        (["--prune", "--check"], "--prune cannot be combined with --check"),
        (["--prune", "--python-patch"], "--prune cannot be combined with --python-patch"),
        (["--prune", "--python-line", "3.15", "--eol", "2031-10"],
         "--prune cannot be combined with --python-line"),
        (["--prune", "--python-patch", "--install"], "--prune cannot be combined"),
        (["--prune", "--install"], "need --python-patch"),
    ],
)  # fmt: skip
def test_prune_option_errors(world, cmd, capsys, argv, msg):
    assert cli.main(["update", *argv]) == 1
    assert msg in capsys.readouterr().err
    assert world.runs == [] and cmd.build_calls == 0 and history(world) == []
