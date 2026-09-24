"""Mount integrity: recorded realpaths, symlinks inside rw mounts."""

import json
import os

import pytest
from agentbox import mountstate
from agentbox.profile import parse_profile


def prof(mounts):
    p = parse_profile({"mount": mounts}, "p1")
    ms = [
        m.__class__(**{**m.__dict__, "host_real": os.path.realpath(os.path.expanduser(m.host))})
        for m in p.mounts
    ]
    return p.__class__(**{**p.__dict__, "mounts": ms})


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "proj").mkdir()
    (tmp_path / "other").mkdir()
    (tmp_path / "b").mkdir()
    os.symlink(tmp_path / "other", tmp_path / "proj" / "link")
    return tmp_path


def test_symlink_inside_rw_mount_refused(tree):
    p = prof(
        [
            {"host": str(tree / "proj"), "mode": "rw"},
            {"host": str(tree / "proj" / "link"), "path": "/o"},
        ]
    )
    probs = mountstate.symlink_problems(p, ci=False)
    assert len(probs) == 1 and "inside the rw mount" in probs[0] and "link" in probs[0]


def test_symlink_inside_ro_mount_ok(tree):
    p = prof(
        [
            {"host": str(tree / "proj"), "mode": "ro"},
            {"host": str(tree / "proj" / "link"), "path": "/o"},
        ]
    )
    assert mountstate.symlink_problems(p, ci=False) == []


def test_symlink_deeper_in_path(tree):
    (tree / "other" / "x").mkdir()
    p = prof(
        [
            {"host": str(tree / "proj"), "mode": "rw"},
            {"host": str(tree / "proj" / "link" / "x"), "path": "/o"},
        ]
    )
    assert mountstate.symlink_problems(p, ci=False)


def test_record_change_accept(tree):
    state = tree / "state"
    state.mkdir()
    os.symlink(tree / "other", tree / "alias")
    p = prof([{"host": str(tree / "alias")}])
    mountstate.check_and_record(state, p, False)
    rec = json.loads((state / "mounts.json").read_text())
    assert rec == {str(tree / "alias"): os.path.realpath(tree / "other")}
    mountstate.check_and_record(state, p, False)  # unchanged: ok
    os.unlink(tree / "alias")
    os.symlink(tree / "b", tree / "alias")
    p2 = prof([{"host": str(tree / "alias")}])
    with pytest.raises(mountstate.MountChangeError, match="--accept-mount-change"):
        mountstate.check_and_record(state, p2, False)
    assert json.loads((state / "mounts.json").read_text()) == rec  # not overwritten
    mountstate.check_and_record(state, p2, True)
    assert json.loads((state / "mounts.json").read_text())[str(tree / "alias")] == (
        os.path.realpath(tree / "b")
    )
    mountstate.check_and_record(state, p2, False)


@pytest.mark.parametrize("content", ["[]", '"x"', "3"])
def test_non_object_state_file_fails_closed(tree, content):
    st = tree / "state"
    st.mkdir()
    (st / mountstate.STATE_FILE).write_text(content)
    p = prof([{"host": str(tree / "proj"), "mode": "rw"}])
    with pytest.raises(mountstate.MountChangeError, match="corrupt"):
        mountstate.check_and_record(st, p, accept=False)


def test_nested_inside_rw_refused_without_symlink(tree):
    (tree / "proj" / "sub").mkdir()
    p = prof([{"host": str(tree / "proj"), "mode": "rw"},
              {"host": str(tree / "proj" / "sub"), "path": "/s"}])  # fmt: skip
    probs = mountstate.symlink_problems(p, ci=False)
    assert len(probs) == 1 and "is inside the rw mount" in probs[0]


def test_nested_via_outside_symlink_refused(tree):
    """Profile path outside, realpath inside the rw mount: refused too."""
    (tree / "proj" / "sub").mkdir()
    os.symlink(tree / "proj" / "sub", tree / "b" / "alias")
    p = prof([{"host": str(tree / "proj"), "mode": "rw"},
              {"host": str(tree / "b" / "alias"), "path": "/s"}])  # fmt: skip
    assert mountstate.nested_problems(p, ci=False)


def test_nested_equal_and_case(tree):
    p = prof([{"host": str(tree / "proj"), "mode": "rw"},
              {"host": str(tree / "proj"), "path": "/again"}])  # fmt: skip
    assert len(mountstate.nested_problems(p, ci=False)) == 1  # the ro one
    p = prof([{"host": str(tree / "proj"), "mode": "rw"},
              {"host": str(tree / "other"), "mode": "rw", "path": "/o"}])  # fmt: skip
    assert mountstate.nested_problems(p, ci=False) == []


def test_rw_inside_ro_allowed(tree):
    (tree / "proj" / "sub").mkdir()
    p = prof([{"host": str(tree / "proj"), "mode": "ro"},
              {"host": str(tree / "proj" / "sub"), "mode": "rw", "path": "/s"}])  # fmt: skip
    assert mountstate.nested_problems(p, ci=False) == []
