"""docker.run never lets a child read the caller's stdin unless input is given."""

import subprocess
import sys

from agentbox import docker


def test_no_input_means_devnull():
    code = "import sys; print(repr(sys.stdin.read()))"
    child = f"from agentbox import docker; print(docker.run([{sys.executable!r}, '-c', {code!r}]).stdout)"  # noqa: E501
    r = subprocess.run(
        [sys.executable, "-c", child],
        input="CALLER-STDIN", capture_output=True, text=True,
        env={"PYTHONPATH": docker.__file__.rsplit("/agentbox/", 1)[0]},
    )  # fmt: skip
    assert r.stdout.strip() == "''", r.stdout + r.stderr


def test_input_is_passed():
    r = docker.run([sys.executable, "-c", "import sys; print(sys.stdin.read())"], input="x")
    assert r.stdout.strip() == "x"
