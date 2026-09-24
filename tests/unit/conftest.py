import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "cli"))

import os  # noqa: E402

import pytest  # noqa: E402


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    # On Linux pytest's default basetemp is under /tmp, a reserved container
    # root; profiles built from tmp_path would be refused (correctly). Move the
    # base under a non-reserved, writable dir. macOS keeps the default.
    if not sys.platform.startswith("linux") or config.option.basetemp:
        return
    base = os.environ.get("AGENTBOX_TEST_TMP") or str(Path.home() / "agentbox-pytest")
    from agentbox.profile import RESERVED_ROOTS

    if any(base == r or base.startswith(r + "/") for r in RESERVED_ROOTS):
        raise pytest.UsageError(
            f"test temp base {base} is under a reserved container root; "
            "set AGENTBOX_TEST_TMP to a writable dir outside " + " ".join(RESERVED_ROOTS)
        )
    Path(base).mkdir(parents=True, exist_ok=True)
    config.option.basetemp = str(Path(base) / f"run-{os.getpid()}")


@pytest.fixture(autouse=True)
def _linux_home(tmp_path_factory, monkeypatch):
    # On Linux HOME may be /root (reserved), so `~/...` paths in example
    # profiles would be refused. Give each test a HOME under the basetemp.
    if sys.platform.startswith("linux"):
        home = tmp_path_factory.mktemp("home")
        monkeypatch.setenv("HOME", str(home))
