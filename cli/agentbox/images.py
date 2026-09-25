"""Image tags and builds (PLAN §2.1, §2.2, §2.5).

- agent: images/agent/build.sh tags agentbox/agent:<hash> and :latest. The
  hash here mirrors build.sh; after a build the CLI checks that the tag it
  expects exists (a drift between the two is a hard error, not a rebuild loop).
- egress, ollama-gate: agentbox/<name>:<hash of the build context>.
- packages: agentbox/agent-pkgs:<hash of base image id + sorted packages>.
  Built on the host Docker build (normal build network), never in a box.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

from . import docker

AGENT_REPO = "agentbox/agent"
AGENT_LATEST = f"{AGENT_REPO}:latest"
PKGS_REPO = "agentbox/agent-pkgs"
# Same list and order as images/agent/build.sh `inputs`.
AGENT_INPUTS = (
    "Dockerfile",
    "versions.env",
    "managed-mcp.json",
    "managed-settings.json",
    "pi-mcp.json",
    "pi-wrapper",
    "pi-models.ts",
    "with-secrets",
    "pi-mcp-adapter/package.json",
    "pi-mcp-adapter/package-lock.json",
    "pi-mcp-adapter/.npmrc",
)
SIDECARS = {
    "egress": "images/egress",
    "ollama-gate": "images/ollama-gate",
    "mcp-gateway": "images/mcp-gateway",
    "router": "images/router",
}
PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy")


class ImageError(Exception):
    pass


def agent_hash(repo: Path) -> str:
    """sha256 over NAME\\0CONTENT\\0 for each input (build.sh algorithm), 12 hex."""
    h = hashlib.sha256()
    d = repo / "images" / "agent"
    for f in AGENT_INPUTS:
        p = d / f
        if not p.is_file():
            raise ImageError(f"missing agent build input {p}")
        h.update(f.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()[:12]


def dir_hash(d: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(d.rglob("*")):
        rel = p.relative_to(d).as_posix()
        if not p.is_file() or "__pycache__" in rel or rel.endswith(".pyc"):
            continue
        h.update(rel.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()[:12]


def log(msg: str) -> None:
    print(f"agentbox: {msg}", file=sys.stderr, flush=True)


def build_agent(repo: Path) -> None:
    log("building the agent image (images/agent/build.sh); first build takes minutes")
    docker.run(["bash", str(repo / "images/agent/build.sh")], capture=False)


def ensure_agent(repo: Path) -> str:
    """Return the agent image ref, building it when its hash tag is missing."""
    want = f"{AGENT_REPO}:{agent_hash(repo)}"
    want_id = docker.image_id(want)
    if want_id is None:
        build_agent(repo)
        want_id = docker.image_id(want)
        if want_id is None:
            raise ImageError(f"build.sh did not tag {want}: hash algorithm drift")
    if docker.image_id(AGENT_LATEST) != want_id:
        # latest must be the image of the current build inputs
        log(f"tagging {want} as {AGENT_LATEST}")
        docker.run(["docker", "tag", want, AGENT_LATEST])
    return AGENT_LATEST


def sidecar_tag(repo: Path, name: str) -> str:
    return f"agentbox/{name}:{dir_hash(repo / SIDECARS[name])}"


def ensure_sidecar(repo: Path, name: str) -> str:
    tag = sidecar_tag(repo, name)
    if docker.image_id(tag) is None:
        log(f"building {tag}")
        docker.run(["docker", "build", "-q", "-t", tag, str(repo / SIDECARS[name])])
    return tag


def pkgs_tag(base_id: str, packages: list[str]) -> str:
    key = base_id + "\n" + "\n".join(sorted(set(packages)))
    return f"{PKGS_REPO}:{hashlib.sha256(key.encode()).hexdigest()[:12]}"


def pkgs_dockerfile(base_ref: str, packages: list[str]) -> str:
    """Root only for apt-get; proxy env from the base image is unset for the
    build (the box proxy does not exist at build time); setuid/setgid bits
    that packages bring are removed (doctor 16); back to USER agent."""
    unset = " ".join(f"-u {v}" for v in PROXY_VARS)
    pk = " ".join(sorted(set(packages)))
    return (
        f"FROM {base_ref}\n"
        "USER root\n"
        f"RUN env {unset} sh -c 'apt-get update"
        f" && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pk}"
        " && rm -rf /var/lib/apt/lists/*'"
        " && find / -xdev -perm /6000 -type f -exec chmod a-s {} +\n"
        "USER agent\n"
        "WORKDIR /home/agent\n"
    )


def ensure_pkgs(base_ref: str, packages: list[str]) -> str:
    """Derived image for `[box] packages`; cached by tag."""
    base_id = docker.image_id(base_ref)
    if base_id is None:
        raise ImageError(f"base image {base_ref} not found")
    tag = pkgs_tag(base_id, packages)
    if docker.image_id(tag) is not None:
        return tag
    # Pin FROM to the exact base image id through a content-derived tag.
    base_pin = f"{AGENT_REPO}:base-{base_id.split(':')[-1][:12]}"
    docker.run(["docker", "tag", base_id, base_pin])
    log(f"building {tag} with packages: {' '.join(sorted(set(packages)))}")
    with tempfile.TemporaryDirectory() as d:
        Path(d, "Dockerfile").write_text(pkgs_dockerfile(base_pin, packages))
        docker.run(["docker", "build", "-q", "-t", tag, d])
    return tag
