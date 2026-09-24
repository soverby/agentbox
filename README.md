# agentbox

agentbox runs AI coding agents (Claude Code, Codex, Pi, and the ollama
client) in Docker sandboxes. Each sandbox ("box") serves one purpose
("profile"). A profile lists the host paths, network destinations, secrets,
and MCP servers that the agents can use. The box blocks everything else. The
host CLI starts the box, gives it only the secrets it needs, and runs a
self-test (`agentbox doctor`) that proves the isolation.

## Security model

The adversary is the agent itself: prompt injection, a malicious dependency,
or a wrong tool call. The box keeps these properties against it:

- **T1 Files.** The agent sees only the host paths that the profile mounts.
  It writes only to mounts with `mode = "rw"`.
- **T2 Network.** All traffic goes through an egress proxy. In `strict` mode
  (default) the agent reaches only allowlisted domains. The proxy always
  blocks IP addresses, private ranges, the host, and cloud metadata.
- **T3 Host control.** The box has no Docker socket, no host network, no
  privileged mode, and no Linux capabilities. The agent is not root.
- **T4 Secrets.** A box gets only the secrets that its profile gives to it.
  Keys for model routers and MCP servers stay in those sidecars.
- **T5 MCP.** The agent reaches MCP servers only through one gateway. The
  gateway allows only the servers and tools in the profile and logs each
  call.
- **T6 Boxes.** Boxes of different profiles cannot reach each other.

Read [docs/SECURITY.md](docs/SECURITY.md) for the enforcement of each
property and for the risks that agentbox accepts.

## Quick start

```sh
uv tool install -e ./cli
claude setup-token
agentbox setup
agentbox init myproject --mount ~/Projects/myproject
cd ~/Projects/myproject
agentbox claude
```

Read [docs/USAGE.md](docs/USAGE.md) for each step and for all other tasks.

## Requirements

- macOS with Docker Desktop, or Linux with Docker Engine and Compose v2.
- `uv`, and Python 3.11 or later for the host CLI (stdlib only).
- Free disk space for the images: the agent image is about 1.6 GB, the
  optional router image about 2 GB, and the build downloads more.
- A Claude subscription for Claude Code. A ChatGPT subscription for Codex
  and Pi (optional).
- Host Ollama 0.14.0 or later for local models (optional).

## Status and limits

- The main test host is macOS on Intel (x86_64) with Docker Desktop. The
  images are amd64 only.
- Linux is a secondary target. The Linux CI workflow is in the repository,
  but it has not run yet. Linux is not tested.
- On Linux, the default secret backend (macOS Keychain) is not available.
  Use the 1Password backend (`op`).
- Host tools (git, VS Code, direnv, npm, make) that you run in a writable
  mount can run files that the agent planted there. Read "Running host
  tools in a mounted folder" in [docs/SECURITY.md](docs/SECURITY.md).
- The box does not stop exfiltration to an allowed domain. Read the
  residual risks in [docs/SECURITY.md](docs/SECURITY.md).

## Links

- [docs/USAGE.md](docs/USAGE.md): install, profiles, and all commands.
- [docs/SECURITY.md](docs/SECURITY.md): threat model and residual risks.
- [docs/PLAN.md](docs/PLAN.md): design and phase plan.
- [profiles/example.toml](profiles/example.toml): an example profile.
