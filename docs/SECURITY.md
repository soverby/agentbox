# agentbox security

This document states what agentbox protects, how, and where the code
enforces it. It also lists every risk that agentbox accepts. Source of
truth for the design: [PLAN.md](PLAN.md) §1, §2, and §4.

References:

- "doctor N" is check N of `agentbox doctor` (list in
  [USAGE.md](USAGE.md#doctor)). In-box checks are in
  `tests/isolation/doctor_checks.sh`; host-side checks are in
  `cli/agentbox/doctor.py`, `doctor_mcp.py`, and `doctor_router.py`.
- "smoke Pn" is `tests/integration/pn_smoke.py`, the acceptance test of that
  build phase.

## Threat model

**Adversary.** The agent itself: prompt injection, a malicious dependency,
or a wrong tool call. It can run any code as the non-root user `agent`
(uid 1000) in the agent container. It can send any request to any sidecar
that it can reach.

**Not the adversary.** The host user, the host OS, Docker, and the vendors
of the agents, models, and MCP servers. agentbox trusts the profile files:
the user writes them, not the agent.

**Assets.**

- Host files outside the declared mounts.
- The host itself: its processes, services, network position, and the
  Docker daemon.
- Secrets of other profiles and secrets meant for sidecars (model router
  keys, MCP upstream tokens and OAuth token sets).
- The user's LAN and cloud metadata services.
- Other boxes.

**Properties that must hold against the adversary.**

| ID | Property |
| --- | --- |
| T1 | No read or write of host paths that the profile does not mount. Writes only where the mount is `rw`. |
| T2 | No network egress except through the egress proxy. `strict`: allowlisted domains only. `open`: any public domain. Both: port 443 only (80 opt-in), no IP literals, no private, loopback, or link-local destinations, no external DNS in the box, no host services except the filtered `ollama-gate`, no cloud metadata. Also when a sidecar is abused (SSRF). |
| T3 | No Docker socket, host network, privileged mode, or added capabilities. |
| T4 | Secrets of other profiles and secrets for sidecars are not visible in the agent container. |
| T5 | MCP access only to the allowed servers and tools, through one gateway that logs every call. No other MCP path (claude.ai connectors, Codex apps, remote plugins). |
| T6 | Boxes of different profiles cannot reach each other. |

## Running host tools in a mounted folder

**Read this before you run any host tool in a `rw` mount.** The box stops
the agent from running code on the host. But the agent can write files in a
`rw` mount, and many host tools run code from files in the folder where you
use them. When you run such a tool on the host, it runs what the agent
planted, with your host rights. This is the largest risk that agentbox does
not close.

Files that host tools run or load:

| File | Host tool that runs it |
| --- | --- |
| `.git/config` (`core.fsmonitor`, `core.hooksPath`, aliases, filters) | Any `git` command, also `git status` and shell prompts that call git. |
| `.git/hooks/*` | `git commit`, `git checkout`, `git merge`, `git push`. |
| `.envrc` | direnv, when you `cd` into the folder (after `direnv allow`). |
| `.vscode/tasks.json`, `.vscode/settings.json` | VS Code (tasks that run on folder open). |
| `package.json` scripts | `npm install`, `npm run`, `npm test`. |
| `Makefile` and other build files | `make`, build tools. |
| `.claude/`, `.mcp.json` | Host Claude Code started in that folder. |

Safe practice:

1. Run git for agent-written folders in the box (`agentbox shell`), not on
   the host.
2. If you must run git on the host, first check the config and hooks with
   tools that do not run them:

   ```sh
   cat .git/config
   ls -la .git/hooks
   cat .git/commondir 2>/dev/null
   ```

   Look for `fsmonitor`, `hooksPath`, `sshCommand`, `alias`, `filter`, and
   any hook file that is not a `.sample`. `git config --local --list` shows
   the config, but git itself reads the folder, so prefer `cat`.
3. Do not open an agent-written folder in VS Code with automatic tasks on.
   Use Restricted Mode (do not trust the workspace).
4. Do not run `direnv allow` for an `.envrc` that you did not read after
   the agent last ran.
5. Read `package.json` scripts and Makefiles before you run them on the
   host.
6. Do not start host Claude Code in the folder before you check `.claude/`
   and `.mcp.json`.

**Detection.** The CLI snapshots the host-executed config in each `rw`
mount before each session and headless run, scans again at the end, and
warns about every change (`cli/agentbox/hostscan.py`; called from
`cli/agentbox/cli.py`). It covers risky `.git/config` keys, non-sample
hooks, `.git/commondir`, a `.git` file or symlink, unparsed or non-UTF-8
config, `.envrc`, and `.vscode/{tasks,settings,launch}.json`, in
repositories at the mount root, enclosing it, or one level below.
Scope, output, and limits:
[USAGE.md](USAGE.md#host-config-detection).

Detection reduces this risk; it does not remove it:

- It only warns. It never blocks.
- It does not compare between sessions. A process that the agent leaves
  in a pinned box can change files after the session ends.
- It does not watch `package.json`, Makefiles, `.claude/`, `.mcp.json`,
  repositories two or more levels deep, or `include.path` targets.
- Its git config parser is tolerant, not identical to git. A 1-second
  budget and file caps can make a scan incomplete (it says so), and the
  agent can force that on purpose. A config already over 256 KiB at
  session start can hide a key.

A read-only overlay of `.git` in the box was rejected: Docker Desktop drops
nested bind mounts from a running container whenever another container
starts, and git follows `.git/commondir`, which the agent can write anyway.

## Architecture

Each profile is one Compose project `agentbox-<profile>` with two networks.
`internal` has no gateway and holds all containers. `external` is a normal
bridge and holds only `egress` and `ollama-gate`.

```text
                         host (macOS)
  ┌────────────────────────────────────────────────────────────────┐
  │ agentbox CLI ── secret backend (Keychain / 1Password)          │
  │ launchd jobs     host ollama :11434     host MCP servers :port │
  └──────┬────────────────────▲────────────────────▲───────────────┘
         │ compose up         │                    │ (via egress)
  ┌──────▼──── net: internal (no gateway) ─────────┼───────────────┐
  │  agent ──► egress (squid, per-source ACL) ─────┴──► internet   │
  │    │          ▲            ▲                        [external] │
  │    │          │            │                                   │
  │    ├──► router (LiteLLM, optional; Modal/remote keys)          │
  │    ├──► mcp-gateway (MCP tokens, tool allowlist)               │
  │    └──► ollama-gate :11434 ───► host.docker.internal:11434     │
  │                                               [external]       │
  └────────────────────────────────────────────────────────────────┘
```

- `agent`, `router`, and `mcp-gateway` have no route out. They reach the
  outside only through `egress`. Squid applies a separate allowlist for each
  source IP, so an SSRF in a sidecar reaches only that sidecar's allowlist.
- Source IPs are fixed in Compose. The agent has no `CAP_NET_ADMIN` or
  `CAP_NET_RAW`, so it cannot change its IP.
- Each profile gets its own subnet (`10.213.<n>.0/24` by default). The CLI
  checks it against the subnets that Docker uses at each `up`.

Enforced in: `cli/agentbox/compose.py` (services, networks, fixed IPs),
`cli/agentbox/network.py` (subnet allocation and check),
`cli/agentbox/egress.py` (squid.conf render).

## How each property is enforced

### T1: files

- The CLI mounts only the `[[mount]]` entries of the profile. The agent
  home is a named volume, not a host path.
- The CLI resolves the realpath of each mount. It refuses a missing path
  and any path that is, contains, or is inside a denylist entry (system
  directories, the Docker socket, and credential directories in `$HOME`).
  On macOS the compare ignores letter case.
- A dot-path under `$HOME` needs `allow_dotpath = true`.
- A `rw` mount must not overlap `/usr`, `/opt`, `/Applications`, the
  directories of the host `docker` and `git` commands, the agentbox
  repository, or the host Python, venv, `agentbox` command, or `PYTHONPATH`
  entries. These run on the host; write access would let the agent change
  host code. Read-only mounts of them are permitted.
- A mount that is equal to or inside another `rw` mount of the same profile
  is refused. The agent could swap a directory on that path for a symlink
  between the check and the bind mount.
- The CLI records each mount realpath. A changed realpath stops `up` until
  the user runs `--accept-mount-change`. A mount path that goes through a
  symlink inside another `rw` mount is always refused.
- Enforced in: `cli/agentbox/profile.py` (`check_mount_host`,
  `rw_deny_paths`, `code_mount_problem`), `cli/agentbox/mountstate.py`
  (`symlink_problems`, nested mounts),
  `cli/agentbox/compose.py`.
- Proved by: doctor 10 (only declared mounts; `ro` refuses writes), unit
  tests `tests/unit/` (symlink, `..`, trailing slash, descendant cases),
  smoke P3.

### T2: network

- The agent is only on the `internal` network: no default route, and
  Docker's DNS returns no answer for external names and
  `host.docker.internal`.
- The agent environment sets `HTTPS_PROXY`/`HTTP_PROXY` to
  `http://egress:3128`. A tool that ignores them fails closed.
- Squid rules, in all modes: `dstdomain -n` (no reverse-DNS match), deny
  IP-literal hosts, deny private and special IPv4 and IPv6 ranges on the
  address squid resolves and connects to, deny `CONNECT` to ports other
  than 443 (80 only with `allow_http`), deny the cache manager. In `open`
  mode the agent may reach any other public domain.
- `mcp-proxy.anthropic.com` is denied in every mode.
- The router and gateway have their own allowlists: remote model hosts for
  the router; MCP upstream hosts, OAuth token hosts, and package registries
  for stdio servers for the gateway. The router `NO_PROXY` holds only
  `localhost,127.0.0.1`, so an SSRF to an internal name still goes to squid.
- `ollama-gate` is the only path to the host. It forwards only a fixed list
  of methods and paths, checks the JSON body and the model name, and refuses
  cloud models. The full Ollama API would let the agent make the host pull
  from any registry (unproxied egress) and write or delete models.
- `agentbox allow` changes the allowlist with `squid -k parse` and then
  `squid -k reconfigure`. A bad config keeps the old config active.
- Enforced in: `cli/agentbox/egress.py`, `cli/agentbox/compose.py`,
  `images/egress/`, `images/ollama-gate/gate.py`, `presets/*.toml`.
- Proved by: doctor 1, 2, 3, 4, 5, 6, 7, 8 (agent), 13 (router and
  gateway), 15 (gate), 19 (open mode and IPv6), and
  `tests/isolation/p2_harness.py` (negative controls, both modes).

### T3: host control

- Compose sets `cap_drop: [ALL]`, `no-new-privileges:true`, user uid 1000,
  `init`, `pids_limit`, `mem_limit`, and `cpus`. There is no `privileged`,
  no Docker socket, and no host network.
- The image has no `sudo` and no setuid or setgid files. System paths are
  root-owned. The home `PATH` entries come after all system entries.
- Sessions start through `docker compose exec`, never a login shell.
- Enforced in: `cli/agentbox/compose.py` (`HARDEN`), `images/agent/Dockerfile`.
- Proved by: doctor 9 (no socket, `CapEff` and `CapBnd` are 0), doctor 16
  (no writable system path, no setuid, `PATH` order, root-owned
  `managed-mcp.json`), doctor 20 `gateway-fs` (gateway user), smoke P1.

### T4: secrets

- Secrets live in the host backend. No box has backend access. The CLI
  reads only the secrets that the profile needs, at `up`.
- Each secret has targets (`agent`, `router`, `mcp-gateway`). A secret used
  by a sidecar and without an explicit `to` goes only to that sidecar.
- Delivery uses Compose `secrets:` with an `environment:` source. The values
  exist only in the environment of the `docker compose up` process and in
  `/run/secrets/<NAME>` of the target container. They are not in
  `docker inspect`, in generated files, in image layers, or on host disk.
- In the agent, `/run/secrets/*` are root:root 0444. `with-secrets` exports
  them for each session. The profile validator refuses reserved names
  (`PATH`, `LD_*`, `BASH_ENV`, `NODE_*`, `GIT_*`, TLS CA overrides, proxy
  variables, and others). `with-secrets` and the router and gateway start
  scripts refuse them again when they export.
- Per-box random tokens (router master key, `MCP_GATEWAY_TOKEN`) and the
  HMAC key for the secret-set label are 0600 files in the state directory.
  The tokens rotate at `down`.
- Keychain writes go to `security -i` on stdin, never argv. Errors are
  scrubbed of the value.
- With `--model ollama/…` or `remote/…`, the Claude session unsets
  `CLAUDE_CODE_OAUTH_TOKEN`, so the subscription token does not reach the
  gate or the router.
- Enforced in: `cli/agentbox/profile.py` (`_parse_secrets`, reserved
  names), `cli/agentbox/delivery.py`, `cli/agentbox/secretstore.py`,
  `images/agent/with-secrets`, `images/router/entrypoint.sh`,
  `images/mcp-gateway/entrypoint.sh`, `cli/agentbox/launch.py`.
- Proved by: doctor 11 (only agent-targeted secrets, root-owned files),
  doctor 17 (headless run with env tokens only), smoke P4 (no user secret in
  state dir, `docker inspect`, image layers, or logs).

### T5: MCP

- Claude Code loads only the root-owned
  `/etc/claude-code/managed-mcp.json`, which lists only the gateway. This
  blocks `claude mcp add`, plugin servers, `--mcp-config`, and claude.ai
  connectors. The image also sets `ENABLE_CLAUDEAI_MCP_SERVERS=false`.
- Codex gets `-c features.apps=false -c features.remote_plugin=false
  -c apps._default.enabled=false` and the gateway entry on every launch.
  These overrides have higher precedence than the agent-writable
  `~/.codex/config.toml`.
- Pi gets the root-owned `/etc/agentbox/pi-mcp.json` from its wrapper.
- The gateway exposes only allowlisted tools as `<server>_<tool>`, rejects
  other `tools/call` requests, hides resources and prompts, never forwards
  client headers upstream, and logs each call (server, tool, argument hash,
  status) to `<state>/logs/mcp/calls.jsonl`.
- The agent authenticates with `MCP_GATEWAY_TOKEN`, random for each box.
- Upstream bearers and OAuth token sets go to the gateway only. OAuth login
  runs on the host (PKCE S256, exact issuer match, RFC 8707 `resource`,
  https-only endpoints). Rotated tokens stay in a gateway-only volume.
- Enforced in: `images/agent/managed-mcp.json`, `images/agent/pi-wrapper`,
  `cli/agentbox/launch.py` (`CODEX_OVERRIDES`), `cli/agentbox/mcpgw.py`,
  `images/mcp-gateway/gateway.py`, `cli/agentbox/mcpoauth.py`.
- Proved by: doctor 14 (connector proxy denied, Claude `/mcp` lists only
  `agentbox`, Codex effective config, Pi config), doctor 20 (auth, policy,
  no direct upstream access, OAuth store private), smoke P6 and P6b.
  `14 codex-apps-live` is not automated: it always reports SKIP. Check it by
  hand: type `/apps` in a Codex session that agentbox started; it must list
  no apps.

### T6: boxes

- Each profile has its own Compose project, networks, subnet, and fixed
  IPs. Docker refuses overlapping subnets. The CLI checks the subnet at
  each `up`.
- Squid denies private ranges, so one box cannot reach another through
  `egress`.
- Enforced in: `cli/agentbox/network.py`, `cli/agentbox/compose.py`,
  `cli/agentbox/egress.py`.
- Proved by: doctor 12 (runs only when another profile is running; else
  SKIP).

### Doctor on every session

Each `up` and each session start runs checks 1, 2, 6, and 9. If one fails,
no session starts (`cli/agentbox/cli.py`, `ensure_up`). The full suite runs
on `agentbox doctor`, at `setup`, and after `agentbox update`.

## Accepted residual risks

agentbox does not solve these risks. It documents them.

1. **Exfiltration to an allowed domain.** The agent can send data to any
   allowed domain, for example a gist on github.com. In `open` mode, that
   is any public domain.
2. **Open mode.** `mode = "open"` permits any public domain. It still blocks
   the host, the LAN, metadata, IP literals, and `mcp-proxy.anthropic.com`,
   and it keeps secret and MCP isolation (doctor 19).
3. **Domain fronting.** Squid sees the `CONNECT` host, not the TLS SNI or
   the HTTP `Host` inside TLS. A CDN-hosted allowed domain (npm, PyPI) can
   front other tenants of that CDN.
4. **Provider-side web tools.** Claude `WebFetch` and `WebSearch` and Codex
   web search run at the provider. They read URLs outside the allowlist and
   return the content into the box. Opt-out: `[box] web_tools = false`.
5. **The agent can read its own credentials.** These are the subscription
   tokens and `GH_TOKEN`. With the ChatGPT token and `chatgpt.com` allowed,
   the agent can call the ChatGPT connector backend by raw HTTP, outside
   the gateway.
6. **Shared secrets.** A shared secret (for example the Claude token) is
   visible in every box that uses it.
7. **Process environment on the host.** The secret values are in the
   environment of the `docker compose up` process. The same host user can
   read that environment (`ps -E` on macOS) while the process runs.
8. **Doctor can be faked.** A persistent agent process (same uid, no Yama
   ptrace restriction) can change what doctor sees in the box. Isolation
   does not depend on doctor; only its report does.
9. **stdio MCP servers.** They run as the gateway user. They can read the
   gateway's secrets: upstream bearers and OAuth token sets in
   `/run/secrets` and the OAuth volume. A stdio server can rotate a refresh
   token and lock the gateway out. A server with a shell or file tool hands
   these secrets to the agent. It also shares the gateway's network
   position. `uvx` and `npx` packages are pinned only as far as the profile
   pins them.
10. **MCP servers that the agent adds to Codex or Pi.** T5 for these relies
    on T2. Strict mode limits them to allowed domains. Open mode permits any
    public domain, and the gateway does not log them. This is no worse than
    raw HTTP. A mounted repository can also declare stdio MCP servers for
    Codex or Pi; they are only code in the box.
11. **LiteLLM routes outside `allowed_routes`.** Without a database, some
    non-admin LiteLLM routes answer (the `/ui` bundle, `/openapi.json`,
    `/health/readiness`, SSO and login stubs). None reaches an admin action
    (doctor 21 samples them).
12. **`count_tokens` bypasses the router guard.**
    `/v1/messages/count_tokens` does not pass through the pre-call hook. It
    cannot carry headers or the key elsewhere, and it only counts tokens.
13. **A sidecar compromise** gives that sidecar's own secrets. Each sidecar
    holds only its own.
14. **Container escape.** A kernel bug in the Docker Desktop VM (or the Linux
    host kernel) can let the agent leave the container.
15. **Egress log size.** The proxy caps each logged URL at 256 characters
    and each User-Agent at 128 (`cli/agentbox/egress.py`). A loop in the
    egress container rotates `egress.log` above 20 MB and truncates it above
    30 MB (`images/egress/entrypoint.sh`). An agent can therefore push old
    denials out of the log. `agentbox denied` reads at most the last 16 MB
    of each file and at most 5,000 hosts (`cli/agentbox/denied.py`).
16. **Pinned boxes keep running.** `agentbox up` and interactive sessions
    pin the box until `agentbox down`. A process that the agent leaves in a
    pinned box keeps running, with the secrets and network access of the
    box. An unpinned box stops after a headless run, and the CLI kills
    leftover processes (recorded in `schedule ls`). A timed-out run in an
    unpinned box kills all processes except init (`cli/agentbox/cli.py`,
    `cli/agentbox/box.py`, `cli/agentbox/runs.py`).
17. **Host tools in a mounted folder.** Host tools run config that the agent
    planted in a `rw` mount. Read
    [Running host tools in a mounted folder](#running-host-tools-in-a-mounted-folder).
18. **The home volume persists.** Hooks and rc files that the agent plants
    in `/home/agent` (for example `~/.bashrc`, `~/.npmrc`, agent config) run
    in every later session, scheduled runs included. `agentbox down` keeps
    the volume. For a full reset:

    ```sh
    agentbox down -v myproject
    ```

    This removes the home volume and the gateway OAuth volume. You must log
    in to Codex and Pi again. If an MCP provider rotated its refresh token,
    run `agentbox mcp login` again too.
19. **Terminal escape sequences.** In interactive sessions, output from the
    box reaches your terminal raw. A terminal emulator bug, or an OSC 52
    clipboard write, can affect the host. The CLI cleans only the strings
    that it prints itself.
20. **Disk fill.** The agent can fill the home volume (the Docker Desktop VM
    disk, shared with other containers) and, through `rw` mounts, the host
    disk.
21. **`agentbox denied` offers names that the agent chose.** An agent can
    request a lookalike or attacker-owned domain so that you allow it. Allow
    only names that you know.

## Supply chain

| Item | Pin | Where |
| --- | --- | --- |
| Ubuntu base | Image digest | `images/agent/versions.env` |
| Claude Code | apt version; repository key fingerprint checked at build | `versions.env` |
| GitHub CLI | apt version; key fingerprints checked | `versions.env` |
| Node.js | Version and SHA-256 (also checked against `SHASUMS256.txt`) | `versions.env`, `images/mcp-gateway/Dockerfile` |
| Codex, Pi | npm version, `--ignore-scripts` | `versions.env`, `images/agent/Dockerfile` |
| pi-mcp-adapter | Version and committed lockfile, `npm ci --ignore-scripts` | `images/agent/pi-mcp-adapter/` |
| Ollama client, uv | Version and SHA-256 | `versions.env` |
| Python (agent) | Version, installed by `uv python install` | `versions.env` |
| squid | Image digest | `images/egress/Dockerfile` |
| LiteLLM | Container image digest (not the PyPI package) | `images/router/Dockerfile` |
| Gateway Python packages | Hash-locked, `--require-hashes --only-binary=:all:` | `images/mcp-gateway/requirements.lock` |
| Gateway and gate base | `python:3.13-slim` digest | `images/mcp-gateway/Dockerfile`, `images/ollama-gate/Dockerfile` |
| vLLM on Modal | Image digest and Hugging Face revision | `modal/serve_vllm.py` |

`agentbox update` is the only command that changes the agent image pins. It
looks up the latest releases, checks the form of each value (version,
64-digit SHA-256, or `name:tag@sha256:` digest), writes `versions.env`,
rebuilds, and runs the full doctor on a scratch profile. If any step fails,
it restores the old pins and the previous image (`cli/agentbox/update.py`).
Key fingerprints change only by hand, after a check against the vendor
documentation. These pins also change only by hand: `SQUID_IMAGE`,
`LITELLM_IMAGE`, the `python:3.13-slim` `PYTHON_IMAGE` of the gate and
gateway, the gateway `UV_IMAGE`, `NODE_VERSION`, and `NODE_SHA256`, the
gateway `requirements.lock`, and the Modal `VLLM_IMAGE` and
`MODEL_REVISION`.

Not pinned: the `apt` packages from `[box] packages`, packages that the
agent installs at runtime, and stdio MCP packages unless the profile pins
them. The Linux CI workflow pins its GitHub Actions by full commit SHA
(`.github/workflows/isolation.yml`); these pins change only by hand.

## What agentbox does NOT protect against

- An agent that sends your code or data to a site that the profile allows.
- An agent that misuses the credentials you gave it: it can push with your
  GitHub token and use your subscriptions.
- Content from the web, provider web tools, or MCP servers that tries to
  control the agent (prompt injection). agentbox limits what the agent can
  reach; it does not make the agent obey you.
- Damage inside a `rw` mount. The agent can delete or change any file there.
  Keep backups or use git.
- Host tools that you run in a `rw` mount (git, VS Code, direnv, npm, make,
  host Claude Code). They run what the agent planted there, with your host
  rights. Host config detection warns about some of these files; it does
  not stop them.
- Changes that the agent makes to its home volume. They stay until you
  remove the volume.
- Terminal escape sequences in interactive sessions.
- A malicious or compromised model vendor, MCP server, or package registry.
- Bugs in Docker, the Linux kernel, or the Docker Desktop VM.
- Other software on your host, and other users of your host account.
- Leaks from the host side, for example a secret that you paste into a
  prompt.

## Report a problem

Do not open a public issue for a security problem. Report it privately
with GitHub private vulnerability reporting:
<https://github.com/soverby/agentbox/security/advisories/new>. Include:

1. The agentbox commit (`git rev-parse HEAD`).
2. The host OS and Docker version.
3. The profile, with secrets removed.
4. The output of `agentbox doctor <profile>`.
5. The steps that show the problem.

Do not put exploit details in a public issue.
