# agentbox — Implementation Plan

Status: r5 + usability pass u1. Adversarial design review: APPROVED in
round 5 of 5, conditional on the R5 edits (applied). The usability pass (§9)
was done by the architect after the review closed. Requirements: `PROJECT.md`.
Change log: §8.

## 1. Goal and threat model

One command starts a sandbox ("box") for one purpose ("profile"). AI agents in
the box can use only what the profile grants: listed host paths, network
destinations, secrets, and MCP servers. **The box must be easy enough to use
every day** — usability targets are in §9.

Host platform today: macOS 26 on Intel (x86_64), Docker Desktop 4.67 (Engine
29.3, Compose v5). Linux hosts with Docker Engine are a secondary target.

**Adversary:** the agent itself (prompt injection, a malicious dependency, a
wrong tool call). It has arbitrary code execution as a non-root user inside
the agent container, and it can send any request to any sidecar it can reach.

**Must hold against that adversary:**

| ID | Property |
| --- | --- |
| T1 | No read or write to host paths that the profile does not mount. rw only where declared. |
| T2 | No network egress except through the egress proxy. In `strict` mode (default) only allowlisted domains; in `open` mode (explicit per-profile opt-in) any public domain. In both modes: port 443 only (80 opt-in), no direct IP, no IP-literal requests, no private / loopback / link-local destinations, no DNS resolution of external names in the box, no host services except the filtered `ollama-gate`, no cloud metadata. This holds also when a sidecar is abused (SSRF). |
| T3 | No access to the Docker socket, host network, privileged mode, or added capabilities. |
| T4 | Secrets of other profiles, and secrets targeted at sidecars (router keys, MCP upstream tokens), are not visible in the agent container. |
| T5 | MCP access only to the servers and tools the profile allows, through one gateway that logs every call. No other MCP path (claude.ai connectors, Codex apps, remote plugins). |
| T6 | Boxes of different profiles cannot reach each other. |

**Accepted residual risks (documented, not solved):**

- Exfiltration to an allowed domain (for example a gist on github.com). In
  `open` mode, any public domain (`mcp-proxy.anthropic.com` stays denied
  in every mode).
- The agent can read the credentials its own CLIs need (subscription tokens,
  `GH_TOKEN`). With the ChatGPT token and chatgpt.com allowed, the agent can
  also call the connector backend by raw HTTP.
- A shared secret (§2.4) is visible in every box that uses it.
- Domain fronting: squid sees the `CONNECT` host, not the TLS SNI, so a
  CDN-hosted allowed domain (npm, PyPI) can front other tenants of that CDN.
- Doctor results can be faked by a persistent agent process (same uid, no
  Yama ptrace restriction). Isolation does not depend on doctor; only its
  report does.
- A container-escape kernel bug in the Docker Desktop VM.
- A sidecar compromise gives that sidecar's own secrets (each sidecar holds
  only its own).
- Provider-side web tools (Claude `WebFetch`/`WebSearch`, Codex web search)
  read arbitrary URLs outside the egress allowlist and return the content
  into the box. Opt-out per profile: `[box] web_tools = false`.
- T5 for remote MCP servers the agent adds to its own Codex/Pi config
  relies on T2: strict mode limits them to allowlisted domains; open mode
  allows any public domain, unlogged by the gateway (no worse than raw
  HTTP).
- stdio MCP servers run as the gateway user and can read the gateway's
  secrets (upstream bearers); one with a shell or file tool hands them to
  the agent, and it shares the gateway's network position. Declare only trusted stdio servers; `uvx`/
  `npx` packages are pinned only as far as the profile pins them.
- A mounted repo can declare stdio MCP servers for Codex or Pi. They are only
  in-box code. Claude Code loads only the root-owned `managed-mcp.json`.

## 2. Architecture

Per profile, one Compose project `agentbox-<profile>` with two networks:

- `internal` (`internal: true`, fixed subnet, fixed IP per service): all
  containers.
- `external` (normal bridge): only `egress` and `ollama-gate`.
- At every `up` the CLI calls `network.verify()` against Docker's in-use
  subnets, excluding the profile's own Compose project.
- The CLI allocates each profile a unique internal subnet (`10.213.<n>.0/24`,
  `n` stored in the profile state dir; Docker refuses overlapping bridge
  subnets) and fixed IPs inside it. `n` is 1–254; freed values are reused.
  The base is configurable in `~/.config/agentbox/config.toml` (Linux hosts
  with a VPN route in `10.213.0.0/16` must change it).

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

- `agent`, `router`, `mcp-gateway` have no route out. They reach the outside
  only through `egress`, which applies a separate allowlist per source IP.
  An SSRF in `router` or `mcp-gateway` therefore reaches only that sidecar's
  allowlist.
- `ollama-gate` forwards to host Ollama only inference paths and allowed
  models (§2.5). It is the only host path for the agent. A raw TCP relay is
  rejected: the full Ollama API lets the agent make the host pull from any
  registry host (unproxied egress with data in the URL) and write or delete
  host models.
- Source IPs are fixed in Compose. The agent cannot change its IP (no
  `CAP_NET_ADMIN`, no `CAP_NET_RAW`; confirmed in round 2).
- Verified on this host (round 1): on an internal network there is no
  default route, embedded DNS returns SERVFAIL for external names and for
  `host.docker.internal`, and TCP to external or VM IPs fails with
  ENETUNREACH. Container names still resolve. Doctor checks keep this true.

### 2.1 Agent container (`images/agent/Dockerfile`)

- Base `ubuntu:24.04` (ARG; 26.04 LTS is an option, see §7). The image
  ships user `ubuntu` at uid 1000: `userdel -r ubuntu` before creating `agent`.
- Tools, each version pinned by build ARG in `images/agent/versions.env`
  (`agentbox update` bumps them, §2.3):
  - Claude Code ≥ 2.1.246 — Anthropic signed apt repository, pinned version.
    Key fingerprint checked at build against the value in Anthropic docs.
    Env `DISABLE_AUTOUPDATER=1`, `DISABLE_UPDATES=1`,
    `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`,
    `ENABLE_CLAUDEAI_MCP_SERVERS=false`.
    Root-owned `/etc/claude-code/managed-mcp.json` lists only the gateway
    (`http://mcp-gateway:8080/mcp`, header
    `Authorization: Bearer ${MCP_GATEWAY_TOKEN}`). This blocks
    `claude mcp add`, plugin and `--mcp-config` servers, and claude.ai
    connectors, in interactive and headless sessions. The CLI never passes
    `--mcp-config` or `--strict-mcp-config` (with a managed file present,
    Claude Code exits at startup).
  - Codex CLI — `@openai/codex` (npm), pinned.
  - Pi — `@earendil-works/pi-coding-agent` (npm, `--ignore-scripts`), pinned;
    plus `pi-mcp-adapter` (pinned) for MCP. Pi has no system-wide extension
    directory, so `/usr/local/bin/pi` is a wrapper that adds
    `--extension /usr/local/lib/agentbox/pi-mcp-adapter/node_modules/pi-mcp-adapter`
    (adapter installed by `npm ci` from a committed lockfile; not for
    `install|remove|uninstall|update|list|config|auth`).
  - Node.js 24 LTS (Pi needs Node ≥ 22.19).
  - Ollama — client binary only: a build stage downloads the release archive
    (`ollama-linux-amd64.tar.zst`, ~1.4 GB of GPU libs; needs `zstd`) and
    copies only `bin/ollama`.
    Docker Desktop on macOS has no GPU passthrough; models run on the host or
    on Modal.
  - GitHub CLI `gh` — official apt repository.
  - Python — the latest stable CPython release on python.org at build time
    (3.14.x today; 3.15.0 is due 2026-10-01), pinned in `versions.env`,
    installed with `uv python install`; `python3`/`python` symlinked to it.
    `uv` also installed.
  - `jq`, `git`, `ripgrep`, `curl`, `ca-certificates`, `unzip`, `less`,
    `build-essential`, `make`.
- Per-profile extra packages: `[box] packages = ["ffmpeg", …]`. The CLI
  builds a derived image (`FROM agentbox/agent`, `apt-get install`) at `up`,
  cached by package-list hash. The runtime stays non-root.
- User-space installs work at runtime through the proxy: `uv`/`pip`
  (`pip install --user` works: the image removes the `EXTERNALLY-MANAGED`
  marker),
  `npm -g` (`NPM_CONFIG_PREFIX=~/.npm-global` on `PATH`), `cargo`, `go`.
- Runtime hardening (Compose): user `agent` (uid 1000, no sudo),
  `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `pids_limit`,
  `mem_limit`, `cpus`, `init: true`, no `privileged`, no Docker socket.
  `read_only: true` is not used: Compose refuses `secrets` with an
  `environment:` source on read-only services (confirmed in round 1), and the
  non-root user protects system paths (doctor 16).
- `/home/agent` is a per-profile named volume (logins, caches, config).
- Git setup at `up`: the CLI copies host `user.name`/`user.email` into the
  box `~/.gitconfig`, sets `url."https://github.com/".insteadOf
  git@github.com:` (port 22 is blocked), and runs `gh auth setup-git` so
  `git push` uses `GH_TOKEN`.
- The container runs `sleep infinity` under `init`. All agent processes start
  through `docker compose exec agent /usr/local/bin/with-secrets <cmd>`
  (§2.4). `docker exec` uses the container config env, not PID 1's runtime
  env, so an entrypoint export never reaches exec sessions (confirmed in
  round 2).

### 2.2 Egress proxy (`images/egress/`)

- Squid (pinned `ubuntu/squid` digest). Generated `squid.conf`:
  - One `src` ACL per client (agent, router, mcp-gateway), fixed IPs.
  - Per-client domain allowlist files, `dstdomain -n` (`-n` stops
    reverse-DNS matching, so an IP-literal request never matches a domain).
  - Always denied, all modes: IP-literal hosts (`dstdom_regex -n` for IPv4
    and bracketed IPv6); `dst` ACL for `0/8`, `10/8`, `100.64/10`, `127/8`,
    `169.254/16`, `172.16/12`, `192.168/16`, `::/96` (unspecified,
    loopback, IPv4-compatible), `100::/64`, `2001::/32`, `2001:db8::/32`,
    `64:ff9b:1::/48`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8`,
    `2002::/16` (never `::ffff:0:0/96`: squid stores IPv4 as mapped IPv6, so
    it means all IPv4; `::1` next to `::/96` makes a squid warning)
    (checked on squid's resolved address, which is also the address it
    connects to); `CONNECT` to any port other than 443 (80 only with
    `allow_http`); `manager`.
  - Agent network mode (profile `[network] mode`):
    - `strict` (default): agent allowlist = presets + `allow`.
    - `open`: any public domain, subject to the always-denied rules.
  - Host MCP servers (plain HTTP): the gateway sends absolute-URI forward
    requests, not `CONNECT`, and `dstdomain` carries no port. Rule:
    `http_access allow gw_src !CONNECT host_dom host_mcp_ports` with a
    separate `port` ACL built from the profile, placed before the private-
    range deny. Only the gateway source gets this rule.
  - No cache. Access log to `<state>/logs/egress.log`.
- Allowlist files are bind-mounted read-only from the host state dir. Changes
  apply with `squid -k reconfigure` in the egress container — no box restart.
- Squid rejects `a.com` together with `.a.com` (FATAL), so allowlists are
  merged with `merge_domains`. A bad config fails `squid -k reconfigure` and
  the old config stays active; the CLI runs `squid -k parse` first.
- Doctor checks call curl with `--noproxy ''` wherever traffic must go
  through the proxy (curl honours `NO_PROXY` even with `-x`).
- Agent env: `HTTPS_PROXY`/`HTTP_PROXY=http://egress:3128`,
  `NO_PROXY=router,mcp-gateway,ollama-gate,localhost,127.0.0.1` (upper and
  lower case forms). Tools that ignore proxy env fail
  closed (no route).
- Presets in `presets/*.toml` (builder confirms each list against real
  traffic):
  - `anthropic`: `api.anthropic.com`, `claude.ai`, `claude.com`,
    `platform.claude.com`. Never `mcp-proxy.anthropic.com`.
  - `openai`: API, ChatGPT login and Codex domains.
  - `github`: github.com, API, codeload, raw/objects/release-assets
    githubusercontent.
  - `dev`: PyPI, npm, crates.io, Go proxy/sum, RubyGems, python-build-
    standalone downloads.
- A blocked domain is fixed in one command: `agentbox denied` lists recent
  denials from the log and offers to allow each; `agentbox allow <domain>`
  adds it to the profile and reloads squid.

### 2.3 Host CLI (`cli/agentbox/`, Python stdlib only, host Python ≥ 3.11)

Install: `uv tool install -e ./cli` (editable: the CLI reads `images/`,
`presets/`, and `tests/isolation/doctor_checks.sh` from the repo it was
installed from). Profiles live in
`~/.config/agentbox/profiles/<name>.toml`; state (generated config, logs,
transcripts) in `~/.local/state/agentbox/<name>/`. The CLI works from any
directory.

Profile resolution: commands take `[profile]`; if it is omitted, the CLI uses
the profile whose mount contains the current directory, and starts the agent
in that directory.

| Command | Purpose |
| --- | --- |
| `agentbox setup` | First run: check Docker, build images, choose secret backend, store the shared Claude token (`claude setup-token` output, pasted), detect host Ollama, run `doctor` on a scratch profile. |
| `agentbox init <name> --mount <path> [--agents …] [--open]` | Create a working profile with defaults (below). |
| `agentbox claude\|codex\|pi [profile] [-- args]` | Start the box if needed and open that agent interactively in the current (or first) mount. |
| `agentbox shell [profile]` | Bash in the box. |
| `agentbox run <profile> --agent X --prompt-file F` | Headless run (`claude -p`, `codex exec`, `pi -p`); exit code and transcript to `<state>/runs/`. Starts and stops the box if it is not running. |
| `agentbox login <profile> codex\|pi` | Subscription login in the box (`codex login --device-auth`; Pi paste-redirect-URL). |
| `agentbox allow [profile] <domain>` / `agentbox denied [profile]` | Allowlist edit + live reload / review recent denials. |
| `agentbox secret set/ls/rm [--shared \| profile] <NAME> [--stdin]` | Manage secrets (hidden prompt by default). |
| `agentbox mcp login <profile> <server>` | OAuth for an MCP upstream, on the host (§2.6). |
| `agentbox up/down/ls` | Explicit start/stop/status (sessions auto-start). |
| `agentbox schedule add/ls/rm` | Host scheduling (§2.7). |
| `agentbox update` | Bump `versions.env` to current releases, rebuild, run full `doctor`; keep the previous image tag if doctor fails. |
| `agentbox doctor [profile]` | Full isolation self-test (§4). |

Agent launch flags set by the CLI (the box is the external sandbox):

- Claude Code: `--dangerously-skip-permissions` (opt-out per profile:
  `[box] skip_permissions = false`; default `true`).
  `web_tools = false` adds `--disallowedTools WebFetch WebSearch` (two
  arguments).
- Codex, on every launch (interactive and `exec`), highest-precedence layer
  that the agent cannot edit: `-c features.apps=false
  -c features.remote_plugin=false -c apps._default.enabled=false`
  (`-c features.plugins=false` too if P6 shows remote plugins survive);
  `--dangerously-bypass-approvals-and-sandbox` (Codex's own Landlock/seccomp
  sandbox can fail inside a hardened container and report the failure only
  to the model); `codex exec` adds `--skip-git-repo-check`;
  `web_tools = false` adds `-c web_search=disabled`.
- Pi: default mode.
- Working directory: current host dir if inside a mount, else first mount.
- Sessions never start through a login shell (`bash -l`): Ubuntu's
  `~/.profile` would put `~/.local/bin` before system `PATH` entries.

Profile file — what `agentbox init foo --mount ~/Projects/foo` writes:

```toml
[box]
agents = ["claude", "codex", "pi"]
resources = { cpus = 4, memory = "8g" }
# packages = ["ffmpeg"]
# web_tools = true

[[mount]]
host = "~/Projects/foo"
mode = "rw"                  # init writes rw for the project; schema default is ro
# path defaults to the same absolute path as on the host

[network]
mode = "strict"              # or "open"
presets = ["anthropic", "openai", "github", "dev"]
allow = []

[secrets]
# NAME = "shared": agent, keychain agentbox/_shared/NAME.
# NAME = { to = "...", ref = "..." }: defaults agent + agentbox/<profile>/NAME.
GH_TOKEN = "shared"
# CLAUDE_CODE_OAUTH_TOKEN is implicit (shared) when "claude" is in agents.

[models]
ollama = "local"             # all non-cloud models on the host; or a list

# [models.remote.qwen-modal]
# api_base = "https://<workspace>--vllm-serve.modal.run/v1"
# key = "MODAL_API_KEY"      # goes to router automatically

# [mcp.servers.docs]
# url = "https://mcp.example.com/mcp"
# bearer = "DOCS_MCP_TOKEN"  # goes to mcp-gateway automatically; or auth = "oauth"
# tools = ["search", "fetch"]
```

Mount validation (T1):

- Resolve realpath of the host path. Refuse when it is missing (Docker would
  create it as root).
- Container path defaults to the host realpath (paths in errors and
  transcripts match the host). Override with `path`.
- Refuse when the realpath equals, is an ancestor of, or is a descendant of
  any denylist entry: `/`, `/etc`, `/private`, `/var`, `/System`, `/Library`,
  `/Users` (itself), `$HOME` (itself), the Docker socket, `~/Library`,
  `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.docker`, `~/.config`,
  `~/.cache`, `~/.local`, `~/.claude`, `~/.codex`, `~/.pi`, `~/.netrc`,
  `~/.npmrc`, `~/.pypirc`, `~/.gitconfig`.
- Any other dot-path under `$HOME` needs `allow_dotpath = true` on that mount.
- Unit tests include symlink, `..`, and trailing-slash cases.

### 2.4 Secrets (T4)

- The secret store lives on the host, outside every box. No box has backend
  access. The CLI fetches only the secrets the profile needs, at `up` time.
- Backends behind one interface (`get(ref)`): `keychain` (macOS `security`,
  zero install, default), `op` (1Password CLI, read-only; service account
  per profile: its token is the keychain item
  `agentbox/<profile>/_OP_SERVICE_ACCOUNT_TOKEN`, else the ambient `op`
  session), `env` (tests only). `bws` and Linux `secret-tool` later.
- Keychain values: never in argv (`security -i` on stdin). agentbox-owned
  items are stored as `agentbox:b64v1:` + base64, so any value without NUL
  works (multi-line PEM, JSON); raw size cap 1,500 bytes (the `security -i`
  line limit); larger secrets use the `op` backend. Explicit `keychain:`
  refs read items of any account, raw.
- Scopes: profile (`agentbox/<profile>/<NAME>`, default) and shared
  (`agentbox/_shared/<NAME>`, opt-in per secret). Shared secrets are for
  credentials that are the same in every box anyway (the Claude token) or
  that the user chooses to share (a GitHub PAT). A profile-scoped secret is
  still the recommendation for sensitive work.
- Targets: a secret's targets are its explicit `to` (a name or a list) plus
  the inferred ones: named by `[models.remote.*].key` → `router`; by
  `[mcp.servers.*].bearer` → `mcp-gateway`; no explicit `to` and no
  inference → `agent`. Inference adds targets, never removes them. The
  shorthand `NAME = "shared"` means `{ shared = true, to = "agent" }`, so a
  shared `GH_TOKEN` for the agent can also serve a GitHub MCP server. A
  table without `to` that a sidecar uses goes only to that sidecar (T4).
  `CLAUDE_CODE_OAUTH_TOKEN`, when declared, must target exactly `agent`.
- Reserved names (rejected in `[secrets]`, `key`, `bearer`):
  `MCP_GATEWAY_TOKEN`, `AGENTBOX_*`, `PATH`, `HOME`, `USER`, `SHELL`,
  `LD_*`, `*_PROXY` and `NPM_CONFIG_*` (any case), `NODE_OPTIONS`,
  `PYTHON*`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, `OLLAMA_HOST`,
  `DISABLE_AUTOUPDATER`, `DISABLE_UPDATES`, `ENABLE_CLAUDEAI_MCP_SERVERS`,
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` (the CLI sets these),
  `BASH_ENV`, `ENV`, `IFS`, `PS4`, `NODE_*`, `SSL_CERT_*`,
  `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `GIT_*` (code execution or TLS
  weakening). `with-secrets` enforces the same list, except the names the
  CLI itself delivers as secrets (`MCP_GATEWAY_TOKEN`, `AGENTBOX_*`,
  `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`); the profile validator is
  the policy point for those. Also
  `CLAUDE_CODE_OAUTH_TOKEN` as a `key` or `bearer`.
- Ref formats: `keychain:<service>`, `op://<vault>/<item>/<field>`,
  `env:<VAR>`.
- Delivery: Compose `secrets:` with `environment:` source; the CLI passes the
  values only in the environment of the `docker compose up` process. Compose
  copies each secret into the target container at `/run/secrets/<NAME>` at
  create time (confirmed: not in `docker inspect`; not on host disk). The CLI
  recreates a container when its secret set changes (hash compare).
- Sidecars: an entrypoint shim exports `/run/secrets/*` as env and then
  `exec`s the service.
- Agent: `/usr/local/bin/with-secrets` exports each `/run/secrets/<NAME>` as
  `NAME` and `exec`s its arguments. The CLI never execs a bare command in the
  agent container.
- Per-box random tokens (router master key, `MCP_GATEWAY_TOKEN`) are
  generated by the CLI at first `up`, rotated at `down`, and delivered the
  same way. They and the per-profile HMAC key for the secret-set label live
  in the state dir as 0600 files: box-local random values, not user
  credentials. User secrets never touch disk.
- In the agent, `/run/secrets/*` are root:root 0444 (the agent cannot
  rewrite them; it is the only uid in the box). Compose hands the file to
  the container user whenever `uid`/`gid` is set, so neither is set. Rendered Compose strings escape `$`.
- A secret change recreates the target container only when no session is
  using it; otherwise `up` keeps the running container and says the change
  applies after sessions end (or `agentbox down`).
- Claude: one shared `CLAUDE_CODE_OAUTH_TOKEN` (one-year token from
  `claude setup-token`, stored at `agentbox setup`) serves interactive and
  headless sessions in every profile. No per-profile Claude login.
- Codex and Pi: login once per profile, stored in the profile home volume.
  Not shared: their refresh tokens rotate, and one box refreshing would
  break the others.

### 2.5 Model routing

Requirement: subscription access must work; routing must not require API keys
for Claude Code or Codex. Routing is per session (choose agent + model at
launch), not per request: subscription traffic cannot pass through a
third-party router.

| Agent | Default (subscription) | Open models |
| --- | --- | --- |
| Claude Code | `CLAUDE_CODE_OAUTH_TOKEN`, direct to Anthropic via egress | Host ollama: `ANTHROPIC_BASE_URL=http://ollama-gate:11434`, `ANTHROPIC_AUTH_TOKEN=ollama` (Ollama serves `/v1/messages`). Remote: `ANTHROPIC_BASE_URL=http://router:4000` + router key. CLI shortcut: `agentbox claude --model ollama/<m>` or `--model remote/<m>`. |
| Codex | ChatGPT login, direct to OpenAI via egress | `model_providers.<x>` with `wire_api = "responses"` (the only supported value): host ollama (`/v1/responses`, host Ollama ≥ 0.14.0) or router (LiteLLM Responses API bridged to chat completions for vLLM). Rendered by the CLI; same `--model` shortcut. |
| Pi | `openai-codex` (ChatGPT login). Not the Claude plan: Anthropic does not permit subscription OAuth in third-party tools. | `models.json` custom provider → ollama-gate or router, rendered by the CLI. |
| ollama CLI | — | `OLLAMA_HOST=http://ollama-gate:11434`, in `NO_PROXY`. Read and inference commands (`list`, `show`, `ps`, `run`). `pull`/`rm`/`cp`/`create`/`push` are denied: run them on the host. |

- Host Ollama ≥ 0.14.0 (`/v1/messages`; `/v1/responses` non-stateful only).
- `models.ollama = "local"` (default): the gate reads host `/api/tags` at
  start and every 60 s and allows every model with an empty `remote_host`.
  Ollama routes any model reference ending `:cloud` or `:<tag>-cloud` (any
  case) to ollama.com even without a local model (`server/cloud_proxy.go`);
  the gate always denies such names, in `local` and list modes.
  Cloud models (`*-cloud`, non-empty `remote_host`) are never allowed: they
  send the prompt from the host to ollama.com outside squid. A list instead
  of `"local"` pins the allowed models.
- `ollama-gate` (`images/ollama-gate/`): stdlib Python streaming proxy
  (`ThreadingHTTPServer`, `protocol_version = "HTTP/1.1"`, upstream read with
  `read1()`, streamed responses re-chunked) on both networks. Rules:
  - Explicit method + path list, nothing else (403):
    `GET /api/tags`, `/api/ps`, `/api/version`, `/v1/models`,
    `/v1/models/<name>` (allowed name);
    `POST /api/chat`, `/api/generate`, `/api/embed`, `/api/embeddings`,
    `/api/show`, `/v1/chat/completions`, `/v1/completions`,
    `/v1/embeddings`, `/v1/responses`, `/v1/messages`.
    No `/v1/*` wildcard (Ollama routes multipart `/v1/audio/transcriptions`
    to the chat handler with `model` as a form field).
  - Every POST: media type `application/json` (parameters allowed);
    `Transfer-Encoding` and `Content-Encoding` rejected; body size cap; body
    parsed with `object_pairs_hook` and `parse_constant` (rejects
    `NaN`/`Infinity`) into a JSON object, else 400.
  - Model check: exactly one top-level key that ASCII-case-insensitively
    equals `model` (on `/api/show`: `model` or `name`, one in total),
    spelled exactly, value allowed. Go's JSON decoder matches keys
    case-insensitively, so `{"MODEL": …}` would otherwise reach Ollama
    unchecked.
  - Forwards its own re-serialized body with a fresh `Content-Length`.
  - Log: method, path, model, status, byte counts. Never bodies.
- Router (only when the profile has `[models.remote.*]`): LiteLLM container
  image pinned by digest, no database, `DISABLE_ADMIN_UI=True`,
  `store_model_in_db` off. The agent gets the per-box random master key
  (virtual keys need Postgres). `general_settings.allowed_routes` lists every
  client route exactly (§5 P5). Router `NO_PROXY` is only
  `localhost,127.0.0.1` (for its healthcheck), so an SSRF to any internal
  name still goes to squid and is denied. Router egress allowlist: the
  remote model domains only.
- Modal: `modal/serve_vllm.py` template deploys vLLM with an OpenAI-compatible
  endpoint and a bearer token.
- Note: a custom `ANTHROPIC_BASE_URL` turns off Claude Code MCP tool search.

### 2.6 MCP gateway (T5)

- One gateway container per profile, `images/mcp-gateway/`, a thin Python
  service on FastMCP 4.x (builder checks proxy/mount and visibility API
  against v4 docs), Python 3.13 (FastMCP 4.0.x supports 3.10–3.13). It mounts
  each allowed upstream (streamable HTTP or SSE through squid; stdio servers
  run inside the gateway container), hides and blocks non-allowlisted tools,
  and serves one streamable-HTTP endpoint `http://mcp-gateway:8080/mcp`. It
  logs each call (server, tool, args hash, status). It always runs, with zero
  tools when the profile lists no servers.
- Implementation notes (P6): FastMCP 4.0.5 `create_proxy` + `mount(namespace=)`
  (tools exposed as `<server>_<tool>`; a server name may not prefix another
  plus `_`), `enable(only=True)` plus a policy middleware (second layer);
  tools only in v1 (resources/prompts hidden and rejected). Incoming headers
  are never forwarded upstream (FastMCP forwards them by default; that
  leaked the gateway token). Not `read_only` (same Compose secrets limit as
  the agent): non-root uid, no caps, tmpfs `/tmp` (exec). stdio servers:
  `uvx`/`python3` and `npx`/`node` (Node 24 in the image); PyPI or npm
  registry domains join the gateway allowlist only when a stdio server
  needs them. Remote servers: `https://` port 443; host servers:
  `http://host.docker.internal:<port>`. An upstream that fails to connect
  is reported by doctor (it would otherwise vanish from `tools/list`).
- Files and text the agent controls are untrusted input to the CLI: agent
  config merges never block a session (warn, leave the file), reads of
  in-box files are size-capped regular files only, and every string from
  the box, the gateway, or an upstream is stripped of control characters
  before it reaches the terminal. No agent config file is parsed or written
  by the CLI: Claude uses the image's `managed-mcp.json`, Codex gets the
  gateway entry as `-c` launch overrides, and Pi gets
  `--mcp-config /etc/agentbox/pi-mcp.json` (root-owned, in the image) from
  its wrapper.
- Host-side logs (egress, gate, gateway calls, status) are size-rotated
  (the CLI at `up`; gate and gateway by size themselves); logged
  agent-chosen strings are truncated.
- Agent → gateway auth: `MCP_GATEWAY_TOKEN`, random per box (FastMCP
  `StaticTokenVerifier`; acceptable: random per box, private network).
- Upstream auth:
  - Static bearer (`bearer = "<SECRET>"`), P6.
  - OAuth (`auth = "oauth"`), P6b: `agentbox mcp login <profile> <server>`
    runs the MCP OAuth flow on the host (discovery, dynamic client
    registration, PKCE, loopback redirect on `127.0.0.1`), stores the token
    set in the backend (profile scope), and delivers it to the gateway only.
    The gateway refreshes tokens and keeps rotated refresh tokens in a
    gateway-only volume. The agent never sees upstream tokens.
- Host MCP servers: reached by the gateway through squid forward requests
  (§2.2). P6 tests streamable HTTP and SSE through squid; if squid buffers
  streams, fall back to a per-port relay reachable only from the gateway.
- Agent wiring: Claude Code via the image's `managed-mcp.json` (§2.1); Codex
  via CLI-rendered `[mcp_servers.agentbox]` (`url`,
  `bearer_token_env_var = "MCP_GATEWAY_TOKEN"`); Pi via `~/.pi/agent/mcp.json`
  for `pi-mcp-adapter` — superseded: `/etc/agentbox/pi-mcp.json` via the Pi
  wrapper (see above).
- Claude.ai connectors off (`managed-mcp.json`,
  `ENABLE_CLAUDEAI_MCP_SERVERS=false`, `mcp-proxy.anthropic.com` never
  allowed). Codex apps and remote plugins off by `-c` overrides on every
  launch (§2.3), not by the agent-writable `~/.codex/config.toml`.
- Rejected: Docker MCP Gateway (ties to Docker Desktop MCP Toolkit, weaker
  per-tool policy); direct per-server access from the agent (no single policy
  point).

### 2.7 Scheduling

- Host-side. `agentbox schedule add <profile> --agent claude --prompt-file F
  --cron "0 7 * * 1-5"` writes a launchd plist (`~/Library/LaunchAgents/
  com.agentbox.<profile>.<name>.plist`) on macOS, or a crontab entry on Linux.
  The plist uses absolute paths for `agentbox` and `docker` and sets `PATH`
  and `HOME`. The job calls `agentbox run`.
- When Docker Desktop is not running, the job starts it (`open -ga Docker`)
  and waits up to 120 s for `docker info`, then fails with a clear log line.
- `agentbox schedule ls` shows last run time, exit code, and transcript path.
- Headless Claude runs use the shared `CLAUDE_CODE_OAUTH_TOKEN` through
  `with-secrets`.
- The box does not need to run between jobs.

## 3. Repository layout

```text
cli/agentbox/          host CLI (stdlib), pyproject.toml
images/agent/          Dockerfile, entrypoint, with-secrets, managed-mcp.json, versions.env
images/egress/         squid.conf template
images/mcp-gateway/    gateway service, entrypoint
images/router/         LiteLLM config template, entrypoint
images/ollama-gate/    path/model-filtering Ollama proxy
presets/               network allowlist presets
profiles/              example.toml (user profiles live in ~/.config/agentbox)
modal/                 vLLM deploy template
tests/unit/            CLI unit tests (pytest)
tests/isolation/       doctor checks run inside the box
docs/                  PLAN.md, SECURITY.md, USAGE.md
```

## 4. Isolation test suite (`agentbox doctor`)

Checks run inside the agent container (and, where marked, inside sidecars).
Each check is pass/fail. The full suite runs on `agentbox doctor`, after
`agentbox update`, and in Linux CI (GitHub Actions workflow committed; it
runs once the repo has a GitHub remote — until then Linux is untested). Every `up` runs a fast subset (1, 2, 6,
9; target < 3 s) and refuses to start a session if it fails.

1. `curl https://example.com` without proxy → fails (no route).
2. Via proxy to a non-allowlisted domain → 403 (`strict`).
3. Via proxy to an allowlisted domain → 200.
4. Direct TCP to `1.1.1.1:443`, `169.254.169.254:80`, Docker Desktop VM IPs →
   fails.
5. Via proxy, `CONNECT <literal IP>:443` and `GET http://<literal IP>/` →
   403; the squid.conf loaded in the running egress is byte-identical to the
   CLI render (whose `-n` and `deny ip_literal` semantics the harness
   negative controls prove). The PTR case runs live only when an allowlisted
   entry covers the PTR of a resolved IP; else it reports that it relies on
   the config check.
6. `getent hosts example.com` and `host.docker.internal` → no answer.
7. Via proxy from agent, `CONNECT host.docker.internal:<port>` and
   `GET http://host.docker.internal:<port>/` (MCP ports included) → 403.
8. Via proxy, `CONNECT <allowlisted domain>:22` → 403; cache-manager URL →
   denied.
9. `/var/run/docker.sock` absent; `/proc/self/status` CapEff and CapBnd = 0.
10. Only declared mounts present; ro mounts reject writes.
11. `/run/secrets` and env hold only agent-targeted secrets.
12. Another running profile's containers unreachable.
13. From `router` and `mcp-gateway`: direct egress fails; via proxy only their
    own allowlists succeed.
14. `mcp-proxy.anthropic.com` → 403; Claude Code `/mcp` lists only
    `agentbox`; with the box `~/.codex/config.toml` deliberately set to
    `features.apps = true`, a CLI-launched Codex session lists no apps and
    no remote plugins (checks the effective session, not the file).
15. `ollama-gate`: only port 11434 open; `/api/pull`, `/api/delete`,
    `/api/copy`, `/api/create`, `/api/push`, `/api/blobs/*`,
    `/v1/audio/transcriptions`, `/v1/responses/compact` → 403; model not
    allowed → 403; `{"MODEL": …}`, duplicate model keys,
    `{"name":ok,"model":other}` on `/api/show`, chunked body,
    `Content-Encoding`, non-JSON content type → 4xx; allowed chat → 200 and
    streams.
16. No path under `/usr`, `/etc`, `/opt`, or on the system part of `PATH`
    is writable by the agent user; home `PATH` entries (`~/.npm-global/bin`,
    `~/.local/bin`) come after every system entry; no setuid/setgid files;
    `managed-mcp.json` is root-owned and not writable.
17. Headless `agentbox run` with only env-delivered tokens
    (`CLAUDE_CODE_OAUTH_TOKEN`, `MCP_GATEWAY_TOKEN`) succeeds.
20. Gateway: missing/wrong token → 401; only allowlisted namespaced tools
    listed; non-allowlisted `tools/call` rejected; agent cannot reach
    upstreams; gateway user writes only `/tmp` and its log dir, no setuid;
    every declared upstream connected (else FAIL naming it).
18. Host Ollama ≥ 0.14.0; no allowed model has a non-empty `remote_host`.
19. `open` mode: public domain → 200; IP literal, RFC 1918, loopback,
    link-local, `host.docker.internal`, and a public name that resolves to a
    private IP → 403. IPv6 cases run only when a canary IPv6 name resolves
    from egress (squid `ERR_DNS_FAIL` → SKIP; Docker Desktop DNS returns no
    AAAA). The harness adds a test-only squid `hosts_file` for its IPv6 test
    names; no resolver runs in any box.

## 5. Phases

Each phase: builder (Sonnet, high) → reviewer (Opus, medium), max 3
rounds, then escalate. Coordinator signs off.

| Phase | Deliverable | Acceptance gate |
| --- | --- | --- |
| P0 | Layout, CLAUDE.md, profile schema + example, lint config | `pytest tests/unit` runs; schema validates `example.toml` and the `init` output |
| P1 | Agent image | Build succeeds on amd64; doctor 16 passes; `claude --version` ≥ 2.1.246; `codex`, `pi`, `ollama`, `gh`, `jq` `--version` pass; `python --version` equals `versions.env` pin; no GPU libs; Pi loads `pi-mcp-adapter` with an empty home volume |
| P2 | Egress proxy (both modes, live reload), networks, subnet allocation, ollama-gate | Doctor 1–9, 13 (stub containers at the sidecar IPs), 15, 18, 19 pass on macOS host and Linux CI; `agentbox allow` takes effect without restart |
| P3 | CLI core: init/up/down/ls/shell/claude/codex/pi/run/allow/denied/update/doctor, Compose rendering (agent, egress, ollama-gate), profile resolution from cwd, mount validation, derived `packages` image, git config | Mount unit tests (symlink, `..`, descendant) pass; full doctor passes on a real profile (checks 1–10, 12, 15, 16, 19 as applicable) and the fast subset gates `up`; from inside a mounted dir, `agentbox claude <p> -- --version` runs in that dir; `run` records transcript and exit code; `allow` takes effect without restart and `denied` lists denials; derived image with `packages` builds (root for `apt-get`, back to `agent`) and is cached; re-`up` of a running box succeeds; `update --check` lists newer versions |
| P4 | Secrets backends, scopes, target inference, delivery, `with-secrets` wiring, `setup`, `login codex\|pi`, `secret` commands, git credential setup | Doctor 11 and 17 pass; unit tests per backend and scope; no user secret in state dir (box tokens and HMAC key only, 0600), `docker inspect`, image layers, or logs; with the user: `setup` stores the Claude token, `login codex` and `login pi` (paste flow) complete, `git push` to a test repo works |
| P5 | Model routing: ollama-gate paths, optional router, Modal template, agent configs, `--model` shortcut | Claude (shared token) and Claude → host ollama answer (despite `count_tokens` 403); Codex (subscription) and Codex → host ollama via Responses API; Pi → host ollama; `codex exec` runs a shell command in a non-git mount and its output is in the transcript; `ollama list` shows host models; router with a stub server; `allowed_routes` lists exactly `/v1/messages`, `/v1/messages/count_tokens`, `/v1/responses`, `/v1/chat/completions`, `/chat/completions`, `/v1/models`, `/models`, `/health/liveliness`; router healthy; with the master key `/model/info`, `/config/yaml`, `/key/generate` → 403/404 and `api_base: http://agent:9` does not connect; `web_tools = false` removes web tools from Claude and Codex |
| P6 | MCP gateway (static bearer, host servers) | Doctor 14 passes (Codex tested with a ChatGPT account that has a connector enabled; remote curated plugins absent, else add `features.plugins=false`); interactive and headless Claude start with `managed-mcp.json`; host MCP server via squid works for streamable HTTP and SSE; allowed tool call succeeds; disallowed tool absent from `tools/list` and `tools/call` rejected; unlisted server unreachable; bad token rejected; calls logged; works from Claude, Codex, Pi |
| P6b | OAuth MCP upstreams | `agentbox mcp login` completes against one real OAuth MCP server; gateway refreshes an expired access token; token never visible in the agent container |
| P7 | Scheduling | launchd job fires `agentbox run`; transcript and exit code recorded; Docker Desktop auto-start works; failure logged; `schedule ls` shows last result |
| P8 | SECURITY.md, USAGE.md (quick start first), security review pass | Independent review finds no BLOCKER; a new user reaches a first Claude session with the quick start alone |

P1 and P2 can build in parallel; P3 needs P1+P2; P4–P6 need P3; P6b needs
P6; P7 needs P3.

## 6. Risks and scope limits

- **Proxy compatibility.** Some CLIs may ignore `HTTPS_PROXY` for part of
  their traffic; such traffic fails closed and shows in `agentbox denied`.
- **Allowlist drift.** Vendor domains change; presets need maintenance.
  `agentbox denied` makes a missing domain a one-command fix.
- **Docker Desktop behavior** (internal-network DNS and routing, Compose
  secrets) is proven by the doctor subset on every `up`, not assumed.
- **Supply chain.** Pin every image by digest and every tool version. The
  LiteLLM PyPI package was compromised in March 2026; use only the pinned
  container image. npm installs use `--ignore-scripts` where possible.
  `agentbox update` is the only path that changes pins, and it runs doctor.
- **Subscription login flows.** Codex: `codex login --device-auth` needs
  "Allow device code login" enabled in ChatGPT settings. Pi `openai-codex`
  login uses Pi's paste fallback (paste the final redirect URL). No login
  container with a published port: on Docker Desktop that needs a normal
  bridge, which gives a default route and breaks T2 (confirmed in round 3).
- **Linux hosts.** `egress` and `ollama-gate` need
  `extra_hosts: ["host.docker.internal:host-gateway"]`; host Ollama must bind
  to an address the bridge can reach.
- **Out of scope v1:** in-box `ollama serve` (Linux + NVIDIA only);
  per-request routing between subscription and local models; sharing Codex/Pi
  logins across profiles.

## 7. Decisions (user, 2026-09-23)

1. Secret backend: macOS Keychain (`op` stays a second backend).
2. Base image: Ubuntu 24.04 LTS.
3. CLI name: `agentbox`.
4. Default network mode for `agentbox init`: `strict`.

## 8. Change log

- r1: R1-01 drop `read_only`, keep env-source secrets. R1-02 sidecars
  internal-only, per-source squid ACLs, `ollama-relay`, router optional.
  R1-03 `dstdomain -n`, IP-literal doctor check, keep `deny manager`. R1-04
  Codex bypass flag + exec gate. R1-05 Responses API only. R1-06 Pi package
  rename, `pi-mcp-adapter`. R1-07 `tools/call` gate, claude.ai connectors off,
  static-bearer upstreams only. R1-08 Pi row. R1-09 denylist ancestor +
  descendant, more entries. R1-10 Python pin rule. R1-11 client-only ollama
  binary. R1-12 apt repo, update env vars, anthropic preset. R1-13 sidecar
  shims, launchd paths, drop `dns` fallback.
- r2: R2-01 `with-secrets` exec wrapper, doctor 17. R2-02 socat relay →
  `ollama-gate` (path + model allowlist), doctor 15. R2-03 no virtual keys;
  per-box master key, no DB. R2-04 non-CONNECT squid rule for host MCP,
  non-CONNECT doctor forms, SSE test. R2-05 `userdel ubuntu`. R2-06 host
  Ollama ≥ 0.14.0, `ANTHROPIC_AUTH_TOKEN`, doctor 18. R2-07 login flows,
  Pi gate and fallback. R2-08 gateway Python 3.13. R2-09 subnet allocation,
  Linux `extra_hosts`. R2-10 doctor 16.
- r3: R3-01 gate canonical JSON, case-insensitive model key check, reject
  chunked/encoded bodies, cloud-model check. R3-02 explicit method + path
  list, no `/v1/*`. R3-03 drop login container; Pi paste fallback. R3-04
  workdir + `--skip-git-repo-check`. R3-05 `allowed_routes`, P5 admin-route
  gate. R3-06 doctor 13 with stubs in P2. R3-07 configurable subnet base.
  R3-08 `login claude --setup-token`. R3-09 gate implementation notes.
- r4: R4-01 Codex apps/remote plugins off, doctor 14, P6 gate. R4-02
  `/api/show` counts `model`+`name`. R4-03 setup-token via `secret set
  --stdin`. R4-04 exact `allowed_routes` list, router healthcheck NO_PROXY.
  R4-05 gate JSON/HTTP traps. R4-06 `--strict-mcp-config`. R4-07 web-tools
  residual + opt-out. R4-08 Ollama version aligned.
- r5: R5-01 Codex `-c` overrides on every launch; doctor 14 checks the
  effective session. R5-02 chose root-owned `managed-mcp.json`; removed
  `--strict-mcp-config`/`--mcp-config`. R5-03 `--disallowedTools WebFetch
  WebSearch`, Codex `web_search=disabled`. R5-04 Claude Code ≥ 2.1.246. R5-05
  router `NO_PROXY` text. R5-06 remote-plugin gate + `features.plugins`
  fallback.
- u1: usability pass, see §9.

## 9. Usability balance (architect, post-review)

Rule applied: keep every control that costs the user nothing (invisible
plumbing), and reduce friction where a control costs daily effort for little
risk reduction. Every reversal keeps T1–T6 intact or is an explicit,
per-profile opt-in with its residual documented in §1.

**Targets:** clone to first Claude session ≤ 10 min (mostly image build); new
profile ≤ 1 min; session start ≤ 5 s warm, ≤ 30 s cold; blocked domain fixed
in one command without restart; Claude login once per machine.

**Changed for usability:**

| Area | Before (review outcome) | Now | Security effect |
| --- | --- | --- | --- |
| Network | Strict allowlist only; `--learn` log-only | `strict` default + `denied`/`allow` with live reload; `open` mode opt-in per profile; `dev` preset | `open` widens exfil targets to any public domain. It still blocks host, LAN, metadata, IP literals, and keeps secrets/MCP isolation. Explicit choice, doctor 19. |
| Ollama models | Explicit per-profile list; pull denied | Default all local non-cloud models, auto-discovered; pull/rm still denied | Other local models become usable (not secrets). Cloud models and pull (the real egress paths) stay blocked. |
| Claude login | Per-profile login; setup-token manual per profile | One shared setup-token at `agentbox setup` | Same subscription in every box anyway; a leak from any box was already a leak of this account. Revoke once, re-run setup. |
| Secrets | Full `ref` + `to` per secret | Default refs, shared scope, target inference | Shared scope is opt-in per secret; default stays per-profile. |
| MCP upstreams | Static bearer only; OAuth out of scope | OAuth via host-side `mcp login` (P6b) | Most hosted MCP servers need OAuth; the token stays in the gateway. |
| MCP config for Claude | Per-launch `--strict-mcp-config` on headless only | Image-level `managed-mcp.json`, all sessions | Stronger and zero-config. The user adds MCP servers in the profile, not with `claude mcp add`. |
| Packages | Fixed image; no root | `packages` list → cached derived image; user-space installers on PATH | None: runtime stays non-root. |
| Mount paths | `/work/<name>` | Same path as host by default; init writes `rw` for the project | Paths in errors match the host. The mount is still explicit. |
| Git | Not specified | Host identity copied, HTTPS rewrite, `gh` credential helper | None beyond the existing `GH_TOKEN`. |
| Commands | `shell --agent X`, profile always named | `agentbox claude` etc., profile from cwd, auto-start | None. |
| Health checks | "doctor on every up" | Fast subset on `up` (< 3 s), full suite on demand, after `update`, and in CI | Full coverage stays on every image change. |
| Updates | Pins changed by hand | `agentbox update` with doctor gate and rollback | Pins stay; updating becomes cheap, so boxes stay current. |
| Scheduling | Fails when Docker is down | Auto-starts Docker Desktop, `schedule ls` status | None. |

**Kept, because they are invisible or the risk is high:** internal-only
network and per-source squid ACLs; `dstdomain -n` and IP-literal/private
denies; sidecar egress limits; `ollama-gate` path filtering and JSON
canonicalization; `with-secrets`; secrets per target container; non-root,
no capabilities, no Docker socket; mount denylist; Codex apps and
claude.ai connectors off; version and digest pins.

**Considered and not reversed:**

- `read_only` rootfs — already dropped in r1; nothing to gain.
- Codex/Pi login sharing — refresh-token rotation makes it break, not only
  less safe.
- `sudo` in the box — packages list covers the need without root at runtime.
- Allowing `ollama pull` through the gate — it is unproxied host egress; one
  host command (`ollama pull`) is a small cost.
- Web tools default off — they are the main way agents read docs in `strict`
  mode; kept on, with opt-out.
