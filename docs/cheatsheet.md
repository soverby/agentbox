---
geometry: margin=0.45in
fontsize: 8pt
colorlinks: true
header-includes:
  - \usepackage{longtable,booktabs}
  - \setlength{\parskip}{2pt}
  - \pagenumbering{gobble}
---

# agentbox cheatsheet (1.3.0)

## First session

```sh
uv tool install -e ./cli          # host CLI (stdlib, Python >= 3.11)
claude setup-token                 # one-year token, pasted into setup
agentbox setup                     # Docker check, images, token, self-test
agentbox init myproj --mount ~/Projects/myproj
cd ~/Projects/myproj && agentbox claude
```

Where `[profile]` is optional, the CLI picks the profile whose mount holds the
current directory. Put `--` after all agentbox options; the words after it go
to the agent or command.

## Boxes and sessions

| Command | What it does |
| :--- | :--- |
| `agentbox claude/codex/pi [profile] [--model M] [-- args]` | Interactive agent session. |
| `agentbox shell [profile] [-- cmd]` | Bash, or one command, in the box. |
| `agentbox up [profile]` / `down [profile]` | Start and keep up / stop. Home volume stays. |
| `agentbox down -v [profile]` | Full reset: home and gateway OAuth volumes removed. |
| `agentbox ls` | Profiles, state, mode, mounts, `image outdated`. |
| `agentbox login <profile> codex/pi` | Subscription login in the box (once per profile). |
| `agentbox validate <file>` | Check a profile file and print it resolved. |
| `agentbox doctor [profile]` | Full isolation self-test. A fast subset runs on every `up`. |

## Network

| Command | What it does |
| :--- | :--- |
| `agentbox denied [profile] [--since S]` | Recent blocked requests. |
| `agentbox allow [profile] <domain>` | Add a domain; live reload, no restart. |

Modes: `strict` (default; presets plus `allow`) or `open` (any public domain).
Both: port 443 only, no IP literals, no host or LAN, no metadata. Presets:
`anthropic`, `openai`, `github`, `dev`.

## Secrets

| Command | What it does |
| :--- | :--- |
| `agentbox secret set [--shared or profile] NAME [--stdin]` | Store (hidden prompt). Keychain `agentbox/<profile>/NAME`. |
| `agentbox secret ls/rm [--shared or profile] [NAME]` | Names and status, never values / delete. |
| `agentbox secret set/rm/ls --stack <name> [NAME]` | Secrets of a plain Compose stack: `agentbox/_stack/<name>/NAME`. |
| `agentbox stack ls [-C DIR]` | Manifest secrets: name, ref, present or missing. |
| `agentbox stack run [-C DIR] -- <command...>` | Run with `AGENTBOX_SECRET_<NAME>` and `<NAME>` in the env only. |

Stack manifest `agentbox-stack.toml` (names only, safe to commit):

```toml
[stack]
name = "myapp"
compose_files = ["compose.yaml", "compose.secrets.yaml"]   # sets COMPOSE_FILE
[secrets]
API_KEY = {}                                # default Keychain item
OTHER = { ref = "keychain:service-name" }   # explicit item, read raw
```

Overlay `compose.secrets.yaml`: `secrets: { API_KEY: { environment: AGENTBOX_SECRET_API_KEY } }`
and per service `secrets: [API_KEY]`. The value lands at `/run/secrets/API_KEY`
(root, 0444). Start with `agentbox stack run -- docker compose up -d`.

## Headless runs, scheduling, MCP, models

| Command | What it does |
| :--- | :--- |
| `agentbox run <profile> --agent A --prompt-file F [--timeout T]` | Headless agent run; transcript and exit code recorded. |
| `agentbox run <profile> --cmd-file F [--timeout T]` | Command job: a shell script in the box, no agent. |
| `agentbox schedule add/ls/rm/edit/run-now` | launchd (macOS) or cron (Linux) jobs on the host. |
| `agentbox schedule report [--since S] [--post]` | Fleet report: due, ran, idle boxes. `--install` for a daily job. |
| `agentbox mcp login/status/logout <profile> <server>` | OAuth for an MCP upstream; the token stays in the gateway. |
| `--model ollama/<name>` or `remote/<name>` | Session shortcut: host Ollama model or a `[models.remote.*]` entry. |

## Maintenance

| Command | What it does |
| :--- | :--- |
| `agentbox update [--check]` | Bump tool pins, rebuild, self-test; rollback if doctor fails. |
| `agentbox update --python-patch [--install [--at HH:MM]]` | Python patch only; `--install` makes the daily job. |
| `agentbox update --python-line X.Y --eol YYYY-MM` | Move Python to another line, after the lock check. |
| `agentbox update --prune [--dry-run]` | Remove superseded images and old build cache. |

## Profile keys (`~/.config/agentbox/profiles/<name>.toml`)

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `[box] agents` | all three | `claude`, `codex`, `pi`. |
| `[box] resources.cpus` / `memory` | `4` / `"8g"` | Box limits. |
| `[box] packages` | `[]` | apt packages; builds a cached derived image. |
| `[box] web_tools` / `skip_permissions` | `true` / `true` | Provider web tools; Claude permission prompts off. |
| `[[mount]] host`, `path`, `mode`, `allow_dotpath` | - / host path / `ro` / `false` | Host dir, container path, `ro` or `rw`. |
| `[network] mode`, `presets`, `allow`, `allow_http` | `strict` / all / `[]` / `false` | Egress policy. |
| `[secrets] NAME = {}` | profile scope, to `agent` | `shared`, `ref`, `to` (`agent`, `router`, `mcp-gateway`). |
| `[models.remote.<n>] api_base`, `key` | - | Remote model through the router; `key` goes to the router only. |
| `[mcp.servers.<n>] url` or `command`, `bearer` or `auth="oauth"`, `tools` | - | Upstream MCP server; `tools` allowlist. |

## Paths

| Path | Content |
| :--- | :--- |
| `~/.config/agentbox/profiles/<name>.toml`, `config.toml` | Profiles, host settings. |
| `~/.local/state/agentbox/<name>/` | Generated config, logs, runs, schedules (0700). |
| `<state>/logs/egress/egress.log`, `logs/mcp/calls.jsonl` | Proxy access log, MCP call log. |
| `<state>/runs/<time>-<agent>/`, `<state>/schedules/<job>/` | Run records, scheduled job files. |
| `/run/secrets/<NAME>` (in a container) | A delivered secret. Docs: `docs/USAGE.md`, `docs/SECURITY.md`. |

