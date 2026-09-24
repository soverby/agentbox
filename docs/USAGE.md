# agentbox usage

This guide starts with the quick start. The quick start takes you to a first
sandboxed Claude Code session. The task sections after it are a reference.

## Quick start

Before you start, make sure that you have:

- macOS with Docker Desktop running, or Linux with Docker Engine (read
  [Linux host notes](#linux-host-notes) first).
- `uv` on the host.
- Claude Code on the host, for the one-time `claude setup-token` step.
- A clone of this repository.

1. Go to the repository root.

   ```sh
   cd /path/to/agentbox
   ```

2. Install the CLI. The install is editable: the CLI reads `images/`,
   `presets/`, and `tests/isolation/` from this clone. Do not move or delete
   the clone.

   ```sh
   uv tool install -e ./cli
   ```

3. Make a Claude token. The command opens a browser and prints a token that
   starts with `sk-ant-oat01-`. Copy the token.

   ```sh
   claude setup-token
   ```

4. Run the first-time setup. It checks Docker, builds the images (the first
   build takes several minutes), writes `~/.config/agentbox/config.toml`,
   asks for the token (paste it; the input is hidden), checks host Ollama,
   and runs the full self-test on a scratch profile.

   ```sh
   agentbox setup
   ```

5. Create a profile for your project. The name has lowercase letters, digits,
   and `-` (at most 31 characters). The mount must exist.

   ```sh
   agentbox init myproject --mount ~/Projects/myproject
   ```

6. Start Claude Code in the box. Go into the mounted directory and give the
   command without a profile name. The CLI finds the profile whose mount
   contains the current directory.

   ```sh
   cd ~/Projects/myproject
   agentbox claude
   ```

   From another directory, name the profile: `agentbox claude myproject`.
   Then the session starts in the first mount.

   The first session starts the box and runs four fast isolation checks. If
   a check fails, no session starts. The box stays up after you quit the
   agent.

7. Before you trust the box, run the full self-test. All lines must show
   PASS or SKIP.

   ```sh
   agentbox doctor myproject
   ```

To stop the box:

```sh
agentbox down myproject
```

If a step fails, read [Troubleshooting](#troubleshooting).

## Commands

| Command | What it does |
| --- | --- |
| `agentbox setup [--skip-token] [--token-stdin] [--skip-doctor]` | First run. |
| `agentbox init <name> --mount <dir> [--agents a,b] [--open] [--allow-dotpath]` | Write a new profile. |
| `agentbox validate <file> [--name N]` | Check a profile file and print it resolved. |
| `agentbox claude\|codex\|pi [profile] [--model M] [-- args]` | Interactive agent session. |
| `agentbox shell [profile] [-- cmd]` | Bash (or a command) in the box. |
| `agentbox run <profile> --agent A --prompt-file F [--model M] [--timeout T]` | Headless run. |
| `agentbox login <profile> codex\|pi` | Subscription login in the box. |
| `agentbox up [profile] [--accept-mount-change]` | Start the box and keep it up. |
| `agentbox down [profile]` | Stop the box. The home volume stays. |
| `agentbox down -v [profile]` | Full reset: also remove the home volume and the gateway OAuth volume. You must log in to Codex and Pi again (and `mcp login` again if a provider rotated its refresh token). |
| `agentbox ls` | Profiles, running or stopped, mode, mounts. |
| `agentbox allow [profile] <domain>` | Add a domain to the allowlist; live reload. |
| `agentbox denied [profile] [--since S] [--json]` | Recent denied requests. |
| `agentbox secret set\|rm [--shared \| profile] NAME` | Store or delete a secret. |
| `agentbox secret ls [--shared \| profile]` | Secret names and status, never values. |
| `agentbox mcp login\|status\|logout` | OAuth for MCP servers. |
| `agentbox schedule add\|ls\|rm\|edit\|run-now` | Scheduled headless runs. |
| `agentbox doctor [profile]` | Full isolation self-test. |
| `agentbox update [--check]` | Update tool versions, rebuild, self-test. |

Where `[profile]` is optional, the CLI uses the profile whose mount contains
the current directory. If no profile or more than one profile matches, the
CLI stops and lists the profiles. `run`, `login`, `mcp login`, `mcp logout`,
and all `schedule` commands except `ls` need the profile name.

Put `--` after all agentbox options. The CLI gives the words after `--` to
the agent. Example: `agentbox claude myproject -- --version`. Only `shell`,
`claude`, `codex`, and `pi` accept `--`.

Files and directories:

| Path | Content |
| --- | --- |
| `~/.config/agentbox/profiles/<name>.toml` | Profiles. |
| `~/.config/agentbox/config.toml` | Host settings (below). |
| `~/.local/state/agentbox/<name>/` | Generated config, logs, runs, schedules (0700). |
| `<state>/logs/egress/egress.log` | Proxy access log. |
| `<state>/logs/gate/` | ollama-gate log. |
| `<state>/logs/mcp/calls.jsonl` | MCP gateway call log. |
| `<state>/runs/<time>-<agent>/` | Headless run records. |
| `<state>/schedules/<job>/` | Scheduled job files and logs. |

The environment variables `AGENTBOX_CONFIG_HOME`, `AGENTBOX_STATE_HOME`, and
`AGENTBOX_REPO` change these roots.

### Host settings (`config.toml`)

All values are TOML strings. An unknown key is an error.

| Key | Default | Rule |
| --- | --- | --- |
| `secret_backend` | `"keychain"` | `keychain`, `op`, or `env` (tests only). |
| `op_vault` | none | Required when `secret_backend = "op"`. |
| `secret_prefix` | `"agentbox"` | First part of default secret names. |
| `subnet_base` | `10.213.0.0/16` | A private `/16`. Change it if a VPN uses the range. |
| `runs_keep` | `"200"` | Run records kept per profile, a whole number ≥ 1. |

## Profiles

`agentbox init` writes a working profile. Edit it with a text editor. The
CLI reads the file again at each command. Check a file with
`agentbox validate <file>`. The CLI reports all problems at once, each with
its key path.

The profile has six top-level tables: `[box]`, `[[mount]]`, `[network]`,
`[secrets]`, `[models]`, and `[mcp]`. An unknown key in a known table is an
error. Strings must not contain control characters.

### `[box]`

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `agents` | list of strings | all three | `claude`, `codex`, `pi`; no duplicates; not empty. |
| `resources.cpus` | number | 4 | Finite, > 0. |
| `resources.memory` | string | `"8g"` | Number + `k`, `m`, or `g`; at least `64m`. |
| `packages` | list of strings | `[]` | apt package names (`[a-z0-9][a-z0-9+.-]*`). |
| `web_tools` | boolean | `true` | `false` turns off provider web tools. |
| `skip_permissions` | boolean | `true` | `false` keeps Claude Code permission prompts. |

With `packages`, the CLI builds a derived image at `up` and caches it by the
package list. The box still runs as the non-root user `agent`.

`web_tools = false` adds `--disallowedTools WebFetch WebSearch` to Claude
Code and `-c web_search=disabled` to Codex.

Launch flags that the CLI always sets (source: `cli/agentbox/launch.py`):

- Claude Code: `--dangerously-skip-permissions` (unless
  `skip_permissions = false`).
- Codex: `-c features.apps=false -c features.remote_plugin=false
  -c apps._default.enabled=false`, the gateway entry as `-c` overrides, and
  `--dangerously-bypass-approvals-and-sandbox`. `codex exec` also gets
  `--skip-git-repo-check`.
- Pi: default mode.

### `[[mount]]`

At least one mount is required.

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `host` | string | required | Absolute, or starts with `~/`. Must exist. |
| `path` | string | host realpath | Absolute container path. |
| `mode` | string | `"ro"` | `ro` or `rw`. `init` writes `rw` for its mount. |
| `allow_dotpath` | boolean | `false` | Needed for a dot-path under `$HOME`. |

Container path rules: no `..`, `:`, `,`, or newline. Not `/`, `/home`, a
path that starts with `/lib`, or a path under `/usr`, `/etc`, `/bin`,
`/sbin`, `/opt`, `/proc`, `/sys`, `/dev`, `/run`, `/var`, `/tmp`,
`/home/agent`, `/root`, or `/boot`. Two mounts cannot use the same path.

## Mounts

Use `ro` for data that the agent must only read. Use `rw` only for the
project that the agent must change. The container path is the host realpath
by default, so paths in errors and transcripts match the host.

The CLI refuses a mount when its realpath is, contains, or is inside one of
these paths (on macOS the compare ignores letter case):

- `/etc`, `/private`, `/var`, `/System`, `/Library`, and the Docker socket.
- `/`, `/Users`, and `$HOME` (only the path itself; subdirectories are
  permitted).
- In `$HOME`: `Library`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`,
  `.config`, `.cache`, `.local`, `.claude`, `.codex`, `.pi`, `.netrc`,
  `.npmrc`, `.pypirc`, `.gitconfig`.

Any other path under `$HOME` with a part that starts with `.` needs
`allow_dotpath = true` on that mount (`init --allow-dotpath`).

A `rw` mount must not be, contain, or be inside:

- `/usr`, `/opt`, or `/Applications`.
- The directory of the host `docker` or `git` command (as found on `PATH`,
  and its realpath).
- The agentbox repository that the CLI runs from. The CLI is an editable
  install, so an agent that can write the repository can change code that
  runs on the host.
- The host Python interpreter, its prefix or venv, the installed `agentbox`
  command, or a `PYTHONPATH` entry. The reason is the same.

A `ro` mount of these paths is permitted. For example, you can mount
`~/Projects` read-only when it holds the agentbox repository.

At the first `up`, the CLI records the realpath of each mount in
`<state>/mounts.json`. If a later `up` finds a different realpath, it stops.
An agent in a `rw` mount can change a symlink that a mount path goes
through. Make sure that the change is yours, then run:

```sh
agentbox up myproject --accept-mount-change
```

The CLI always refuses a mount that is equal to or inside another `rw`
mount of the same profile, also through a symlink. The agent could replace
a directory on that path with a symlink before Docker mounts it. Mount a
directory outside the `rw` mount instead.

### Host config detection

Host tools that you run in a `rw` mount (git, direnv, VS Code) can run
files that the agent planted there. The CLI watches the most common of
these files. It only warns; it never blocks a session or run.

When it runs:

- Before each session (`claude`, `codex`, `pi`, `shell`, `login`) and each
  headless run, after the box is up, the CLI takes a snapshot.
- When the session or run ends, the CLI scans again and reports every
  change.
- Changes between sessions are not compared. For example, a process that
  the agent left running in a pinned box can change files after the
  session ended; the next session starts with a new snapshot.

What it scans, in each `rw` mount:

- Repositories at the mount root, the repository that encloses the mount,
  and repositories one directory level below the root (at most 200
  subdirectories).
- In `.git/config`, these keys: `core.fsmonitor`, `core.hooksPath`,
  `core.sshCommand`, `core.pager`, `core.editor`, `core.askPass`,
  `core.gitProxy`, `sequence.editor`, `gpg.program` and
  `gpg.<format>.program`, `diff.external`, `diff.<driver>.textconv` and
  `.command`, `pager.*`, `merge.<driver>.driver`, `difftool.<tool>.cmd`,
  `mergetool.<tool>.cmd`, `remote.<name>.uploadpack` and `.receivepack`,
  `alias.*` values that start with `!`, `filter.*`, `credential.helper`,
  `include.path`, and `includeIf.*.path`.
- Files in `.git/hooks` that do not end in `.sample` (at most 200).
- A `.git/commondir` file.
- A `.git` that is a file (worktree or submodule `gitdir:`) or a symlink.
- Lines in `.git/config` that the parser cannot classify (git can read
  them differently), and a `.git/config` that is not UTF-8. A leading
  UTF-8 BOM is accepted, as git accepts it.
- `.envrc`, `.vscode/tasks.json`, `.vscode/settings.json`, and
  `.vscode/launch.json` at the mount root and in the repositories one
  level below.

The warning goes to the terminal when the session or run ends:

```text
agentbox: WARNING: host-executed config changed in a rw mount during this session:
  /Users/me/Projects/myproject: .git/config [core.fsmonitor]: added: 1a2b3c4d5e6f /tmp/x.sh
  /Users/me/Projects/myproject: .git/hooks/pre-commit: added: sha256:0123456789abcdef
Review before you run host tools there: `cat .git/config`, `ls -la .git/hooks`, `cat .git/commondir`, `cat .envrc`, `ls -la .vscode`. Do not run host git (or direnv, VS Code tasks) in that directory until you have reviewed it.
```

Each change line is `<mount>: <item>: added: …`, `removed`, or
`changed: <old> -> <new>`. For a headless run, the changes are also in the
run's `meta.json` (`host_config_changes`). For a scheduled job,
`schedule ls` shows each one as `WARNING host config changed: …`.

Limits:

- The parser is tolerant, not identical to git. Lines it cannot classify
  are reported as `(unparsed lines)` when they change.
- Each scan has a 1-second budget. If it runs out, or a cap is hit, the CLI
  prints `agentbox: note: host config scan incomplete (time or file-count
  cap)`, and the run meta records `host_config_scan: scan incomplete`.
- The CLI reads at most 256 KiB of each file. A `.git/config` that is
  already larger at session start can hide a key past that point.
- It does not scan repositories two or more levels below the mount root,
  or the files that `include.path` names (only the path itself).
- The agent controls the mount, so it can force `scan incomplete` (for
  example with many directories). Treat a repeated note as a warning.
- It watches files that run code. It does not flag keys that redirect
  pushes (`url.*.insteadOf`, `http.*.extraHeader`); the egress allowlist
  bounds where those can send data.
- It does not watch `package.json`, Makefiles, `.claude/`, or `.mcp.json`.
- Symlinks are recorded, not followed. The CLI never runs git on these
  directories.

If you see the warning, do not run host tools in that directory yet.
Follow the review steps in
[SECURITY.md](SECURITY.md#running-host-tools-in-a-mounted-folder). Read the
files with `cat` and `ls`; do not run git there to inspect them.

## Network

### Modes

- `strict` (default): the agent reaches only the domains in the presets and
  in `allow`.
- `open`: the agent reaches any public domain. Use it only when you accept
  exfiltration to any site.

In both modes the proxy denies: IP-literal hosts, private, loopback,
link-local, and other special ranges (also after DNS resolution), ports
other than 443 (80 with `allow_http = true`), the host (except through
`ollama-gate`), and `mcp-proxy.anthropic.com`. The box has no DNS for
external names. Tools that ignore the proxy settings fail.

### `[network]` keys

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `mode` | string | `"strict"` | `strict` or `open`. |
| `presets` | list of strings | all four presets | File names in `presets/`. |
| `allow` | list of strings | `[]` | Host names; a leading `.` adds all subdomains. |
| `allow_http` | boolean | `false` | Also permit port 80. |

`allow` entries must be host names with two or more labels. Ports, schemes,
paths, wildcards, IP addresses, non-ASCII names (use punycode), and local
names (`localhost`, `*.local`, `*.internal`, `*.home.arpa`, and similar) are
refused.

Presets (in `presets/`, with their sources in comments):

| Preset | Content |
| --- | --- |
| `anthropic` | Claude Code and the Anthropic API. |
| `openai` | OpenAI API, ChatGPT login, Codex backend. |
| `github` | GitHub web, API, git, raw files, release assets. |
| `dev` | PyPI, npm, crates.io, Go proxy, RubyGems, Python downloads for `uv`. |

### Fix a blocked domain

1. Show the recent denials:

   ```sh
   agentbox denied myproject --since 1h
   ```

2. In a terminal, `denied` asks for each domain that you can allow. Type
   `y` to allow it.
3. Or allow a domain directly:

   ```sh
   agentbox allow myproject pypi.example.org
   ```

`denied` shows host names that the agent chose. Allow only names that you
know and need; an agent can request a lookalike name to make you allow it.

`denied` reads at most the last 16 MB of each log file and lists at most
5,000 hosts. The proxy log stores at most 256 characters of each URL and
128 of each User-Agent. If the cap cut a host name, `denied` shows it as not
allowable.

`allow` edits only the `allow = [...]` line of the profile. If the box runs,
the CLI reloads the proxy; no restart is necessary. If the reload fails, the
CLI restores the old profile. `--since` accepts `30m`, `2h`, `1d`, or an ISO
date or time.

## Secrets

The secret store is on the host. No box can read it. At `up`, the CLI reads
only the secrets that the profile needs. Docker Compose copies each secret
into its target container as `/run/secrets/<NAME>`. In the agent,
`with-secrets` exports each file as an environment variable for the agent
session.

### Backends

| Backend | Use |
| --- | --- |
| `keychain` | macOS Keychain. Default. macOS only. Values up to 1,500 bytes. |
| `op` | 1Password CLI. Read-only in agentbox. For larger values and Linux. |
| `env` | Tests only. |

`keychain` stores agentbox items with the account `agentbox` and the
service `agentbox/<profile>/<NAME>` or `agentbox/_shared/<NAME>`. Values
never go on a command line.

`op` reads `op://<vault>/<prefix>-<profile>/<NAME>` (or
`<prefix>-_shared`) for default locations. Create the items in 1Password;
`agentbox secret set` cannot write to `op`. To use a service account per
profile, store its token in the keychain:

```sh
agentbox secret set myproject _OP_SERVICE_ACCOUNT_TOKEN
```

Without it, the CLI uses your normal `op` session. A scheduled job cannot
answer a 1Password prompt, so it needs the service account token. The token
item is in the macOS Keychain, so this is macOS only (read
[Linux host notes](#linux-host-notes)).

### `[secrets]` entries

```toml
[secrets]
GH_TOKEN = "shared"                     # shared scope, to the agent
HF_TOKEN = {}                           # profile scope, to the agent
SENTRY = { ref = "op://v/sentry/token", to = ["agent", "router"] }
TEAM_KEY = { shared = true, to = "mcp-gateway" }
```

| Form or key | Meaning |
| --- | --- |
| `NAME = "shared"` | Same as `{ shared = true, to = "agent" }`. |
| `shared` | `true`: item `agentbox/_shared/NAME`. Default: `agentbox/<profile>/NAME`. |
| `ref` | Explicit location: `keychain:<service>`, `op://<vault>/<item>/<field>`, or `env:<VAR>`. Not with `shared`. |
| `to` | `agent`, `router`, `mcp-gateway`, or a list of them. |

Targets:

- A secret named by `[models.remote.*].key` goes to `router`.
- A secret named by `[mcp.servers.*].bearer` or `client_secret` goes to
  `mcp-gateway`.
- These rules add targets. They never remove targets that `to` gives.
- A secret with no `to` and no rule goes to `agent`.
- You do not have to list a `key` or `bearer` secret in `[secrets]`. The CLI
  adds it with profile scope.
- `CLAUDE_CODE_OAUTH_TOKEN` is implicit (shared, to the agent) when `claude`
  is in `agents`. If you declare it, it must go only to `agent`.

Scopes: a shared secret is visible in every box that uses it. Use shared
scope for values that are the same in every box (the Claude token) or that
you decide to share. Use profile scope for sensitive work.

Names: letters, digits, and `_`, not starting with a digit. These names are
reserved and refused in `[secrets]`, `key`, and `bearer`:
`MCP_GATEWAY_*`, `AGENTBOX_*`, `PATH`, `HOME`, `USER`, `SHELL`, `LD_*`,
`*_PROXY` and `NPM_CONFIG_*` (any letter case), `NODE_*`, `PYTHON*`,
`BASH_ENV`, `ENV`, `IFS`, `PS4`, `SSL_CERT_*`, `CURL_CA_BUNDLE`,
`REQUESTS_CA_BUNDLE`, `GIT_*`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`,
`OLLAMA_HOST`, `DISABLE_AUTOUPDATER`, `DISABLE_UPDATES`,
`ENABLE_CLAUDEAI_MCP_SERVERS`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`,
`_OP_SERVICE_ACCOUNT_TOKEN`, and `_MCP_OAUTH_*`. `CLAUDE_CODE_OAUTH_TOKEN`
cannot be a `key` or `bearer`. The agent (`with-secrets`) and the router
and gateway start scripts also refuse to export reserved names.

### Secret commands

```sh
agentbox secret set myproject HF_TOKEN          # hidden prompt
agentbox secret set --shared GH_TOKEN
printf '%s\n' "$VALUE" | agentbox secret set myproject HF_TOKEN --stdin
agentbox secret ls myproject
agentbox secret ls --shared
agentbox secret rm myproject HF_TOKEN
```

- Without a profile and without `--shared`, the CLI uses the profile of the
  current directory.
- `--stdin` reads the whole input and removes one trailing newline.
- A value must not be empty or contain a NUL byte. Multi-line values work.
- If a name is shared in the profile, `set myproject NAME` stops and tells
  you to use `--shared`.
- If the name is not in `[secrets]`, the CLI stores it and warns that the
  box does not get it until you add it.
- `secret ls` shows name, scope, status (`present` or `missing`), targets,
  and location. It also shows the per-box tokens that the CLI makes.

A missing secret does not stop `up`. The CLI prints a warning with the fix
command, and the box starts without that secret. A change to secrets
recreates the target container at the next `up`. If a session uses the box,
the change waits until the sessions end or you run `agentbox down`.

## Logins

### Claude Code

One shared token serves all profiles, interactive and headless. There is no
login per profile.

1. Run `claude setup-token` on the host and copy the token.
2. Run `agentbox setup`, or `agentbox setup --skip-doctor` to only store the
   token. When a token is already stored, setup asks before it replaces it.

To revoke the token, revoke it in your Claude account, then run
`agentbox setup` again with a new token.

### Codex

The login stays in the profile home volume. Each profile logs in once.
Logins are not shared, because Codex rotates its refresh token.

1. In ChatGPT (web), open Settings > Security. Turn on "Allow device code
   login".
2. Run the login:

   ```sh
   agentbox login myproject codex
   ```

3. Open the URL that Codex prints in a host browser. Type the code.

### Pi

1. Run:

   ```sh
   agentbox login myproject pi
   ```

2. In Pi, type `/login`. Choose the provider (for ChatGPT: `openai-codex`).
3. Open the printed URL in a host browser and sign in.
4. The browser then goes to a `localhost` URL that does not load. Copy the
   full URL from the address bar and paste it into Pi.
5. Quit Pi with `/quit` or Ctrl+C two times.

Pi cannot use the Claude subscription: Anthropic does not permit
subscription OAuth in third-party tools.

## Git and GitHub

At each `up`, the CLI:

- Copies your host `user.name` and `user.email` into the box.
- Rewrites `git@github.com:` to `https://github.com/`, because port 22 is
  blocked.
- Runs `gh auth setup-git`, so `git push` uses `GH_TOKEN`.

To set up the token:

1. On GitHub, make a fine-grained personal access token. Give it access only
   to the repositories that the agent needs, with the smallest permissions
   (for example Contents: read and write).
2. Store it:

   ```sh
   agentbox secret set --shared GH_TOKEN
   ```

3. Keep `GH_TOKEN = "shared"` in `[secrets]` (the `init` default). For a
   token per profile, use `GH_TOKEN = {}` and
   `agentbox secret set myproject GH_TOKEN`.

The agent can read this token. Give it only the access that you accept to
lose.

## Models

Each session uses one model route. Choose it at launch with `--model`:

| Value | Route |
| --- | --- |
| (none) | The agent's subscription: Claude token, or ChatGPT login for Codex and Pi. |
| `ollama/<model>` | Host Ollama through `ollama-gate`. |
| `remote/<name>` | `[models.remote.<name>]` through the router. |
| other name | Passed to the agent as `--model <name>`. |

```sh
agentbox claude myproject --model ollama/qwen3-coder:30b
agentbox codex myproject --model remote/qwen-modal
```

With `ollama/` or `remote/`, Claude sessions do not get the Claude token.
Claude background and subagent calls use the same model.

### `[models]` keys

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `ollama` | `"local"` or list of strings | `"local"` | `"local"`: all non-cloud host models. A list pins the models. |
| `remote.<name>.api_base` | string | required | `https://`, port 443. |
| `remote.<name>.key` | string | none | Secret name; goes to the router only. |
| `remote.<name>.model` | string | `<name>` | Upstream model ID. |
| `remote.<name>.provider` | string | `"openai"` | `openai` or `vllm`. |

### Host Ollama

1. Install Ollama 0.14.0 or later on the host. `agentbox setup` shows the
   version.
2. Pull models on the host: `ollama pull qwen3-coder:30b`. The box cannot
   pull, remove, copy, create, or push models.
3. In the box, the `ollama` client works for `list`, `show`, `ps`, and
   `run`. `ollama list` shows only the models that the box can use.

`ollama-gate` refuses cloud models (`:cloud`, `:<tag>-cloud`, or a non-empty
`remote_host`) in all modes. Cloud models send the prompt from the host to
ollama.com outside the proxy.

On Linux, Ollama listens on `127.0.0.1` by default, and the box cannot
reach that address. Make Ollama listen on an address that the Docker bridge
can reach:

1. Run `sudo systemctl edit ollama`.
2. Add these lines:

   ```ini
   [Service]
   Environment="OLLAMA_HOST=0.0.0.0:11434"
   ```

3. Run `sudo systemctl restart ollama`.
4. Block port 11434 from other hosts with your firewall. `OLLAMA_HOST`
   `0.0.0.0` also opens Ollama to your LAN.

### Remote models and Modal

The router (LiteLLM) starts only when the profile has `[models.remote.*]`.
The agent gets a random router key for each box. The upstream key stays in
the router.

To serve a model on Modal with the template `modal/serve_vllm.py`:

1. Make a random key. Store it in Modal and in agentbox:

   ```sh
   KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
   modal secret create agentbox-vllm-key VLLM_API_KEY="$KEY"
   printf '%s\n' "$KEY" | agentbox secret set myproject MODAL_API_KEY --stdin
   unset KEY
   ```

2. Deploy: `modal deploy modal/serve_vllm.py`. Modal prints the server URL.
3. Add the model to the profile:

   ```toml
   [models.remote.qwen-modal]
   api_base = "https://<workspace>--agentbox-vllm-server.modal.run/v1"
   key = "MODAL_API_KEY"
   model = "qwen3-coder"
   provider = "vllm"
   ```

4. Start a session: `agentbox claude myproject --model remote/qwen-modal`.
5. Stop the GPU when you do not need it: `modal app stop agentbox-vllm`.

The GPU runs while requests come in and for 10 minutes after the last one.

## MCP servers

The agent reaches MCP servers only through the gateway of its box
(`http://mcp-gateway:8080/mcp`). The gateway always runs. With no servers,
it has no tools. Tool names are `<server>_<tool>`. A server name must not
be the start of another server name plus `_`.

### `[mcp.servers.<name>]` keys

| Key | Type | Rule |
| --- | --- | --- |
| `url` | string | Remote: `https://`, port 443. Host: `http://host.docker.internal:<port>/`. |
| `command` | list of strings | stdio server in the gateway: `uvx`, `python3`, `npx`, or `node`. |
| `bearer` | string | Secret name of a static token (url servers). |
| `auth` | string | `"oauth"` (remote url servers). Not with `bearer`. |
| `tools` | list of strings | Allowed tools. Omit it for all tools; not empty. |
| `scopes` | list of strings | OAuth scopes. Default: what the server offers. |
| `client_id` | string | Pre-registered OAuth client. Default: dynamic registration. |
| `client_secret` | string | Secret name; needs `client_id`. |

Each server needs exactly one of `url` or `command`.

Examples:

```toml
[mcp.servers.docs]                 # static bearer
url = "https://mcp.example.com/mcp"
bearer = "DOCS_MCP_TOKEN"
tools = ["search", "fetch"]

[mcp.servers.local]                # MCP server on the host
url = "http://host.docker.internal:8765/mcp"

[mcp.servers.files]                # stdio server in the gateway
command = ["npx", "-y", "@modelcontextprotocol/server-filesystem@2.0.0", "/srv"]
tools = ["read_file", "list_directory"]
```

Notes:

- A stdio server runs in the gateway container. It can read the gateway's
  secrets. Use only servers that you trust. Pin a version in `command`,
  because agentbox does not pin it for you.
- `uvx` adds PyPI to the gateway allowlist; `npx` adds the npm registry.
- An upstream that does not connect disappears from `tools/list`. `up` and
  `doctor` report it.
- Upstream hosts go only to the gateway allowlist, not to the agent
  allowlist.

### OAuth servers

1. Add the server with `auth = "oauth"`.
2. Log in on the host. The CLI opens a browser and waits on `127.0.0.1`:

   ```sh
   agentbox mcp login myproject tracker
   ```

3. If the box runs, the CLI applies the token at once. If not, the next
   `up` applies it.
4. Check the state: `agentbox mcp status myproject`.
5. To remove the token: `agentbox mcp logout myproject tracker`. The CLI
   revokes the token when the server supports revocation.

The token set goes to the gateway only. The gateway refreshes it and keeps
rotated tokens in a gateway-only volume. Use `--redirect-port <port>` when
a pre-registered `client_id` needs a fixed redirect port. `mcp login` needs
the keychain backend: the `op` backend is read-only.

### `claude mcp add` in a box

Claude Code in the box loads only the root-owned
`/etc/claude-code/managed-mcp.json`. That file lists only the gateway. Thus
`claude mcp add`, plugin servers, `--mcp-config`, and claude.ai connectors
do not load. Add MCP servers to the profile instead.

Codex and Pi can load servers that the agent adds to its own config files.
Those servers are ordinary code in the box and get only the network access
of the box (see [SECURITY.md](SECURITY.md)).

## Headless runs

```sh
agentbox run myproject --agent claude --prompt-file task.md --timeout 30m
```

- The CLI gives the prompt file to the agent on stdin (`claude -p`,
  `codex exec -`, `pi -p`). The prompt is never on a command line.
- The run starts in the mount that contains the current directory, else in
  the first mount.
- If the box is not running, `run` starts it and stops it at the end. See
  [Pinned boxes](#pinned-boxes).
- `--timeout` accepts `30m`, `2h`, `1d`. Without it, `run` has no time
  limit.
- The record goes to `<state>/runs/<UTC time>-<agent>/`: `transcript.log`
  (stdout and stderr, capped at 50 MB), `exit_code`, and `meta.json`. The
  CLI keeps the newest `runs_keep` records (default 200).

### Pinned boxes

`agentbox up` and each interactive session (`claude`, `codex`, `pi`,
`shell`, `login`) pin the box. `agentbox down` removes the pin.

- A pinned box stays up after a headless run.
- An unpinned box stops after a headless run, unless another agentbox
  session uses it. Processes that the agent left running do not keep it up;
  the CLI kills them and records this (`stopped: killed leftover
  processes` in `schedule ls`).
- When `--timeout` expires in an unpinned box, the CLI kills all processes
  in the box except init. In a pinned box it kills only the run's
  processes.

Exit codes of `run`:

| Code | Meaning |
| --- | --- |
| agent's code | The agent ran and exited. |
| 124 | Killed after `--timeout`. |
| 143 | Stopped by SIGTERM or Ctrl+C. |
| 1 | CLI error, message on stderr. If the box did not start, the run record has `exit_code` 125. |

## Scheduling

Scheduled jobs run `agentbox run` on the host: launchd on macOS, crontab on
Linux. The box does not have to run between jobs.

1. Add a job. Give exactly one of `--cron`, `--every`, or `--at`:

   ```sh
   agentbox schedule add myproject --name daily --agent claude \
     --prompt-file task.md --at 07:00 --days mon-fri
   ```

2. Test it now, exactly as the scheduler runs it:

   ```sh
   agentbox schedule run-now myproject daily
   ```

3. Check the status: `agentbox schedule ls`.

| Option | Format |
| --- | --- |
| `--cron` | 5 fields, local time: `"m h dom mon dow"`. |
| `--every` | `30m`, `2h`, `1d`. |
| `--at` | `HH:MM` local time, each day, or with `--days`. |
| `--days` | With `--at`: `mon-fri`, `sat-sun`, `mon,wed,fri`. |
| `--timeout` | Default `2h`; `none` for no limit. |
| `--model` | Same values as for sessions. |
| `--force` | Replace a job with the same name. |

Limits:

- Cron macros (`@daily`), `L`, `W`, `#`, and `?` are not supported.
  `* * * * *` is refused; use `--every 1m`.
- On macOS, one cron expression can expand to at most 500 launchd entries.
  `--every` is approximate: launchd counts from load and wake.
- On Linux, `--every` must divide 60 minutes or 24 hours, or be `1d`.
- A schedule that does not fire within one year is refused.

`add` copies the prompt file into the job directory. To change it later:

```sh
agentbox schedule edit myproject daily --prompt-file task.md
agentbox schedule edit myproject daily --timeout 1h
```

To remove a job: `agentbox schedule rm myproject daily`. Run records stay.

When a job fires:

- If Docker is down, the job starts Docker Desktop (`open -ga Docker`) and
  waits up to 120 seconds.
- The job fails before the run only when the agent's own credential is
  missing (today only the Claude token is checked). Other missing secrets
  become warnings in `schedule ls`.
- If the same job still runs, the new fire is skipped.
- At the end, the box stops unless it is pinned or another session uses it
  (read [Pinned boxes](#pinned-boxes)). `schedule ls` shows why a box stayed
  up, or which leftover processes the CLI killed.

Exit codes of a fire:

| Code | Meaning |
| --- | --- |
| 0 or agent's code | The run happened. |
| 69 | Docker did not come up within 120 seconds. |
| 75 | Skipped: the same job was still running. |
| 78 | Preflight failed (missing credential, agent not in profile, unsafe mount). |
| 124 | Killed after the timeout. |
| 125 | The run failed to start. |
| 143 | Stopped by SIGTERM (for example logout). |

Job files are in `<state>/schedules/<name>/`: `job.json`, `prompt.md`,
`last.json`, and the logs `launchd.out` and `launchd.err` (rotated at
5 MB). On macOS the plist is
`~/Library/LaunchAgents/com.agentbox.<profile>.<name>.plist`.

`schedule add` refuses a profile with a `rw` mount that overlaps the code
that the job runs on the host.

## doctor

`agentbox doctor [profile]` runs the full self-test. If the box does not
run, doctor starts it and stops it again after the test, unless it became
pinned or another session uses it. Each line shows PASS, FAIL, SKIP, or
WARN and the check number. The exit code is 1 when a check fails.

Each session start and each `up` runs the fast subset (checks 1, 2, 6, 9).
If one fails, no session starts; the box stays up so that you can inspect
it. `setup` and `update` run the full suite on a scratch profile.

| Check | Proves |
| --- | --- |
| 1 | The agent has no direct route out. |
| 2 | The proxy refuses a domain that is not allowed (strict mode). |
| 3 | The proxy permits an allowed domain. |
| 4 | Direct TCP to public, metadata, and VM addresses fails. |
| 5 | IP-literal requests are refused; the running proxy config equals the CLI render. |
| 6 | External names and `host.docker.internal` do not resolve in the box. |
| 7 | The proxy refuses the host, also on MCP ports. |
| 8 | Ports other than 443 and the proxy manager are refused. |
| 9 | No Docker socket; no capabilities. |
| 10 | Only declared mounts are present; `ro` mounts refuse writes. |
| 11 | The box holds only agent-targeted secrets; the files are root-owned. |
| 12 | Other running profiles are unreachable (SKIP if none runs). |
| 13 | Router and gateway have no direct egress and only their own allowlists. |
| 14 | Connector proxy denied; Claude, Codex, and Pi see only the gateway. |
| 15 | `ollama-gate` refuses management paths and request tricks. |
| 16 | The agent cannot write system paths; no setuid files; home `PATH` entries come last. |
| 17 | Headless Claude works with the env token (`17 env`, `17 live`). |
| 18 | Host Ollama is 0.14.0 or later; no allowed cloud model. |
| 19 | Open-mode denials (IP, private ranges, host); IPv6 when available. |
| 20 | Gateway: token required, tool policy, no upstream access for the agent, all upstreams connected, OAuth store private. |
| 21 | Router: admin routes refused, no `api_base` override (SKIP without router). |

`14 codex-apps-live` is always SKIP: check `/apps` in a Codex session by
hand. Doctor results can be faked by an agent process that stays running in
the box; read [SECURITY.md](SECURITY.md).

## update

```sh
agentbox update --check     # show current and latest versions only
agentbox update
```

`update` looks up the latest versions of the agent image pins in
`images/agent/versions.env` (Ubuntu base, Claude Code, gh, Node.js, Codex,
Pi, pi-mcp-adapter, Ollama, uv, Python). Then it writes the new pins,
rebuilds the agent image, and runs the full doctor on a scratch profile. If
a step fails, it restores the old pins and the previous image. Each
looked-up value must have the correct form (version, SHA-256, or image
digest); a lookup that fails or returns a bad value leaves that pin
unchanged. Key fingerprints (`CLAUDE_KEY_FPR`,
`GH_KEY_FPRS`) change only by hand.

`update` does not change these pins. Change them by hand:

- `SQUID_IMAGE` in `images/egress/Dockerfile`.
- `LITELLM_IMAGE` in `images/router/Dockerfile`.
- `PYTHON_IMAGE` in `images/ollama-gate/Dockerfile` and
  `images/mcp-gateway/Dockerfile`.
- `UV_IMAGE`, `NODE_VERSION`, and `NODE_SHA256` in
  `images/mcp-gateway/Dockerfile`.
- `images/mcp-gateway/requirements.lock` (`images/mcp-gateway/lock.sh`).
- `VLLM_IMAGE` and `MODEL_REVISION` in `modal/serve_vllm.py`.

## Troubleshooting

| Symptom (CLI message) | Cause | Fix |
| --- | --- | --- |
| `Docker is not running` | Docker Desktop is stopped. | Start Docker, then run the command again. |
| `... is not an agentbox repo (no images/agent/build.sh)` | The CLI is not an editable install of a clone. | `uv tool install -e ./cli` in the clone, or set `AGENTBOX_REPO`. |
| `no profile mounts <dir>; name one explicitly` | The current directory is in no mount. | Give the profile name, or `cd` into a mount. |
| `several profiles mount <dir>` | Two profiles mount this directory. | Give the profile name. |
| `host path does not exist (Docker would create it as root)` | The mount path is missing. | Create the directory, or fix `host`. |
| `... is, contains, or is inside the denied path ...` | The mount hits the denylist. | Mount a narrower directory. |
| `a dot-path under $HOME; set allow_dotpath = true` | The path has a `.` part under `$HOME`. | Add `allow_dotpath = true` if you mean it. |
| `... inside the agentbox repo ...` or `... overlaps ...` (rw) | A `rw` mount covers host code. | Use `mode = "ro"` or another directory. |
| `... (system software or the docker/git the host runs) ...` | `rw` mount of `/usr`, `/opt`, `/Applications`, or a tool directory. | Use `mode = "ro"`. |
| `mount ... is inside the rw mount ...` | Nested mounts. | Mount a directory outside the `rw` mount. |
| `WARNING: host-executed config changed in a rw mount` | The agent changed files that host tools run. | Review them (see [Host config detection](#host-config-detection)) before you run host tools there. |
| `host config scan incomplete` | Time or file-count cap hit. | Review the mount by hand. |
| `the keychain secret backend is macOS-only` | Linux with the default backend. | Set `secret_backend = "op"` and `op_vault`. |
| `mount target changed since the last up` | A symlink in the mount path changed. | Check it, then `agentbox up <p> --accept-mount-change`. |
| `fast isolation checks failed, so no session starts` | Checks 1, 2, 6, or 9 failed. | `agentbox doctor <p>`; fix the cause; `agentbox up <p>`. |
| `CLAUDE_CODE_OAUTH_TOKEN is not set` | No shared Claude token. | `claude setup-token`, then `agentbox setup`. |
| `the token must start with sk-ant-oat01-` | Wrong value pasted. | Paste the output of `claude setup-token`. |
| `secret NAME (...) is missing, so it is not delivered` | The secret is not stored. | Run the command in the message. |
| `the value is N bytes; the keychain backend holds at most 1500` | Value too large. | Use an `op://` ref. |
| `stdin is not a terminal: use --stdin` | The value comes from a pipe. | Add `--stdin`. |
| `NAME is shared in profile P: use --shared NAME` | Wrong scope. | `agentbox secret set --shared NAME`. |
| `NAME is a reserved name` | The name is on the reserved list. | Use another name. |
| `secret change applies after sessions end` | A session uses the box. | End the sessions or `agentbox down <p>`. |
| Tool fails with a proxy 403, or a download hangs | Domain not allowed. | `agentbox denied <p>`, then `agentbox allow`. |
| `reload failed, profile and allowlist restored` | Squid refused the new config. | Read the message; fix the entry. |
| `login is interactive: run it in a terminal` | `login` without a TTY. | Run it in a terminal. |
| Codex device login refused | "Allow device code login" is off. | Turn it on in ChatGPT Settings > Security. |
| `--model ...: not in [models] ollama of P` | The model is not in the pinned list. | Add it, or use `ollama = "local"`. |
| `--model ...: cloud models are never allowed` | Cloud models bypass the proxy. | Use a local model. |
| `--model remote/...: no [models.remote.X]` | Missing remote model. | Add `[models.remote.X]`. |
| `host Ollama: not running` / gate checks SKIP | Ollama is stopped or not reachable. | Start Ollama; on Linux set `OLLAMA_HOST`. |
| `remote MCP servers must use https://` / `port 443` | Unsupported URL. | Use https on port 443. |
| `host MCP servers must use http://host.docker.internal:<port>/` | Host server URL uses `localhost`. | Use `host.docker.internal`. |
| `is not in the mcp-gateway image` | stdio launcher not supported. | Use `uvx`, `python3`, `npx`, or `node`. |
| `MCP server S is not logged in` | No OAuth token set. | `agentbox mcp login <p> S`. |
| `the op backend is read-only ... mcp login cannot store` | `op` default backend. | Use `keychain` for that profile. |
| `20 upstreams` FAIL: `not connected` | Upstream down, wrong token, or blocked. | Check the server, the secret, and `agentbox denied`. |
| `schedule ... exists; use --force` | Same job name. | Add `--force`, or choose another name. |
| `never fires within a year` | Impossible date fields. | Fix `--cron`. |
| `needs N launchd calendar entries (limit 500)` | Cron expression too wide. | Use fewer values or `--every`. |
| `schedule ls` shows exit 69 | Docker did not start in 120 s. | Start Docker; `schedule run-now`. |
| `schedule ls` shows exit 78 | Preflight failed. | Run the fix in `message:`. |
| Box stays up after `run` (`left up: ...`) | Pinned box or a leftover process. | `agentbox down <p>`. |
| `another agentbox up/down holds ... up.lock` | A parallel `up` or `down` hangs. | Wait, or stop the other command. |
| `no free subnet index` / subnet overlap | 254 profiles, or a VPN route. | Remove old state, or set `subnet_base`. |

## Linux host notes

Linux is a secondary target and is not tested yet.

- Install Docker Engine and the Compose v2 plugin. Your user must be able
  to run `docker`.
- The CLI adds `host.docker.internal:host-gateway` to `egress` and
  `ollama-gate`.
- Host Ollama must listen on an address that the Docker bridge can reach.
  Read [Host Ollama](#host-ollama).
- A host MCP server must also listen on an address that the bridge can
  reach, not only on `127.0.0.1`.
- The Keychain backend is macOS only. `agentbox setup` stops on Linux until
  `config.toml` sets another backend. Do these steps:
  1. Install the 1Password CLI (`op`) and sign in.
  2. Write `~/.config/agentbox/config.toml`:

     ```toml
     secret_backend = "op"
     op_vault = "agentbox"
     ```

  3. In 1Password, create the item `agentbox-_shared` in that vault with
     the field `CLAUDE_CODE_OAUTH_TOKEN` (the output of
     `claude setup-token`). Create other secrets the same way:
     item `agentbox-<profile>` or `agentbox-_shared`, field `<NAME>`.
  4. Run `agentbox setup --skip-token`.
- agentbox does not write to 1Password (the `op` backend is read-only), so
  `secret set` and `secret rm` do not work. `mcp login` does not work
  either: it must store the token set, and today only the keychain can.
- The per-profile 1Password service account token is a keychain item, so
  it is not available on Linux. The CLI uses your `op` session. A scheduled
  job cannot answer a 1Password prompt.
- Scheduling uses your crontab. Each job line has a tag; `schedule rm`
  removes it.
- If a VPN uses `10.213.0.0/16`, set another private `/16` as
  `subnet_base`.
