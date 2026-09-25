# Example: daily news brief (Perigon MCP, PDF, Slack)

A complete example that exercises the main agentbox features: the shared
Claude token, profile secrets, the MCP gateway with a bearer-token server,
the egress allowlist and `denied`/`allow`, headless `run`, `schedule`, and
`doctor`. Use it as a guided first project.

Each weekday morning, Claude runs headless in an agentbox. It gets the top
news from the [Perigon](https://perigon.io) MCP server, writes a Markdown
brief, renders it to PDF, and sends it to a Slack channel.

## Set up your copy

The example must live outside the agentbox repository: agentbox refuses a
writable mount inside its own repository (the agent could change the CLI).
Copy it first, and run every command below from the copy:

```sh
cp -R ~/agentbox/examples/news-brief ~/agentbox-news   # your clone path
cd ~/agentbox-news
```

## Architecture

```text
 host (macOS)                         agentbox "news" (strict network)
 ------------                         -------------------------------------------
 launchd --> agentbox run ----------> claude -p < prompts/daily-brief.md
 (schedule)  (transcript in            |  MCP server "agentbox"
             ~/.local/state/agentbox/  v
             news/runs/)              mcp-gateway --(PERIGON_API_KEY)--> mcp.perigon.io
                                       |  tools perigon_*
                                       v
                                      reports/YYYY-MM-DD.md   (rw mount = this repo)
                                       |
                                      uv run tools/deliver.py  (fpdf2 from PyPI)
                                       |  reports/YYYY-MM-DD.pdf
                                       v  via egress proxy (allowlist)
             PDF mode:     slack.com/api + files.slack.com   (SLACK_BOT_TOKEN)
             Webhook mode: hooks.slack.com/services/...      (SLACK_WEBHOOK_URL)
```

The agent never sees the Perigon key. Only the gateway has it.

## Files

| File | Purpose |
| --- | --- |
| `agentbox/news.toml` | The agentbox profile. |
| `prompts/daily-brief.md` | The headless prompt. |
| `topics.toml` | Sections, queries, languages, regions, story count. Edit freely. |
| `tools/deliver.py` | Markdown to PDF (fpdf2 2.8.8), then Slack. |
| `tests/` | pytest suite and `fixtures/sample-brief.md`. |
| `reports/` | Output. Git ignores it. |

`deliver.py` selects the Slack mode from the secrets that are present:

| Secrets present | Mode | Result |
| --- | --- | --- |
| `SLACK_BOT_TOKEN` (with or without webhook) | PDF | PDF file in the channel, with the headline as comment. |
| Only `SLACK_WEBHOOK_URL` | Webhook | Text summary (max 3,500 chars) in the channel. PDF stays in `reports/`. |
| Neither | none | Exit 4, clear message. |

Exit codes: 0 OK, 2 usage (bad path, bad secret value, not UTF-8), 3 PDF
render error, 4 Slack error.

`deliver.py` reads briefs only from `reports/` and `tests/fixtures/` (`.md`).
`deliver.py --failure "<reason>"` posts a short failure notice. The prompt
calls it once on each failure path, so a failed scheduled run is not silent.

## Walkthrough

### (a) Prerequisites

1. Perigon key: sign in at <https://perigon.io/dev/keys> and create an API key.
2. Slack, text mode: create an
   [incoming webhook](https://api.slack.com/messaging/webhooks) for your
   channel. It posts a text summary; it cannot upload files.
3. Slack, PDF mode (upgrade, optional):
   1. At <https://api.slack.com/apps>, open the app that owns the webhook
      (or create an app).
   2. OAuth & Permissions > Bot Token Scopes. Add `files:write` (for
      `files.getUploadURLExternal` and `files.completeUploadExternal`) and
      `chat:write` (for the failure notice, `chat.postMessage`).
   3. Only if `SLACK_TARGET` is a user ID (DM): also add `im:write`
      (for `conversations.open`).
   4. Reinstall the app to the workspace. Copy the Bot User OAuth Token
      (`xoxb-...`).
   5. In your channel, type `/invite @<app name>`. Without this, the upload
      fails with `not_in_channel`.
   6. Get the target ID for `SLACK_TARGET`: the channel ID (channel
      details > About, `C...`), or for a DM your member ID (profile > More >
      Copy member ID, `U...`).

### (b) Install agentbox and the Claude token

Install the CLI as a tool first. `schedule add` records the path of the
`agentbox` command; a temporary `uv run` path does not work for launchd.

```sh
cd ~/agentbox && uv tool install -e ./cli   # your clone of the agentbox repo
agentbox --version
claude setup-token        # prints a long-lived subscription token
agentbox setup            # stores it as the shared token; runs doctor
```

### (c) Install the profile

```sh
mkdir -p ~/.config/agentbox/profiles
cp agentbox/news.toml ~/.config/agentbox/profiles/news.toml
agentbox validate ~/.config/agentbox/profiles/news.toml --name news
```

If your copy is not at `~/agentbox-news`, edit `[[mount]] host` in the
profile. The box sees the repo at the same path.

### (d) Store the secrets

All secrets have profile scope (`agentbox/news/NAME`). The gateway gets
`PERIGON_API_KEY`; the agent gets the Slack secrets.

```sh
agentbox secret set news PERIGON_API_KEY                 # hidden prompt
agentbox secret set news SLACK_WEBHOOK_URL               # paste https://hooks.slack.com/services/...
# PDF mode (after step a.3):
agentbox secret set news SLACK_BOT_TOKEN                 # xoxb-...
# Required with the bot token: the channel (C...) or a DM user (U...).
agentbox secret set news SLACK_TARGET                    # C... or U...
agentbox secret ls news
```

To pipe a value instead of pasting it, add `--stdin`, for example
`printf %s "$SLACK_WEBHOOK_URL" | agentbox secret set news SLACK_WEBHOOK_URL --stdin`.

Do not write the webhook URL or tokens into any file. A missing secret does
not stop `up`; `secret ls` shows `missing`.

Webhook mode only: `up`, `run`, and each scheduled run print a warning that
`SLACK_BOT_TOKEN` and `SLACK_TARGET` are missing. This is expected.
agentbox has no optional-secret flag. The warning goes away when you store
a bot token.

### (e) Start the box and run the self-test

```sh
agentbox up news
agentbox doctor news
```

All lines must show PASS or SKIP. Check 20 must show all upstreams
connected (here: 1, `perigon`). It shows counts only, not tool names.

Before the first headless run, this is the test for the Perigon URL and
key. If check 20 fails, fix it first (see Troubleshooting).

The profile allows all Perigon tools. Get the tool names in step (f), then
narrow them if you want.

### (f) Try it interactively

```sh
cd ~/agentbox-news
agentbox claude news
```

Ask: "List your MCP tools whose names start with mcp__agentbox__perigon_."
Then ask for one search. In the box, `claude mcp list` shows the server
`agentbox`.

Claude sees each tool as `mcp__agentbox__perigon_<tool>`. In `tools = [...]`,
use only `<tool>`: remove the prefix `mcp__agentbox__perigon_`. Example: if
Claude lists `mcp__agentbox__perigon_search_news` and
`mcp__agentbox__perigon_search_stories`, edit
`~/.config/agentbox/profiles/news.toml`:

```toml
[mcp.servers.perigon]
url = "https://mcp.perigon.io/v1/mcp"
bearer = "PERIGON_API_KEY"
tools = ["search_news", "search_stories"]
```

Then run `agentbox up news` and `agentbox doctor news` again.

### (g) Dry run in the box

```sh
agentbox shell news -- uv run tools/deliver.py --dry-run tests/fixtures/sample-brief.md
```

The first run downloads fpdf2 from PyPI (`pypi.org`,
`files.pythonhosted.org` in `allow`). Expect
`rendered tests/fixtures/sample-brief.pdf (1 pages, ...)`, the mode, and
the webhook text. No network call to Slack. Delete the sample PDF after.

### (h) Headless run

```sh
cd ~/agentbox-news
agentbox run news --agent claude --prompt-file prompts/daily-brief.md --timeout 20m
```

`agentbox run` prints only `run: <dir> (exit N)`. The agent output is in
`<dir>/transcript.log`. The exit code does not prove success: `claude -p`
exits 0 also after `BRIEF FAILED`. Read the last line:

```sh
RUN=$(ls -td ~/.local/state/agentbox/news/runs/*/ | head -1)
tail -1 "$RUN/transcript.log"      # must start with BRIEF OK
```

Also check:

- `reports/<today>.md` and `reports/<today>.pdf` in your copy.
- The message in your channel. On failure, a "Daily news brief FAILED"
  notice is there instead.

### (i) Blocked requests

```sh
agentbox denied news --since 1h
agentbox allow news <domain>     # only for a domain that you know and need
```

`allow` edits the profile and reloads the proxy.

### (j) Schedule

```sh
agentbox schedule add news --name daily-brief --agent claude \
  --prompt-file prompts/daily-brief.md --at 07:00 --days mon-fri --timeout 20m
agentbox schedule run-now news daily-brief
agentbox schedule ls
```

`schedule add` copies the prompt. After you edit the prompt, add the job
again with `--force`.

### (k) Clean up

```sh
agentbox schedule rm news daily-brief
agentbox down news               # add -v to also remove the home volume
agentbox secret rm news SLACK_BOT_TOKEN
agentbox secret rm news SLACK_WEBHOOK_URL
agentbox secret rm news SLACK_TARGET
agentbox secret rm news PERIGON_API_KEY
rm ~/.config/agentbox/profiles/news.toml
uv tool uninstall agentbox       # only if you do not keep agentbox
```

## Tests (host)

```sh
uv run --with pytest --with fpdf2==2.8.8 pytest -q
uv run tools/deliver.py --dry-run tests/fixtures/sample-brief.md
```

The tests use a local fake Slack server (`SLACK_API_BASE`,
`SLACK_HOOKS_BASE`; tests only). The Unicode test skips if DejaVu is not
installed. To run it on macOS, set `DELIVER_FONT_DIR` to a directory with
`DejaVuSans.ttf` and `DejaVuSans-Bold.ttf`.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Doctor 20: `perigon` not connected, or 401 | Wrong or missing `PERIGON_API_KEY`. | `agentbox secret set news PERIGON_API_KEY`; `agentbox up news`. |
| `BRIEF FAILED: Perigon tools are not available` | Gateway has no Perigon tools. | Run `agentbox doctor news`; check 20 and the key. |
| `slack: files.completeUploadExternal: not_in_channel` | Bot is not in the channel. | `/invite @<app>` in your channel. |
| `slack: ...: missing_scope` | Bot lacks a scope. | Add `files:write` and `chat:write` (DM: `im:write`); reinstall; store the new token. |
| `... contains whitespace or control characters` (exit 2) | Secret stored with a space or newline. | Store it again with `printf %s ... \| agentbox secret set ... --stdin`. |
| `brief must be under reports/ ...` (exit 2) | Wrong path. | Use `reports/YYYY-MM-DD.md`. |
| Emoji or CJK characters are blank in the PDF | DejaVu Sans has no glyphs for them. | Expected. Latin, Greek, and Cyrillic render. |
| `slack: ...: channel_not_found` | Wrong `SLACK_TARGET`, or private channel without the bot. | Fix the ID; invite the bot. |
| `slack: ...: invalid_auth` | Wrong token. | Store the `xoxb-...` Bot User OAuth Token. |
| `slack: webhook: HTTP 404 no_service` / `HTTP 403` | Webhook removed or disabled. | Make a new webhook; store it again. |
| `SLACK_WEBHOOK_URL is not an https://hooks.slack.com/services/... URL` | Wrong value. | Store the full webhook URL. |
| `no Slack secret` (exit 4) | Neither Slack secret stored. | Step (d). |
| Proxy 403, or `uv` hangs | Domain not allowed. | `agentbox denied news`, then `agentbox allow`. |
| `warning: DejaVu font not found` | `fonts-dejavu-core` not in the box. | Check `[box] packages`; `agentbox up news`. Output then uses Helvetica; non-Latin-1 characters become `?`. |
