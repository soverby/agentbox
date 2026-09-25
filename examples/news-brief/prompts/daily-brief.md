# Daily news brief (headless)

You run without a human. Do these steps in order. Do not ask questions.

## Rules

- Get news only from the Perigon tools. In this box they come from the MCP
  server `agentbox`, with names that start with `perigon_`. Web search and web
  fetch are off. Do not use `curl`, `wget`, or other HTTP clients for news.
- Do not print, echo, or write any secret or environment variable value
  (`SLACK_BOT_TOKEN`, `SLACK_WEBHOOK_URL`, `SLACK_TARGET`, or other). Do not run `env`, `printenv`,
  or `set`.
- Do not install packages. Do not use `pip`, `apt`, or `npm`. The only
  allowed dependency step is the `uv run` command in step 5.
- Write files only in `reports/`.

## Failure notice

On any failure below, run this command exactly once, then print the
`BRIEF FAILED: ...` line and end the run:

`uv run tools/deliver.py --failure "<short reason>"`

The reason must be one plain line, at most 200 characters, with no secret,
no environment variable value, no URL with a token, and no double quotes.
Do not run `--failure` more than once per run. Do not run it after a
successful delivery.

## Step 1: Check the tools

List your tools. If there is no tool whose name starts with `perigon_`
(for example `mcp__agentbox__perigon_...`), stop now. Print exactly:

`BRIEF FAILED: Perigon tools are not available (check agentbox doctor 20 and PERIGON_API_KEY).`

Send the failure notice with reason `Perigon tools are not available`.
Then end the run. Do not write a report. Do not run the delivery step.

## Step 2: Read the scope

Read `topics.toml`. It gives `max_stories`, `min_stories`, `lookback_hours`,
`languages`, `regions`, and one `[[section]]` per section with a `name` and a
`query`. Get today's date with `date -u +%F`. Call it DATE.

## Step 3: Gather stories

For each section, search Perigon for articles and stories from the last
`lookback_hours` hours that match `query`, `languages`, and `regions`. Prefer
story or cluster tools (many sources on one event) over single articles. Pick
the most important stories. Remove duplicates across sections. Keep between
`min_stories` and `max_stories` stories in total, with at least one per
section if Perigon has one.

For each story, keep: a headline, a 2 to 3 sentence factual summary, one to
three source links (outlet name and URL, as Perigon returns them), and the
publish time in UTC. Do not invent facts, URLs, or times. If a tool call
fails, try again once, then continue with what you have. If you have zero
stories after all sections, send the failure notice with reason
`Perigon returned no stories`, then print
`BRIEF FAILED: Perigon returned no stories.`

## Step 4: Write the report

Write `reports/DATE.md` in this format (Markdown subset: headings, bullets,
bold, links only; no tables, no images, no code):

```text
# Daily News Brief — DATE

**Top line:** <one or two sentences: the most important news today>

## <section name>

### <story headline>
- **Summary:** <2 to 3 sentences>
- **Source:** [<outlet>](<url>) — published <YYYY-MM-DD HH:MM> UTC
- **Source:** [<outlet>](<url>) — published <YYYY-MM-DD HH:MM> UTC

---

Generated from Perigon via the agentbox MCP gateway at <HH:MM> UTC.
```

## Step 5: Deliver

Run this command exactly once:

`uv run tools/deliver.py reports/DATE.md`

Do not run it again if it fails. Do not change `tools/deliver.py`. The
script picks the mode: PDF upload if a bot token is set, else a text summary
to the webhook (the PDF stays in `reports/`).

## Step 6: Report

Print a short final result:

- `BRIEF OK: <n> stories, reports/DATE.md, <the last stdout line of the
  script>` if the exit code was 0.
- If the exit code was not 0: send the failure notice with reason
  `delivery exit <code>: <the error line from stderr>` (it has no secrets),
  then print `BRIEF FAILED: delivery exit <code>: <the error line>`. If the
  notice also fails, do not try again.
  Exit codes: 2 usage, 3 PDF render error, 4 Slack error (including no
  Slack secret set).
