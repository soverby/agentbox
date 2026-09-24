# CLAUDE.md

Project: `agentbox` — Docker sandboxes for AI agents (Claude Code, Codex, Pi,
ollama) with controlled filesystem, network, secrets, and MCP access.

- Requirements: `PROJECT.md`. Design and phase plan: `docs/PLAN.md`. Read both
  before any change. The plan is the source of truth; change the plan first,
  then the code.
- Status: v1 built (P0–P8, P6b). Pending: user live acceptance (see docs/USAGE.md quick start).

## Security invariants (never weaken without a plan change)

- The agent container attaches only to the internal network. All egress goes
  through the egress proxy allowlist.
- No Docker socket, no `privileged`, no added capabilities, non-root user.
- Secrets live on the host backend. A container receives only the secrets the
  profile targets at it. Never write a secret into a generated file, log, or
  image layer.
- Host mounts only from the profile, validated by realpath against the denylist.
- Every isolation property has a check in `agentbox doctor`. A new isolation
  claim needs a new check.

## Conventions

- Host CLI: Python, stdlib only, Python ≥ 3.11 (`tomllib`). Tests: pytest.
- Pin every tool version (build ARG) and every image (digest).
- Docs use ASD-STE100 style: short sentences, active voice.

## Workflow

- Builders: `subagent_type: builder`. Validators: `subagent_type: reviewer`.
  Design review: `subagent_type: design-reviewer` (adversarial).
