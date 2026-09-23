# Project Brief

Create easy to run and use docker containers that can run network and file system sandboxed AI agents.
The goal is to create an easy to user environment that allows agents to run in a contained sandbox 
where access to the host machine, credentials, the internet, and outside resources are tightly controlled.

Must support a combination of Anthropic subscription models (Claude Code), OpenAI subscription models (Codex),
and open weight models run locally or on Modal Labs or other GPU hosting services. 

# Requirements
- Runs Ubuntu linux. 
- Runs Claude Code from the command line. 
- Runs Codex from the command line. 
- Runs Pi from the command line. 
- Support ollama at the command line.
- Support model routing (must not require the API version of Claude Code or Codex, subscription access).
- Has github client. 
- Has the latest production release of Python. 
- Has the jq tool installed. 
- Mounts one or more specified file system paths from the host.
- Runs a password manager or similar - effectively we need a way to store secrets so that the AI agents can only access secrets the particular container is used for. 
- Can run scheduled tasks or be launched on a scheduled basis from the host machine.
- Has a way to access external MCP servers. Thinking is to have one bridge server / MCP or similar that manages or is the arbiter controlling access from within the sandbox to running MCP servers outside the sandbox.
