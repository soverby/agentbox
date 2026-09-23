"""Stub MCP upstream for the P6 smoke (host process on 127.0.0.1).

Usage: python p6_stub.py <http|sse> <port> <calls-log>
Env STUB_BEARER: the only accepted bearer (FastMCP StaticTokenVerifier), so
a successful call proves the gateway sent it. Each tool call appends
"<transport> <tool>" to the calls log (never the bearer), plus
" AGENT-HEADER-FORWARDED" when the agent's X-Agentbox-Probe header arrived.
"""

import os
import sys

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware

transport, port, log = sys.argv[1], int(sys.argv[2]), sys.argv[3]
auth = StaticTokenVerifier(tokens={os.environ["STUB_BEARER"]: {"client_id": "gw", "scopes": []}})


class Record(Middleware):
    async def on_call_tool(self, context, call_next):
        h = get_http_headers(include_all=True)
        leak = " AGENT-HEADER-FORWARDED" if "x-agentbox-probe" in h else ""
        with open(log, "a") as f:
            f.write(f"{transport} {context.message.name}{leak}\n")
        return await call_next(context)


mcp = FastMCP(f"stub-{transport}", auth=auth, middleware=[Record()])


@mcp.tool
def allowed_a(x: int) -> str:
    return f"A{x + 1}"


@mcp.tool
def allowed_b(text: str) -> str:
    return f"B:{text[::-1]}"


@mcp.tool
def forbidden() -> str:
    return "FORBIDDEN-RAN"


@mcp.resource("stub://secret")
def secret_resource() -> str:
    return "RESOURCE"


if __name__ == "__main__":
    path = "/sse" if transport == "sse" else "/mcp"
    mcp.run(transport=transport, host="127.0.0.1", port=port, path=path, show_banner=False)
