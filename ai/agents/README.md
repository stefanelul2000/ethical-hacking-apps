# MCP Agents

This directory contains two cooperating FastAPI services that demonstrate Model Context Protocol (MCP) tooling:

1. `mcp_server.py` — demo FastMCP server exposing:
   - `ping`, `find_best_teacher`, `add`.
   - `execute_command`, guarded by an allowlist (`ls`, `pwd`, `whoami`) and disabled unless `ENABLE_MCP_COMMAND_TOOL=1`.
2. `mcp_client.py` — Groq-powered LangChain gateway with:
   - `POST /link`: register MCP servers (Basic Auth required).
   - `POST /ask`: natural-language queries; anonymous callers are rate limited (default 5/min), authenticated callers bypass the cap.
   - `GET /servers`: list linked servers (Basic Auth).
   - `GET /health`: unauthenticated liveness check.

## Local setup

```bash
cd ai
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export GROQ_API_KEY=...
export GROQ_MODEL=llama-3.1-8b-instruct
export MCP_ADMIN_USER=admin
export MCP_ADMIN_PASS=changeme
```

### Run the MCP server

```bash
ENABLE_MCP_COMMAND_TOOL=0 python agents/mcp_server.py
```

### Run the MCP client

```bash
uvicorn agents.mcp_client:app --host 0.0.0.0 --port 8000
```

### Link & ask

1. `POST /link` (Basic Auth) with `{"name":"demo","url":"http://127.0.0.1:8001/mcp"}`.
2. `POST /ask` with `{"question":"Ping the server"}` to trigger the MCP tools.
