# AI Workspace

This module groups the experimental AI services used for the ethical-hacking lab. It currently contains:

1. `agents/` – the MCP client/server demo where a Groq-powered LangChain agent (`agents/mcp_client.py`) links to FastMCP tool servers (`agents/mcp_server.py`). Supports Basic Auth, CORS restrictions, anonymous rate limiting, and optional safe command execution.
2. `iris/` – a FastAPI microservice (`iris/iris.py`) that lets you append Iris dataset samples, retrain a RandomForest, and request predictions. Data and models persist under `iris/data` and `iris/model`.
3. `library/` – C/ctypes utilities for low-level ML primitives (`library/mlops.c`) plus a Python harness (`library/demo.py`) that exercises matmul, ReLU, softmax, and raw weight serialization.

Each submodule ships its own README and entry point. Install dependencies from `ai/pyproject.toml` (or `requirements.txt`) and run the individual services as needed. Let us know if you add new AI experiments so this overview can stay current.
