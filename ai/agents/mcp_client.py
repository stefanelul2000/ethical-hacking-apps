import os
import secrets
import time
from collections import defaultdict, deque
from typing import Dict, Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, AnyHttpUrl
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

load_dotenv()

app = FastAPI(title="FastMCP Client", version="1.0")

default_origins = "https://ai-mcp-client.ciubi.net,https://dev-ai-mcp-client.ciubi.net"
allowed_origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", default_origins).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=True,
)

MCP_SERVERS: Dict[str, Dict[str, Any]] = {}

GROQ_MODEL = os.getenv("GROQ_MODEL")
_llm = ChatGroq(model=GROQ_MODEL, temperature=0)

ADMIN_USER = os.getenv("MCP_ADMIN_USER")
ADMIN_PASS = os.getenv("MCP_ADMIN_PASS")
security = HTTPBasic(auto_error=False)


def enforce_auth(credentials: HTTPBasicCredentials = Depends(security)) -> None:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    if not ADMIN_USER or not ADMIN_PASS:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server authentication not configured",
        )
    valid_user = secrets.compare_digest(credentials.username, ADMIN_USER)
    valid_pass = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (valid_user and valid_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )


ASK_RATE_LIMIT = int(os.getenv("ASK_RATE_LIMIT", "5"))
ASK_RATE_WINDOW = int(os.getenv("ASK_RATE_WINDOW_SECONDS", "60"))
_request_log: Dict[str, deque] = defaultdict(deque)


def enforce_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    window = _request_log[client_ip]
    now = time.time()
    while window and now - window[0] > ASK_RATE_WINDOW:
        window.popleft()
    if len(window) >= ASK_RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many /ask requests, slow down.")
    window.append(now)

class LinkRequest(BaseModel):
    name: str
    url: AnyHttpUrl
    headers: Optional[Dict[str, str]] = None

class LinkResponse(BaseModel):
    name: str
    url: AnyHttpUrl
    tool_count: int

class AskRequest(BaseModel):
    question: str

class AskResponse(BaseModel):
    answer: str

def _build_client() -> MultiServerMCPClient:
    return MultiServerMCPClient(MCP_SERVERS)

async def _load_tools(client: MultiServerMCPClient):
    return await client.get_tools()

@app.post("/link", response_model=LinkResponse)
async def link_server(req: LinkRequest, _: None = Depends(enforce_auth)):
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Server name cannot be empty.")
    if name in MCP_SERVERS:
        raise HTTPException(status_code=409, detail=f"Server '{name}' already exists.")

    MCP_SERVERS[name] = {
        "transport": "streamable_http",
        "url": str(req.url),
        **({"headers": req.headers} if req.headers else {}),
    }

    try:
        tmp_client = MultiServerMCPClient({name: MCP_SERVERS[name]})
        tools = await tmp_client.get_tools()
        tool_count = len(tools)
    except Exception as e:
        MCP_SERVERS.pop(name, None)
        raise HTTPException(status_code=400, detail=f"Failed to connect to '{name}': {e}")

    return LinkResponse(name=name, url=req.url, tool_count=tool_count)

@app.post("/ask", response_model=AskResponse)
async def ask(
    req: AskRequest,
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
):
    authenticated = False
    if credentials:
        try:
            enforce_auth(credentials)
            authenticated = True
        except HTTPException as exc:
            if exc.status_code != status.HTTP_401_UNAUTHORIZED:
                raise

    if not authenticated:
        enforce_rate_limit(request)
    if not MCP_SERVERS:
        raise HTTPException(status_code=400, detail="No MCP servers linked yet. Use /link first.")

    client = _build_client()
    try:
        tools = await _load_tools(client)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load MCP tools: {e}")

    agent = create_react_agent(_llm, tools)

    messages = [
        SystemMessage(content="You are a helpful assistant. Use tools when relevant."),
        HumanMessage(content=req.question),
    ]

    try:
        result = await agent.ainvoke({"messages": messages})
        answer = result["messages"][-1].content
        return AskResponse(answer=answer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent error: {e}")

@app.get("/servers")
async def list_servers(_: None = Depends(enforce_auth)):
    return {"linked_servers": list(MCP_SERVERS.keys())}

@app.get("/health")
async def health():
    return {"ok": True, "linked_servers": list(MCP_SERVERS.keys())}
