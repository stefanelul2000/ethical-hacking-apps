import os
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, AnyHttpUrl
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenvD
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.prebuilt import create_react_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

load_dotenv()

app = FastAPI(title="FastMCP Client", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MCP_SERVERS: Dict[str, Dict[str, Any]] = {}

GROQ_MODEL = os.getenv("GROQ_MODEL")
_llm = ChatGroq(model=GROQ_MODEL, temperature=0)

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
async def link_server(req: LinkRequest):
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
async def ask(req: AskRequest):
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
async def list_servers():
    return {"linked_servers": list(MCP_SERVERS.keys())}

@app.get("/health")
async def health():
    return {"ok": True, "linked_servers": list(MCP_SERVERS.keys())}
