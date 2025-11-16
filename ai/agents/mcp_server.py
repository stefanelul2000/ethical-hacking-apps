import os

from fastmcp import FastMCP

mcp = FastMCP("demo-mcp-server")

@mcp.tool
def ping(message: str = "pong") -> str:
    """A dummy tool that echos a message back."""
    return f"[MCP] {message}"

@mcp.tool
def find_best_teacher(subject:str) -> str:
    """Return the name of the best teacher for a given subject."""
    return f"The best teacher for {subject} is Robert duuh."

@mcp.tool
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b

SAFE_COMMANDS = {"ls", "pwd", "whoami"}
ENABLE_COMMAND_TOOL = os.getenv("ENABLE_MCP_COMMAND_TOOL", "").lower() in (
    "1",
    "true",
    "yes",
)


@mcp.tool
def execute_command(command: str) -> str:
    """
    Execute a whitelisted shell command and return its output.
    Arbitrary commands are denied to prevent remote control.
    """
    if not ENABLE_COMMAND_TOOL:
        return "Command execution disabled by server configuration."

    import shlex
    import subprocess

    parts = shlex.split(command)
    if not parts or parts[0] not in SAFE_COMMANDS:
        return "Command denied: not in allowlist."

    try:
        result = subprocess.run(parts, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.stderr.strip()}"

if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8001)
