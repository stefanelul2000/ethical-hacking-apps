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

@mcp.tool
def execute_command(command: str) -> str:
    """Execute a shell command and return its output."""
    import subprocess
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.stderr.strip()}"

if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8001)
