from pathlib import Path as P
import re as R
import time as T
import uuid as UUID
_B = P(__file__).parent.resolve()
_U = (_B / "uploads").resolve()
_U.mkdir(exist_ok=True)
_MAX = (1 << 20) * 10
_RX = R.compile(r"[^A-Za-z0-9_.-]")
# MITIGATION: Block dangerous executable file extensions to prevent malware uploads
_BLOCKED_EXT = {".exe", ".bat", ".cmd", ".sh",
                ".ps1", ".scr", ".com", ".pif", ".vbs", ".js"}
# MITIGATION: Block Windows reserved filenames (CON, PRN, AUX, etc.) to prevent system issues
_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                   "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}
# MITIGATION: Limit filename length to prevent buffer overflow attacks
_MAX_FILENAME_LEN = 255


def s(filename: str) -> str:
    """Sanitize filename to prevent security issues"""
    try:
        safe_name = P(filename).name
    except Exception:
        safe_name = "x"

    # MITIGATION: Limit filename length to prevent buffer overflow attacks
    if len(safe_name) > _MAX_FILENAME_LEN:
        name_part = P(safe_name).stem[:(_MAX_FILENAME_LEN - 20)]
        ext_part = P(safe_name).suffix[:20]
        safe_name = name_part + ext_part

    # MITIGATION: Block executable file extensions to prevent malware uploads
    extension = P(safe_name).suffix.lower()
    if extension in _BLOCKED_EXT:
        safe_name = P(safe_name).stem + ".blocked"

    # MITIGATION: Block Windows reserved names (CON, PRN, AUX, etc.) to prevent system issues
    name_upper = P(safe_name).stem.upper()
    if name_upper in _RESERVED_NAMES:
        unique_id = UUID.uuid4().hex[:8]
        safe_name = f"file_{unique_id}{P(safe_name).suffix}"

    # Remove dangerous characters
    safe_name = _RX.sub("_", safe_name)
    safe_name = R.sub(r"^\.+", "", safe_name)

    # Fallback for invalid names
    if not safe_name or safe_name == "." or safe_name == "..":
        safe_name = f"f_{UUID.uuid4().hex[:8]}"

    return safe_name


def d() -> P:
    """Get uploads directory path"""
    return _U


def M() -> int:
    """Get max file size in bytes"""
    return _MAX


def v(path: str) -> P:
    """Validate and resolve file path within uploads directory"""
    # MITIGATION: Sanitize path BEFORE resolve() to prevent path traversal attacks (CWE-22)
    # Remove all path traversal attempts recursively to prevent bypasses like ....//
    clean_path = path
    while "../" in clean_path or "..\\" in clean_path:
        clean_path = clean_path.replace("../", "").replace("..\\", "")

    clean_path = clean_path.lstrip("/").lstrip("\\")

    if not clean_path or clean_path.strip() == "":
        raise ValueError("bad")

    resolved_path = (d() / clean_path).resolve()

    # MITIGATION: Verify resolved path is actually inside uploads directory
    try:
        resolved_path.relative_to(d())
    except Exception:
        raise ValueError("bad")

    return resolved_path


def c(relative_path: str) -> str:
    """Clean relative path by removing traversal patterns"""
    # MITIGATION: Remove path traversal patterns
    clean = relative_path.replace("../", "").replace("..\\", "").lstrip("/\\")
    return clean
