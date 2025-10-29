from pathlib import Path
import re
import uuid

BASE_DIR = Path(__file__).parent.resolve()
UPLOAD_DIR = (BASE_DIR / "uploads").resolve()
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
SAFE_CHARS_REGEX = re.compile(r"[^A-Za-z0-9_.-]")

# MITIGATION: Block dangerous executable file extensions to prevent malware uploads
BLOCKED_EXTENSIONS = {".exe", ".bat", ".cmd", ".sh",
                      ".ps1", ".scr", ".com", ".pif", ".vbs", ".js"}

# MITIGATION: Block Windows reserved filenames (CON, PRN, AUX, etc.) to prevent system issues
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                  "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}

# MITIGATION: Limit filename length to prevent buffer overflow attacks
MAX_FILENAME_LENGTH = 255


def s(filename: str) -> str:
    """Sanitize filename to prevent security issues"""
    try:
        safe_name = Path(filename).name
    except Exception:
        safe_name = "x"

    # MITIGATION: Limit filename length to prevent buffer overflow attacks
    if len(safe_name) > MAX_FILENAME_LENGTH:
        name_part = Path(safe_name).stem[:(MAX_FILENAME_LENGTH - 20)]
        ext_part = Path(safe_name).suffix[:20]
        safe_name = name_part + ext_part

    # MITIGATION: Block executable file extensions to prevent malware uploads
    extension = Path(safe_name).suffix.lower()
    if extension in BLOCKED_EXTENSIONS:
        safe_name = Path(safe_name).stem + ".blocked"

    # MITIGATION: Block Windows reserved names (CON, PRN, AUX, etc.) to prevent system issues
    name_upper = Path(safe_name).stem.upper()
    if name_upper in RESERVED_NAMES:
        unique_id = uuid.uuid4().hex[:8]
        safe_name = f"file_{unique_id}{Path(safe_name).suffix}"

    # Remove dangerous characters
    safe_name = SAFE_CHARS_REGEX.sub("_", safe_name)
    safe_name = re.sub(r"^\.+", "", safe_name)

    # Fallback for invalid names
    if not safe_name or safe_name == "." or safe_name == "..":
        safe_name = f"f_{uuid.uuid4().hex[:8]}"

    return safe_name


def d() -> Path:
    """Get uploads directory path"""
    return UPLOAD_DIR


def M() -> int:
    """Get max file size in bytes"""
    return MAX_FILE_SIZE


def v(path: str) -> Path:
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
