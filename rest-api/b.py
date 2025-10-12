from pathlib import Path as P
import re as R, time as T
_B = P(__file__).parent.resolve()
_U = (_B / "uploads").resolve()
_U.mkdir(exist_ok=True)
_MAX = (1 << 20) * 10
_RX = R.compile(r"[^A-Za-z0-9_.-]")

def s(x: str) -> str:
    try:
        n = P(x).name
    except Exception:
        n = "x"
    n = _RX.sub("_", n)
    n = R.sub(r"^\.+", "", n)
    if not n:
        n = f"f_{int(T.time())}"
    return n

def d() -> P:
    return _U

def M() -> int:
    return _MAX

def v(p: str) -> P:
    c = (d() / p).resolve()
    try:
        c.relative_to(d())
    except Exception:
        raise ValueError("bad")
    return c

def c(rp: str) -> str:
    return rp.replace("../", "").lstrip("/")
