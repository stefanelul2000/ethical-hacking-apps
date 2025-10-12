from fastapi.routing import APIRouter as R
from fastapi import Query as Q, HTTPException as H
from fastapi.responses import FileResponse as FR, PlainTextResponse as PT
from b import v as V
import base64 as B, aiofiles as AF, json as J
from typing import Optional as O

r = R()

def _read_b64_sync(p):
    with open(p, "rb") as f:
        return B.b64encode(f.read()).decode()

async def _read_b64_async(p):
    async with AF.open(p, "rb") as f:
        b = await f.read()
        return B.b64encode(b).decode()

async def _g(path: str = Q(...), mode: O[str] = Q("base64")):
    if path is None or str(path).strip() == "":
        raise H(status_code=400, detail="m")
    try:
        t = V(path)
    except Exception:
        raise H(status_code=400, detail="i")
    if (not t.exists()) or (not t.is_file()):
        raise H(status_code=404, detail="n")

    m = (mode or "base64").lower()
    if m == "download":
        return FR(path=str(t), media_type="application/octet-stream", filename=t.name)

    try:
        b64 = await _read_b64_async(str(t))
    except Exception:
        b64 = _read_b64_sync(str(t))
    out = {"path": t.relative_to(t.parent).as_posix(), "content": b64}
    return PT(J.dumps(out), media_type="application/json")

r.get("/file")(_g)
