import base64
import json
from typing import Optional

import aiofiles
from fastapi import HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.routing import APIRouter

from storage_utils import v as validate_path

router = APIRouter()


def read_file_base64_sync(file_path):
    with open(file_path, "rb") as f:
        return base64.b64encode(f.read()).decode()


async def read_file_base64_async(file_path):
    async with aiofiles.open(file_path, "rb") as f:
        content = await f.read()
        return base64.b64encode(content).decode()


async def get_file(path: str = Query(...), mode: Optional[str] = Query("base64")):
    if not path or not path.strip():
        raise HTTPException(status_code=400, detail="Missing path")

    try:
        target_path = validate_path(path)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path")

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    mode = (mode or "base64").lower()

    if mode == "download":
        return FileResponse(
            path=str(target_path),
            media_type="application/octet-stream",
            filename=target_path.name
        )

    try:
        base64_content = await read_file_base64_async(str(target_path))
    except Exception:
        base64_content = read_file_base64_sync(str(target_path))

    result = {
        "path": target_path.relative_to(target_path.parent).as_posix(),
        "content": base64_content
    }
    return PlainTextResponse(json.dumps(result), media_type="application/json")

router.get("/file")(get_file)
