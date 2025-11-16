import base64
import json
import os
from pathlib import Path
from typing import Optional

import aiofiles
from fastapi import Depends, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.routing import APIRouter
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth_utils import authenticate
from storage_utils import (
    cleanup_expired_files,
    get_file_record_by_token,
    resolve_stored_path,
)

router = APIRouter()
security = HTTPBasic()
UPLOAD_TTL_SECONDS = int(os.getenv("UPLOAD_TTL_SECONDS", 7 * 24 * 3600))


def read_file_base64_sync(file_path):
    with open(file_path, "rb") as f:
        return base64.b64encode(f.read()).decode()


async def read_file_base64_async(file_path):
    async with aiofiles.open(file_path, "rb") as f:
        content = await f.read()
        return base64.b64encode(content).decode()


async def get_file(
    token: str = Query(..., alias="path"),
    mode: Optional[str] = Query("base64"),
    credentials: HTTPBasicCredentials = Depends(security),
):
    if not token or not token.strip():
        raise HTTPException(status_code=400, detail="Missing path")

    username = authenticate(credentials)
    cleanup_expired_files(UPLOAD_TTL_SECONDS)

    file_id, record = get_file_record_by_token(token)
    if not record:
        raise HTTPException(status_code=404, detail="File not found")

    if record.get("owner") != username:
        raise HTTPException(status_code=403, detail="Forbidden")

    stored_name = record.get("stored_name")
    if not stored_name:
        raise HTTPException(status_code=404, detail="File not found")

    try:
        target_path = resolve_stored_path(stored_name)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid file reference")
    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    mode = (mode or "base64").lower()

    if mode == "download":
        download_name = record.get("original_name") or target_path.name
        download_name = Path(download_name).name
        return FileResponse(
            path=str(target_path),
            media_type="application/octet-stream",
            filename=download_name
        )

    try:
        base64_content = await read_file_base64_async(str(target_path))
    except Exception:
        base64_content = read_file_base64_sync(str(target_path))

    result = {
        "file_id": file_id,
        "original_name": record.get("original_name"),
        "content": base64_content
    }
    return PlainTextResponse(json.dumps(result), media_type="application/json")

router.get("/file")(get_file)
