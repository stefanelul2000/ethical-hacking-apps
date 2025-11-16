import os
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional
import threading

import aiofiles
from fastapi import Depends, File, HTTPException, UploadFile, status
from fastapi.routing import APIRouter
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth_utils import authenticate
from storage_utils import (
    M as get_max_size,
    cleanup_expired_files,
    d as get_upload_dir,
    get_usage_bytes,
    register_file_record,
    s as sanitize_filename,
)

router = APIRouter()
CHUNK_SIZE = 65536
security = HTTPBasic()

MAX_USER_STORAGE = int(os.getenv("UPLOAD_MAX_STORAGE_PER_USER", 50 * 1024 * 1024))
MAX_GLOBAL_STORAGE = int(os.getenv("UPLOAD_MAX_STORAGE_GLOBAL", 500 * 1024 * 1024))
UPLOAD_RATE_WINDOW_SECONDS = int(os.getenv("UPLOAD_RATE_WINDOW_SECONDS", 60))
UPLOAD_RATE_MAX_REQUESTS = int(os.getenv("UPLOAD_RATE_MAX_REQUESTS", 30))
UPLOAD_TTL_SECONDS = int(os.getenv("UPLOAD_TTL_SECONDS", 7 * 24 * 3600))

_RATE_LIMIT_STATE: dict[str, deque] = defaultdict(deque)
_RATE_LIMIT_LOCK = threading.Lock()

ALLOWED_EXTENSIONS = {
    ".txt",
    ".csv",
    ".json",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
}

ALLOWED_MIME_TYPES = {
    "text/plain",
    "text/csv",
    "application/json",
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
}

FILE_SIGNATURES = (
    ("application/pdf", b"%PDF-"),
    ("image/png", b"\x89PNG\r\n\x1a\n"),
    ("image/jpeg", b"\xFF\xD8\xFF"),
    ("image/gif", b"GIF87a"),
    ("image/gif", b"GIF89a"),
)

def _normalize_content_type(content_type: Optional[str]) -> Optional[str]:
    if not content_type:
        return None
    normalized = content_type.split(";")[0].strip().lower()
    return normalized or None


def _detect_mime(first_chunk: bytes) -> Optional[str]:
    for mime, signature in FILE_SIGNATURES:
        if first_chunk.startswith(signature):
            return mime
    return None


def _enforce_file_type(
    filename: str, declared_content_type: Optional[str], first_chunk: bytes
) -> None:
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported file extension",
        )

    normalized_declared = _normalize_content_type(declared_content_type)
    if normalized_declared and normalized_declared not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported content type",
        )

    detected_mime = _detect_mime(first_chunk)
    if detected_mime and detected_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="File content type is not allowed",
        )

    if (
        normalized_declared
        and detected_mime
        and normalized_declared != detected_mime
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Declared content type does not match file contents",
        )


def _enforce_rate_limit(username: str) -> None:
    if UPLOAD_RATE_MAX_REQUESTS <= 0:
        return
    now = time.time()
    with _RATE_LIMIT_LOCK:
        bucket = _RATE_LIMIT_STATE[username]
        while bucket and now - bucket[0] > UPLOAD_RATE_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= UPLOAD_RATE_MAX_REQUESTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Upload rate limit exceeded",
            )
        bucket.append(now)


def _enforce_storage_quota(
    *,
    username: str,
    user_usage_start: int,
    global_usage_start: int,
    bytes_written: int,
) -> None:
    if MAX_USER_STORAGE > 0 and user_usage_start + bytes_written > MAX_USER_STORAGE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User storage quota exceeded",
        )
    if MAX_GLOBAL_STORAGE > 0 and global_usage_start + bytes_written > MAX_GLOBAL_STORAGE:
        raise HTTPException(
            status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
            detail="Global storage quota exceeded",
        )


async def upload_file(
    credentials: HTTPBasicCredentials = Depends(security),
    file: UploadFile = File(...),
):
    username = authenticate(credentials)

    cleanup_expired_files(UPLOAD_TTL_SECONDS)
    _enforce_rate_limit(username)

    original_name = file.filename or "upload"
    safe_name = sanitize_filename(original_name)
    extension = Path(safe_name).suffix.lower() or ".bin"
    file_id = uuid.uuid4().hex
    stored_name = f"{file_id}{extension}"
    destination = get_upload_dir() / stored_name

    first_chunk = await file.read(CHUNK_SIZE)
    if not first_chunk:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file uploads are not allowed",
        )

    _enforce_file_type(safe_name, file.content_type, first_chunk)

    written_bytes = len(first_chunk)
    user_usage_start = get_usage_bytes(owner=username)
    global_usage_start = get_usage_bytes()

    _enforce_storage_quota(
        username=username,
        user_usage_start=user_usage_start,
        global_usage_start=global_usage_start,
        bytes_written=written_bytes,
    )

    try:
        async with aiofiles.open(destination, "wb") as output:
            if written_bytes > get_max_size():
                raise HTTPException(status_code=413, detail="File too large")

            await output.write(first_chunk)

            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break

                written_bytes += len(chunk)

                if written_bytes > get_max_size():
                    await output.close()
                    destination.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413, detail="File too large")

                _enforce_storage_quota(
                    username=username,
                    user_usage_start=user_usage_start,
                    global_usage_start=global_usage_start,
                    bytes_written=written_bytes,
                )

                await output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

    download_token = uuid.uuid4().hex
    register_file_record(
        file_id=file_id,
        stored_name=stored_name,
        owner=username,
        original_name=original_name,
        size=written_bytes,
        download_token=download_token,
    )

    return {
        "result": "ok",
        "file_id": file_id,
        "download_token": download_token,
        "size": written_bytes
    }

router.post("/file")(upload_file)
