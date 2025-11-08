import os
import secrets
import time
from pathlib import Path
from typing import Optional

import aiofiles
from fastapi import Depends, File, HTTPException, UploadFile, status
from fastapi.routing import APIRouter
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from storage_utils import M as get_max_size
from storage_utils import d as get_upload_dir
from storage_utils import s as sanitize_filename

router = APIRouter()
CHUNK_SIZE = 65536
security = HTTPBasic()

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

UPLOAD_BASIC_USER = os.getenv("UPLOAD_BASIC_AUTH_USERNAME", "uploader")
UPLOAD_BASIC_PASSWORD = os.getenv("UPLOAD_BASIC_AUTH_PASSWORD", "upload-secret")


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


def _verify_basic_auth(credentials: HTTPBasicCredentials) -> None:
    username_ok = secrets.compare_digest(credentials.username, UPLOAD_BASIC_USER)
    password_ok = secrets.compare_digest(credentials.password, UPLOAD_BASIC_PASSWORD)
    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


async def upload_file(
    credentials: HTTPBasicCredentials = Depends(security),
    file: UploadFile = File(...),
):
    _verify_basic_auth(credentials)

    original_name = file.filename or "upload"
    safe_name = sanitize_filename(original_name)
    destination = get_upload_dir() / safe_name

    if destination.exists():
        safe_name = f"{destination.stem}_{int(time.time())}{destination.suffix}"
        destination = get_upload_dir() / safe_name

    first_chunk = await file.read(CHUNK_SIZE)
    if not first_chunk:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file uploads are not allowed",
        )

    _enforce_file_type(original_name, file.content_type, first_chunk)

    written_bytes = len(first_chunk)

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

                await output.write(chunk)
    finally:
        await file.close()

    return {
        "result": "ok",
        "path": destination.name,
        "size": written_bytes
    }

router.post("/file")(upload_file)
