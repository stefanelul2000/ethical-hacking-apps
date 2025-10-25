from fastapi.routing import APIRouter
from fastapi import UploadFile, File, HTTPException
import aiofiles
import time
from b import s as sanitize_filename, d as get_upload_dir, M as get_max_size

router = APIRouter()
CHUNK_SIZE = 65536


async def upload_file(file: UploadFile = File(...)):
    original_name = file.filename or "upload"
    safe_name = sanitize_filename(original_name)
    destination = get_upload_dir() / safe_name

    if destination.exists():
        safe_name = f"{destination.stem}_{int(time.time())}{destination.suffix}"
        destination = get_upload_dir() / safe_name

    written_bytes = 0

    try:
        async with aiofiles.open(destination, "wb") as output:
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
