# REST API

FastAPI-based service that lets you upload vetted files and retrieve them later. The codebase is intentionally compact so you can quickly grasp every moving part.

## Quick start
```bash
uv venv
uv pip install -r requirements.txt
UPLOAD_BASIC_AUTH_USERNAME=uploader \
UPLOAD_BASIC_AUTH_PASSWORD=upload-secret \
uvicorn main:app --reload
```

- The HTTP Basic credentials default to the values above; override them in your shell or `.env` before launching the server.
- Uploads are saved inside `uploads/` (created automatically on first run).

## File guide

- `main.py` (formerly `a.py`) - FastAPI entrypoint. Builds the application object, wires the upload and download routers, and exposes lightweight health/root helpers so orchestration platforms can probe the service.
- `uploads.py` (formerly `u.py`) - Implements `POST /file`. The router enforces HTTP Basic auth, rejects empty bodies, validates filenames via `storage_utils.py`, enforces an allow-list of extensions/MIME types (including lightweight signature sniffing), and streams data to disk while checking the max file size.
- `downloads.py` (formerly `g.py`) - Implements `GET /file`. Accepts a sanitized relative path, verifies the target lives under the uploads directory, and either responds with a Base64 payload (default) or a binary download when `mode=download`.
- `storage_utils.py` (formerly `b.py`) - Shared helpers for anything touching the filesystem. Responsibilities include computing the uploads directory, sanitizing filenames, limiting file size, and defending against path traversal (CWE-22) before resolving a requested file.
- `requirements.txt` / `pyproject.toml` / `uv.lock` - Dependency definitions. Use `pyproject.toml` for editable metadata, `requirements.txt` for reproducible installs via `uv pip install -r`, and `uv.lock` if you need fully pinned builds.
- `.python-version` - Indicates the minimum Python version (`>=3.10`) for local tooling such as `pyenv` or `uv`.
- `TEST/` - Scratchpad for manual experiments. Nothing inside this folder is imported by the API, so feel free to iterate there safely.

**Legacy-to-current filename reference**
- `a.py` -> `main.py`
- `u.py` -> `uploads.py`
- `g.py` -> `downloads.py`
- `b.py` -> `storage_utils.py`

## Upload security recap

1. **Auth required** - `POST /file` uses HTTP Basic auth. Configure `UPLOAD_BASIC_AUTH_USERNAME` and `UPLOAD_BASIC_AUTH_PASSWORD` to rotate credentials without code changes.
2. **File type verification** - Extensions, declared MIME types, and detected signatures must all line up with the allow-list (`.txt`, `.csv`, `.json`, `.pdf`, `.png`, `.jpg`, `.jpeg`, `.gif`).
3. **Size limits** - Files larger than 10 MB are rejected mid-stream to avoid resource exhaustion.
4. **Path hygiene** - Every filename is sanitized and stored under `uploads/`, and downloads validate the path before reading the disk.
