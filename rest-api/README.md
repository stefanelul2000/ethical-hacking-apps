# REST API

FastAPI-based service that lets you upload vetted files and retrieve them later. The codebase is intentionally compact so you can quickly grasp every moving part.

## Quick start
```bash
uv venv
uv pip install -r requirements.txt
UPLOAD_BASIC_AUTH_USERNAME=uploader \
UPLOAD_BASIC_AUTH_PASSWORD=upload-secret \
UPLOAD_MAX_STORAGE_PER_USER=$((50 * 1024 * 1024)) \
UPLOAD_MAX_STORAGE_GLOBAL=$((500 * 1024 * 1024)) \
UPLOAD_RATE_WINDOW_SECONDS=60 \
UPLOAD_RATE_MAX_REQUESTS=30 \
UPLOAD_TTL_SECONDS=$((7 * 24 * 3600)) \
uvicorn main:app --reload
```

- The HTTP Basic credentials default to the values above; override them in your shell or `.env` before launching the server.
- Uploads are saved inside `uploads/` (created automatically on first run) with metadata stored in `uploads/metadata.json`.
- Tweak per-user/global quotas, rate limits, and TTL retention via the environment variables shown in the command above.

## File guide

- `main.py` (formerly `a.py`) - FastAPI entrypoint. Builds the application object, wires the upload and download routers, and exposes lightweight health/root helpers so orchestration platforms can probe the service.
- `uploads.py` (formerly `u.py`) - Implements `POST /file`. The router enforces HTTP Basic auth, rejects empty bodies, validates filenames via `storage_utils.py`, enforces an allow-list of extensions/MIME types (including signature sniffing), streams data to disk under randomized UUID filenames, rate-limits each identity, enforces per-user/global storage quotas, and records metadata with opaque download tokens.
- `downloads.py` (formerly `g.py`) - Implements `GET /file`. Requires HTTP Basic auth, accepts an opaque download token (legacy `path` query parameter), validates ownership against metadata, performs TTL cleanup, and responds with Base64 content (default) or a binary download when `mode=download`.
- `storage_utils.py` (formerly `b.py`) - Shared helpers for anything touching the filesystem. Responsibilities include computing the uploads directory, sanitizing filenames, limiting file size, persisting metadata (owner/original name/size/token/timestamp), enforcing TTL cleanup, and defending against path traversal (CWE-22) before resolving a requested file.
- `requirements.txt` / `pyproject.toml` / `uv.lock` - Dependency definitions. Use `pyproject.toml` for editable metadata, `requirements.txt` for reproducible installs via `uv pip install -r`, and `uv.lock` if you need fully pinned builds.
- `.python-version` - Indicates the minimum Python version (`>=3.10`) for local tooling such as `pyenv` or `uv`.
- `TEST/` - Scratchpad for manual experiments. Nothing inside this folder is imported by the API, so feel free to iterate there safely.

**Legacy-to-current filename reference**
- `a.py` -> `main.py`
- `u.py` -> `uploads.py`
- `g.py` -> `downloads.py`
- `b.py` -> `storage_utils.py`

## Upload security recap

1. **Auth required** - `POST /file` and `GET /file` both require HTTP Basic auth. Configure `UPLOAD_BASIC_AUTH_USERNAME` and `UPLOAD_BASIC_AUTH_PASSWORD` (rotate frequently) without touching the codebase.
2. **Opaque tokens** - Successful uploads return `file_id` and `download_token`. Download tokens, together with auth, are required to retrieve content so filenames never leak.
3. **File type verification** - Extensions, declared MIME types, and detected signatures must all line up with the allow-list (`.txt`, `.csv`, `.json`, `.pdf`, `.png`, `.jpg`, `.jpeg`, `.gif`).
4. **Resource governance** - Files larger than 10 MB are rejected mid-stream; per-user/global quotas, configurable rate limits, and TTL cleanup protect disk and bandwidth.
5. **Path hygiene** - Every filename is sanitized and written under randomized UUIDs inside `uploads/`, and downloads validate storage paths before touching the filesystem.
