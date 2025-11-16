import os
import secrets
from fastapi import HTTPException, status
from fastapi.security import HTTPBasicCredentials

UPLOAD_BASIC_USER = os.getenv("UPLOAD_BASIC_AUTH_USERNAME", "uploader")
UPLOAD_BASIC_PASSWORD = os.getenv("UPLOAD_BASIC_AUTH_PASSWORD", "upload-secret")


def authenticate(credentials: HTTPBasicCredentials) -> str:
    """Validate HTTP Basic credentials and return the username."""
    username_ok = secrets.compare_digest(credentials.username, UPLOAD_BASIC_USER)
    password_ok = secrets.compare_digest(credentials.password, UPLOAD_BASIC_PASSWORD)
    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username
