from fastapi import FastAPI
from downloads import router as downloads_router
from uploads import router as uploads_router

app = FastAPI(title="File API")
app.include_router(uploads_router)
app.include_router(downloads_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {"message": "Welcome!"}


@app.get("/upload", tags=["upload"])
def upload_info():
    return {"message": "Use POST /file to upload files."}
