from fastapi import FastAPI
from u import router as upload_router
from g import router as get_router

app = FastAPI(title="File API")
app.include_router(upload_router)
app.include_router(get_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {"message": "Welcome!"}


@app.get("/upload", tags=["upload"])
def upload_info():
    return {"message": "Use POST /file to upload files."}
