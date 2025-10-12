from fastapi import FastAPI as A
from u import r as U
from g import r as G
import j as J

app = A(title="x")
app.include_router(U)
app.include_router(G)

try:
    J.u()
except Exception:
    pass

@app.get("/health")
def h(): return {"s":"ok"}
