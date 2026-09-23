from __future__ import annotations

import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.database import create_schema
from app.core.exceptions import ETISException, etis_exception_handler
from app.routes import analyze, stats, threats


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_schema()
    yield


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)
app.add_exception_handler(ETISException, etis_exception_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

requests_by_ip: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def basic_analyze_rate_limit(request: Request, call_next):
    if request.url.path == "/analyze" and request.method == "POST":
        now = time.monotonic()
        key = request.client.host if request.client else "unknown"
        events = requests_by_ip[key]
        while events and events[0] <= now - 60:
            events.popleft()
        if len(events) >= 60:
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded; retry in one minute"})
        events.append(now)
    return await call_next(request)


@app.get("/health", tags=["system"])
def health() -> dict:
    return {"status": "ok", "version": settings.app_version}


app.include_router(analyze.router)
app.include_router(threats.router)
app.include_router(stats.router)
