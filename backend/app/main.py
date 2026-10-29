import contextvars
import json
import logging
import os
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "request_id": getattr(record, "request_id", "-"),
            },
            ensure_ascii=False,
        )


handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
handler.addFilter(RequestIdFilter())
root_logger = logging.getLogger()
root_logger.handlers.clear()
root_logger.addHandler(handler)
root_logger.setLevel(logging.INFO)
logger = logging.getLogger("api")

app = FastAPI(title="AI-Assisted Reverse Engineering Assistant", version="0.1.0")


class ExactCORSMiddleware(CORSMiddleware):
    """Keep Starlette's safelisted header additions out of this fixed allowlist."""

    def __init__(self, *args, allow_headers, **kwargs):
        super().__init__(*args, allow_headers=allow_headers, **kwargs)
        self.allow_headers = sorted({header.lower() for header in allow_headers})
        self.preflight_headers["Access-Control-Allow-Headers"] = ", ".join(self.allow_headers)


app.add_middleware(
    ExactCORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Last-Event-ID"],
    allow_credentials=False,
)


@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request_id = str(uuid.uuid4())
    token = request_id_var.set(request_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.error("unhandled_request_error")
        response = JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "message": "An internal error occurred.", "request_id": request_id}},
        )
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "request_completed",
        extra={"method": request.method, "path": request.url.path, "status_code": response.status_code,
               "latency_ms": round((time.perf_counter() - started) * 1000, 2)},
    )
    request_id_var.reset(token)
    return response


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    rid = request_id_var.get()
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content={"error": {"code": "HTTP_ERROR", "message": str(exc.detail), "request_id": rid}},
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": {"code": "VALIDATION_ERROR", "message": "Request validation failed.", "request_id": request_id_var.get()}},
    )


@app.get("/health")
async def health():
    return {"status": "ok"}
