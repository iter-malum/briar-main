import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from jose import jwt, JWTError
import httpx
import time
from collections import defaultdict
from shared.config import settings
from shared.logger import setup_logger

logger = setup_logger("api-gateway")
app = FastAPI(title="Briar API Gateway", version="0.1.0")

INTEGRATION_SERVICE_URL = os.getenv("INTEGRATION_SERVICE_URL", "http://integration-service:8000")

# Simple in-memory rate limiter
RATE_LIMIT_PER_MIN = 120
rate_limit_store: defaultdict = defaultdict(list)


def _validate_token(token: str) -> "JSONResponse | None":
    """Returns a JSONResponse error if the token is invalid, None if valid."""
    try:
        jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return None
    except JWTError:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})


async def _gateway_dispatch(request: Request, call_next):
    path = request.url.path

    # ── Public paths — no auth, no rate-limit ─────────────────────────────────
    public_paths = {"/health", "/docs", "/openapi.json", "/redoc"}
    if path in public_paths:
        return await call_next(request)

    # ── CORS preflight — already handled by CORSMiddleware (outermost),
    #    but guard here too for safety ─────────────────────────────────────────
    if request.method == "OPTIONS":
        return Response(status_code=204)

    # ── Rate limiting ─────────────────────────────────────────────────────────
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if now - t < 60]
    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_PER_MIN:
        return JSONResponse(
            status_code=429,
            content={"detail": "Too Many Requests. Try again in a minute."},
        )
    rate_limit_store[client_ip].append(now)

    # ── Optional JWT auth ─────────────────────────────────────────────────────
    # GitLab webhook uses X-Gitlab-Token — skip JWT entirely.
    # For all other routes: if an Authorization header IS present, validate it.
    # If no header → allow through (token is optional).
    is_gitlab_webhook = path.startswith("/api/v1/integrations/gitlab/webhook")
    if not is_gitlab_webhook:
        auth_header = request.headers.get("Authorization", "")
        if auth_header:
            parts = auth_header.split(" ", 1)
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return JSONResponse(status_code=401, content={"detail": "Invalid Authorization header format"})
            error = _validate_token(parts[1])
            if error is not None:
                return error

    # ── Routing ───────────────────────────────────────────────────────────────
    if path.startswith("/api/v1/integrations/"):
        target_url = f"{INTEGRATION_SERVICE_URL}{path}"
    else:
        target_path = path.replace("/api/v1", "", 1) if path.startswith("/api/v1") else path
        target_url = f"{settings.ORCHESTRATOR_URL}{target_path or '/'}"

    if request.url.query:
        target_url += f"?{request.url.query}"

    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding")
    }
    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
            )

        content_type = resp.headers.get("content-type", "application/json")

        # Pass-through binary/text (SARIF, Prometheus metrics, etc.)
        pass_through_types = (
            "application/sarif",
            "text/plain",
            "text/html",
            "application/octet-stream",
        )
        if any(ct in content_type for ct in pass_through_types):
            response_headers = {
                k: v for k, v in resp.headers.items()
                if k.lower() not in ("transfer-encoding", "content-encoding")
            }
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=response_headers,
                media_type=content_type,
            )

        if "application/json" in content_type:
            try:
                return JSONResponse(status_code=resp.status_code, content=resp.json())
            except Exception:
                pass

        return JSONResponse(
            status_code=resp.status_code,
            content={"detail": resp.text or "Upstream error"},
        )

    except httpx.RequestError as exc:
        logger.error(f"Proxy error → {target_url}: {exc}")
        return JSONResponse(status_code=502, content={"detail": f"Upstream unreachable: {exc}"})
    except Exception as exc:
        logger.error(f"Unexpected gateway error: {exc}", exc_info=True)
        return JSONResponse(status_code=500, content={"detail": f"Gateway error: {exc}"})


# ── Middleware registration order matters in Starlette:
#    add_middleware() prepends — the LAST call becomes the OUTERMOST layer.
#    We want: CORSMiddleware (outermost) → gateway logic → routes
#    So: register gateway first, then CORS. ─────────────────────────────────

app.add_middleware(BaseHTTPMiddleware, dispatch=_gateway_dispatch)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # tighten in production (e.g. ["http://localhost:3000"])
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "gateway"}
