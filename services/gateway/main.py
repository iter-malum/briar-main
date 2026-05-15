import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from jose import jwt, JWTError
import httpx
import time
from collections import defaultdict
from shared.config import settings
from shared.logger import setup_logger

logger = setup_logger("api-gateway")
app = FastAPI(title="Briar API Gateway", version="0.1.0")

INTEGRATION_SERVICE_URL = os.getenv("INTEGRATION_SERVICE_URL", "http://integration-service:8000")

# ── CORS — allow browser preflight (OPTIONS) through cleanly ──────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Simple in-memory rate limiter ─────────────────────────────────────────────
RATE_LIMIT_PER_MIN = 120
rate_limit_store: defaultdict = defaultdict(list)


def _check_token(request: Request) -> "JSONResponse | None":
    """
    Validates JWT from the Authorization header.
    Returns a JSONResponse on failure, None on success.
    Never raises — middleware must return responses, not raise exceptions.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return JSONResponse(status_code=401, content={"detail": "Missing Authorization header"})
    try:
        scheme, token = auth_header.split(" ", 1)
        if scheme.lower() != "bearer":
            return JSONResponse(status_code=401, content={"detail": "Invalid auth scheme"})
        jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return None  # OK
    except JWTError:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})
    except ValueError:
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization header format"})


@app.middleware("http")
async def gateway_middleware(request: Request, call_next):
    path = request.url.path

    # ── Skip auth for public / infra paths ────────────────────────────────────
    public_paths = {"/health", "/docs", "/openapi.json", "/redoc"}
    if path in public_paths:
        return await call_next(request)

    # ── CORS preflight is handled by CORSMiddleware before we get here,
    #    but guard just in case it reaches this point ─────────────────────────
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

    # ── Auth — GitLab webhook uses X-Gitlab-Token, not JWT ───────────────────
    is_gitlab_webhook = path.startswith("/api/v1/integrations/gitlab/webhook")
    if not is_gitlab_webhook:
        error_resp = _check_token(request)
        if error_resp is not None:
            return error_resp

    # ── Routing ───────────────────────────────────────────────────────────────
    if path.startswith("/api/v1/integrations/"):
        target_url = f"{INTEGRATION_SERVICE_URL}{path}"
    else:
        # Strip /api/v1 prefix before forwarding to orchestrator
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

        # Pass-through binary/text responses (SARIF downloads, Prometheus, etc.)
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

        # JSON responses
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


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "gateway"}
