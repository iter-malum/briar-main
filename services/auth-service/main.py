import sys
import os
import ast
import json
import re
import textwrap
import logging
import asyncio
from dataclasses import dataclass, field as dc_field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, Field, HttpUrl
from pydantic_settings import BaseSettings
from playwright.async_api import async_playwright, Browser, Playwright, Page
import redis.asyncio as redis

# --- Конфигурация ---
class Settings(BaseSettings):
    REDIS_HOST: str = "redis"
    REDIS_PORT: str = "6379"
    PLAYWRIGHT_TIMEOUT: int = 30000 # ms
    SESSION_TTL_SECONDS: int = 7200 # 2 hours
    
    @property
    def redis_url(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"

settings = Settings()
logger = logging.getLogger("auth-service")

# In-memory store for active interactive recording sessions
@dataclass
class ActiveRecording:
    session_id: str
    target_url: str
    codegen_proc: Any   # asyncio subprocess (playwright codegen)
    script_path: str    # path to generated .py file
    storage_path: str   # path to --save-storage JSON

_active_recordings: dict = {}
_recording_lock = asyncio.Lock()

app = FastAPI(title="Briar Auth Service", version="0.1.0")
redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)

# --- Модели данных (Pydantic) ---

class Credentials(BaseModel):
    username: str
    password: str
    extra_fields: Dict[str, str] = {} # Для кастомных полей формы

class AuthSessionCreate(BaseModel):
    target_url: HttpUrl
    auth_type: str = Field("custom_script", pattern="^(form|oauth2|custom_script)$")
    credentials: Optional[Credentials] = None
    script: Optional[str] = None # JS/Python скрипт для выполнения
    timeout: Optional[int] = 30000

class AuthSessionResponse(BaseModel):
    session_id: UUID
    expires_at: datetime
    status: str

class AuthSessionRetrieve(BaseModel):
    cookies: List[Dict[str, Any]]
    headers: Dict[str, str]
    storage_state: str # JSON storage state
    status: str
    error: Optional[str] = None

class RecordStartRequest(BaseModel):
    target_url: HttpUrl

class RecordStartResponse(BaseModel):
    recording_id: str
    vnc_url: str          # Full URL to noVNC: http://host:6080/vnc.html?...
    status: str = "recording"

class RecordSaveResponse(BaseModel):
    session_id: UUID
    expires_at: datetime
    status: str
    recorded_script: Optional[str] = None

# --- Валидация скриптов (Безопасность) ---

# FILE: services/auth-service/main.py — ЗАМЕНИТЕ ЭТИ ДВЕ ФУНКЦИИ

# --- Валидация скриптов (Безопасность) ---

ALLOWED_API_CALLS = {
    "fill", "click", "type", "press", "check", "uncheck", "select_option",
    "wait_for_url", "wait_for_selector", "wait_for_load_state", "wait_for_timeout",
    "goto", "evaluate", "screenshot", "locator", "get_by_text", "get_by_role",
    "is_visible", "is_enabled", "text_content", "inner_text", "content_frame",
    "new_page", "new_context", "close", "set_extra_http_headers"
}

FORBIDDEN_CALLS = {
    "__import__", "eval", "exec", "compile", "open", "input",
    "system", "popen", "subprocess", "os.system", "os.popen",
    "__class__", "__bases__", "__subclasses__", "__mro__", "breakpoint"
}

def validate_script(script_code: str):
    """Проверяет, что скрипт содержит только разрешённые вызовы Playwright."""
    if not script_code or not script_code.strip():
        raise ValueError("Script cannot be empty")
    
    # ✅ FIX: Оборачиваем скрипт в async def для корректного парсинга await
    wrapped_code = f"async def _user_script(page):\n    {script_code.strip()}"
    
    try:
        tree = ast.parse(wrapped_code, mode='exec')
    except SyntaxError as e:
        raise ValueError(f"Script syntax error: {e}")

    for node in ast.walk(tree):
        # Пропускаем все безопасные узлы
        if isinstance(node, (
            ast.Expression, ast.Module, ast.Expr, ast.Call, ast.Attribute,
            ast.Name, ast.Constant, ast.keyword, ast.Str, ast.Num, ast.Bytes,
            ast.List, ast.Dict, ast.Tuple, ast.Assign, ast.Await,
            ast.Load, ast.Store, ast.Del,
            ast.Subscript, ast.Index, ast.Slice,
            ast.UnaryOp, ast.BinOp, ast.BoolOp,
            ast.Compare, ast.IfExp,
            ast.FormattedValue, ast.JoinedStr,
            ast.FunctionDef, ast.AsyncFunctionDef, ast.arguments, ast.arg,
            ast.Return, ast.Pass, ast.Break, ast.Continue
        )):
            continue
        
        # Проверяем вызовы функций
        if isinstance(node, ast.Call):
            method_name = None
            if isinstance(node.func, ast.Attribute):
                method_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                method_name = node.func.id
            
            if method_name:
                # Блокируем опасные вызовы
                if method_name in FORBIDDEN_CALLS or method_name.startswith("__"):
                    raise ValueError(f"Forbidden method call: {method_name}")
                # Проверяем whitelist (с гибким матчингом)
                if method_name not in ALLOWED_API_CALLS:
                    allowed_patterns = ['wait', 'fill', 'click', 'goto', 'get', 'locator', 
                                       'evaluate', 'press', 'check', 'select', 'screenshot',
                                       'page', 'context', 'browser']
                    if not any(p in method_name.lower() for p in allowed_patterns):
                        raise ValueError(f"Method '{method_name}' is not allowed. Allowed patterns: {allowed_patterns}")
    
    return True


# --- Playwright Runner ---

async def run_auth_script(playwright: Playwright, payload: AuthSessionCreate):
    """Запускает браузер, выполняет скрипт, возвращает сессию."""
    
    # Подготовка скрипта
    final_script = payload.script
    if not final_script and payload.auth_type == "form" and payload.credentials:
        creds = payload.credentials
        final_script = f"""
await page.goto('{payload.target_url}')
await page.fill('input[name="username"]', '{creds.username}')
await page.fill('input[name="password"]', '{creds.password}')
await page.click('button[type="submit"]')
await page.wait_for_load_state('networkidle')
"""
    
    if not final_script:
        raise ValueError("No script provided and cannot auto-generate one.")

    # Валидация
    validate_script(final_script)

    # ✅ FIX: Оборачиваем скрипт в async def для выполнения
    indented_script = "\n    ".join(final_script.strip().split("\n"))
    wrapper_code = f"async def _run_auth_flow(page):\n    {indented_script}"
    
    browser: Optional[Browser] = None
    try:
        browser = await playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox']
        )
        context = await browser.new_context()
        page = await context.new_page()
        
        # Создаём локальный скоуп с объектом page
        local_vars = {"page": page}
        
        # Компиляция и выполнение обёрнутого кода
        compiled_code = compile(wrapper_code, "<script>", "exec")
        exec(compiled_code, {}, local_vars)
        
        # Вызов функции
        await local_vars["_run_auth_flow"](page)
        
        # --- Сбор результатов ---
        cookies = await context.cookies()
        headers = {}
        storage_state = await context.storage_state()
        
        # Поиск токена авторизации
        auth_token = None
        for c in cookies:
            if any(kw in c["name"].lower() for kw in ["token", "jwt", "sid", "session", "auth"]):
                auth_token = c["value"]
                break
        
        if not auth_token:
            try:
                local_storage = await page.evaluate("() => JSON.stringify(window.localStorage)")
                ls_data = json.loads(local_storage)
                for k, v in ls_data.items():
                    if any(kw in k.lower() for kw in ["token", "jwt", "access", "auth"]):
                        auth_token = v
                        break
            except:
                pass

        if auth_token:
            if auth_token.count(".") == 2 and len(auth_token.split(".")) == 3:
                headers["Authorization"] = f"Bearer {auth_token}"
            else:
                headers["Cookie"] = f"session={auth_token}"

        return {
            "cookies": cookies,
            "headers": headers,
            "storage_state": json.dumps(storage_state),
            "status": "success"
        }

    except Exception as e:
        logger.error(f"Auth execution failed: {str(e)}", exc_info=True)
        return {
            "cookies": [],
            "headers": {},
            "storage_state": "",
            "status": "failed",
            "error": str(e)
        }
    finally:
        if browser:
            await browser.close()

# --- API Endpoints ---

@app.on_event("startup")
async def startup():
    # Проверка подключения к Redis
    try:
        await redis_client.ping()
        logger.info("Connected to Redis")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")

@app.post("/api/v1/auth/sessions", response_model=AuthSessionResponse)
async def create_session(payload: AuthSessionCreate):
    async with async_playwright() as pw:
        result = await run_auth_script(pw, payload)

    if result["status"] == "failed":
        raise HTTPException(status_code=400, detail=result["error"])

    session_id = uuid4()
    expires_at = datetime.utcnow() + timedelta(seconds=settings.SESSION_TTL_SECONDS)

    # Сохранение в Redis
    await redis_client.setex(
        f"auth:session:{session_id}",
        settings.SESSION_TTL_SECONDS,
        json.dumps({
            "cookies": result["cookies"],
            "headers": result["headers"],
            "storage_state": result["storage_state"],
            "status": "ready"
        })
    )

    # Store metadata for listing
    await redis_client.setex(
        f"auth:meta:{session_id}",
        settings.SESSION_TTL_SECONDS,
        json.dumps({
            "target_url": str(payload.target_url),
            "auth_type": payload.auth_type,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat(),
        })
    )

    return AuthSessionResponse(
        session_id=session_id,
        expires_at=expires_at,
        status="ready"
    )

@app.get("/api/v1/auth/sessions")
async def list_sessions():
    """List all sessions by scanning auth:meta:* keys in Redis."""
    keys = []
    async for key in redis_client.scan_iter("auth:meta:*"):
        keys.append(key)

    sessions = []
    for key in keys:
        raw = await redis_client.get(key)
        if raw:
            meta = json.loads(raw)
            session_id = key.replace("auth:meta:", "")
            sessions.append({
                "session_id": session_id,
                **meta,
                "status": "ready",
            })
    return sessions

@app.post("/api/v1/auth/sessions/from-curl", response_model=AuthSessionResponse)
async def create_session_from_curl(body: Dict[str, Any]):
    """Parse a cURL command and create a session without Playwright."""
    curl_command = body.get("curl_command", "")
    target_url = body.get("target_url", "")

    if not curl_command or not target_url:
        raise HTTPException(status_code=422, detail="curl_command and target_url are required")

    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}

    # Parse -H "Header: value" or --header "Header: value"
    for m in re.finditer(r'(?:-H|--header)\s+["\']([^"\']+)["\']', curl_command):
        header_line = m.group(1)
        idx = header_line.find(":")
        if idx > 0:
            k = header_line[:idx].strip()
            v = header_line[idx + 1:].strip()
            if k.lower() == "cookie":
                # Parse cookie header into cookies dict
                for part in v.split(";"):
                    part = part.strip()
                    eq = part.find("=")
                    if eq > 0:
                        cookies[part[:eq].strip()] = part[eq + 1:].strip()
            else:
                headers[k] = v

    # Parse -b "cookie=val" or --cookie "..."
    for m in re.finditer(r'(?:-b|--cookie)\s+["\']([^"\']+)["\']', curl_command):
        cookie_str = m.group(1)
        for part in cookie_str.split(";"):
            part = part.strip()
            eq = part.find("=")
            if eq > 0:
                cookies[part[:eq].strip()] = part[eq + 1:].strip()

    # Parse -u "user:pass" → Basic auth header
    m = re.search(r'(?:-u|--user)\s+["\']([^"\']+)["\']', curl_command)
    if m:
        import base64
        credentials_b64 = base64.b64encode(m.group(1).encode()).decode()
        headers["Authorization"] = f"Basic {credentials_b64}"

    session_id = uuid4()
    expires_at = datetime.utcnow() + timedelta(seconds=settings.SESSION_TTL_SECONDS)

    # Build cookie list compatible with AuthSessionRetrieve
    cookie_list = [{"name": k, "value": v} for k, v in cookies.items()]

    await redis_client.setex(
        f"auth:session:{session_id}",
        settings.SESSION_TTL_SECONDS,
        json.dumps({
            "cookies": cookie_list,
            "headers": headers,
            "storage_state": "{}",
            "status": "ready"
        })
    )

    await redis_client.setex(
        f"auth:meta:{session_id}",
        settings.SESSION_TTL_SECONDS,
        json.dumps({
            "target_url": target_url,
            "auth_type": "curl",
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat(),
        })
    )

    return AuthSessionResponse(
        session_id=session_id,
        expires_at=expires_at,
        status="ready"
    )

@app.post("/api/v1/auth/sessions/{session_id}/test")
async def test_session(session_id: UUID):
    """Make a GET request to the session's target_url using stored headers/cookies."""
    session_raw = await redis_client.get(f"auth:session:{session_id}")
    meta_raw = await redis_client.get(f"auth:meta:{session_id}")

    if not session_raw or not meta_raw:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    session_data = json.loads(session_raw)
    meta = json.loads(meta_raw)
    target_url = meta.get("target_url", "")

    request_headers = dict(session_data.get("headers", {}))
    # Build cookie header from stored cookies
    cookie_list = session_data.get("cookies", [])
    if cookie_list:
        cookie_str = "; ".join(
            f"{c['name']}={c['value']}" for c in cookie_list if "name" in c and "value" in c
        )
        if cookie_str:
            request_headers["Cookie"] = cookie_str

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(target_url, headers=request_headers)
        alive = resp.status_code < 400
        return {"alive": alive, "status_code": resp.status_code}
    except Exception as e:
        return {"alive": False, "status_code": 0}

@app.delete("/api/v1/auth/sessions/{session_id}")
async def delete_session(session_id: UUID):
    """Delete a session from Redis."""
    await redis_client.delete(f"auth:session:{session_id}")
    await redis_client.delete(f"auth:meta:{session_id}")
    return {"deleted": True}

@app.post("/api/v1/auth/sessions/record/start", response_model=RecordStartResponse)
async def start_recording(payload: RecordStartRequest):
    """
    Launch `playwright codegen` on the virtual Xvfb display.
    User sees the browser + Playwright Inspector (live code generation) via noVNC.
    Call /record/{id}/save when done to capture session + script.
    """
    async with _recording_lock:
        if _active_recordings:
            raise HTTPException(
                status_code=409,
                detail="Another recording session is already active. Save or cancel it first.",
            )

        recording_id = str(uuid4())
        script_path  = f"/tmp/briar_script_{recording_id}.py"
        storage_path = f"/tmp/briar_storage_{recording_id}.json"

        env = {**os.environ, "DISPLAY": ":1"}

        try:
            proc = await asyncio.create_subprocess_exec(
                "python", "-m", "playwright", "codegen",
                "--browser", "chromium",
                "--output",       script_path,
                "--save-storage", storage_path,
                str(payload.target_url),
                env=env,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to start codegen: {e}")

        _active_recordings[recording_id] = ActiveRecording(
            session_id=recording_id,
            target_url=str(payload.target_url),
            codegen_proc=proc,
            script_path=script_path,
            storage_path=storage_path,
        )

        logger.info(f"Codegen recording started: {recording_id} → {payload.target_url}")
        vnc_url = "http://HOST:6080/vnc.html?autoconnect=true&resize=scale&quality=6&compression=2"
        return RecordStartResponse(recording_id=recording_id, vnc_url=vnc_url, status="recording")


@app.post("/api/v1/auth/sessions/record/{recording_id}/save", response_model=RecordSaveResponse)
async def save_recording(recording_id: str):
    """
    Terminate codegen → read --save-storage (cookies/localStorage) and --output (script) →
    persist session to Redis → return session_id + recorded_script to frontend.
    """
    rec = _active_recordings.get(recording_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Recording session not found")

    try:
        # Terminate codegen — this flushes --save-storage and --output files
        try:
            rec.codegen_proc.terminate()
            await asyncio.wait_for(rec.codegen_proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            try:
                rec.codegen_proc.kill()
                await rec.codegen_proc.wait()
            except Exception:
                pass
        except Exception:
            pass

        await asyncio.sleep(0.5)  # Let filesystem flush

        # ── Read generated Playwright script ────────────────────────────────
        recorded_script: str = ""
        try:
            with open(rec.script_path, "r", encoding="utf-8") as f:
                recorded_script = f.read()
            logger.info(f"Recorded script: {len(recorded_script)} chars")
        except FileNotFoundError:
            logger.warning(f"Script file not found: {rec.script_path}")

        # ── Read storage state (cookies + localStorage) ─────────────────────
        cookies: list = []
        headers: dict = {}
        storage_state_json: str = "{}"

        try:
            with open(rec.storage_path, "r", encoding="utf-8") as f:
                storage_data = json.load(f)

            cookies = storage_data.get("cookies", [])
            storage_state_json = json.dumps(storage_data)

            # Extract auth token from localStorage origins
            for origin in storage_data.get("origins", []):
                for item in origin.get("localStorage", []):
                    k = item.get("name", "")
                    v = item.get("value", "")
                    if any(kw in k.lower() for kw in ["token", "jwt", "access", "auth"]):
                        if isinstance(v, str) and v.count(".") == 2:
                            headers["Authorization"] = f"Bearer {v}"
                            break

            logger.info(f"Captured {len(cookies)} cookies from storage")
        except FileNotFoundError:
            logger.warning(f"Storage file not found: {rec.storage_path}")
        except json.JSONDecodeError as e:
            logger.warning(f"Storage JSON parse error: {e}")

        # ── Persist to Redis ────────────────────────────────────────────────
        new_session_id = uuid4()
        expires_at = datetime.utcnow() + timedelta(seconds=settings.SESSION_TTL_SECONDS)

        await redis_client.setex(
            f"auth:session:{new_session_id}",
            settings.SESSION_TTL_SECONDS,
            json.dumps({
                "cookies": cookies,
                "headers": headers,
                "storage_state": storage_state_json,
                "status": "ready",
            }),
        )
        await redis_client.setex(
            f"auth:meta:{new_session_id}",
            settings.SESSION_TTL_SECONDS,
            json.dumps({
                "target_url": rec.target_url,
                "auth_type": "interactive",
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": expires_at.isoformat(),
                "has_script": bool(recorded_script),
            }),
        )
        # Store script separately (may be large)
        if recorded_script:
            await redis_client.setex(
                f"auth:script:{new_session_id}",
                settings.SESSION_TTL_SECONDS,
                recorded_script,
            )

        logger.info(f"Interactive session saved: {new_session_id}")
        return RecordSaveResponse(
            session_id=new_session_id,
            expires_at=expires_at,
            status="ready",
            recorded_script=recorded_script or None,
        )

    finally:
        _active_recordings.pop(recording_id, None)
        for path in [rec.script_path, rec.storage_path]:
            try:
                os.unlink(path)
            except Exception:
                pass


@app.delete("/api/v1/auth/sessions/record/{recording_id}")
async def cancel_recording(recording_id: str):
    """Cancel and discard an active recording session."""
    rec = _active_recordings.pop(recording_id, None)
    if rec:
        try:
            rec.codegen_proc.terminate()
            await asyncio.wait_for(rec.codegen_proc.wait(), timeout=3.0)
        except Exception:
            try:
                rec.codegen_proc.kill()
            except Exception:
                pass
        for path in [rec.script_path, rec.storage_path]:
            try:
                os.unlink(path)
            except Exception:
                pass
        logger.info(f"Recording cancelled: {recording_id}")
    return {"cancelled": True}


@app.get("/api/v1/auth/sessions/{session_id}/script")
async def get_session_script(session_id: UUID):
    """Retrieve the recorded Playwright script for a session."""
    script = await redis_client.get(f"auth:script:{session_id}")
    if not script:
        raise HTTPException(status_code=404, detail="No recorded script for this session")
    return {"script": script}


@app.get("/api/v1/auth/sessions/{session_id}", response_model=AuthSessionRetrieve)
async def get_session(session_id: UUID):
    data = await redis_client.get(f"auth:session:{session_id}")
    if not data:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    session_data = json.loads(data)
    return AuthSessionRetrieve(**session_data)

@app.get("/health")
async def health():
    return {"status": "healthy"}