import sys
import os
import ast
import json
import textwrap
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID, uuid4

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
    
    return AuthSessionResponse(
        session_id=session_id,
        expires_at=expires_at,
        status="ready"
    )

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