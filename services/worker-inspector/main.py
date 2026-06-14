#!/usr/bin/env python3
"""
Briar Inspector Worker
======================
Smart pre-exploitation triage fuzzer.  Sits between the FUZZ phase and
DAST/EXPLOIT.  For each high-value (endpoint, parameter) pair it:

  1. Establishes a clean baseline response
  2. Sends lightweight canary payloads tuned to the parameter's semantic type
  3. Compares responses (body diff, status change, size delta, timing)
  4. Emits structured candidates that the orchestrator routes to specialized tools:
       sqli_candidate   → sqlmap
       ssti_candidate   → tplmap
       cmdi_candidate   → commix
       path_traversal   → nuclei (path-traversal templates)
       open_redirect    → nuclei (redirect templates)
       xss_candidate    → dalfox

Queue:  scan.inspect.inspector
Phase:  inspect  (after fuzz, before dast)

Detection methods per finding type
-----------------------------------
  sqli_candidate
    • Error-based   – DB error keywords in response body
    • Boolean-based – true condition ≈ baseline, false condition ≠ baseline
    • Time-based    – response time > baseline + TIMING_THRESHOLD

  ssti_candidate
    • Math eval     – inject {{7*7}}, ${7*7}, #{7*7} etc. → "49" in response
    • Engine tag    – specific engine error strings in response

  cmdi_candidate
    • Output reflection – inject unique random echo marker → marker in response
    • Blind via timing  – inject sleep command → response delay

  path_traversal
    • Content reflection – inject ../../etc/passwd → "root:" pattern in response

  open_redirect
    • Location header – inject redirect target → Location header reflects injected URL

  xss_candidate
    • HTML reflection – inject unique tag → unescaped in response body
"""

import asyncio
import hashlib
import json
import logging
import os
import random
import re
import string
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel
from shared.app_strategies import get_strategy

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False
    httpx = None  # type: ignore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("inspector-worker")

# ── Tuning ─────────────────────────────────────────────────────────────────────

MAX_ENDPOINTS      = int(os.getenv("INSPECTOR_MAX_ENDPOINTS",  "300"))
MAX_PARAMS_PER_EP  = int(os.getenv("INSPECTOR_MAX_PARAMS",     "15"))
REQUEST_TIMEOUT    = float(os.getenv("INSPECTOR_TIMEOUT",      "10"))
TIMING_THRESHOLD   = float(os.getenv("INSPECTOR_TIMING_DELTA", "2.5"))  # seconds
MAX_CONCURRENCY    = int(os.getenv("INSPECTOR_CONCURRENCY",    "20"))
BOOL_DIFF_RATIO    = float(os.getenv("INSPECTOR_BOOL_DIFF",    "0.15"))  # ≥15% diff = suspicious


# ── Parameter semantic classification ─────────────────────────────────────────

# Each set assigns a vulnerability-type score weight to a parameter name.
# A parameter can be in multiple sets (e.g. "id" → SQL + IDOR).

SQL_PARAM_NAMES: Set[str] = {
    "id", "uid", "user_id", "userid", "item_id", "product_id", "post_id",
    "order_id", "cat_id", "category_id", "thread_id", "parent_id",
    "search", "q", "query", "keyword", "keywords", "kw", "s", "term",
    "filter", "where", "having", "group", "sort", "orderby", "order_by",
    "column", "col", "field", "fields", "select",
    "category", "cat", "type", "kind", "class", "tag", "genre",
    "from", "to", "start", "end", "date", "year", "month", "day",
    "page", "limit", "offset", "per_page", "count", "num", "rows",
    "user", "username", "email", "login", "account", "member",
    "name", "title", "description", "text", "content", "message",
    "parent", "ref", "reference", "code", "sku", "slug",
}

SSTI_PARAM_NAMES: Set[str] = {
    "template", "render", "view", "page", "content", "layout",
    "message", "email_body", "body", "subject", "html", "tpl", "tmpl",
    "format", "output", "theme", "header", "footer", "section",
    "block", "widget", "component", "partial", "include",
    "notification", "greeting", "signature",
}

CMDI_PARAM_NAMES: Set[str] = {
    "cmd", "exec", "command", "run", "shell", "process", "execute",
    "ping", "host", "ip", "addr", "address", "server", "domain",
    "url", "uri", "link", "href", "src", "endpoint",
    "path", "file", "filename", "filepath", "dir", "folder",
    "program", "binary", "script", "tool", "util", "action",
    "debug", "trace", "log", "import", "export",
}

REDIRECT_PARAM_NAMES: Set[str] = {
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "returnurl", "next", "goto", "url", "uri", "target", "dest",
    "destination", "forward", "redir", "back", "callback", "continue",
    "location", "referer", "href", "link", "go",
}

PATH_TRAVERSAL_PARAM_NAMES: Set[str] = {
    "file", "filename", "path", "filepath", "dir", "folder", "directory",
    "include", "require", "load", "read", "page", "template", "tpl",
    "lang", "language", "locale", "module", "resource", "asset",
    "config", "conf", "cfg", "data",
}

XSS_PARAM_NAMES: Set[str] = {
    "name", "q", "search", "query", "keyword", "message", "comment",
    "text", "content", "title", "description", "subject", "body",
    "username", "email", "url", "ref", "callback", "redirect",
    "error", "info", "msg", "alert", "notice", "status",
}

# ── JWT detection pattern ─────────────────────────────────────────────────────
# Three base64url segments: header.payload.signature
# JWT headers always start with eyJ (base64url of '{"')
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
    re.ASCII,
)

# JSON keys that commonly hold access tokens
_JWT_JSON_KEYS = frozenset({
    "token", "access_token", "accessToken", "id_token", "idToken",
    "jwt", "bearer", "auth_token", "authToken", "refresh_token", "refreshToken",
})

# ── SQL error detection patterns ───────────────────────────────────────────────

_SQL_ERROR_RE = re.compile(
    r"(?:"
    r"you have an error in your sql syntax"
    r"|warning:\s*mysql"
    r"|unclosed quotation mark"
    r"|quoted string not properly terminated"
    r"|pg::syntaxerror"
    r"|pg::undefinedcolumn"
    r"|ora-\d{4,5}"
    r"|microsoft ole db provider for sql server"
    r"|incorrect syntax near"
    r"|unexpected end of sql command"
    r"|sqlite.*(?:error|exception)"
    r"|psql.*error"
    r"|mariadb server version for the right syntax"
    r"|com\.mysql\.jdbc\."
    r"|org\.postgresql\.util\.psqlexception"
    r"|system\.data\.sqlclient"
    r"|odbc.*(?:driver|error)"
    r"|jdbc.*exception"
    r"|sqlsyntaxerrorexception"
    r"|pdo.*sqlstate"
    r"|db2 sql error"
    r"|sql server.*error"
    r"|operationalerror.*sqlite"
    r"|operationalerror.*mysql"
    r"|hy000.*1064"
    r")",
    re.IGNORECASE,
)

# ── SSTI canaries ──────────────────────────────────────────────────────────────

# Each entry: (payload, expected_result, engine_hint)
# We inject the payload and look for expected_result in the response body.
SSTI_CANARIES: List[Tuple[str, str, str]] = [
    ("{{7*7}}",           "49",  "Jinja2/Twig"),
    ("${7*7}",            "49",  "FreeMarker/Groovy"),
    ("#{7*7}",            "49",  "Ruby/Thymeleaf"),
    ("<%= 7*7 %>",        "49",  "ERB"),
    ("${{7*7}}",          "49",  "Spring EL"),
    ("{{7*'7'}}",         "7777777", "Jinja2"),          # Jinja2: '7'*7 = '7777777'
    ("{#7*7}",            "49",  "Smarty3"),
    ("{$smarty.version}", "Smarty", "Smarty"),
]

_SSTI_ENGINE_RE = re.compile(
    r"(?:jinja2|twig|freemarker|smarty|erb|thymeleaf|velocity|pebble|"
    r"TemplateEngine|TemplateNotFound|TemplateSyntaxError)",
    re.IGNORECASE,
)

# ── Path traversal patterns ────────────────────────────────────────────────────

PATH_TRAVERSAL_CANARIES = [
    ("../../etc/passwd",        "unix"),
    ("../../../etc/passwd",     "unix"),
    ("....//....//etc/passwd",  "unix"),
    ("%2e%2e%2fetc%2fpasswd",   "unix"),
    ("..\\..\\windows\\win.ini","win"),
    ("%2e%2e\\windows\\win.ini","win"),
]

_PATH_TRAVERSAL_RE = re.compile(
    r"(?:root:.*:0:0:|nobody:.*:/|daemon:.*:/|"
    r"\[boot loader\]|for 16-bit app support|"
    r"\[fonts\]|windows\\system32)",
    re.IGNORECASE,
)

# ── SQL boolean canaries ───────────────────────────────────────────────────────

# True/false condition pairs.  The first injected value should give a response
# similar to the baseline (true condition); the second should differ (false).
# We use AND-based conditions so the WHERE clause becomes: original AND 1=1 (same)
# vs original AND 1=2 (different result set).
SQL_BOOL_TRUE  = "' AND '1'='1"
SQL_BOOL_FALSE = "' AND '1'='2"

# For numeric parameters
SQL_BOOL_TRUE_NUM  = " AND 1=1"
SQL_BOOL_FALSE_NUM = " AND 1=2"

# ── SQL time-based canaries ────────────────────────────────────────────────────
# These inject a 1-second delay — short enough to be reliable, long enough to detect.
SQL_TIME_CANARIES = [
    "1 AND SLEEP(1)--",          # MySQL
    "1; WAITFOR DELAY '0:0:1'--",# MSSQL
    "1 AND pg_sleep(1)--",       # PostgreSQL
    "1 OR SLEEP(1)--",           # MySQL alternate
    "1' AND SLEEP(1)--",
]


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class Baseline:
    status:  int
    body:    str
    size:    int
    time_ms: float


@dataclass
class EndpointTarget:
    url:        str
    method:     str
    params:     Dict[str, List[str]]   # name → [current value] for query/form params
    json_body:  Dict[str, Any] = field(default_factory=dict)  # JSON body template for REST API
    score:      int = 0
    vuln_types: List[str] = field(default_factory=list)


# ── Scoring ────────────────────────────────────────────────────────────────────

def score_endpoint(url: str, params: Dict[str, List[str]]) -> Tuple[int, List[str]]:
    """
    Score an (endpoint, params) pair for injection potential.
    Returns (score, [vuln_type, ...]) where higher score = test first.
    """
    score = 0
    vuln_types: Set[str] = set()
    path = urlparse(url).path.lower()

    # URL path signals
    for pattern in ("/search", "/find", "/filter", "/query", "/list", "/get",
                    "/fetch", "/execute", "/run", "/render", "/template",
                    "\.php", "\.asp", "\.aspx", "\.jsp", "\.cfm"):
        if re.search(pattern, path):
            score += 1
            break

    for name in params:
        n = name.lower().strip()

        if n in SQL_PARAM_NAMES:
            score += 3
            vuln_types.add("sqli")
        if n in SSTI_PARAM_NAMES:
            score += 3
            vuln_types.add("ssti")
        if n in CMDI_PARAM_NAMES:
            score += 3
            vuln_types.add("cmdi")
        if n in PATH_TRAVERSAL_PARAM_NAMES:
            score += 2
            vuln_types.add("path_traversal")
        if n in REDIRECT_PARAM_NAMES:
            score += 2
            vuln_types.add("open_redirect")
        if n in XSS_PARAM_NAMES:
            score += 1
            vuln_types.add("xss")

    # If no named param matched anything specific, still test for sqli/xss
    # (catches generic params like "data", "value", "input")
    if not vuln_types:
        score += 1
        vuln_types.update({"sqli", "xss"})

    return score, list(vuln_types)


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _build_headers(auth_context: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "User-Agent": "Mozilla/5.0 (compatible; Briar-Inspector/1.0)",
    }
    headers.update(auth_context.get("headers", {}))
    cookies = auth_context.get("cookies", [])
    if cookies:
        headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    return headers


def _inject_param(
    url: str,
    params: Dict[str, List[str]],
    param_name: str,
    payload: str,
    method: str = "GET",
) -> Tuple[str, Optional[Dict[str, str]]]:
    """
    Return (modified_url, post_data) with payload injected into param_name.
    For GET: encodes into query string.  For POST: returns as form dict.
    """
    modified = dict(params)
    modified[param_name] = [payload]

    if method.upper() == "GET":
        p = urlparse(url)
        new_qs = urlencode({k: v[0] for k, v in modified.items()})
        new_url = urlunparse(p._replace(query=new_qs))
        return new_url, None
    else:
        return url, {k: v[0] for k, v in modified.items()}


def _inject_json_field(
    body: Dict[str, Any],
    field_name: str,
    payload: str,
) -> Dict[str, Any]:
    """Return a copy of JSON body with payload injected into field_name."""
    modified = dict(body)
    modified[field_name] = payload
    return modified


async def _request(
    client: "httpx.AsyncClient",
    method: str,
    url: str,
    data: Optional[Dict] = None,
    timeout: float = REQUEST_TIMEOUT,
    json_body: bool = False,
) -> Optional[Tuple[int, str, float]]:
    """Returns (status, body, elapsed_seconds) or None on error."""
    try:
        t0 = time.monotonic()
        if method.upper() == "POST" and data:
            if json_body:
                resp = await client.post(url, json=data, timeout=timeout)
            else:
                resp = await client.post(url, data=data, timeout=timeout)
        else:
            resp = await client.get(url, timeout=timeout)
        elapsed = time.monotonic() - t0
        body = resp.text
        return resp.status_code, body, elapsed
    except Exception as exc:
        logger.debug(f"Request failed {url}: {exc}")
        return None


def _body_diff_ratio(base: str, modified: str) -> float:
    """Rough content-similarity ratio — 0.0 = identical, 1.0 = totally different."""
    if not base and not modified:
        return 0.0
    if not base or not modified:
        return 1.0
    # Quick hash comparison
    if base == modified:
        return 0.0
    # Size-based diff as a proxy (fast, avoids full diff on large pages)
    longer = max(len(base), len(modified))
    shorter = min(len(base), len(modified))
    return 1.0 - (shorter / longer)


# ── Detection strategies ───────────────────────────────────────────────────────

async def _detect_sqli(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    params: Dict[str, List[str]],
    param_name: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """
    SQL injection detection (error-based, boolean-based, time-based).
    Returns a finding dict or None.
    """
    original_val = (params.get(param_name) or ["1"])[0]
    is_numeric = original_val.lstrip("-").isdigit()

    # ── Error-based ────────────────────────────────────────────────────────
    for payload in ("'", '"', "')", "'))", "';--", '";--'):
        inject_url, post_data = _inject_param(url, params, param_name, payload, method)
        result = await _request(client, method, inject_url, post_data)
        if result is None:
            continue
        status, body, _ = result
        if _SQL_ERROR_RE.search(body):
            m = _SQL_ERROR_RE.search(body)
            engine = m.group(0)[:60] if m else "unknown"
            return {
                "detection": "error-based",
                "payload": payload,
                "evidence": f"DB error: {engine}",
            }

    # ── Boolean-based ──────────────────────────────────────────────────────
    true_payload  = (SQL_BOOL_TRUE_NUM  if is_numeric else SQL_BOOL_TRUE)  + original_val
    false_payload = (SQL_BOOL_FALSE_NUM if is_numeric else SQL_BOOL_FALSE) + original_val

    r_true  = await _request(client, method, *_inject_param(url, params, param_name, true_payload,  method)[0:2])
    r_false = await _request(client, method, *_inject_param(url, params, param_name, false_payload, method)[0:2])

    if r_true and r_false:
        _, body_true,  _ = r_true
        _, body_false, _ = r_false

        true_vs_base  = _body_diff_ratio(baseline.body, body_true)
        false_vs_base = _body_diff_ratio(baseline.body, body_false)
        true_vs_false = _body_diff_ratio(body_true, body_false)

        # True condition ≈ baseline AND False condition ≠ baseline
        if (true_vs_base < BOOL_DIFF_RATIO
                and false_vs_base >= BOOL_DIFF_RATIO
                and true_vs_false >= BOOL_DIFF_RATIO):
            return {
                "detection": "boolean-based",
                "payload": f"TRUE={true_payload!r} vs FALSE={false_payload!r}",
                "evidence": (
                    f"True diff={true_vs_base:.2f}, False diff={false_vs_base:.2f} "
                    f"vs baseline — significant content difference detected"
                ),
            }

    # ── Time-based ─────────────────────────────────────────────────────────
    for payload in SQL_TIME_CANARIES:
        inject_url, post_data = _inject_param(url, params, param_name, payload, method)
        result = await _request(
            client, method, inject_url, post_data,
            timeout=REQUEST_TIMEOUT + 5,  # extra buffer for intentional delay
        )
        if result is None:
            continue
        _, _, elapsed = result
        delay = elapsed - (baseline.time_ms / 1000.0)
        if delay >= TIMING_THRESHOLD:
            return {
                "detection": "time-based",
                "payload": payload,
                "evidence": (
                    f"Response delayed by {delay:.2f}s (baseline: {baseline.time_ms:.0f}ms) "
                    f"— consistent with intentional SLEEP/WAITFOR injection"
                ),
            }

    return None


async def _detect_ssti(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    params: Dict[str, List[str]],
    param_name: str,
) -> Optional[Dict[str, Any]]:
    """SSTI detection via mathematical evaluation of injected expressions."""
    for payload, expected, engine in SSTI_CANARIES:
        inject_url, post_data = _inject_param(url, params, param_name, payload, method)
        result = await _request(client, method, inject_url, post_data)
        if result is None:
            continue
        _, body, _ = result
        if expected in body:
            return {
                "detection": "math-eval",
                "payload": payload,
                "evidence": (
                    f"Expression {payload!r} evaluated to {expected!r} in response — "
                    f"indicates {engine} template engine execution"
                ),
                "engine": engine,
            }
        if _SSTI_ENGINE_RE.search(body):
            m = _SSTI_ENGINE_RE.search(body)
            return {
                "detection": "engine-error",
                "payload": payload,
                "evidence": f"Template engine error leaked: {m.group(0)!r}",
                "engine": engine,
            }
    return None


async def _detect_cmdi(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    params: Dict[str, List[str]],
    param_name: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """Command injection detection via unique echo marker reflection."""
    marker = "briar_" + "".join(random.choices(string.ascii_lowercase, k=8))

    payloads = [
        f"|echo {marker}",
        f";echo {marker}",
        f"`echo {marker}`",
        f"$(echo {marker})",
        f"\necho {marker}",
        f"||echo {marker}",
        f"&&echo {marker}",
        f"& echo {marker} &",
    ]

    for payload in payloads:
        inject_url, post_data = _inject_param(url, params, param_name, payload, method)
        result = await _request(client, method, inject_url, post_data)
        if result is None:
            continue
        _, body, _ = result
        if marker in body and marker not in baseline.body:
            return {
                "detection": "output-reflection",
                "payload": payload,
                "evidence": (
                    f"Unique echo marker {marker!r} found in response — "
                    f"OS command was executed and output reflected"
                ),
                "marker": marker,
            }

    return None


async def _detect_path_traversal(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    params: Dict[str, List[str]],
    param_name: str,
) -> Optional[Dict[str, Any]]:
    """Path traversal detection via /etc/passwd and win.ini content reflection."""
    for payload, os_type in PATH_TRAVERSAL_CANARIES:
        inject_url, post_data = _inject_param(url, params, param_name, payload, method)
        result = await _request(client, method, inject_url, post_data)
        if result is None:
            continue
        _, body, _ = result
        if _PATH_TRAVERSAL_RE.search(body):
            m = _PATH_TRAVERSAL_RE.search(body)
            return {
                "detection": "content-reflection",
                "payload": payload,
                "evidence": (
                    f"System file content in response: {m.group(0)[:60]!r} — "
                    f"path traversal to {'Unix' if os_type == 'unix' else 'Windows'} system file succeeded"
                ),
                "os_type": os_type,
            }
    return None


async def _detect_open_redirect(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    params: Dict[str, List[str]],
    param_name: str,
) -> Optional[Dict[str, Any]]:
    """Open redirect detection via Location header inspection."""
    evil_url = "https://briar-evil-redirect-canary.example.com/"
    inject_url, post_data = _inject_param(url, params, param_name, evil_url, method)

    try:
        if method.upper() == "POST" and post_data:
            resp = await client.post(inject_url, data=post_data,
                                     timeout=REQUEST_TIMEOUT, follow_redirects=False)
        else:
            resp = await client.get(inject_url,
                                    timeout=REQUEST_TIMEOUT, follow_redirects=False)

        location = resp.headers.get("location", "")
        if "briar-evil-redirect-canary.example.com" in location:
            return {
                "detection": "header-reflection",
                "payload": evil_url,
                "evidence": (
                    f"Location header reflects injected URL: {location!r} — "
                    f"open redirect confirmed, status {resp.status_code}"
                ),
            }
    except Exception:
        pass

    return None


async def _detect_xss(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    params: Dict[str, List[str]],
    param_name: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """
    Lightweight XSS surface detection — checks if input is reflected unescaped.
    Does NOT confirm exploitability (that's dalfox's job).
    """
    marker = "briar_xss_" + "".join(random.choices(string.ascii_lowercase, k=6))
    payload = f"<{marker}>"

    inject_url, post_data = _inject_param(url, params, param_name, payload, method)
    result = await _request(client, method, inject_url, post_data)
    if result is None:
        return None
    _, body, _ = result

    # Check if our tag is reflected literally (not HTML-escaped)
    if payload in body and payload not in baseline.body:
        return {
            "detection": "html-reflection",
            "payload": payload,
            "evidence": (
                f"Tag {payload!r} reflected unescaped in response — "
                f"XSS surface confirmed, route to dalfox for payload crafting"
            ),
        }
    return None


# ── Endpoint extractor ─────────────────────────────────────────────────────────

def _extract_targets(
    endpoints: List[str],
    arjun_results: List[Dict[str, Any]],
    target: str,
    json_endpoint_map: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[EndpointTarget]:
    """
    Build EndpointTarget list from raw endpoints + arjun discoveries.
    Deduplicates, scores, and caps at MAX_ENDPOINTS.
    """
    seen: Set[str] = set()
    targets: List[EndpointTarget] = []

    # Build arjun param map: url → [param_names]
    arjun_map: Dict[str, List[str]] = {}
    for r in arjun_results:
        ep_url = r.get("url", "")
        ep_params = r.get("parameters", [])
        if ep_url and ep_params:
            arjun_map[ep_url] = ep_params

    def _process(url: str, extra_params: Optional[List[str]] = None):
        nonlocal targets
        if url in seen:
            return
        seen.add(url)

        p = urlparse(url)
        qs_params: Dict[str, List[str]] = {}
        if p.query:
            qs_params = dict(parse_qs(p.query, keep_blank_values=True))

        # Merge arjun-discovered hidden params
        for param_name in (arjun_map.get(url, []) + (extra_params or [])):
            if param_name not in qs_params:
                qs_params[param_name] = ["1"]  # placeholder value

        if not qs_params:
            # If URL has integer path segments it's still IDOR/SQLi candidate
            parts = [s for s in p.path.split("/") if s]
            has_int = any(s.isdigit() for s in parts)
            if not has_int:
                return  # No params + no IDs → not interesting for injection

        # Cap params per endpoint
        if len(qs_params) > MAX_PARAMS_PER_EP:
            # Prioritise: SQL params first, then SSTI, then everything else
            def param_prio(name: str) -> int:
                n = name.lower()
                if n in SQL_PARAM_NAMES:   return 0
                if n in SSTI_PARAM_NAMES:  return 1
                if n in CMDI_PARAM_NAMES:  return 2
                if n in REDIRECT_PARAM_NAMES: return 3
                return 4
            sorted_names = sorted(qs_params.keys(), key=param_prio)[:MAX_PARAMS_PER_EP]
            qs_params = {k: qs_params[k] for k in sorted_names}

        score, vuln_types = score_endpoint(url, qs_params)

        # If arjun found params on this endpoint via POST, test as POST.
        # REST APIs accept JSON bodies — GET-only misses most injection surfaces.
        arjun_method = None
        for r in arjun_raw:
            if r.get("url") == url and r.get("method", "GET").upper() == "POST":
                arjun_method = "POST"
                break
        method = arjun_method or "GET"

        # Canonical URL without query string (for dedup)
        base_url = urlunparse(p._replace(query=""))

        targets.append(EndpointTarget(
            url=base_url,
            method=method,
            params=qs_params,
            score=score,
            vuln_types=vuln_types,
        ))

    def _process_json_endpoint(url: str, json_body: Dict[str, Any], method: str):
        """Register a REST API POST endpoint with JSON body for injection testing."""
        if url in seen:
            return
        seen.add(url)
        if not json_body:
            return
        p = urlparse(url)
        base_url = urlunparse(p._replace(query=""))
        score, vuln_types = score_endpoint(url, {k: [str(v)] for k, v in json_body.items()})
        targets.append(EndpointTarget(
            url=base_url,
            method=method,
            params={},
            json_body=json_body,
            score=score + 2,  # boost: REST JSON endpoints are high-value
            vuln_types=vuln_types,
        ))

    # Process all endpoints
    for ep in endpoints:
        _process(ep)

    # Also process arjun-discovered params on URLs that might not be in endpoints
    for arjun_url in arjun_map:
        _process(arjun_url)

    # Process JSON body endpoints from katana (REST API POST requests with JSON body)
    if json_endpoint_map:
        for json_url, json_body in json_endpoint_map.items():
            _process_json_endpoint(json_url, json_body, "POST")

    # Sort by score descending — test most promising targets first
    targets.sort(key=lambda t: t.score, reverse=True)
    return targets[:MAX_ENDPOINTS]


# ── Finding builder ────────────────────────────────────────────────────────────

_FINDING_TYPE_META: Dict[str, Dict[str, Any]] = {
    "sqli_candidate": {
        "severity": SeverityLevel.high,
        "route_to":  "sqlmap",
        "owasp":     "A03:2021 – Injection",
    },
    "ssti_candidate": {
        "severity": SeverityLevel.critical,
        "route_to":  "tplmap",
        "owasp":     "A03:2021 – Injection",
    },
    "cmdi_candidate": {
        "severity": SeverityLevel.critical,
        "route_to":  "commix",
        "owasp":     "A03:2021 – Injection",
    },
    "path_traversal": {
        "severity": SeverityLevel.high,
        "route_to":  "nuclei",
        "owasp":     "A01:2021 – Broken Access Control",
    },
    "open_redirect": {
        "severity": SeverityLevel.medium,
        "route_to":  "nuclei",
        "owasp":     "A01:2021 – Broken Access Control",
    },
    "xss_candidate": {
        "severity": SeverityLevel.medium,
        "route_to":  "dalfox",
        "owasp":     "A03:2021 – Injection",
    },
}


def _build_finding(
    ep: EndpointTarget,
    param_name: str,
    finding_type: str,
    detection_detail: Dict[str, Any],
) -> Dict[str, Any]:
    meta = _FINDING_TYPE_META[finding_type]
    param_url = ep.url
    if ep.params:
        qs = urlencode({k: v[0] for k, v in ep.params.items()})
        param_url = f"{ep.url}?{qs}"

    return {
        "url":      param_url,
        "type":     finding_type,
        "severity": meta["severity"],
        "description": (
            f"[inspector] {finding_type.upper()} — parameter '{param_name}' "
            f"on {ep.url} | Method: {detection_detail['detection']} | "
            f"{detection_detail['evidence']}"
        ),
        "raw_output": {
            "url":          ep.url,
            "parameter":    param_name,
            "method":       ep.method,
            "payload":      detection_detail.get("payload", ""),
            "evidence":     detection_detail.get("evidence", ""),
            "detection":    detection_detail.get("detection", ""),
            "finding_type": finding_type,
            "route_to":     meta["route_to"],
            "owasp":        meta["owasp"],
            "engine":       detection_detail.get("engine"),
            "os_type":      detection_detail.get("os_type"),
            "route_context": {
                "param":   param_name,
                "method":  ep.method,
                "payload": detection_detail.get("payload", ""),
            },
        },
    }


# ── JSON body injection helpers ───────────────────────────────────────────────


async def _detect_sqli_json(
    client: "httpx.AsyncClient",
    url: str,
    json_body: Dict[str, Any],
    field_name: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """SQLi detection via JSON body injection — tests error-based and time-based."""
    for payload in ("'", '"', "')", "'))", "';--", '";--'):
        modified = _inject_json_field(json_body, field_name, payload)
        result = await _request(client, "POST", url, data=modified, json_body=True)
        if result is None:
            continue
        _, body, _ = result
        if _SQL_ERROR_RE.search(body):
            m = _SQL_ERROR_RE.search(body)
            return {
                "detection": "error-based",
                "payload": payload,
                "evidence": f"DB error in JSON response: {(m.group(0) if m else '')[:60]}",
            }

    for payload in SQL_TIME_CANARIES:
        modified = _inject_json_field(json_body, field_name, payload)
        result = await _request(
            client, "POST", url, data=modified, json_body=True,
            timeout=REQUEST_TIMEOUT + 5,
        )
        if result is None:
            continue
        _, _, elapsed = result
        delay = elapsed - (baseline.time_ms / 1000.0)
        if delay >= TIMING_THRESHOLD:
            return {
                "detection": "time-based",
                "payload": payload,
                "evidence": (
                    f"JSON body injection delayed response by {delay:.2f}s "
                    f"(baseline: {baseline.time_ms:.0f}ms)"
                ),
            }
    return None


async def _detect_xss_json(
    client: "httpx.AsyncClient",
    url: str,
    json_body: Dict[str, Any],
    field_name: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """XSS surface detection via JSON body field — checks if input reflects unescaped."""
    marker = "briar_xss_" + "".join(random.choices(string.ascii_lowercase, k=6))
    payload = f"<{marker}>"
    modified = _inject_json_field(json_body, field_name, payload)
    result = await _request(client, "POST", url, data=modified, json_body=True)
    if result is None:
        return None
    _, body, _ = result
    if payload in body and payload not in baseline.body:
        return {
            "detection": "html-reflection",
            "payload": payload,
            "evidence": (
                f"Tag {payload!r} reflected unescaped in JSON response — "
                f"XSS surface in JSON body field"
            ),
        }
    return None


def _build_json_finding(
    ep: EndpointTarget,
    field_name: str,
    finding_type: str,
    detection_detail: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a finding dict for JSON body injection discoveries."""
    meta = _FINDING_TYPE_META[finding_type]
    return {
        "url":      ep.url,
        "type":     finding_type,
        "severity": meta["severity"],
        "description": (
            f"[inspector] {finding_type.upper()} (JSON body) — field '{field_name}' "
            f"on {ep.url} | Method: {detection_detail['detection']} | "
            f"{detection_detail['evidence']}"
        ),
        "raw_output": {
            "url":          ep.url,
            "parameter":    field_name,
            "method":       "POST",
            "payload":      detection_detail.get("payload", ""),
            "evidence":     detection_detail.get("evidence", ""),
            "detection":    detection_detail.get("detection", ""),
            "finding_type": finding_type,
            "route_to":     meta["route_to"],
            "owasp":        meta["owasp"],
            "inject_mode":  "json_body",
            "route_context": {
                "param":   field_name,
                "method":  "POST",
                "payload": detection_detail.get("payload", ""),
            },
        },
    }


# ── JWT detection helper ───────────────────────────────────────────────────────

async def _detect_jwt_tokens(
    target: str,
    auth_context: Dict[str, Any],
    endpoints: List[str],
) -> List[Dict[str, Any]]:
    """
    Scan for JWT tokens in:
      1. Existing auth_context headers/cookies (token already in hand)
      2. Probe baseline responses from the target for Set-Cookie / body JWTs

    Returns a list of jwt_found findings.
    """
    findings: List[Dict[str, Any]] = []
    seen_tokens: set = set()

    def _emit(token: str, url: str, param: str, source: str):
        if token in seen_tokens:
            return
        seen_tokens.add(token)
        findings.append({
            "url":      url,
            "type":     "jwt_found",
            "severity": SeverityLevel.info,
            "description": (
                f"[inspector] JWT token detected ({source}) in {param!r} at {url}. "
                f"Route to jwt_tool for algorithm confusion + weak-secret tests. "
                f"Token prefix: {token[:40]}…"
            ),
            "raw_output": {
                "url":           url,
                "token":         token,
                "param":         param,
                "source":        source,
                "finding_type":  "jwt_found",
                "route_to":      "jwt_tool",
                "route_context": {
                    "param":  param,
                    "method": "GET",
                    "payload": token,
                },
            },
        })

    # ── 1. Auth context scan ─────────────────────────────────────────────
    headers = auth_context.get("headers", {})
    auth_hdr = headers.get("Authorization") or headers.get("authorization", "")
    if auth_hdr.startswith("Bearer "):
        token = auth_hdr[7:].strip()
        if _JWT_RE.match(token):
            _emit(token, target, "Authorization", "auth_context:header")

    for c in auth_context.get("cookies", []):
        val = c.get("value", "")
        if _JWT_RE.match(val):
            _emit(val, target, c.get("name", "cookie"), "auth_context:cookie")

    # ── 2. Probe baseline responses for JWT leakage ──────────────────────
    if not _HTTPX_AVAILABLE:
        return findings

    probe_urls = list(dict.fromkeys([target] + (endpoints or [])[:5]))
    headers_map: Dict[str, str] = _build_headers(auth_context)

    async with httpx.AsyncClient(
        headers=headers_map,
        verify=False,
        follow_redirects=True,
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
    ) as client:
        for url in probe_urls:
            try:
                resp = await client.get(url, timeout=REQUEST_TIMEOUT)

                # Set-Cookie headers
                for cookie_header in resp.headers.get_list("set-cookie"):
                    # Cookie value is after "=" and before ";" or end
                    m = re.search(r"=([^;]+)", cookie_header)
                    if m:
                        val = m.group(1).strip()
                        if _JWT_RE.match(val):
                            name_m = re.match(r"([^=]+)=", cookie_header)
                            cname = name_m.group(1).strip() if name_m else "session"
                            _emit(val, url, cname, "response:set-cookie")

                # Response body JSON keys
                content_type = resp.headers.get("content-type", "")
                if "json" in content_type:
                    try:
                        body = resp.json()
                        if isinstance(body, dict):
                            for key in _JWT_JSON_KEYS:
                                val = body.get(key, "")
                                if isinstance(val, str) and _JWT_RE.match(val):
                                    _emit(val, url, key, "response:json_body")
                    except Exception:
                        pass
                else:
                    # Plain body scan (e.g. HTML pages with embedded tokens)
                    body_text = resp.text
                    for match in _JWT_RE.finditer(body_text):
                        _emit(match.group(0), url, "body", "response:body")
                        break  # one per page is enough

            except Exception as exc:
                logger.debug(f"[inspector] JWT probe failed for {url}: {exc}")

    if findings:
        logger.info(f"[inspector] JWT detection: {len(findings)} token(s) found")

    return findings


# ── Worker ─────────────────────────────────────────────────────────────────────

class InspectorWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="inspector", queue_name="scan.inspect.inspector")
        self.timeout = int(os.getenv("INSPECTOR_WORKER_TIMEOUT", "3600"))

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        if not _HTTPX_AVAILABLE:
            logger.error("httpx library not available — cannot run inspector")
            return []

        endpoints: List[str] = task_payload.get("endpoints", [])
        if not endpoints and target:
            endpoints = [target]

        # arjun results come through the normal endpoint injection mechanism
        # but we also support explicit arjun_results for richer context
        arjun_raw = task_payload.get("arjun_results", [])

        # M8: app-type adaptive strategy — derive forced vuln types from strategy
        # priority_types (e.g. API always tests sqli+cmdi regardless of param names).
        app_type  = task_payload.get("app_type", "unknown")
        framework = task_payload.get("framework")
        strategy  = get_strategy(app_type, "inspector", framework)
        # priority_types use "_candidate" suffix; vuln_types inside EndpointTarget do not
        priority_types: List[str] = strategy.get("priority_types", [])
        # "sqli_candidate" → "sqli",  "open_redirect" → "open_redirect" (no suffix)
        forced_vuln_types: List[str] = [
            t.replace("_candidate", "") for t in priority_types
        ]
        if forced_vuln_types:
            logger.info(
                f"[inspector] M8 forced vuln types "
                f"(app_type={app_type!r}): {forced_vuln_types}"
            )

        # Load JSON body context from katana's captured POST requests.
        # Katana with -aff and -xhr captures XHR/fetch calls including JSON bodies.
        # These are stored in scan_results.raw_output.params.json for tool=katana.
        # The inspector uses them to test REST API JSON body parameters for injection.
        scan_id: str = task_payload.get("scan_id", "")
        json_endpoint_map: Dict[str, Dict[str, Any]] = {}
        if scan_id:
            try:
                from shared.models import ScanResultORM
                from sqlalchemy import select
                from uuid import UUID as _UUID
                async with self.session_factory() as _s:
                    stmt = (
                        select(ScanResultORM.url, ScanResultORM.raw_output)
                        .where(
                            ScanResultORM.scan_id == _UUID(scan_id),
                            ScanResultORM.tool == "katana",
                            ScanResultORM.vulnerability_type == "endpoint",
                        )
                    )
                    rows = await _s.execute(stmt)
                    for row_url, row_raw in rows:
                        if not row_url or not isinstance(row_raw, dict):
                            continue
                        params = row_raw.get("params", {})
                        json_body = params.get("json", {}) if isinstance(params, dict) else {}
                        if isinstance(json_body, dict) and json_body:
                            json_endpoint_map[row_url] = json_body
                logger.info(
                    f"[inspector] Found {len(json_endpoint_map)} katana endpoint(s) "
                    f"with JSON body context for injection testing"
                )
            except Exception as exc:
                logger.debug(f"[inspector] JSON endpoint query failed: {exc}")

        targets = _extract_targets(endpoints, arjun_raw, target, json_endpoint_map)
        if not targets:
            logger.warning("[inspector] No testable endpoints found (no parameters)")
            return []

        # M8: Merge strategy priority_types into every endpoint's vuln_types so they
        # are always tested, even if parameter-name heuristics didn't flag them.
        if forced_vuln_types:
            for ep in targets:
                for vt in forced_vuln_types:
                    if vt not in ep.vuln_types:
                        ep.vuln_types.append(vt)

        logger.info(
            f"[inspector] {len(targets)} endpoint(s) to test "
            f"(top score: {targets[0].score if targets else 0})"
        )

        headers = _build_headers(auth_context)
        semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

        findings: List[Dict[str, Any]] = []
        findings_lock = asyncio.Lock()

        async def test_endpoint(ep: EndpointTarget):
            async with semaphore:
                partial = await self._test_one(ep, headers)
                if partial:
                    async with findings_lock:
                        findings.extend(partial)
                        logger.info(
                            f"[inspector] {ep.url} → "
                            f"{len(partial)} candidate(s) found"
                        )

        # Run injection tests + JWT detection concurrently
        jwt_task = asyncio.create_task(
            _detect_jwt_tokens(target, auth_context, endpoints)
        )
        await asyncio.gather(*[test_endpoint(ep) for ep in targets])
        jwt_findings = await jwt_task
        findings.extend(jwt_findings)

        # Sort by severity: critical > high > medium > low > info
        _sev_order = {
            SeverityLevel.critical: 0,
            SeverityLevel.high:     1,
            SeverityLevel.medium:   2,
            SeverityLevel.low:      3,
            SeverityLevel.info:     4,
        }
        findings.sort(key=lambda f: _sev_order.get(f["severity"], 5))

        logger.info(
            f"[inspector] Completed. {len(findings)} candidate(s) across "
            f"{len(targets)} endpoint(s) "
            f"({len(jwt_findings)} JWT token(s) found)"
        )
        return findings

    async def _test_one(
        self,
        ep: EndpointTarget,
        headers: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """Test one endpoint across all applicable detection strategies."""
        findings: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(
            headers=headers,
            verify=False,
            follow_redirects=True,
            timeout=httpx.Timeout(REQUEST_TIMEOUT),
        ) as client:

            # Establish baseline
            baseline_url = ep.url
            if ep.params:
                qs = urlencode({k: v[0] for k, v in ep.params.items()})
                baseline_url = f"{ep.url}?{qs}"

            bl = await _request(client, ep.method, baseline_url)
            if bl is None:
                logger.debug(f"[inspector] Baseline failed for {ep.url}")
                return []

            bl_status, bl_body, bl_time = bl
            baseline = Baseline(
                status=bl_status,
                body=bl_body,
                size=len(bl_body),
                time_ms=bl_time * 1000,
            )

            for param_name in ep.params:
                vuln_types = ep.vuln_types

                # SQL injection
                if "sqli" in vuln_types or not vuln_types:
                    result = await _detect_sqli(
                        client, ep.url, ep.method, ep.params, param_name, baseline
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "sqli_candidate", result))
                        continue  # Found SQLi — no need to test other injection types for this param

                # SSTI
                if "ssti" in vuln_types:
                    result = await _detect_ssti(
                        client, ep.url, ep.method, ep.params, param_name
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "ssti_candidate", result))
                        continue

                # Command injection
                if "cmdi" in vuln_types:
                    result = await _detect_cmdi(
                        client, ep.url, ep.method, ep.params, param_name, baseline
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "cmdi_candidate", result))
                        continue

                # Path traversal
                if "path_traversal" in vuln_types:
                    result = await _detect_path_traversal(
                        client, ep.url, ep.method, ep.params, param_name
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "path_traversal", result))

                # Open redirect
                if "open_redirect" in vuln_types:
                    result = await _detect_open_redirect(
                        client, ep.url, ep.method, ep.params, param_name
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "open_redirect", result))

                # XSS (only if no higher-severity vuln found for this param)
                if "xss" in vuln_types and not any(
                    f["raw_output"]["parameter"] == param_name for f in findings
                ):
                    result = await _detect_xss(
                        client, ep.url, ep.method, ep.params, param_name, baseline
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "xss_candidate", result))

            # ── JSON body injection pass (REST API endpoints) ──────────────────
            # When katana captured a POST request with a JSON body, test each
            # JSON field for injection vulnerabilities.  Uses the same detection
            # strategies as query-param injection but sends payloads inside
            # application/json bodies — covering REST API surfaces that form-based
            # injection misses entirely.
            if ep.json_body:
                json_baseline = await _request(
                    client, "POST", ep.url,
                    data=ep.json_body, json_body=True,
                )
                if json_baseline is not None:
                    jbl_status, jbl_body, jbl_time = json_baseline
                    jbaseline = Baseline(
                        status=jbl_status,
                        body=jbl_body,
                        size=len(jbl_body),
                        time_ms=jbl_time * 1000,
                    )

                    for field_name, field_val in ep.json_body.items():
                        if not isinstance(field_val, str):
                            continue  # only inject into string fields
                        # Build params-like structure for scoring
                        json_params_as_qs = {field_name: [str(field_val)]}
                        _, field_vuln_types = score_endpoint(ep.url, json_params_as_qs)
                        if not field_vuln_types:
                            field_vuln_types = ["sqli", "xss"]

                        # Test SQLi via JSON body
                        sqli_det = await _detect_sqli_json(
                            client, ep.url, ep.json_body, field_name, jbaseline
                        )
                        if sqli_det:
                            findings.append(
                                _build_json_finding(ep, field_name, "sqli_candidate", sqli_det)
                            )
                            continue

                        # Test XSS via JSON body
                        if "xss" in field_vuln_types:
                            xss_det = await _detect_xss_json(
                                client, ep.url, ep.json_body, field_name, jbaseline
                            )
                            if xss_det:
                                findings.append(
                                    _build_json_finding(ep, field_name, "xss_candidate", xss_det)
                                )

        return findings


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    worker = InspectorWorker()
    try:
        await worker.start()
        while worker.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await worker.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
