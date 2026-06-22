"""
Katana Crawler Worker
=====================
Phase: RECON — endpoint discovery and parameter extraction.

M8 improvements:
  1. Cookie auth fix — was incorrectly using "-H @file"; now builds a proper
     "Cookie: name=val; ..." header string.
  2. POST body capture — saves request body and method in raw_output so
     downstream DAST workers (dalfox, sqlmap) can reconstruct full requests.
  3. Full parameterised URL preservation — query-string is kept in saved URL
     so DAST tools receive /search?q=test, not just /search.
  4. OpenAPI / Swagger / GraphQL auto-discovery — probes well-known API schema
     endpoints after the crawl and injects discovered paths.
  5. Headless Chromium enabled by default (configurable via KATANA_HEADLESS=false).
  6. XHR/Fetch capture (-xhr flag) — intercepts async API calls from JS code.
  7. Crawl-scope enforcement (-cs regex) — stays on-domain, avoids external drift.
  8. SPA-aware depth — uses depth 5 when headless mode is active.
  9. JS endpoint extraction — post-crawl regex pass over collected .js files to
     surface hidden API paths not reachable by following DOM links.
  10. gau passive URL discovery integrated inline.
"""

import asyncio
import json
import logging
import os
import re
import sys
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import httpx as _httpx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel
from shared.app_strategies import get_strategy

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("katana-worker")

# ── Well-known API spec paths to probe ────────────────────────────────────────

API_SPEC_PATHS = [
    # Swagger UI / API Docs pages first — these are the most common spec hosts.
    # Probed with Accept:application/json so frameworks that serve HTML by default
    # (Juice Shop /api-docs → JSON when asked) are handled correctly.
    "/api-docs",
    "/api-docs/",
    "/swagger",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/docs",
    "/redoc",
    # Spring Boot / Actuator — also common and respond correctly
    "/v2/api-docs",
    "/v3/api-docs",
    # OpenAPI / Swagger JSON at root — often serve SPA shell on 200, not real spec
    "/openapi.json",
    "/swagger.json",
    "/openapi.yaml",
    "/swagger.yaml",
    # OpenAPI / Swagger YAML
    "/api/swagger.yaml",
    "/api/openapi.yaml",
    # /api/* paths — Juice Shop returns 500 for these; kept last to avoid early bail
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/api/docs/openapi.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/docs/openapi.json",
    "/actuator",
    "/actuator/mappings",
    # GraphQL
    "/graphql",
    "/api/graphql",
    "/graphiql",
    # WSDL (SOAP)
    "/wsdl",
    "/?wsdl",
    "/service?wsdl",
]

# Sensitive paths probed directly — not spec endpoints but high-value findings.
# These supplement katana's crawl on common targets (Juice Shop, Laravel, etc.)
SENSITIVE_PROBE_PATHS = [
    # Exposed data directories
    "/ftp/",
    "/ftp",
    "/.git/",
    "/.env",
    "/.env.production",
    "/.env.local",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/secrets.json",
    "/backup.zip",
    "/dump.sql",
    # Admin / management interfaces
    "/administration",
    "/admin",
    "/admin/",
    "/manage",
    "/dashboard",
    "/private",
    # Juice Shop specific well-known paths
    "/rest/user/whoami",
    "/rest/products/search?q=test",
    "/api/Users",
    "/api/Users/1",
    "/metrics",
    "/robot.txt",
    "/security.txt",
    "/.well-known/security.txt",
]

# Paths that may return Swagger JSON when requested with Accept: application/json
# (e.g. OWASP Juice Shop /api-docs serves HTML by default but JSON when asked)
_API_DOCS_JSON_PROBE = frozenset({"/api-docs", "/api-docs/", "/swagger", "/docs"})

# Seed JSON bodies for known endpoint patterns.  For these paths we skip the
# "POST {} → extract fields from 422" heuristic and use the pre-filled body
# directly.  This guarantees Inspector gets the correct field set even when the
# server returns a terse 401/403 with no field names in the error message
# (e.g. Juice Shop /rest/user/login returns {"error":"..."} on empty body).
_REST_SEED_BODIES: Dict[str, Dict[str, Any]] = {
    "/rest/user/login":     {"email": "test@test.com", "password": "test"},
    "/rest/user/register":  {"email": "test@test.com", "password": "test", "passwordRepeat": "test"},
    "/login":               {"email": "test@test.com", "password": "test"},
    "/signin":              {"email": "test@test.com", "password": "test"},
    "/api/login":           {"email": "test@test.com", "password": "test"},
    "/api/signin":          {"email": "test@test.com", "password": "test"},
    "/auth/login":          {"email": "test@test.com", "password": "test"},
    "/auth/signin":         {"email": "test@test.com", "password": "test"},
    "/api/auth/login":      {"email": "test@test.com", "password": "test"},
    "/api/auth/signin":     {"email": "test@test.com", "password": "test"},
    "/api/v1/login":        {"email": "test@test.com", "password": "test"},
    "/api/v2/login":        {"email": "test@test.com", "password": "test"},
    "/user/login":          {"email": "test@test.com", "password": "test"},
    "/account/login":       {"email": "test@test.com", "password": "test"},
    "/register":            {"email": "test@test.com", "password": "test", "name": "Test"},
    "/signup":              {"email": "test@test.com", "password": "test", "name": "Test"},
    "/api/register":        {"email": "test@test.com", "password": "test"},
    "/api/signup":          {"email": "test@test.com", "password": "test"},
    "/api/v1/register":     {"email": "test@test.com", "password": "test"},
    "/api/v1/users":        {"email": "test@test.com", "password": "test", "username": "test"},
    "/api/users":           {"email": "test@test.com", "password": "test", "username": "test"},
    "/forgot-password":     {"email": "test@test.com"},
    "/api/forgot-password": {"email": "test@test.com"},
    "/reset-password":      {"token": "test", "password": "Newpassword1!"},
    "/api/reset-password":  {"token": "test", "password": "Newpassword1!"},
    "/change-password":     {"current": "test", "new": "Newpassword1!"},
    "/api/change-password": {"current": "test", "new": "Newpassword1!"},
    "/session":             {"email": "test@test.com", "password": "test"},
    "/token":               {"grant_type": "password", "username": "test", "password": "test"},
    "/oauth/token":         {"grant_type": "password", "username": "test", "password": "test"},
}

# Common REST POST endpoint patterns probed actively to discover JSON body fields.
# A POST {} is sent to each; 400/422 validation errors reveal required field names.
_REST_PROBE_PATHS = [
    "/login",
    "/signin",
    "/api/login",
    "/api/signin",
    "/auth/login",
    "/auth/signin",
    "/api/auth/login",
    "/api/auth/signin",
    "/rest/user/login",
    "/register",
    "/signup",
    "/api/register",
    "/api/signup",
    "/api/v1/login",
    "/api/v1/register",
    "/api/v1/users",
    "/api/v2/login",
    "/api/v2/register",
    "/api/users",
    "/api/user",
    "/users",
    "/user/login",
    "/user/register",
    "/account/login",
    "/account/register",
    "/session",
    "/sessions",
    "/api/session",
    "/token",
    "/api/token",
    "/oauth/token",
    "/forgot-password",
    "/reset-password",
    "/api/forgot-password",
    "/api/reset-password",
    "/change-password",
    "/api/change-password",
]

# GET endpoints with known querystring params — probed as GET to capture
# search/filter/lookup surfaces that Katana's headless crawl might miss.
# Each entry: (path, {param: seed_value})
_GET_PROBE_ENDPOINTS: List[Tuple[str, Dict[str, str]]] = [
    # Search / filter
    ("/rest/products/search",  {"q": "test"}),
    ("/api/products/search",   {"q": "test"}),
    ("/search",                {"q": "test"}),
    ("/api/search",            {"q": "test", "query": "test"}),
    ("/api/v1/search",         {"q": "test"}),
    # User lookup
    ("/api/users",             {"id": "1", "email": "test@test.com"}),
    ("/api/v1/users",          {"id": "1"}),
    ("/rest/user/whoami",      {}),
    # Product / item lookups
    ("/api/products",          {"id": "1", "category": "test"}),
    ("/api/v1/products",       {"id": "1"}),
    # Orders / basket
    ("/api/orders",            {"id": "1"}),
    ("/rest/basket",           {}),
    # Common filter/list endpoints
    ("/api/items",             {"id": "1", "filter": "test"}),
    ("/api/v1/items",          {"id": "1"}),
    # Password reset token check
    ("/api/reset-password",    {"token": "test"}),
    ("/rest/user/reset-password", {"token": "test"}),
]


def _build_cookie_header(cookies: List[Dict[str, str]]) -> str:
    """Build a Cookie: header value from a list of {name, value} dicts."""
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))


def _extract_params_from_url(url: str) -> Dict[str, List[str]]:
    """Parse query string into a params dict."""
    try:
        return parse_qs(urlparse(url).query)
    except Exception:
        return {}


def _base_origin(url: str) -> str:
    """Return scheme://host[:port] for a URL."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


class KatanaWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="katana", queue_name="scan.crawl.katana")
        # Default timeout is 30 min — sufficient for most SPAs with saturation detection.
        # Juice Shop / Angular / React SPAs are fully explored in 10-20 min; remaining
        # time discovers only SPA route permutations returning the same HTML shell.
        # Set KATANA_TIMEOUT=3600 in docker-compose for very large targets.
        self.timeout          = int(os.getenv("KATANA_TIMEOUT",        "1800"))
        self.depth            = int(os.getenv("KATANA_DEPTH",          "3"))
        self.headless_depth   = int(os.getenv("KATANA_HEADLESS_DEPTH", "5"))
        self.concurrency      = int(os.getenv("KATANA_CONCURRENCY",    "10"))
        # Headless Chromium enabled by default for full SPA coverage;
        # set KATANA_HEADLESS=false to disable (faster but misses React/Vue/Angular routes).
        self.headless = os.getenv("KATANA_HEADLESS", "true").lower() not in ("false", "0", "no")
        # JS endpoint extraction: fetch collected .js files and regex-scan for hidden paths
        self.js_extract = os.getenv("KATANA_JS_EXTRACT", "true").lower() not in ("false", "0", "no")

    # ── Main entry point ───────────────────────────────────────────────────────

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        work_dir = "/tmp/katana"
        os.makedirs(work_dir, exist_ok=True)

        # M8: pick up app-type context from orchestrator payload
        app_type  = task_payload.get("app_type", "unknown")
        is_spa    = task_payload.get("is_spa", False)
        framework = task_payload.get("framework")

        # M8: centralised strategy overrides headless/depth/strategy for each app type
        strategy = get_strategy(app_type, "katana", framework)

        # Headless mode:
        #   explicit task_payload flag  >  strategy matrix  >  SPA heuristic  >  env default
        headless_override = task_payload.get("headless")
        if headless_override is not None:
            use_headless = bool(headless_override)
        elif "headless" in strategy:
            use_headless = bool(strategy["headless"])
        elif is_spa:
            use_headless = True
            logger.info(f"[katana] SPA detected ({app_type}) — forcing headless mode")
        else:
            use_headless = self.headless

        # Crawl depth: strategy > worker env default
        if use_headless:
            effective_depth = strategy.get("headless_depth", self.headless_depth)
        else:
            effective_depth = strategy.get("depth", self.depth)

        # Crawl strategy (breadth-first / depth-first): strategy matrix > default
        crawl_strategy = strategy.get("strategy", "breadth-first")

        if strategy:
            logger.info(
                f"[katana] M8 strategy (app_type={app_type!r}, framework={framework!r}): "
                f"headless={use_headless}, depth={effective_depth}, strategy={crawl_strategy!r}"
            )

        # Crawl-duration budget: tell katana to stop itself 60 s before the
        # Python asyncio.wait_for deadline.  Without this, wait_for sends
        # SIGKILL at deadline and every buffered result is discarded — the scan
        # returns 0 endpoints even after an hour of crawling.
        # With -ct, katana flushes output and exits cleanly before the hard kill.
        crawl_duration_s = max(120, self.timeout - 60)

        # Crawl-scope regex: lock katana to the target's origin so we don't
        # follow external links (e.g. CDNs, third-party analytics scripts).
        parsed_origin = urlparse(target)
        scope_regex = re.escape(f"{parsed_origin.scheme}://{parsed_origin.netloc}")

        cmd = [
            "/usr/local/bin/katana",
            "-u", target,
            "-jsonl",
            "-depth",    str(effective_depth),
            "-c",        str(self.concurrency),
            "-silent",
            "-no-color",
            "-jc",           # JavaScript crawling — parse JS bundles for links
            "-xhr",          # M8: XHR/Fetch interception — captures async API calls
            "-fx",           # Form extraction
            "-aff",          # Auto-form fill (discovers POST endpoints)
            "-kf", "all",    # robots.txt, sitemap.xml, /.well-known/*
            "-rl", "100",    # Rate limit (req/s)
            "-timeout", "15",
            "-retry", "1",
            "-cs", scope_regex,             # M8: Crawl-scope — stay on-domain
            "-ct", f"{crawl_duration_s}s",  # Graceful self-termination before worker timeout
            "-strategy", crawl_strategy,    # M8: breadth-first (wide) or depth-first (deep)
        ]

        # Headless Chromium for SPA applications
        if use_headless:
            cmd.extend(["-headless", "-no-sandbox"])
            logger.info(
                f"[katana] Headless Chromium enabled "
                f"(SPA mode, depth={effective_depth}, "
                f"concurrency={self.concurrency}, "
                f"crawl-duration={crawl_duration_s}s)"
            )

        # ── Auth: headers ──────────────────────────────────────────────────────
        headers: Dict[str, str] = auth_context.get("headers", {})
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        # ── Auth: cookies — FIX: was broken "-H @file", now correct header ────
        cookies: List[Dict] = auth_context.get("cookies", [])
        if cookies:
            cookie_header = _build_cookie_header(cookies)
            cmd.extend(["-H", f"Cookie: {cookie_header}"])
            logger.info(f"[katana] Injecting {len(cookies)} auth cookie(s)")

        logger.info(f"[katana] Starting crawl: {' '.join(cmd)}")

        results: List[Dict[str, Any]] = []
        spa_saturated = asyncio.Event()

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=10 * 1024 * 1024,  # 10 MB line buffer
                cwd=work_dir,
            )

            async def _kill_on_saturation():
                await spa_saturated.wait()
                logger.info(
                    "[katana] SPA saturation: 100+ consecutive non-API HTML routes "
                    "with no parameters — stopping crawl early to save time"
                )
                try:
                    process.kill()
                except Exception:
                    pass

            sat_task = asyncio.create_task(_kill_on_saturation())
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        self._read_stream(process.stdout, results, is_stderr=False,
                                         saturation_event=spa_saturated),
                        self._read_stream(process.stderr, None, is_stderr=True),
                        process.wait(),
                    ),
                    timeout=self.timeout,
                )
            finally:
                # Cancel the saturation monitor (no-op if it already completed)
                sat_task.cancel()
                try:
                    await sat_task
                except (asyncio.CancelledError, Exception):
                    pass

            if process.returncode not in (0, None):
                logger.warning(f"[katana] Exited with code {process.returncode}")

            logger.info(f"[katana] Active crawl found {len(results)} endpoints")

        except asyncio.TimeoutError:
            logger.error(f"[katana] Timed out after {self.timeout}s")
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass

        except Exception as exc:
            logger.error(f"[katana] Execution failed: {exc}", exc_info=True)

        # ── Passive discovery: gau ─────────────────────────────────────────────
        gau_results = await self._run_gau(target)
        existing_urls = {r["url"] for r in results}
        for r in gau_results:
            if r["url"] not in existing_urls:
                results.append(r)
                existing_urls.add(r["url"])

        # ── API schema discovery ───────────────────────────────────────────────
        schema_results = await self._probe_api_schemas(target, headers, cookies)
        # Finding-type results (swagger_found, graphql_found) must NOT be deduped
        # by URL — they share the same URL as the spec endpoint record but carry
        # routing information the finding_router needs.  Only skip true endpoint
        # duplicates (things that describe a crawlable URL, not a detection event).
        _ENDPOINT_TYPES = frozenset({
            "endpoint", "api_endpoint", "js_extracted_endpoint",
            "openapi_spec", "api_schema_endpoint", "graphql_endpoint", "graphql_field",
        })
        for r in schema_results:
            r_type = r.get("type", "")
            if r_type in _ENDPOINT_TYPES:
                if r["url"] in existing_urls:
                    continue
                existing_urls.add(r["url"])
            results.append(r)

        # ── M8: JS endpoint extraction ─────────────────────────────────────────
        if self.js_extract:
            js_results = await self._extract_js_endpoints(results, target, headers, cookies)
            for r in js_results:
                if r["url"] not in existing_urls:
                    results.append(r)
                    existing_urls.add(r["url"])

        # ── Sensitive path probing ─────────────────────────────────────────────
        sensitive_results = await self._probe_sensitive_paths(target, headers, cookies)
        for r in sensitive_results:
            results.append(r)

        # ── Active REST POST endpoint discovery ────────────────────────────────
        # Probes common REST paths with an empty JSON body to discover injectable
        # POST endpoints that katana's crawler cannot capture (e.g. Angular XHR
        # login forms).  Extracts field names from 400/422 validation errors so
        # worker-inspector can test JSON body parameters for injection.
        rest_results = await self._probe_rest_endpoints(target, headers, cookies, existing_urls)
        for r in rest_results:
            existing_urls.add(r["url"])
            results.append(r)

        # GET probe: capture querystring endpoints (search, filter, lookup) that
        # the headless crawler may miss because they require user interaction.
        get_results = await self._probe_get_endpoints(target, headers, cookies, existing_urls)
        for r in get_results:
            results.append(r)

        logger.info(f"[katana] Total unique endpoints: {len(results)}")
        return results

    # ── JSONL stream parser ────────────────────────────────────────────────────

    async def _read_stream(
        self,
        stream,
        results_list: Optional[List],
        is_stderr: bool = False,
        saturation_event: Optional[asyncio.Event] = None,
    ):
        # SPA saturation: count consecutive URLs with no params and no API path.
        # Angular SPAs serve the same index.html shell for every client-side route;
        # after ~100 such results in a row we are just cycling through route permutations.
        _spa_streak = 0
        _SPA_SAT_LIMIT = 100
        _API_PREFIXES = ("/api/", "/rest/", "/graphql", "/socket.io/", "/v1/", "/v2/", "/v3/")

        while True:
            try:
                line = await stream.readuntil(b"\n")
                line_str = line.decode("utf-8", errors="ignore").strip()

                if not line_str:
                    continue

                if is_stderr:
                    lower = line_str.lower()
                    if any(kw in lower for kw in ("error", "failed", "exception", "panic")):
                        logger.warning(f"[katana stderr] {line_str[:500]}")
                    continue

                try:
                    data = json.loads(line_str)
                except json.JSONDecodeError as e:
                    logger.debug(f"[katana] Failed to parse JSONL: {line_str[:200]}… {e}")
                    continue

                request = data.get("request", {})

                # ── Full parameterised URL (preserves ?query=string) ───────────
                endpoint_url = request.get("endpoint") or request.get("url")
                if not endpoint_url:
                    continue

                # Drop URLs that are Angular attributes / CSS values / JS APIs
                # parsed as paths by the headless crawler
                if not self._is_quality_crawl_url(endpoint_url):
                    logger.debug(f"[katana] Filtered garbage URL: {endpoint_url[:120]}")
                    continue

                method = request.get("method", "GET").upper()
                body   = request.get("body") or ""

                # Extract GET params from URL
                get_params = _extract_params_from_url(endpoint_url)

                # Extract POST body params — form-encoded or JSON
                post_params: Dict[str, List[str]] = {}
                json_params: Dict[str, Any] = {}
                if body:
                    stripped = body.strip()
                    if stripped.startswith("{"):
                        try:
                            parsed = json.loads(stripped)
                            if isinstance(parsed, dict):
                                json_params = parsed
                        except Exception:
                            pass
                    elif "=" in stripped:
                        try:
                            post_params = parse_qs(stripped)
                        except Exception:
                            pass

                # Combine all known parameter names
                all_param_names = (
                    list(get_params.keys())
                    + list(post_params.keys())
                    + list(json_params.keys())
                )

                results_list.append({
                    "url": endpoint_url,          # Full URL WITH query string
                    "type": "endpoint",
                    "description": f"Discovered via {method}",
                    "severity": SeverityLevel.info,

                    # ── Rich request context for DAST tools ───────────────────
                    "method":      method,
                    "body":        body,
                    "get_params":  get_params,
                    "post_params": post_params,
                    "json_params": json_params,   # JSON REST body fields (if POST with JSON)
                    "has_params":  bool(all_param_names),
                    "param_names": all_param_names,

                    "source": request.get("source", ""),
                    "raw_output": {
                        "request":   request,
                        "response":  data.get("response", {}),
                        "timestamp": data.get("timestamp"),
                        # Structured param data — used by Arjun/SQLmap/Dalfox
                        "params": {
                            "get":  get_params,
                            "post": post_params,
                            "json": json_params,
                            "all":  all_param_names,
                        },
                    },
                })

                # ── SPA saturation detection ───────────────────────────────
                # If we see many consecutive non-API, no-param URLs it means
                # the headless crawler is cycling through Angular client-side
                # route permutations and returning the same SPA shell each time.
                if saturation_event is not None and not saturation_event.is_set():
                    parsed_path = urlparse(endpoint_url).path
                    is_api = any(parsed_path.startswith(p) for p in _API_PREFIXES)
                    has_ext = "." in (parsed_path.rsplit("/", 1)[-1] or "")
                    if not all_param_names and not is_api and not has_ext:
                        _spa_streak += 1
                        if _spa_streak >= _SPA_SAT_LIMIT:
                            saturation_event.set()
                    else:
                        _spa_streak = 0

            except asyncio.LimitOverrunError:
                logger.warning("[katana] Output line exceeded 10 MB limit, skipping…")
                try:
                    await stream.readuntil(b"\n")
                except Exception:
                    break

            except asyncio.IncompleteReadError as exc:
                # End of stream — process any remaining partial line
                if exc.partial:
                    try:
                        data = json.loads(exc.partial.decode("utf-8", errors="ignore").strip())
                        req  = data.get("request", {})
                        url  = req.get("endpoint") or req.get("url")
                        if url and results_list is not None:
                            results_list.append({
                                "url": url,
                                "type": "endpoint",
                                "description": f"Discovered via {req.get('method', 'GET')}",
                                "severity": SeverityLevel.info,
                                "method": req.get("method", "GET"),
                                "body": req.get("body", ""),
                                "has_params": bool(_extract_params_from_url(url)),
                                "param_names": list(_extract_params_from_url(url).keys()),
                                "raw_output": {"request": req},
                            })
                    except Exception:
                        pass
                break

            except Exception as exc:
                logger.error(f"[katana] Stream read error: {exc}", exc_info=True)
                break

    # ── Passive discovery: gau ────────────────────────────────────────────────

    async def _run_gau(self, target: str) -> List[Dict[str, Any]]:
        """Passive URL discovery from Wayback Machine / CommonCrawl via gau."""
        try:
            host = urlparse(target).netloc
            if not host:
                return []

            process = await asyncio.create_subprocess_exec(
                "gau", "--threads", "5", "--timeout", "30",
                "--blacklist", "png,jpg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,webp",
                host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_data, _ = await asyncio.wait_for(
                process.communicate(), timeout=90
            )
            raw_urls = [
                u.strip()
                for u in stdout_data.decode("utf-8", errors="ignore").splitlines()
                if u.strip().startswith("http")
            ]
            results = []
            for u in raw_urls:
                if not self._is_quality_crawl_url(u):
                    continue
                params = _extract_params_from_url(u)
                results.append({
                    "url": u,
                    "type": "endpoint",
                    "description": "Discovered via gau (public archives)",
                    "severity": SeverityLevel.info,
                    "method": "GET",
                    "has_params": bool(params),
                    "param_names": list(params.keys()),
                    "raw_output": {
                        "source": "gau",
                        "params": {"get": params, "post": {}, "all": list(params.keys())},
                    },
                })
            logger.info(f"[gau] Found {len(results)} historical URLs for {host}")
            return results
        except FileNotFoundError:
            logger.debug("[gau] Not installed, skipping passive discovery")
            return []
        except Exception as exc:
            logger.warning(f"[gau] Failed: {exc}")
            return []

    # ── M8: JS Endpoint Extractor ─────────────────────────────────────────────

    # Regex patterns that commonly appear in bundled JS:
    #   /api/users  |  /v1/auth  |  /graphql  |  relative paths like "../user"
    # We avoid matching pure static asset paths (.png, .css, etc.)
    _JS_PATH_RE = re.compile(
        r"""['"`]"""                         # opening quote
        r"""("""
        r"""(?:/(?!/)[\w\-\./\{\}:@%?&=+#]*)"""   # absolute path starting with /
        r"""|"""
        r"""(?:\.{0,2}/[\w\-\./\{\}:@%?&=+#]+)""" # relative ./  ../  or plain slug/
        r""")"""
        r"""['"`]""",                        # closing quote
        re.MULTILINE,
    )
    # Extensions that are not API paths
    _STATIC_EXT_RE = re.compile(
        r"""\.(png|jpg|jpeg|gif|svg|ico|webp|bmp|avif|"""
        r"""css|woff2?|ttf|eot|otf|map|"""
        r"""mp3|mp4|webm|ogg|wav|pdf|zip|gz|tar)$""",
        re.IGNORECASE,
    )
    # Must contain at least one "word" character segment to be an endpoint
    _MIN_PATH_RE = re.compile(r"/\w")

    # ── Active-crawl URL quality filters ──────────────────────────────────────
    # Angular headless crawl extracts HTML attribute values as URL paths.
    # These regexes catch the most common false-positive classes:

    # CSS numeric values: /0.000000001px  /1.5em  /100vh
    _CSS_VALUE_PATH_RE = re.compile(
        r'^/[\d.]+(?:px|em|rem|vh|vw|vmin|vmax|pt|cm|mm|fr|ch|ex|%|s|ms)(?:[/?#]|$)',
        re.IGNORECASE,
    )
    # Angular Flex Layout directives used as HTML attributes:
    # fxFlex.gt-lg, fxFlexAlign.lt-md, fxHide.gt-xs, fxLayout …
    _ANGULAR_FLEX_RE = re.compile(
        r'/fx(?:Flex|Layout|Hide|Show|FlexAlign|FlexFill|FlexOrder|FlexOffset)',
        re.IGNORECASE,
    )
    # Browser / JS API names crawled as paths:
    # /XMLHttpRequest.send  /Promise.then  /Microsoft.XMLHTTP  /Chrome/66
    _JS_API_RE = re.compile(
        r'/(?:XMLHttpRequest|ActiveXObject|Microsoft\.|MozXMLHttp|'
        r'Promise\.|Object\.|Array\.|Function\.|Error\.|'
        r'document\.|window\.|navigator\.|console\.|Math\.|'
        r'Trident|MSIE|WebKit|Gecko|Chrome/\d|Edge/\d|Firefox/\d)',
        re.IGNORECASE,
    )
    # Property-chain path segment: word.word — catches attr.target, fxFlex.gt-lg
    # Exceptions: socket.io (known valid), v1.0 (version strings)
    _PROP_CHAIN_SEG_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_$]*\.[A-Za-z_$]')
    _PROP_CHAIN_ALLOW = frozenset({"socket.io", "engine.io"})

    @classmethod
    def _is_quality_crawl_url(cls, url: str) -> bool:
        """
        Return False for URLs that are clearly not real endpoints:
          - CSS unit values extracted from style attributes
          - Angular Flex Layout responsive directives
          - Browser / JS API name fragments
          - URL-encoded spaces (sentences parsed as paths)
          - Property-chain path segments (Promise.then, attr.target)
        """
        try:
            from urllib.parse import urlparse as _up
            path = _up(url).path
        except Exception:
            return True  # if parsing fails, let it through

        # CSS unit values at path root
        if cls._CSS_VALUE_PATH_RE.match(path):
            return False

        # Angular Flex Layout responsive directives
        if cls._ANGULAR_FLEX_RE.search(path):
            return False

        # Browser / JS API references
        if cls._JS_API_RE.search(url):
            return False

        # URL-encoded spaces → a sentence was crawled as a path
        if "%20" in url or "%09" in url:
            return False

        # Property-chain segments
        segs = [s.split("?")[0].split("#")[0] for s in path.split("/") if s]
        for seg in segs:
            if (
                cls._PROP_CHAIN_SEG_RE.match(seg)
                and seg.lower() not in cls._PROP_CHAIN_ALLOW
            ):
                return False

        return True

    # ── JS extraction quality filters ─────────────────────────────────────────
    # Rule 1: Template literal artifacts — unencoded quote/plus/whitespace means
    #   the "path" is actually a JS string concatenation fragment, not a URL.
    #   e.g.  /juice-shop/js/'+ url +'  →  rejected
    _TEMPLATE_ARTIFACT_RE = re.compile(r"""['"+ \t\\]""")

    # Rule 2: Separator strings — segments that are only dashes/underscores/dots
    #   appear as visual dividers in source maps and minified bundles.
    #   e.g.  /assets/---...---  →  rejected
    _SEPARATOR_SEGMENT_RE = re.compile(r"(?:^|/)[-_.=*]{3,}(?:/|$)")

    # Rule 3: Webpack chunk ID pattern — a known static-asset directory
    #   immediately followed by a 1-3 char alphanumeric chunk ID fragment.
    #   e.g.  /assets/1  /static/T  /dist/4xi  →  rejected
    #   Version indicators (v1, v2…) are intentionally excluded from this set
    #   because /api/v1 and /api/v2 are valid endpoints.
    _STATIC_ASSET_DIRS = frozenset({
        "assets", "static", "dist", "build", "public",
        "chunks", "chunk", "bundles",
    })

    async def _extract_js_endpoints(
        self,
        crawl_results: List[Dict[str, Any]],
        target: str,
        headers: Dict[str, str],
        cookies: List[Dict],
    ) -> List[Dict[str, Any]]:
        """
        Collect every .js URL found during the crawl, fetch each file, and run
        a regex pass to surface hidden API paths embedded in bundled JS code.

        This catches routes that are never reachable by following DOM links
        (deep routes defined in React Router, Angular Router, etc.) as well as
        hard-coded fetch() calls that katana can't follow via headless rendering.
        """
        origin = _base_origin(target)

        # Collect unique JS URLs from the crawl
        js_urls: Set[str] = set()
        for r in crawl_results:
            u = r.get("url", "")
            if u.endswith(".js") or ".js?" in u:
                js_urls.add(u.split("?")[0])  # strip query for dedup

        if not js_urls:
            return []

        logger.info(f"[katana/js-extract] Scanning {len(js_urls)} JS files for hidden endpoints")

        request_headers = dict(headers)
        if cookies:
            request_headers["Cookie"] = _build_cookie_header(cookies)

        results: List[Dict[str, Any]] = []
        found_paths: Set[str] = set()

        async with _httpx.AsyncClient(
            headers=request_headers,
            follow_redirects=True,
            timeout=15.0,
            verify=False,
        ) as client:
            for js_url in list(js_urls)[:50]:  # cap at 50 JS files per scan
                try:
                    resp = await client.get(js_url)
                    if resp.status_code != 200:
                        continue
                    content = resp.text[:500_000]  # cap at 500 KB per file

                    for match in self._JS_PATH_RE.finditer(content):
                        raw_path = match.group(1)

                        # ── Basic filters ──────────────────────────────────────
                        if self._STATIC_EXT_RE.search(raw_path):
                            continue
                        if not self._MIN_PATH_RE.search(raw_path):
                            continue
                        if len(raw_path) > 200:
                            continue

                        # ── Quality filters (false-positive suppression) ───────
                        # Rule 1: template literal artifacts (raw or URL-encoded).
                        # %27 = ', %28 = (, %29 = ), %2B = +, %20 = space.
                        # These appear when a JS string-concatenation expression
                        # like `'+'_(i[11]||f[g])'+'` is captured literally.
                        if self._TEMPLATE_ARTIFACT_RE.search(raw_path):
                            continue
                        if re.search(r'%27|%28|%29|%2B|%20|%09', raw_path, re.IGNORECASE):
                            continue

                        # Rule 2: separator segments (---...---, ___, etc.)
                        if self._SEPARATOR_SEGMENT_RE.search(raw_path):
                            continue

                        # Rule 3: webpack chunk IDs — /<static-dir>/<1-3char>
                        _parts = [p for p in raw_path.strip("/").split("/") if p]
                        if (
                            len(_parts) >= 2
                            and _parts[-2].lower() in self._STATIC_ASSET_DIRS
                            and len(_parts[-1]) <= 3
                            and _parts[-1].isalnum()
                            and not re.match(r"^v\d+$", _parts[-1])
                        ):
                            continue

                        # Rule 4: port-like first segment (e.g. "3000/path/to/file").
                        # These are runtime-evaluated strings like `${port}/${path}`
                        # captured literally; resolving them with urljoin produces
                        # double-path URLs such as:
                        #   http://host:3000/.well-known/3000/.well-known/chunk.js
                        if _parts and re.match(r"^\d{2,5}$", _parts[0]):
                            continue

                        # Resolve to absolute URL
                        if raw_path.startswith("/"):
                            abs_url = origin + raw_path
                        else:
                            abs_url = urljoin(js_url, raw_path)

                        # Only keep URLs on the same origin
                        if not abs_url.startswith(origin):
                            continue

                        # Rule 5: path segment doubling — catches JS extraction artifacts
                        # where urljoin(js_url, relative_path) doubles the JS file's
                        # directory prefix into the resolved URL.
                        # e.g. js_url=/address/assets/public/chunk.js, raw_path=assets/public/chunk.js
                        # → urljoin → /address/assets/public/assets/public/chunk.js
                        # Detect: any meaningful path segment (len>3) that appears ≥2 times.
                        _abs_parts = [s for s in urlparse(abs_url).path.split("/") if s]
                        _seg_counts = Counter(s for s in _abs_parts if len(s) > 3)
                        if _seg_counts and max(_seg_counts.values()) >= 2:
                            continue

                        # Deduplicate
                        norm = abs_url.split("?")[0].rstrip("/")
                        if norm in found_paths:
                            continue
                        found_paths.add(norm)

                        params = _extract_params_from_url(abs_url)
                        results.append({
                            "url": abs_url,
                            "type": "js_extracted_endpoint",
                            "description": f"JS-extracted path from {js_url}",
                            "severity": SeverityLevel.info,
                            "method": "GET",
                            "has_params": bool(params),
                            "param_names": list(params.keys()),
                            "raw_output": {
                                "source": "js_extraction",
                                "js_file": js_url,
                                "params": {"get": params, "post": {}, "all": list(params.keys())},
                            },
                        })

                except (_httpx.TimeoutException, _httpx.ConnectError):
                    continue
                except Exception as exc:
                    logger.debug(f"[katana/js-extract] Failed to fetch {js_url}: {exc}")

        logger.info(f"[katana/js-extract] Extracted {len(results)} additional endpoints from JS files")
        return results

    # ── API schema discovery ───────────────────────────────────────────────────

    async def _probe_api_schemas(
        self,
        target: str,
        headers: Dict[str, str],
        cookies: List[Dict],
    ) -> List[Dict[str, Any]]:
        """
        Probe well-known API spec endpoints.

        For each found spec (OpenAPI JSON/YAML, GraphQL introspection), extract
        all endpoint paths and save them so DAST tools get full API coverage.
        """
        origin = _base_origin(target)
        results: List[Dict[str, Any]] = []

        request_headers = dict(headers)
        if cookies:
            request_headers["Cookie"] = _build_cookie_header(cookies)

        async with _httpx.AsyncClient(
            headers=request_headers,
            follow_redirects=True,
            timeout=10.0,
            verify=False,
        ) as client:

            # Early-exit counters: if the target is consistently returning 5xx
            # (overloaded / WAF blocking), stop probing after a few failures to
            # avoid spending 2+ minutes on 32 sequential 503 responses.
            consecutive_5xx = 0
            _5XX_BAIL_THRESHOLD = 4

            for path in API_SPEC_PATHS:
                if consecutive_5xx >= _5XX_BAIL_THRESHOLD:
                    logger.info(
                        f"[katana] API schema probing aborted after "
                        f"{consecutive_5xx} consecutive 5xx responses — target appears overloaded"
                    )
                    break

                url = urljoin(origin, path)
                try:
                    # For Swagger UI pages, probe with Accept: application/json first —
                    # frameworks like swagger-ui-express serve JSON when explicitly asked.
                    if path in _API_DOCS_JSON_PROBE:
                        json_resp = await client.get(
                            url, headers={"Accept": "application/json"}
                        )
                        if json_resp.status_code == 200:
                            json_preview = json_resp.text[:3000]
                            if (
                                '"openapi"' in json_preview
                                or '"swagger"' in json_preview
                                or ('"paths"' in json_preview and '"info"' in json_preview)
                            ):
                                # Treat this as a discovered JSON spec
                                resp = json_resp
                            else:
                                resp = await client.get(url)
                        else:
                            resp = await client.get(url)
                    else:
                        resp = await client.get(url)

                    if resp.status_code >= 500:
                        consecutive_5xx += 1
                        continue

                    # Reset counter on any non-5xx response
                    consecutive_5xx = 0

                    if resp.status_code not in (200, 201):
                        continue

                    ct = resp.headers.get("content-type", "").lower()

                    # ── OpenAPI / Swagger JSON ─────────────────────────────────
                    if ("json" in ct or url.endswith(".json")) and resp.content:
                        # Guard: confirm the body is actually an OpenAPI/Swagger spec,
                        # not the SPA shell (Angular returns 200 + HTML for any path).
                        raw_preview = resp.text[:3000]
                        is_openapi_json = (
                            '"openapi"' in raw_preview
                            or '"swagger"' in raw_preview
                            or ('"paths"' in raw_preview and '"info"' in raw_preview)
                        )
                        if is_openapi_json:
                            # Emit swagger_found BEFORE any parsing that might raise.
                            # finding_router needs this even if endpoint extraction fails.
                            results.append(self._make_spec_result(url, "openapi_spec"))
                            results.append({
                                "url":      url,
                                "type":     "swagger_found",
                                "severity": SeverityLevel.info,
                                "description": (
                                    f"OpenAPI/Swagger JSON spec discovered at {url}. "
                                    f"Route to worker-openapi for spec-driven testing."
                                ),
                                "raw_output": {
                                    "spec_url":     url,
                                    "finding_type": "swagger_found",
                                    "route_to":     "openapi",
                                    "route_context": {
                                        "param":   "spec_url",
                                        "method":  "GET",
                                        "payload": url,
                                    },
                                },
                            })
                            # Best-effort: extract individual endpoints from the spec.
                            # Failure here is non-fatal — swagger_found is already saved.
                            try:
                                spec = resp.json()
                                api_paths = self._extract_openapi_paths(spec, origin)
                                for ep in self._openapi_to_results(api_paths, url):
                                    results.append(ep)
                                if api_paths:
                                    logger.info(f"[katana] OpenAPI JSON spec at {url}: extracted {len(api_paths)} endpoints")
                            except Exception as exc:
                                logger.debug(f"[katana] OpenAPI JSON spec parsing failed for {url}: {exc}")
                            continue

                    # ── OpenAPI / Swagger YAML ─────────────────────────────────
                    if ("yaml" in ct or url.endswith((".yaml", ".yml"))) and resp.content:
                        raw_preview = resp.text[:3000]
                        is_openapi_yaml = (
                            "openapi:" in raw_preview
                            or "swagger:" in raw_preview
                            or ("paths:" in raw_preview and "info:" in raw_preview)
                        )
                        if is_openapi_yaml:
                            results.append(self._make_spec_result(url, "openapi_spec"))
                            results.append({
                                "url":      url,
                                "type":     "swagger_found",
                                "severity": SeverityLevel.info,
                                "description": (
                                    f"OpenAPI/Swagger YAML spec discovered at {url}. "
                                    f"Route to worker-openapi for spec-driven testing."
                                ),
                                "raw_output": {
                                    "spec_url":     url,
                                    "finding_type": "swagger_found",
                                    "route_to":     "openapi",
                                    "route_context": {
                                        "param":   "spec_url",
                                        "method":  "GET",
                                        "payload": url,
                                    },
                                },
                            })
                            try:
                                import yaml as _yaml
                                spec = _yaml.safe_load(resp.text)
                                api_paths = self._extract_openapi_paths(spec, origin)
                                for ep in self._openapi_to_results(api_paths, url):
                                    results.append(ep)
                                if api_paths:
                                    logger.info(f"[katana] OpenAPI YAML spec at {url}: extracted {len(api_paths)} endpoints")
                            except Exception as exc:
                                logger.debug(f"[katana] OpenAPI YAML spec parsing failed for {url}: {exc}")
                            continue

                    # ── GraphQL endpoint ───────────────────────────────────────
                    if "graphql" in path.lower():
                        gql_endpoints = await self._graphql_introspect(client, url)
                        results.extend(gql_endpoints)
                        # Always record the GraphQL endpoint and emit routing finding
                        results.append(self._make_spec_result(url, "graphql_endpoint"))
                        # M10: emit routing finding so finding_router triggers worker-graphql
                        introspection_enabled = bool(gql_endpoints)
                        results.append({
                            "url":      url,
                            "type":     "graphql_found",
                            "severity": SeverityLevel.medium if introspection_enabled else SeverityLevel.info,
                            "description": (
                                f"GraphQL endpoint discovered at {url}. "
                                f"Introspection: {'enabled' if introspection_enabled else 'disabled/filtered'}. "
                                f"Route to worker-graphql for security testing."
                            ),
                            "raw_output": {
                                "graphql_url":            url,
                                "introspection_enabled":  introspection_enabled,
                                "field_count":            len(gql_endpoints),
                                "finding_type":           "graphql_found",
                                "route_to":               "graphql",
                                "route_context":          {
                                    "param":   "graphql_url",
                                    "method":  "POST",
                                    "payload": url,
                                },
                            },
                        })
                        continue

                    # ── Generic: just record that the endpoint exists ──────────
                    results.append(self._make_spec_result(url, "api_schema_endpoint"))
                    logger.info(f"[katana] API schema found: {url} ({resp.status_code})")

                except (_httpx.TimeoutException, _httpx.ConnectError):
                    continue
                except Exception as exc:
                    logger.debug(f"[katana] API probe {url}: {exc}")
                    continue

        if results:
            logger.info(f"[katana] API schema discovery found {len(results)} additional endpoints")
        return results

    async def _probe_sensitive_paths(
        self,
        target: str,
        headers: Dict[str, str],
        cookies: List[Dict],
    ) -> List[Dict[str, Any]]:
        """Probe well-known sensitive paths and emit findings for accessible ones."""
        parsed = urlparse(target)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        request_headers = dict(headers)
        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            request_headers["Cookie"] = cookie_str

        results: List[Dict[str, Any]] = []

        # SPA baseline: Angular / React apps return 200+HTML for every unknown path.
        # If the baseline for a non-existent path is also 200+HTML we skip that signal.
        spa_baseline_is_html = False
        try:
            async with _httpx.AsyncClient(
                headers=request_headers, follow_redirects=True, timeout=8.0, verify=False
            ) as client:
                canary = await client.get(urljoin(origin, "/briar-canary-path-xyz-does-not-exist"))
                if canary.status_code == 200 and "html" in canary.headers.get("content-type", "").lower():
                    spa_baseline_is_html = True
        except Exception:
            pass

        async with _httpx.AsyncClient(
            headers=request_headers, follow_redirects=True, timeout=10.0, verify=False
        ) as client:
            for path in SENSITIVE_PROBE_PATHS:
                url = urljoin(origin, path)
                try:
                    resp = await client.get(url)
                except (_httpx.TimeoutException, _httpx.ConnectError):
                    continue
                except Exception as exc:
                    logger.debug(f"[katana/sensitive] {url}: {exc}")
                    continue

                if resp.status_code not in (200, 201, 206):
                    continue

                ct = resp.headers.get("content-type", "").lower()
                body_preview = resp.text[:500]

                # Skip SPA shell responses (HTML when we expect directory/JSON/text)
                is_html_response = "html" in ct
                if spa_baseline_is_html and is_html_response:
                    # Extra check: real sensitive HTML pages often contain directory
                    # listings, login forms, or structured content — not Angular root app
                    if not any(kw in body_preview.lower() for kw in (
                        "index of", "directory", "<table", "href=", "parent directory",
                        '"users"', '"email"', '"password"', 'administration', 'login'
                    )):
                        continue

                # Classify the finding
                severity = SeverityLevel.info
                finding_type = "sensitive_path"
                description = f"Sensitive path accessible: {url} (HTTP {resp.status_code})"

                # FTP / backup / data exposure
                if any(kw in path for kw in ("/ftp", ".env", ".git", "backup", "dump", "secrets", "config")):
                    severity = SeverityLevel.high
                    finding_type = "exposed_resource"
                    description = f"Exposed sensitive resource at {url} — file/directory accessible without auth"
                elif path in ("/api/Users", "/api/Users/1"):
                    severity = SeverityLevel.high
                    finding_type = "idor_candidate"
                    description = f"User enumeration endpoint accessible: {url} — may expose PII without auth"
                elif path in ("/administration", "/admin", "/admin/"):
                    severity = SeverityLevel.high
                    finding_type = "admin_panel"
                    description = f"Admin panel accessible at {url}"
                elif "json" in ct or '"' in body_preview:
                    severity = SeverityLevel.medium
                    finding_type = "api_endpoint"
                    description = f"API endpoint responding at {url} (HTTP {resp.status_code})"
                else:
                    finding_type = "endpoint"

                results.append({
                    "url":         url,
                    "type":        finding_type,
                    "severity":    severity,
                    "description": description,
                    "raw_output": {
                        "source":       "sensitive_probe",
                        "status_code":  resp.status_code,
                        "content_type": ct,
                        "body_preview": body_preview,
                    },
                })
                logger.info(f"[katana/sensitive] FOUND {finding_type} at {url} ({resp.status_code})")

        if results:
            logger.info(f"[katana/sensitive] {len(results)} sensitive paths accessible")
        return results

    # ── Active REST POST endpoint discovery ───────────────────────────────────

    async def _probe_rest_endpoints(
        self,
        target: str,
        headers: Dict[str, str],
        cookies: List[Dict],
        existing_urls: Set[str],
    ) -> List[Dict[str, Any]]:
        """
        Probe common REST POST endpoint patterns with an empty JSON body.

        A 400/422 validation error response usually reveals the required field
        names in its body.  We extract those field names and save the endpoint
        as type='endpoint' with raw_output.params.json populated so that
        worker-inspector can test the JSON body fields for injection.

        Only emits results for URLs NOT already in existing_urls (to avoid
        overwriting a katana-crawled record that already has JSON body context).
        """
        origin = _base_origin(target)
        request_headers = dict(headers)
        request_headers["Content-Type"] = "application/json"
        if cookies:
            request_headers["Cookie"] = _build_cookie_header(cookies)

        results: List[Dict[str, Any]] = []

        async with _httpx.AsyncClient(
            headers=request_headers,
            follow_redirects=False,
            timeout=8.0,
            verify=False,
        ) as client:
            for path in _REST_PROBE_PATHS:
                url = urljoin(origin, path)
                if url in existing_urls:
                    continue
                try:
                    seed = _REST_SEED_BODIES.get(path)
                    probe_body = seed if seed is not None else {}
                    resp = await client.post(
                        url,
                        json=probe_body,
                        headers={"Content-Type": "application/json"},
                    )

                    # 404 → endpoint definitely doesn't exist; skip
                    # 405 → wrong method at that path; skip
                    if resp.status_code in (404, 405):
                        continue

                    # 5xx → server-side error unrelated to us; skip
                    if resp.status_code >= 500:
                        continue

                    # Any 2xx or 4xx (400, 401, 422, …) means the path exists.
                    # If we used a seed body, use its keys directly — no extraction needed.
                    fields: Dict[str, Any] = {}

                    if seed:
                        fields = {k: str(v) for k, v in seed.items() if v != ""}
                    elif "json" in resp.headers.get("content-type", "").lower():
                        try:
                            fields = self._extract_json_body_fields(
                                resp.json(), resp.status_code
                            )
                        except Exception:
                            pass

                    if not fields:
                        # Endpoint exists but we couldn't determine field names;
                        # skip — Inspector has nothing to fuzz without field names.
                        continue

                    all_fields = list(fields.keys())
                    logger.info(
                        f"[katana/rest-probe] POST {url} → HTTP {resp.status_code} "
                        f"fields: {all_fields}"
                    )
                    results.append({
                        "url":         url,
                        "type":        "endpoint",
                        "description": "REST POST endpoint (active probe, JSON body)",
                        "severity":    SeverityLevel.info,
                        "method":      "POST",
                        "body":        "{}",
                        "has_params":  True,
                        "param_names": all_fields,
                        "json_params": fields,
                        "raw_output": {
                            "source":      "rest_probe",
                            "status_code": resp.status_code,
                            "params": {
                                "get":  {},
                                "post": {},
                                "json": fields,
                                "all":  all_fields,
                            },
                        },
                    })
                    existing_urls.add(url)

                except (_httpx.TimeoutException, _httpx.ConnectError):
                    continue
                except Exception as exc:
                    logger.debug(f"[katana/rest-probe] {url}: {exc}")

        if results:
            logger.info(f"[katana/rest-probe] Found {len(results)} injectable REST POST endpoint(s)")
        return results

    async def _probe_get_endpoints(
        self,
        target: str,
        headers: Dict[str, str],
        cookies: List[Dict],
        existing_urls: Set[str],
    ) -> List[Dict[str, Any]]:
        """
        Probe common GET endpoints that carry querystring parameters.

        These are search, filter, and lookup endpoints that the headless crawler
        might miss because they require specific user interactions (typing in a
        search box, clicking a filter, etc.).

        Saves discovered endpoints as type='api_endpoint' so Inspector reads
        them via openapi_param_map and tests each querystring param for injection.
        """
        from urllib.parse import urlencode
        origin = _base_origin(target)
        request_headers = dict(headers)
        if cookies:
            request_headers["Cookie"] = _build_cookie_header(cookies)

        results: List[Dict[str, Any]] = []

        async with _httpx.AsyncClient(
            headers=request_headers,
            follow_redirects=True,
            timeout=6.0,
            verify=False,
        ) as client:
            for path, params in _GET_PROBE_ENDPOINTS:
                qs = ("?" + urlencode(params)) if params else ""
                url = urljoin(origin, path)
                full_url = url + qs

                if url in existing_urls or full_url in existing_urls:
                    continue

                try:
                    resp = await client.get(full_url)

                    # Skip true 404s — endpoint doesn't exist
                    if resp.status_code == 404:
                        continue

                    # Any other response (200, 400, 401, 403, 500) means path exists
                    all_param_names = list(params.keys())
                    logger.info(
                        f"[katana/get-probe] GET {full_url} → HTTP {resp.status_code} "
                        f"params: {all_param_names}"
                    )
                    results.append({
                        "url":         full_url,
                        "type":        "api_endpoint",
                        "description": "GET endpoint (active probe, querystring params)",
                        "severity":    SeverityLevel.info,
                        "method":      "GET",
                        "has_params":  True,
                        "param_names": all_param_names,
                        "raw_output": {
                            "source":      "get_probe",
                            "status_code": resp.status_code,
                            "params": {
                                "get":  {k: [v] for k, v in params.items()},
                                "post": {},
                                "json": {},
                                "all":  all_param_names,
                            },
                        },
                    })
                    existing_urls.add(full_url)

                except (_httpx.TimeoutException, _httpx.ConnectError):
                    continue
                except Exception as exc:
                    logger.debug(f"[katana/get-probe] {full_url}: {exc}")

        if results:
            logger.info(f"[katana/get-probe] Found {len(results)} GET endpoint(s) with params")
        return results

    def _extract_json_body_fields(
        self, body: Any, status_code: int
    ) -> Dict[str, Any]:
        """
        Extract injectable field names from a JSON validation error response.

        Handles the most common REST API error formats:
          • {"email": "required", "password": "must be ≥8 chars"}
          • {"errors": {"email": "required"}}
          • {"errors": [{"field": "email", "message": "required"}]}
          • {"message": '"email" is required'}
        """
        if not isinstance(body, dict):
            return {}

        _SKIP_KEYS = frozenset({
            "message", "error", "errors", "status", "code", "statusCode",
            "detail", "details", "msg", "data", "success", "result", "info",
            "timestamp", "path", "trace", "type",
        })
        _FIELD_NAME_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]{0,39}$')

        fields: Dict[str, Any] = {}

        # Pattern 1: top-level keys ARE field names with error strings as values
        # {"email": "required", "password": "min 8 chars"}
        if status_code in (400, 422):
            for key, val in body.items():
                if key in _SKIP_KEYS:
                    continue
                if _FIELD_NAME_RE.match(key) and isinstance(val, (str, list, dict, bool)):
                    fields[key] = ""

        # Pattern 2: nested under "errors" / "error" key as a dict
        # {"errors": {"email": "required"}}
        if not fields:
            for wrapper in ("errors", "error", "validation", "validationErrors", "fieldErrors"):
                sub = body.get(wrapper)
                if isinstance(sub, dict):
                    for key in sub:
                        if _FIELD_NAME_RE.match(key) and key not in _SKIP_KEYS:
                            fields[key] = ""
                    if fields:
                        break

        # Pattern 3: array of {field/param/name/path: "...", message: "..."}
        # {"errors": [{"field": "email", "message": "required"}]}
        if not fields:
            for wrapper in ("errors", "error", "validation", "details"):
                sub = body.get(wrapper)
                if isinstance(sub, list):
                    for item in sub:
                        if not isinstance(item, dict):
                            continue
                        fname = (
                            item.get("field")
                            or item.get("param")
                            or item.get("name")
                            or item.get("path")
                            or item.get("key")
                        )
                        if fname and _FIELD_NAME_RE.match(str(fname)):
                            fields[str(fname)] = ""
                    if fields:
                        break

        # Pattern 4: extract field names from the error message string via regex
        # {"message": '"email" is required, "password" must be a string'}
        if not fields:
            message = (
                body.get("message")
                or body.get("error")
                or body.get("msg")
                or body.get("detail")
                or ""
            )
            if isinstance(message, str) and len(message) < 1000:
                for m in re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})"', message):
                    if m not in _SKIP_KEYS and _FIELD_NAME_RE.match(m):
                        fields[m] = ""

        return fields

    def _openapi_to_results(
        self,
        api_paths: List[Dict[str, Any]],
        spec_url: str,
    ) -> List[Dict[str, Any]]:
        """
        Convert _extract_openapi_paths() dicts to DB result records.

        GET endpoints  → type='api_endpoint' (inspector reads via openapi_param_map)
        POST/PUT/PATCH with JSON body → type='endpoint' with raw_output.params.json
          so inspector reads them via json_endpoint_map and tests JSON body fields.
        POST/PUT/PATCH without JSON body → type='api_endpoint' (fallback)
        """
        results = []
        for ep in api_paths:
            method     = ep["method"]
            json_body  = ep.get("json_body", {})
            is_mutating = method in ("POST", "PUT", "PATCH")

            if is_mutating and json_body:
                # Inspector json_endpoint_map path
                all_fields = list(json_body.keys())
                results.append({
                    "url":         ep["url"],
                    "type":        "endpoint",
                    "description": f"OpenAPI endpoint [{method}] {ep['path']} (JSON body)",
                    "severity":    SeverityLevel.info,
                    "method":      method,
                    "has_params":  True,
                    "param_names": ep["param_names"],
                    "json_params": json_body,
                    "raw_output": {
                        "source":    "openapi_spec",
                        "spec_url":  spec_url,
                        "operation": ep.get("operation", {}),
                        "params": {
                            "get":  {},
                            "post": {},
                            "json": json_body,
                            "all":  ep["param_names"],
                        },
                    },
                })
            else:
                # Inspector openapi_param_map path (query/path params)
                results.append({
                    "url":         ep["url"],
                    "type":        "api_endpoint",
                    "description": f"OpenAPI endpoint [{method}] {ep['path']}",
                    "severity":    SeverityLevel.info,
                    "method":      method,
                    "has_params":  ep["has_params"],
                    "param_names": ep["param_names"],
                    "raw_output": {
                        "source":    "openapi_spec",
                        "spec_url":  spec_url,
                        "operation": ep.get("operation", {}),
                        "params": {
                            "get":  {p: [] for p in ep["param_names"] if ep.get("param_in") == "query"},
                            "post": {p: [] for p in ep["param_names"] if ep.get("param_in") in ("body", "formData")},
                            "all":  ep["param_names"],
                        },
                    },
                })
        return results

    def _make_spec_result(self, url: str, type_: str) -> Dict[str, Any]:
        return {
            "url": url,
            "type": type_,
            "description": f"API schema endpoint: {url}",
            "severity": SeverityLevel.info,
            "method": "GET",
            "has_params": False,
            "param_names": [],
            "raw_output": {"source": type_},
        }

    def _extract_openapi_paths(
        self,
        spec: Dict[str, Any],
        base_url: str,
    ) -> List[Dict[str, Any]]:
        """Parse an OpenAPI 2/3 spec and return a list of endpoint dicts."""
        endpoints = []
        paths = spec.get("paths", {})
        if not isinstance(paths, dict):
            return endpoints

        # Determine base path (Swagger 2) or server URL (OpenAPI 3)
        base_path = spec.get("basePath", "")
        servers = spec.get("servers", [])
        if servers and isinstance(servers, list):
            base_path = servers[0].get("url", "")

        http_methods = ("get", "post", "put", "patch", "delete", "options", "head")

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.lower() not in http_methods:
                    continue
                if not isinstance(operation, dict):
                    continue

                # Collect parameter names and positions
                params   = operation.get("parameters", [])
                # Also include path-level parameters
                params  += methods.get("parameters", [])

                param_names = []
                has_query   = False
                param_in    = None
                example_url = urljoin(base_url, base_path.rstrip("/") + path)

                query_params = []
                for p in params:
                    if not isinstance(p, dict):
                        continue
                    name = p.get("name", "")
                    in_  = p.get("in", "")
                    if name:
                        param_names.append(name)
                    if in_ == "query":
                        has_query = True
                        query_params.append(f"{name}=BRIAR_FUZZ")
                        param_in = "query"
                    elif in_ in ("body", "formData"):
                        param_in = in_

                # Build URL with example query params for GET
                if query_params and method.lower() == "get":
                    example_url += "?" + "&".join(query_params)

                # OpenAPI 3 requestBody — extract JSON schema properties
                # (OpenAPI 2 uses "in: body" parameter handled above)
                json_body_template: Dict[str, Any] = {}
                request_body = operation.get("requestBody", {})
                if request_body and isinstance(request_body, dict):
                    content = request_body.get("content", {})
                    json_schema = (
                        content.get("application/json", {})
                        or content.get("application/x-www-form-urlencoded", {})
                        or content.get("*/*", {})
                    )
                    schema = json_schema.get("schema", {})
                    props  = schema.get("properties", {})
                    for prop_name in props:
                        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]{0,39}$', prop_name):
                            json_body_template[prop_name] = ""
                            if prop_name not in param_names:
                                param_names.append(prop_name)
                    # "required" array may add fields missing from properties
                    for req_field in schema.get("required", []):
                        if (
                            isinstance(req_field, str)
                            and re.match(r'^[a-zA-Z_][a-zA-Z0-9_]{0,39}$', req_field)
                            and req_field not in json_body_template
                        ):
                            json_body_template[req_field] = ""
                            if req_field not in param_names:
                                param_names.append(req_field)

                endpoints.append({
                    "url":         example_url,
                    "path":        path,
                    "method":      method.upper(),
                    "has_params":  bool(param_names),
                    "param_names": param_names,
                    "param_in":    param_in,
                    "json_body":   json_body_template,   # non-empty for POST+requestBody
                    "operation":   {
                        "operationId": operation.get("operationId", ""),
                        "summary":     operation.get("summary", ""),
                        "tags":        operation.get("tags", []),
                    },
                })

        return endpoints

    async def _graphql_introspect(
        self,
        client: _httpx.AsyncClient,
        url: str,
    ) -> List[Dict[str, Any]]:
        """Send a GraphQL introspection query and extract query/mutation names."""
        introspection = {
            "query": """
            {
              __schema {
                queryType { name }
                mutationType { name }
                types {
                  name
                  kind
                  fields { name args { name type { name kind } } }
                }
              }
            }
            """
        }
        try:
            resp = await client.post(url, json=introspection, timeout=10.0)
            if resp.status_code != 200:
                return []
            data = resp.json()
            schema = data.get("data", {}).get("__schema", {})
            types  = schema.get("types", [])
            results = []
            for t in types:
                if t.get("name", "").startswith("__"):
                    continue
                if t.get("kind") not in ("OBJECT",):
                    continue
                for field in (t.get("fields") or []):
                    fname  = field.get("name", "")
                    fargs  = [a.get("name", "") for a in (field.get("args") or [])]
                    gql_url = f"{url}?query={{{fname}}}"
                    results.append({
                        "url": gql_url,
                        "type": "graphql_field",
                        "description": f"GraphQL field: {t['name']}.{fname}",
                        "severity": SeverityLevel.info,
                        "method": "POST",
                        "has_params": bool(fargs),
                        "param_names": fargs,
                        "raw_output": {
                            "source": "graphql_introspection",
                            "type": t["name"],
                            "field": fname,
                            "args": fargs,
                            "params": {"get": {}, "post": {a: [] for a in fargs}, "all": fargs},
                        },
                    })
            logger.info(f"[katana] GraphQL introspection at {url}: {len(results)} fields")
            return results
        except Exception as exc:
            logger.debug(f"[katana] GraphQL introspection failed: {exc}")
            return []


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    worker = KatanaWorker()
    await worker.start()
    try:
        while worker.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await worker.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
