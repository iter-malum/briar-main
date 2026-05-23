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
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import httpx as _httpx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("katana-worker")

# ── Well-known API spec paths to probe ────────────────────────────────────────

API_SPEC_PATHS = [
    # OpenAPI / Swagger
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/api/docs/openapi.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/docs/openapi.json",
    # Swagger UI endpoint hints
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/api-docs",
    "/api-docs/",
    "/swagger",
    "/docs",
    "/redoc",
    # Spring Boot / Actuator
    "/v2/api-docs",
    "/v3/api-docs",
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
        # Default timeout is 1 hour — quality over speed.
        # Juice Shop / Angular / React SPAs need 10-30 min of headless crawling
        # to surface all routes. Set KATANA_TIMEOUT=600 in docker-compose to
        # trade coverage for speed on lightweight targets.
        self.timeout          = int(os.getenv("KATANA_TIMEOUT",        "3600"))
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
        app_type = task_payload.get("app_type", "unknown")
        is_spa   = task_payload.get("is_spa", False)

        # Headless mode: explicit override > env var default > SPA auto-detect
        headless_override = task_payload.get("headless")
        if headless_override is not None:
            use_headless = headless_override
        elif is_spa:
            use_headless = True   # Always enable Chromium for detected SPAs
            logger.info(f"[katana] SPA detected ({app_type}) — forcing headless mode")
        else:
            use_headless = self.headless

        # SPA-aware crawl depth: deeper when rendering JS
        effective_depth = self.headless_depth if use_headless else self.depth

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
            "-strategy", "breadth-first",   # Wider coverage before going deep (better for time-bounded runs)
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

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=10 * 1024 * 1024,  # 10 MB line buffer
                cwd=work_dir,
            )

            await asyncio.wait_for(
                asyncio.gather(
                    self._read_stream(process.stdout, results, is_stderr=False),
                    self._read_stream(process.stderr, None, is_stderr=True),
                    process.wait(),
                ),
                timeout=self.timeout,
            )

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
        for r in schema_results:
            if r["url"] not in existing_urls:
                results.append(r)
                existing_urls.add(r["url"])

        # ── M8: JS endpoint extraction ─────────────────────────────────────────
        if self.js_extract:
            js_results = await self._extract_js_endpoints(results, target, headers, cookies)
            for r in js_results:
                if r["url"] not in existing_urls:
                    results.append(r)
                    existing_urls.add(r["url"])

        logger.info(f"[katana] Total unique endpoints: {len(results)}")
        return results

    # ── JSONL stream parser ────────────────────────────────────────────────────

    async def _read_stream(
        self,
        stream,
        results_list: Optional[List],
        is_stderr: bool = False,
    ):
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

                # Extract POST body params (application/x-www-form-urlencoded)
                post_params: Dict[str, List[str]] = {}
                if body and "=" in body and not body.strip().startswith("{"):
                    try:
                        post_params = parse_qs(body)
                    except Exception:
                        pass

                # Combine all known parameter names
                all_param_names = list(get_params.keys()) + list(post_params.keys())

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
                            "all":  all_param_names,
                        },
                    },
                })

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
                        # Rule 1: template literal artifacts
                        if self._TEMPLATE_ARTIFACT_RE.search(raw_path):
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

                        # Resolve to absolute URL
                        if raw_path.startswith("/"):
                            abs_url = origin + raw_path
                        else:
                            abs_url = urljoin(js_url, raw_path)

                        # Only keep URLs on the same origin
                        if not abs_url.startswith(origin):
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
                        try:
                            spec = resp.json()
                            api_paths = self._extract_openapi_paths(spec, origin)
                            for ep in api_paths:
                                results.append({
                                    "url": ep["url"],
                                    "type": "api_endpoint",
                                    "description": f"API endpoint from {path}: [{ep['method']}] {ep['path']}",
                                    "severity": SeverityLevel.info,
                                    "method": ep["method"],
                                    "has_params": ep["has_params"],
                                    "param_names": ep["param_names"],
                                    "raw_output": {
                                        "source": "openapi_spec",
                                        "spec_url": url,
                                        "operation": ep.get("operation", {}),
                                        "params": {
                                            "get":  {p: [] for p in ep["param_names"] if ep.get("param_in") == "query"},
                                            "post": {p: [] for p in ep["param_names"] if ep.get("param_in") in ("body", "formData")},
                                            "all":  ep["param_names"],
                                        },
                                    },
                                })
                            if api_paths:
                                logger.info(f"[katana] OpenAPI spec at {url}: extracted {len(api_paths)} endpoints")
                            # Save the spec endpoint itself
                            results.append(self._make_spec_result(url, "openapi_spec"))
                            continue
                        except Exception:
                            pass

                    # ── GraphQL endpoint ───────────────────────────────────────
                    if "graphql" in path.lower():
                        gql_endpoints = await self._graphql_introspect(client, url)
                        results.extend(gql_endpoints)
                        if not gql_endpoints:
                            # Still record the endpoint exists
                            results.append(self._make_spec_result(url, "graphql_endpoint"))
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

                endpoints.append({
                    "url":         example_url,
                    "path":        path,
                    "method":      method.upper(),
                    "has_params":  bool(param_names),
                    "param_names": param_names,
                    "param_in":    param_in,
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
