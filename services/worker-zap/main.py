"""
OWASP ZAP Active Scanner Worker
=================================
Phase: DAST (parallel with Nuclei)
Sources: katana + ffuf + httpx endpoints

M8 improvements:
- AJAX Spider runs first (Chromium-based) for full SPA/JS app coverage
- Community add-ons installed on startup: ascanrulesBeta, pscanrulesBeta,
  openapi, graphql, soap — maximises detection breadth
- Active scan policy set to "Default Policy" with all rules enabled,
  plus override strength/threshold for maximum OWASP Top 10 coverage
- Passive scan rules include beta rules for additional header/config checks
- Health-check loop replaces bare sleep(15) for ZAP startup
- Auth cookies/headers properly loaded via ZAP replacer rules
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel
from shared.app_strategies import get_strategy

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("zap-worker")

# Community add-ons that significantly expand detection coverage.
# These are installed once at ZAP startup via the autoupdate API.
ZAP_ADDONS = [
    "ascanrulesBeta",   # Beta active scan rules (SSRF, CSRF bypass, XXE, etc.)
    "pscanrulesBeta",   # Beta passive scan rules (CSP, CORS, Clickjacking, etc.)
    "ascanrulesAlpha",  # Alpha active scan rules (additional experimental checks)
    "pscanrulesAlpha",  # Alpha passive scan rules
    "openapi",          # OpenAPI/Swagger active scanning support
    "graphql",          # GraphQL introspection and active scanning
    "soap",             # WSDL/SOAP service scanning
    "retire",           # Retire.js integration — JS library CVE matching
]

# Extensions that are pointless to scan with ZAP active scanner
_STATIC_EXTS = frozenset({
    ".css", ".js", ".mjs", ".ts", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".webm", ".ogg", ".wav",
    ".pdf", ".zip", ".gz", ".tar", ".rar",
})


def _is_dynamic_url(url: str) -> bool:
    """Return True for URLs ZAP should actively scan (HTML pages, API endpoints)."""
    try:
        path = urlparse(url).path.lower()
        ext = os.path.splitext(path)[1]
        return ext not in _STATIC_EXTS
    except Exception:
        return True


def _extract_base_url(target: str) -> str:
    """Return scheme://host from target URL."""
    try:
        p = urlparse(target)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    except Exception:
        pass
    return target


RISK_MAP = {
    "High":          SeverityLevel.high,
    "Medium":        SeverityLevel.medium,
    "Low":           SeverityLevel.low,
    "Informational": SeverityLevel.info,
}


class ZAPWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="zap", queue_name="scan.dast.zap")
        self.timeout             = int(os.getenv("ZAP_TIMEOUT",             "3600"))
        self.zap_port            = int(os.getenv("ZAP_PORT",                "8090"))
        self.api_key             = os.getenv("ZAP_API_KEY",                 "briar-zap-api-key-2024")
        # Max total active-scan duration in MINUTES (ZAP -config scanner.maxDuration).
        # Keep well below RabbitMQ consumer_timeout (now 4 h) and WORKER_TIMEOUT.
        self.max_duration        = int(os.getenv("ZAP_MAX_DURATION",        "40"))    # minutes
        # Max duration for a single active-scan rule in MINUTES.
        # Without this, one broken rule can stall the entire scan indefinitely.
        self.max_rule_duration   = int(os.getenv("ZAP_MAX_RULE_DURATION",   "5"))     # minutes
        self.ajax_timeout        = int(os.getenv("ZAP_AJAX_TIMEOUT",        "180"))   # seconds
        # Python-side deadline for the ascan poll loop (seconds).
        # Must be > max_duration*60 to let ZAP stop itself first; 45 min gives buffer.
        self.ascan_deadline      = int(os.getenv("ZAP_ASCAN_DEADLINE",      "2700"))  # seconds
        self.install_addons  = os.getenv("ZAP_INSTALL_ADDONS", "true").lower() not in ("false", "0", "no")

    # ── ZAP base URL ───────────────────────────────────────────────────────────

    @property
    def _base(self) -> str:
        return f"http://localhost:{self.zap_port}"

    async def _zap(self, client: httpx.AsyncClient, path: str, **params) -> dict:
        """Call the ZAP JSON API, always injecting the api key."""
        resp = await client.get(
            f"{self._base}/JSON/{path}",
            params={"apikey": self.api_key, **params},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    async def _zap_post(self, client: httpx.AsyncClient, path: str, **params) -> dict:
        """POST variant of _zap — use when params may exceed GET URL length limits.
        JWT tokens are 500-1000+ chars; ZAP's Jetty returns 400 on long query strings.
        ZAP action endpoints accept POST with application/x-www-form-urlencoded body.
        """
        resp = await client.post(
            f"{self._base}/JSON/{path}",
            data={"apikey": self.api_key, **params},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    # ── Tool entry point ───────────────────────────────────────────────────────

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [target])
        if not endpoints:
            endpoints = [target]

        # M8: app-type adaptive strategy
        app_type  = task_payload.get("app_type", "unknown")
        is_spa    = task_payload.get("is_spa", False)
        framework = task_payload.get("framework")

        strategy = get_strategy(app_type, "zap", framework)

        # Strategy flags.
        # Traditional spider is DISABLED by default — on SPAs it follows relative
        # links from Angular/React routes, creating exponentially nested garbage
        # paths (e.g. /address/assets/public/assets/public/…) that flood ZAP's
        # site tree and waste the entire active-scan budget on fake URLs.
        # The AJAX spider (Chromium-based) provides superior SPA coverage anyway.
        run_ajax_spider        = strategy.get("run_ajax_spider",        True)
        run_traditional_spider = strategy.get("run_traditional_spider", False)
        # OpenAPI import is always attempted — the method checks well-known paths
        # and does nothing if no spec is found.  Costs ~1 s; gains full API coverage
        # on targets like Juice Shop that expose /openapi.json without any tech hint.
        run_openapi_import     = strategy.get("run_openapi_import",     True)
        ajax_timeout_strat     = strategy.get("ajax_timeout")

        # SPA: extend AJAX timeout if strategy or is_spa flag says so
        if is_spa and not ajax_timeout_strat:
            ajax_timeout_strat = 240
        if ajax_timeout_strat:
            self.ajax_timeout = max(self.ajax_timeout, int(ajax_timeout_strat))

        logger.info(
            f"[zap] M8 strategy (app_type={app_type!r}, framework={framework!r}): "
            f"ajax={run_ajax_spider}, traditional={run_traditional_spider}, "
            f"openapi={run_openapi_import}, ajax_timeout={self.ajax_timeout}s"
        )

        # Derive the base URL (scheme://host) for spidering and alert collection
        base_url = _extract_base_url(target)

        # Only feed dynamic (non-static) URLs to ZAP — static assets slow it down
        # massively and produce zero useful findings.
        dynamic_endpoints = [ep for ep in endpoints if _is_dynamic_url(ep)]
        logger.info(
            f"[zap] {len(dynamic_endpoints)}/{len(endpoints)} dynamic endpoints "
            f"will be seeded into ZAP (static files excluded)"
        )

        zap_process: Optional[asyncio.subprocess.Process] = None
        try:
            zap_process = await self._start_zap_daemon()
            await self._wait_for_zap_ready()

            async with httpx.AsyncClient() as client:
                # Install community add-ons for maximum coverage
                if self.install_addons:
                    await self._install_addons(client)

                # Load auth into ZAP
                await self._load_auth(client, auth_context)

                # Seed all dynamic endpoints into ZAP's site tree
                for ep in dynamic_endpoints:
                    try:
                        await self._zap(client, "core/action/accessUrl/", url=ep)
                    except Exception:
                        pass

                # ── Phase 1: OpenAPI import (API/GraphQL app types) ───────────
                if run_openapi_import:
                    await self._run_openapi_import(client, target, task_payload)

                # ── Phase 2: AJAX Spider (Chromium-based, best for SPAs) ───────
                if run_ajax_spider:
                    logger.info("[zap] Starting AJAX Spider (SPA/JS coverage phase)…")
                    await self._run_ajax_spider(client, target)
                else:
                    logger.info(f"[zap] AJAX Spider skipped (app_type={app_type!r})")

                # ── Phase 3: Traditional Spider (link following) ───────────────
                if run_traditional_spider:
                    spider_id = await self._start_spider(client, base_url)
                    await self._wait_scan(client, "spider", spider_id)
                else:
                    logger.info(f"[zap] Traditional Spider skipped (app_type={app_type!r})")

                # ── Phase 3.5: Exclusions — keep active scanner on API paths ──
                # Exclude static assets and SPA frontend routes from active scan.
                # Without this, ZAP attacks hundreds of .js/.css files and
                # Angular router paths that all return the same index.html,
                # producing zero findings while consuming the entire scan budget.
                await self._add_ascan_exclusions(client)

                # ── Phase 4: Active Scan ───────────────────────────────────────
                ascan_id = await self._start_ascan(client, base_url)
                # Use a tighter deadline for the active scan so the Python loop
                # exits cleanly before RabbitMQ's consumer_timeout fires.
                await self._wait_scan(client, "ascan", ascan_id,
                                      deadline_secs=self.ascan_deadline)

                return await self._collect_alerts(client, base_url)

        except Exception as exc:
            logger.error(f"[zap] Execution failed: {exc}", exc_info=True)
            return []
        finally:
            if zap_process:
                zap_process.terminate()
                try:
                    await asyncio.wait_for(zap_process.wait(), timeout=15)
                except asyncio.TimeoutError:
                    zap_process.kill()

    # ── ZAP daemon management ──────────────────────────────────────────────────

    async def _kill_stale_zap(self):
        """
        Kill any leftover ZAP process from a previous (timed-out) run.
        Without this, a redelivered task finds the port already in use and fails
        immediately with 'All connection attempts failed'.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "pkill", "-f", f"zap.*port.*{self.zap_port}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            await asyncio.sleep(2)  # give the port time to release
        except Exception:
            pass  # no stale process — that's fine

    async def _start_zap_daemon(self) -> asyncio.subprocess.Process:
        # Clean up any previous ZAP instance before starting a new one.
        await self._kill_stale_zap()

        cmd = [
            "/zap/zap.sh",
            "-daemon",
            "-port",   str(self.zap_port),
            "-host",   "127.0.0.1",
            "-config", f"api.key={self.api_key}",
            "-config", "api.disablekey=false",
            # Hard cap on total active scan time — ZAP stops itself cleanly.
            "-config", f"scanner.maxDuration={self.max_duration}",
            # Per-rule cap — prevents a single slow rule from blocking the scan.
            "-config", f"scanner.maxRuleDurationInMins={self.max_rule_duration}",
            "-config", "spider.maxDuration=5",
            "-config", "ascan.attackPolicy=Default Policy",
        ]
        logger.info(f"[zap] Starting ZAP daemon on port {self.zap_port}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return proc

    async def _wait_for_zap_ready(self, max_wait: int = 120):
        """Poll ZAP's API until it responds — much safer than a fixed sleep."""
        deadline = asyncio.get_event_loop().time() + max_wait
        while asyncio.get_event_loop().time() < deadline:
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        f"{self._base}/JSON/core/view/version/",
                        params={"apikey": self.api_key},
                        timeout=5,
                    )
                    if resp.status_code == 200:
                        version = resp.json().get("version", "?")
                        logger.info(f"[zap] Ready — version {version}")
                        return
            except Exception:
                pass
            await asyncio.sleep(3)
        raise TimeoutError("[zap] ZAP daemon did not start in time")

    # ── Community add-on installation ─────────────────────────────────────────

    async def _install_addons(self, client: httpx.AsyncClient):
        """
        Install community add-ons via ZAP's autoupdate API.
        Each add-on expands the rule set; failures are non-fatal.
        """
        logger.info(f"[zap] Installing {len(ZAP_ADDONS)} community add-ons…")
        for addon_id in ZAP_ADDONS:
            try:
                result = await self._zap(
                    client,
                    "autoupdate/action/installAddon/",
                    id=addon_id,
                )
                logger.info(f"[zap] Add-on '{addon_id}': {result.get('Result', result)}")
            except Exception as exc:
                logger.warning(f"[zap] Could not install add-on '{addon_id}': {exc}")

        # Brief pause to let ZAP reload after add-on installs
        await asyncio.sleep(5)

    # ── Auth loading ───────────────────────────────────────────────────────────

    async def _load_auth(self, client: httpx.AsyncClient, auth_context: Dict[str, Any]):
        """Add cookies and custom headers via ZAP's replacer API.

        ZAP 2.15+ replacer addRule requires the `url` parameter (empty = all URLs).
        Without it the API returns HTTP 400.  Always pass url="" explicitly.
        """
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            try:
                await self._zap(
                    client,
                    "replacer/action/addRule/",
                    description="briar-auth-cookie",
                    enabled="true",
                    matchtype="REQ_HEADER",
                    matchregex="false",
                    matchstring="Cookie",
                    replacement=cookie_str,
                    initiators="",
                    url="",
                )
                logger.info("[zap] Auth cookie injected via replacer")
            except Exception as exc:
                logger.warning(f"[zap] Failed to set cookie: {exc}")

        for name, value in auth_context.get("headers", {}).items():
            try:
                # Use POST: JWT Bearer tokens are 500-1000+ chars and exceed
                # ZAP's Jetty URL length limit when passed as GET query params.
                await self._zap_post(
                    client,
                    "replacer/action/addRule/",
                    description=f"briar-header-{name}",
                    enabled="true",
                    matchtype="REQ_HEADER",
                    matchregex="false",
                    matchstring=name,
                    replacement=value,
                    initiators="",
                    url="",
                )
                logger.info(f"[zap] Auth header '{name}' injected via replacer")
            except Exception as exc:
                logger.warning(f"[zap] Failed to set header {name}: {exc}")

    # ── OpenAPI / Swagger import (M8: API apps) ───────────────────────────────

    async def _run_openapi_import(
        self,
        client: httpx.AsyncClient,
        target: str,
        task_payload: Dict[str, Any],
    ):
        """
        Import an OpenAPI/Swagger spec into ZAP so the active scanner knows
        every endpoint without needing to crawl.

        Tries, in order:
          1. Explicit spec URL from task_payload["openapi_url"]
          2. Well-known spec paths probed against the target host
        """
        # Explicit spec URL takes priority
        spec_url: Optional[str] = task_payload.get("openapi_url")

        if not spec_url:
            # Probe common OpenAPI spec paths.
            # /api-docs first — Juice Shop returns JSON spec when asked with
            # Accept: application/json. Use follow_redirects=True and record
            # the *final* URL so ZAP's importUrl doesn't hit a 301.
            base = _extract_base_url(target)
            candidates = [
                f"{base}/api-docs",
                f"{base}/api-docs/",
                f"{base}/v2/api-docs",   # Spring Boot default
                f"{base}/v3/api-docs",
                f"{base}/openapi.json",
                f"{base}/openapi.yaml",
                f"{base}/swagger.json",
                f"{base}/swagger.yaml",
                f"{base}/api/openapi.json",
                f"{base}/api/swagger.json",
                f"{base}/v1/openapi.json",
            ]
            for candidate in candidates:
                try:
                    resp = await client.get(
                        candidate,
                        timeout=5,
                        follow_redirects=True,
                        headers={"Accept": "application/json"},
                    )
                    if resp.status_code == 200 and (
                        "openapi" in resp.text[:200].lower()
                        or "swagger" in resp.text[:200].lower()
                        or ('"paths"' in resp.text[:500] and '"info"' in resp.text[:500])
                    ):
                        # Use the final URL after redirects so ZAP importUrl succeeds
                        spec_url = str(resp.url)
                        logger.info(f"[zap] OpenAPI spec discovered at {spec_url}")
                        break
                except Exception:
                    continue

        if not spec_url:
            logger.info("[zap] OpenAPI import: no spec found at well-known paths")
            return

        try:
            result = await self._zap(
                client,
                "openapi/action/importUrl/",
                url=spec_url,
                hostOverride=_extract_base_url(target),
            )
            logger.info(f"[zap] OpenAPI import result: {result}")
        except Exception as exc:
            logger.warning(f"[zap] OpenAPI import failed (add-on not loaded?): {exc}")

    # ── AJAX Spider (M8: SPA/JS coverage) ─────────────────────────────────────

    async def _run_ajax_spider(self, client: httpx.AsyncClient, target: str):
        """
        Run the AJAX Spider which uses Chromium to render JS and discover routes
        that the traditional (link-following) spider would miss entirely.

        This is the primary crawling mechanism for React, Angular, Vue, and other
        SPA frameworks where most routes are defined in JS, not in HTML <a> tags.
        """
        try:
            # Start AJAX Spider
            result = await self._zap(client, "ajaxSpider/action/scan/", url=target)
            logger.info(f"[zap] AJAX Spider started: {result}")

            # Poll until stopped (AJAX Spider returns text status, not percentage)
            deadline = asyncio.get_event_loop().time() + self.ajax_timeout
            while asyncio.get_event_loop().time() < deadline:
                await asyncio.sleep(10)
                try:
                    status_data = await self._zap(client, "ajaxSpider/view/status/")
                    status = status_data.get("status", "running")
                    logger.info(f"[zap] AJAX Spider status: {status}")
                    if status == "stopped":
                        # Log what was found
                        try:
                            results_data = await self._zap(
                                client, "ajaxSpider/view/numberOfResults/"
                            )
                            count = results_data.get("numberOfResults", "?")
                            logger.info(f"[zap] AJAX Spider complete — {count} resources discovered")
                        except Exception:
                            pass
                        return
                except Exception as exc:
                    logger.warning(f"[zap] AJAX Spider status poll error: {exc}")

            # If timeout reached, stop it manually
            logger.warning(f"[zap] AJAX Spider timed out after {self.ajax_timeout}s — stopping")
            try:
                await self._zap(client, "ajaxSpider/action/stop/")
            except Exception:
                pass

        except Exception as exc:
            logger.warning(f"[zap] AJAX Spider unavailable (add-on not loaded?): {exc}")

    # ── Traditional Spider ─────────────────────────────────────────────────────

    async def _start_spider(self, client: httpx.AsyncClient, target: str) -> str:
        data = await self._zap(client, "spider/action/scan/", url=target)
        scan_id = data.get("scan", "0")
        logger.info(f"[zap] Traditional Spider started, id={scan_id}")
        return scan_id

    # ── Exclusion patterns ────────────────────────────────────────────────────

    # Patterns for URLs that should NOT be active-scanned.
    # ZAP 2.12+ accepts these via core/action/excludeFromProxy/ which removes
    # the URL from ZAP's proxy tree entirely — the active scanner never sees them.
    #
    # Why excludeFromProxy and not ascan/action/addExcludedURL/:
    #   The addExcludedURL endpoint returns 400 in ZAP ≥2.12 (renamed/removed).
    #   excludeFromProxy is stable across all ZAP 2.x versions.
    _PROXY_EXCLUDES = [
        # Static asset extensions — no injection surface
        r".*\.(css|map|woff2?|ttf|eot|otf|ico|png|jpg|jpeg|gif|svg|webp|mp4|webm)(\?.*)?$",
        # socket.io long-polling — creates many "Session ID in URL" noise findings
        r".*/socket\.io/.*",
        # SPA nested paths created by traditional spider recursion
        r".*/assets/public/assets/.*",
        r".*/node_modules/.*",
        r".*/build/routes/.*",
        # Stack-trace lines leaked as URLs (serve-index / express router)
        r".*\.js:\d+:\d+$",
    ]

    async def _add_ascan_exclusions(self, client: httpx.AsyncClient):
        """
        Exclude static/noisy URLs from ZAP's proxy tree so the active scanner
        focuses on real application endpoints.

        Uses core/action/excludeFromProxy/ (ZAP 2.x stable API).
        """
        ok = 0
        for pattern in self._PROXY_EXCLUDES:
            try:
                await self._zap(client, "core/action/excludeFromProxy/", regex=pattern)
                ok += 1
            except Exception as exc:
                logger.debug(f"[zap] Exclusion failed for {pattern!r}: {exc}")
        logger.info(f"[zap] Registered {ok}/{len(self._PROXY_EXCLUDES)} proxy exclusion patterns")

    # ── Active scan ────────────────────────────────────────────────────────────

    async def _start_ascan(self, client: httpx.AsyncClient, target: str) -> str:
        data = await self._zap(client, "ascan/action/scan/", url=target)
        scan_id = data.get("scan", "0")
        logger.info(f"[zap] Active scan started, id={scan_id}")
        return scan_id

    # ── Poll until done ────────────────────────────────────────────────────────

    async def _wait_scan(
        self,
        client: httpx.AsyncClient,
        scan_type: str,
        scan_id: str,
        deadline_secs: int | None = None,
    ):
        """
        Poll ZAP scan progress until 100 (complete).
        scan_type must be "spider" or "ascan" — these are the actual ZAP API namespaces.
        deadline_secs overrides self.timeout for scans that need a tighter limit.
        """
        limit = deadline_secs if deadline_secs is not None else self.timeout
        deadline = asyncio.get_event_loop().time() + limit
        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(10)
            try:
                data = await self._zap(
                    client, f"{scan_type}/view/status/", scanId=scan_id
                )
                progress = int(data.get("status", 0))
                logger.info(f"[zap] {scan_type} progress: {progress}%")
                if progress >= 100:
                    logger.info(f"[zap] {scan_type} complete")
                    return
            except Exception as exc:
                logger.warning(f"[zap] Status poll error ({scan_type}): {exc}")
        logger.warning(f"[zap] {scan_type} timed out after {self.timeout}s")

    # ── Collect results ────────────────────────────────────────────────────────

    async def _collect_alerts(
        self, client: httpx.AsyncClient, target: str
    ) -> List[Dict[str, Any]]:
        try:
            data = await self._zap(
                client, "core/view/alerts/", baseurl=target, start="0", count="0"
            )
        except Exception as exc:
            logger.error(f"[zap] Failed to collect alerts: {exc}")
            return []

        results: List[Dict[str, Any]] = []
        for alert in data.get("alerts", []):
            results.append({
                "url":         alert.get("url", target),
                "type":        f"ZAP-{alert.get('pluginId', '')}",
                "description": alert.get("name", alert.get("description", "")),
                "severity":    RISK_MAP.get(alert.get("risk", ""), SeverityLevel.info),
                "raw_output": {
                    "name":        alert.get("name"),
                    "description": alert.get("description"),
                    "solution":    alert.get("solution"),
                    "reference":   alert.get("reference"),
                    "cweid":       alert.get("cweid"),
                    "wascid":      alert.get("wascid"),
                    "evidence":    alert.get("evidence"),
                    "param":       alert.get("param"),
                    "attack":      alert.get("attack"),
                    "pluginId":    alert.get("pluginId"),
                    "risk":        alert.get("risk"),
                    "confidence":  alert.get("confidence"),
                    "tags":        alert.get("tags", {}),
                },
            })

        logger.info(f"[zap] Collected {len(results)} alerts")
        return results


async def main():
    worker = ZAPWorker()
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
