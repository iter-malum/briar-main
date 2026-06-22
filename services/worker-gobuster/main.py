"""
Gobuster Brute-Forcer Worker
============================
Runs gobuster in dir / dns / vhost mode against discovered targets from the
PROBE phase.  Queue: scan.probe.gobuster

Modes
-----
dir   – brute-force paths against a web URL
dns   – enumerate sub-domains of a domain
vhost – enumerate virtual-hosts against a web URL
"""

import asyncio
import logging
import os
import re
import sys
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

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
logger = logging.getLogger("gobuster-worker")

# ── Constants ──────────────────────────────────────────────────────────────────

WORK_DIR = "/tmp/gobuster"
OUTPUT_FILE = f"{WORK_DIR}/output.txt"

# Regex patterns for each mode's output format
_DIR_RE = re.compile(r"^(/\S+)\s+\(Status:\s*(\d+)\)")
_DNS_RE = re.compile(r"^Found:\s+(\S+)")
_VHOST_RE = re.compile(r"^Found:\s+(\S+)\s+\(Status:\s*(\d+)\)")


# ── Worker ─────────────────────────────────────────────────────────────────────

class GobusterWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="gobuster", queue_name="scan.probe.gobuster")

        self.default_mode = os.getenv("GOBUSTER_MODE", "dir")
        self.threads = int(os.getenv("GOBUSTER_THREADS", "20"))
        self.timeout = int(os.getenv("GOBUSTER_TIMEOUT", "10"))
        # raft-medium-words covers both classic paths and REST API segments.
        # common.txt is web-page oriented and misses most /api/* REST paths.
        # Override with GOBUSTER_WORDLIST env if a different list is needed.
        self.wordlist = os.getenv(
            "GOBUSTER_WORDLIST",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
        )
        self.extensions = os.getenv("GOBUSTER_EXTENSIONS", "php,html,js,txt")

    # ── Main entry point ───────────────────────────────────────────────────────

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        mode = task_payload.get("mode") or self.default_mode
        endpoints: List[str] = task_payload.get("endpoints", [])

        os.makedirs(WORK_DIR, exist_ok=True)

        # M8: app-type adaptive strategy — override extensions unless explicitly
        # provided in the task payload (payload wins for manual overrides).
        if "extensions" not in task_payload:
            strategy = get_strategy(
                task_payload.get("app_type", "unknown"),
                "gobuster",
                task_payload.get("framework"),
            )
            if strategy.get("extensions"):
                task_payload = {**task_payload, "extensions": strategy["extensions"]}
                logger.info(
                    f"[gobuster] M8 extensions override "
                    f"(app_type={task_payload.get('app_type', 'unknown')!r}): "
                    f"{strategy['extensions']}"
                )

        if mode == "dir":
            return await self._run_dir(endpoints, target, auth_context, task_payload)
        elif mode == "dns":
            return await self._run_dns(endpoints, target, task_payload)
        elif mode == "vhost":
            return await self._run_vhost(endpoints, target, auth_context, task_payload)
        else:
            logger.warning(f"[gobuster] Unknown mode '{mode}', falling back to 'dir'")
            return await self._run_dir(endpoints, target, auth_context, task_payload)

    # ── Dir mode ───────────────────────────────────────────────────────────────

    async def _run_dir(
        self,
        endpoints: List[str],
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        # Always brute-force against the base URL (scheme+host), never a specific file path
        url = _extract_base_url(target, endpoints)
        if not url:
            logger.warning("[gobuster] No URL available for dir mode")
            return []

        wordlist = task_payload.get("wordlist", self.wordlist)
        extensions = task_payload.get("extensions", self.extensions)
        threads = int(task_payload.get("threads", self.threads))
        timeout = int(task_payload.get("timeout", self.timeout))

        # Build auth headers dict for wildcard probe and gobuster -H flags
        auth_headers: Dict[str, str] = dict(auth_context.get("headers", {}))
        cookies = auth_context.get("cookies", [])
        if cookies:
            auth_headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in cookies)

        # Detect wildcard response length.
        # SPAs (Juice Shop, React, Angular, Vue) return HTTP 200 + index.html for
        # every unknown path.  Gobuster 3.5+ detects this and exits with error 1
        # unless we explicitly pass --exclude-length <size> to filter out the
        # wildcard response.  Probe a random UUID path to discover the size.
        exclude_lengths: Optional[str] = None
        wildcard_size = await _probe_wildcard_size(url, auth_headers)
        if wildcard_size is not None:
            exclude_lengths = str(wildcard_size)
            logger.info(
                f"[gobuster] Wildcard detected at {url}: "
                f"all unknown paths → {wildcard_size} bytes. "
                f"Adding --exclude-length {wildcard_size}"
            )

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-x", extensions,
            "-t", str(threads),
            "--timeout", f"{timeout}s",
            "--no-progress",
            "--output", OUTPUT_FILE,
            # Use -b (blacklist) instead of -s (whitelist) — they cannot coexist.
            # Blacklist: hide 404 (not found), 429 (rate-limited), 500/503 (overloaded).
            # Everything else (200, 301, 302, 401, 403, 405) is shown.
            "-b", "404,429,500,503",
        ]

        # Exclude the wildcard response length so gobuster doesn't bail out
        if exclude_lengths:
            cmd.extend(["--exclude-length", exclude_lengths])

        # Inject auth headers
        for key, value in auth_headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        logger.info(f"[gobuster] dir mode → {url}")
        await self._run_gobuster(cmd, timeout)

        results = _parse_dir_output(OUTPUT_FILE, url)

        # Always probe high-value paths directly — these are fast single GETs
        # that ensure critical paths (FTP dumps, admin panels, .git, .env) are
        # never missed even if the main wordlist doesn't cover them.
        supplemental = await _probe_supplemental_paths(url, auth_headers)
        found_urls = {r["url"] for r in results}
        for r in supplemental:
            if r["url"] not in found_urls:
                results.append(r)

        # M19: legacy endpoint + CSP header audit
        legacy_findings = await _probe_legacy_csp(url, auth_headers)
        found_urls = {r["url"] for r in results}
        for r in legacy_findings:
            if r["url"] not in found_urls:
                results.append(r)

        # M23: information disclosure audit
        info_disc = await _probe_info_disclosure(url, auth_headers)
        found_urls = {r["url"] for r in results}
        for r in info_disc:
            if r["url"] not in found_urls:
                results.append(r)

        return results

    # ── DNS mode ───────────────────────────────────────────────────────────────

    async def _run_dns(
        self,
        endpoints: List[str],
        target: str,
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        # Derive domain from first endpoint or target
        domain = task_payload.get("domain") or _extract_domain(endpoints, target)
        if not domain:
            logger.warning("[gobuster] No domain available for dns mode")
            return []

        wordlist = task_payload.get("wordlist", self.wordlist)
        threads = int(task_payload.get("threads", self.threads))
        timeout = int(task_payload.get("timeout", self.timeout))

        cmd = [
            "gobuster", "dns",
            "-d", domain,
            "-w", wordlist,
            "-t", str(threads),
            "--timeout", f"{timeout}s",
            "--no-progress",
            "--output", OUTPUT_FILE,
        ]

        logger.info(f"[gobuster] dns mode → {domain}")
        await self._run_gobuster(cmd, timeout)

        return _parse_dns_output(OUTPUT_FILE)

    # ── VHost mode ─────────────────────────────────────────────────────────────

    async def _run_vhost(
        self,
        endpoints: List[str],
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        url = _extract_base_url(target, endpoints)
        if not url:
            logger.warning("[gobuster] No URL available for vhost mode")
            return []

        wordlist = task_payload.get("wordlist", self.wordlist)
        threads = int(task_payload.get("threads", self.threads))
        timeout = int(task_payload.get("timeout", self.timeout))

        cmd = [
            "gobuster", "vhost",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "--timeout", f"{timeout}s",
            "--no-progress",
            "--output", OUTPUT_FILE,
        ]

        # Inject auth headers
        for key, value in auth_context.get("headers", {}).items():
            cmd.extend(["-H", f"{key}: {value}"])

        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            cmd.extend(["-H", f"Cookie: {cookie_str}"])

        logger.info(f"[gobuster] vhost mode → {url}")
        await self._run_gobuster(cmd, timeout)

        return _parse_vhost_output(OUTPUT_FILE, url)

    # ── Subprocess helper ──────────────────────────────────────────────────────

    async def _run_gobuster(self, cmd: List[str], tool_timeout: int) -> None:
        """Execute gobuster as a subprocess; respects worker-level timeout."""
        # Add a generous process-level timeout on top of gobuster's own timeout
        process_timeout = tool_timeout * 60 + 60  # minutes buffer

        # Remove stale output file
        if os.path.exists(OUTPUT_FILE):
            os.unlink(OUTPUT_FILE)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=WORK_DIR,
            )

            try:
                _, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=process_timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning("[gobuster] Process timed out — partial results may exist")
                return

            if process.returncode not in (0, None):
                err = stderr_data.decode("utf-8", errors="ignore").strip()
                if err:
                    logger.warning(f"[gobuster] exit {process.returncode}: {err[:500]}")

        except FileNotFoundError:
            logger.error("[gobuster] 'gobuster' binary not found in PATH")


# ── High-value supplemental paths ────────────────────────────────────────────
#
# These are known high-value paths that appear in real apps and CTF targets.
# Gobuster's wordlist will find most of them on a slow scan, but we probe these
# directly to ensure they are always surfaced regardless of wordlist coverage.

_SUPPLEMENTAL_PATHS = [
    # FTP / file dumps (OWASP Juice Shop, legacy apps)
    "/ftp",
    "/ftp/acquisitions.md",
    "/ftp/package.json.bak",
    "/ftp/coupons_2013.md.bak",
    "/ftp/eastere.gg",
    "/ftp/incident-support.kdbx",
    "/ftp/legal.md",
    "/ftp/quarantine",
    # Backup / source files
    "/backup",
    "/backup.zip",
    "/backup.tar.gz",
    "/.git/HEAD",
    "/.git/config",
    "/source.zip",
    "/dump.sql",
    # Admin panels
    "/admin",
    "/admin/",
    "/administrator",
    "/manager",
    "/management",
    "/wp-admin",
    "/phpmyadmin",
    # Monitoring / diagnostics
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/debug",
    "/console",
    "/health",
    "/status",
    "/info",
    "/_debug",
    # Logs
    "/logs",
    "/log",
    "/logs/access.log",
    "/error.log",
    # Config / secrets
    "/.env",
    "/config.php",
    "/config.json",
    "/configuration.php",
    "/web.config",
    "/app.config",
    "/settings.py",
    # GraphQL / API schema
    "/graphql",
    "/graphiql",
    "/playground",
    "/api/graphql",
    "/swagger-ui.html",
    "/api-docs",
    "/swagger.json",
    # Test / dev artifacts
    "/test",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
]


# ── M23: Information Disclosure audit ────────────────────────────────────────
#
# Probes for Juice Shop challenges:
#   Access Log              – /ftp/access.log download
#   Misplaced Signature     – /ftp/legal.md, /ftp/encrypt.pyc
#   Error Handling          – trigger 400/500 and detect stack-trace leak
#   Security Policy         – /security.txt, /.well-known/security.txt
#   Blockchain Hype         – chatbot with trigger phrase leaks private key
#   Missing Encoding        – /api/... endpoints with unencoded chars in body

_SENSITIVE_FTP_FILES = [
    ("/ftp/access.log",    "access_log_exposure",        "high",   "A02:2021 – Cryptographic Failures"),
    ("/ftp/encrypt.pyc",   "sensitive_file_exposure",    "high",   "A02:2021 – Cryptographic Failures"),
    ("/ftp/legal.md",      "sensitive_file_exposure",    "medium", "A05:2021 – Security Misconfiguration"),
    ("/ftp/package.json.bak", "sensitive_file_exposure", "high",   "A05:2021 – Security Misconfiguration"),
    ("/ftp/acquisitions.md",  "sensitive_file_exposure", "high",   "A02:2021 – Cryptographic Failures"),
    ("/ftp/coupons_2013.md.bak", "sensitive_file_exposure", "medium", "A05:2021 – Security Misconfiguration"),
]

_ERROR_TRIGGER_PATHS = [
    "/rest/products/search?q=',",
    "/api/Users/undefined",
    "/api/BasketItems/undefined",
    "/rest/basket/undefined",
    "/ftp/invalid\x00.md",
]

_STACK_TRACE_PATTERNS = [
    "at Object.", "at Module.", "at Function.",   # Node.js
    "Error: ", "UnhandledPromiseRejection",        # JS runtime
    "Sequelize", "SequelizeDatabaseError",         # ORM errors
    "sqlite_", "SQLITE_", "sqlite3",               # SQLite internals
    "stack:", "\"stack\":",                         # JSON error bodies
    "Traceback (most recent call last)",           # Python
    "java.lang.", "NullPointerException",          # Java
]

_CHATBOT_TRIGGERS = [
    "blockchain",
    "bitcoin",
    "NFT",
    "cryptocurrency",
    "what is blockchain",
]

_SECURITY_POLICY_PATHS = [
    "/security.txt",
    "/.well-known/security.txt",
    "/humans.txt",
]


async def _probe_info_disclosure(
    base_url: str,
    auth_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    """
    M23: Audit for information disclosure across 4 vectors:
      1. Sensitive files in /ftp/ directory (access log, bytecode, backups)
      2. Error-triggered stack-trace leakage
      3. Security policy presence / absence
      4. Chatbot private-key / blockchain disclosure
    """
    results: List[Dict[str, Any]] = []
    _sev = {"critical": SeverityLevel.critical, "high": SeverityLevel.high,
            "medium": SeverityLevel.medium, "low": SeverityLevel.low,
            "info": SeverityLevel.info}

    async with _httpx.AsyncClient(
        headers=auth_headers,
        follow_redirects=True,
        timeout=8.0,
        verify=False,
    ) as client:

        # ── 1. Sensitive FTP files ─────────────────────────────────────────────
        for path, vtype, sev, owasp in _SENSITIVE_FTP_FILES:
            url = base_url.rstrip("/") + path
            try:
                resp = await client.get(url)
                if resp.status_code in (200, 206):
                    size = len(resp.content)
                    results.append({
                        "url":         url,
                        "type":        vtype,
                        "description": (
                            f"Sensitive file exposed: {path} "
                            f"(HTTP {resp.status_code}, {size} bytes). "
                            f"File should not be publicly accessible."
                        ),
                        "severity":    _sev[sev],
                        "vulnerability_type": vtype,
                        "raw_output":  {
                            "url": url, "path": path,
                            "status_code": resp.status_code,
                            "size": size,
                            "preview": resp.text[:200],
                            "source": "gobuster-info-disclosure",
                            "owasp": owasp,
                        },
                    })
                    logger.info(f"[gobuster/m23] Sensitive file found: {path} ({size}B)")
            except Exception:
                continue

        # ── 2. Error-triggered stack-trace leak ────────────────────────────────
        for path in _ERROR_TRIGGER_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = await client.get(url)
                body = resp.text
                leaked = [p for p in _STACK_TRACE_PATTERNS if p in body]
                if leaked and resp.status_code >= 400:
                    results.append({
                        "url":         url,
                        "type":        "error_information_disclosure",
                        "description": (
                            f"Server error response leaks internal implementation details "
                            f"(HTTP {resp.status_code}). Patterns found: {', '.join(leaked[:3])}"
                        ),
                        "severity":    SeverityLevel.medium,
                        "vulnerability_type": "error_information_disclosure",
                        "raw_output":  {
                            "url": url, "path": path,
                            "status_code": resp.status_code,
                            "leaked_patterns": leaked[:5],
                            "body_preview": body[:300],
                            "source": "gobuster-info-disclosure",
                            "owasp": "A05:2021 – Security Misconfiguration",
                        },
                    })
                    logger.info(f"[gobuster/m23] Stack trace leak at {path}: {leaked[:2]}")
                    break
            except Exception:
                continue

        # ── 3. Security policy ─────────────────────────────────────────────────
        policy_found = False
        for path in _SECURITY_POLICY_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.content) > 10:
                    policy_found = True
                    results.append({
                        "url":         url,
                        "type":        "security_policy_found",
                        "description": f"Security policy file found at {path}",
                        "severity":    SeverityLevel.info,
                        "vulnerability_type": "security_policy_found",
                        "raw_output":  {
                            "url": url, "path": path,
                            "preview": resp.text[:200],
                            "source": "gobuster-info-disclosure",
                        },
                    })
                    break
            except Exception:
                continue

        if not policy_found:
            results.append({
                "url":         base_url,
                "type":        "missing_security_policy",
                "description": (
                    "No security.txt or /.well-known/security.txt found. "
                    "RFC 9116 recommends publishing a security disclosure policy."
                ),
                "severity":    SeverityLevel.info,
                "vulnerability_type": "missing_security_policy",
                "raw_output":  {
                    "url": base_url,
                    "checked_paths": _SECURITY_POLICY_PATHS,
                    "source": "gobuster-info-disclosure",
                    "owasp": "A05:2021 – Security Misconfiguration",
                },
            })

        # ── 4. Chatbot blockchain / private-key disclosure ─────────────────────
        chatbot_url = base_url.rstrip("/") + "/api/Chatbot/respond"
        for trigger in _CHATBOT_TRIGGERS:
            try:
                resp = await client.post(
                    chatbot_url,
                    json={"action": "query", "query": trigger},
                    headers={**auth_headers, "Content-Type": "application/json"},
                )
                body = resp.text.lower()
                if resp.status_code == 200 and any(
                    kw in body for kw in ("private key", "blockchain", "bitcoin", "nft", "0x")
                ):
                    results.append({
                        "url":         chatbot_url,
                        "type":        "chatbot_disclosure",
                        "description": (
                            f"Chatbot discloses sensitive information when prompted with "
                            f"blockchain/cryptocurrency query ({trigger!r})"
                        ),
                        "severity":    SeverityLevel.medium,
                        "vulnerability_type": "chatbot_disclosure",
                        "raw_output":  {
                            "url": chatbot_url,
                            "trigger": trigger,
                            "response_preview": resp.text[:300],
                            "source": "gobuster-info-disclosure",
                            "owasp": "A02:2021 – Cryptographic Failures",
                        },
                    })
                    logger.info(f"[gobuster/m23] Chatbot disclosure triggered by {trigger!r}")
                    break
            except Exception:
                continue

    if results:
        logger.info(f"[gobuster/m23] Info disclosure: {len(results)} finding(s)")
    return results


# ── Legacy endpoints known to lack CSP ────────────────────────────────────────
#
# These paths are common in apps that migrated from v1 → v2 but left old routes
# alive without applying modern security headers (CSP, HSTS, X-Frame-Options).
# Juice Shop exposes /rest/products/search and /redirect?to= without full CSP.

_LEGACY_PATHS = [
    # Old REST versions
    "/v1/", "/v1/users", "/v1/products", "/v1/search",
    "/v2/", "/api/v1/", "/api/v2/",
    # Juice Shop legacy / redirect endpoints
    "/redirect",
    "/rest/products/search",
    "/rest/user/whoami",
    "/rest/track-order",
    "/rest/repeat-notification",
    "/rest/continue-code",
    "/rest/memories",
    # Common legacy admin/test pages
    "/old/",
    "/legacy/",
    "/beta/",
    "/dev/",
    "/staging/",
    "/test/",
    # Common debug / info endpoints that may skip CSP
    "/trace",
    "/dump",
    "/env",
    "/version",
    "/build-info",
    "/whoami",
    "/server-info",
]

# Headers that constitute a minimal security policy
_SECURITY_HEADERS = {
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
}


async def _probe_legacy_csp(
    base_url: str,
    auth_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    """
    Probe legacy / outdated endpoints and report those lacking CSP headers.

    Findings:
      - csp_missing   (medium)  — live endpoint without Content-Security-Policy
      - legacy_endpoint (info) — deprecated path still alive (400/401 counts too)
    """
    results: List[Dict[str, Any]] = []

    async with _httpx.AsyncClient(
        headers=auth_headers,
        follow_redirects=True,
        timeout=6.0,
        verify=False,
    ) as client:
        for path in _LEGACY_PATHS:
            full_url = base_url.rstrip("/") + path
            try:
                resp = await client.get(full_url)
                if resp.status_code == 404:
                    continue

                resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                has_csp    = "content-security-policy" in resp_headers_lower
                has_xframe = "x-frame-options" in resp_headers_lower

                missing = []
                if not has_csp:
                    missing.append("Content-Security-Policy")
                if not has_xframe:
                    missing.append("X-Frame-Options")

                if missing:
                    results.append({
                        "url":         full_url,
                        "type":        "csp_missing",
                        "description": (
                            f"Legacy/outdated endpoint {path!r} is live "
                            f"(HTTP {resp.status_code}) but missing security headers: "
                            + ", ".join(missing)
                        ),
                        "severity":    SeverityLevel.medium,
                        "vulnerability_type": "csp_missing",
                        "raw_output":  {
                            "url":            full_url,
                            "status_code":    resp.status_code,
                            "path":           path,
                            "missing_headers": missing,
                            "response_headers": dict(list(resp_headers_lower.items())[:10]),
                            "source":         "gobuster-legacy-csp",
                            "owasp":          "A05:2021 – Security Misconfiguration",
                        },
                    })
                else:
                    # Endpoint exists with headers — still worth reporting as info
                    results.append({
                        "url":         full_url,
                        "type":        "legacy_endpoint",
                        "description": f"Legacy endpoint {path!r} is live (HTTP {resp.status_code})",
                        "severity":    SeverityLevel.info,
                        "raw_output":  {
                            "url": full_url, "status_code": resp.status_code,
                            "path": path, "source": "gobuster-legacy-csp",
                        },
                    })
            except Exception:
                continue

    if results:
        import logging as _log
        csp_count = sum(1 for r in results if r["type"] == "csp_missing")
        _log.getLogger("gobuster").info(
            f"[gobuster/legacy-csp] {len(results)} legacy path(s) found, "
            f"{csp_count} without CSP"
        )
    return results


async def _probe_supplemental_paths(
    base_url: str,
    auth_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    """
    Directly probe _SUPPLEMENTAL_PATHS with a single HTTP GET each.
    Returns discovered paths in the same format as _parse_dir_output.
    """
    results: List[Dict[str, Any]] = []
    async with _httpx.AsyncClient(
        headers=auth_headers,
        follow_redirects=False,
        timeout=6.0,
        verify=False,
    ) as client:
        for path in _SUPPLEMENTAL_PATHS:
            full_url = base_url.rstrip("/") + path
            try:
                resp = await client.get(full_url)
                if resp.status_code == 404:
                    continue
                # Anything non-404 is worth reporting
                results.append({
                    "url":         full_url,
                    "type":        "endpoint",
                    "description": f"Supplemental probe: HTTP {resp.status_code} {path}",
                    "severity":    SeverityLevel.info,
                    "raw_output": {
                        "url":         full_url,
                        "status_code": resp.status_code,
                        "path":        path,
                        "size":        len(resp.content),
                        "source":      "supplemental_probe",
                    },
                })
            except Exception:
                continue
    if results:
        import logging as _log
        _log.getLogger("gobuster").info(
            f"[gobuster/supplemental] Found {len(results)} path(s) in supplemental probe"
        )
    return results


# ── Wildcard detection ────────────────────────────────────────────────────────

async def _probe_wildcard_size(
    base_url: str,
    headers: Dict[str, str],
) -> Optional[int]:
    """
    Probe a random UUID path.  If the server returns 200, we have a wildcard
    handler (SPA routing) — return the response body size so gobuster can
    filter it via --exclude-length.  Return None if the server correctly 404s.
    """
    probe_path = f"/{uuid.uuid4()}"
    probe_url  = base_url.rstrip("/") + probe_path
    try:
        async with _httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=8.0
        ) as client:
            resp = await client.get(probe_url, headers=headers)
            if resp.status_code == 200:
                return len(resp.content)
    except Exception:
        pass
    return None


# ── Output parsers ─────────────────────────────────────────────────────────────

def _parse_dir_output(output_file: str, base_url: str) -> List[Dict[str, Any]]:
    """Parse gobuster dir output lines like: /path  (Status: 200) [Size: 1234]"""
    results: List[Dict[str, Any]] = []
    try:
        with open(output_file, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                m = _DIR_RE.match(line)
                if not m:
                    continue
                path, status_str = m.group(1), m.group(2)
                status = int(status_str)
                full_url = base_url.rstrip("/") + path
                severity = (
                    SeverityLevel.medium
                    if status in (200, 301, 302)
                    else SeverityLevel.info
                )
                results.append({
                    "url": full_url,
                    "type": "discovered_path",
                    "description": f"HTTP {status} - {path}",
                    "severity": severity,
                    "status_code": status,
                    "raw_output": {"path": path, "status": status},
                })
    except FileNotFoundError:
        logger.warning(f"[gobuster] Output file not found: {output_file}")
    return results


def _parse_dns_output(output_file: str) -> List[Dict[str, Any]]:
    """Parse gobuster dns output lines like: Found: sub.domain.com"""
    results: List[Dict[str, Any]] = []
    try:
        with open(output_file, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                m = _DNS_RE.match(line)
                if not m:
                    continue
                subdomain = m.group(1)
                results.append({
                    "url": subdomain,
                    "type": "discovered_subdomain",
                    "description": f"Subdomain found: {subdomain}",
                    "severity": SeverityLevel.info,
                    "raw_output": {"subdomain": subdomain},
                })
    except FileNotFoundError:
        logger.warning(f"[gobuster] Output file not found: {output_file}")
    return results


def _parse_vhost_output(output_file: str, base_url: str) -> List[Dict[str, Any]]:
    """Parse gobuster vhost output lines like: Found: virtualhost.com (Status: 200) [Size: 1234]"""
    results: List[Dict[str, Any]] = []
    try:
        with open(output_file, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                # Try vhost format first (with status)
                m = _VHOST_RE.match(line)
                if m:
                    vhost = m.group(1)
                    status = int(m.group(2))
                else:
                    # Fallback: plain "Found: vhost" with no status
                    m2 = _DNS_RE.match(line)
                    if not m2:
                        continue
                    vhost = m2.group(1)
                    status = 0

                severity = (
                    SeverityLevel.medium
                    if status in (200, 301, 302)
                    else SeverityLevel.info
                )
                results.append({
                    "url": base_url,
                    "type": "discovered_vhost",
                    "description": f"Virtual host found: {vhost}" + (f" (Status: {status})" if status else ""),
                    "severity": severity,
                    "raw_output": {"vhost": vhost, "status": status, "base_url": base_url},
                })
    except FileNotFoundError:
        logger.warning(f"[gobuster] Output file not found: {output_file}")
    return results


# ── Utilities ──────────────────────────────────────────────────────────────────

def _extract_base_url(target: str, endpoints: List[str]) -> str:
    """Extract base URL (scheme://host) for gobuster — never use a deep file path."""
    for candidate in ([target] if target else []) + (endpoints or []):
        try:
            p = urlparse(candidate)
            if p.scheme and p.netloc:
                return f"{p.scheme}://{p.netloc}"
        except Exception:
            continue
    return target


def _extract_domain(endpoints: List[str], fallback: str) -> str:
    """Extract bare hostname from the first available endpoint."""
    for url in (endpoints or []) + ([fallback] if fallback else []):
        try:
            host = urlparse(url).hostname or ""
            if host:
                return host
        except Exception:
            continue
    return ""


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    worker = GobusterWorker()
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
