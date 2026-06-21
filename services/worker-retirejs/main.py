"""
Retire.js CVE Scanner Worker
=============================
Phase: PROBE  (parallel with httpx/gobuster, after katana)
Queue: scan.probe.retirejs

Downloads JavaScript files discovered by katana, runs retire.js CLI against
them, and emits structured vulnerability findings for any CVE-affected library
versions detected.

Why retire.js and not an internal CVE database?
  retire.js maintains its own curated vulnerability database
  (https://github.com/RetireJS/retire.js/blob/master/repository/jsrepository.json)
  covering hundreds of CVEs across all major JS libraries.  Keeping that
  database in Briar's source would require constant manual maintenance.

Output types
------------
  vulnerable_library  — a JS library at a known-CVE version (medium/high/critical)
  js_library          — library detected but retire found no known vulnerabilities
                        (forwarded from js_fingerprint; not re-emitted here to avoid
                        duplicate with worker-jsscanner output)

Severity mapping (retire.js → Briar)
  critical → critical
  high     → high
  medium   → medium
  low      → low  (mapped as info)
"""

import asyncio
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel
from shared.js_fingerprint import fingerprint_js, aggregate_tech_stack

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("retirejs-worker")

MAX_JS_FILES    = int(os.getenv("RETIREJS_MAX_FILES",    "150"))
MAX_FILE_SIZE   = int(os.getenv("RETIREJS_MAX_FILE_BYTES", str(5 * 1024 * 1024)))  # 5 MB
FETCH_TIMEOUT   = float(os.getenv("RETIREJS_FETCH_TIMEOUT", "15"))
CONCURRENCY     = int(os.getenv("RETIREJS_CONCURRENCY", "10"))
RETIRE_TIMEOUT  = int(os.getenv("RETIREJS_RETIRE_TIMEOUT", "120"))
WORKER_TIMEOUT  = int(os.getenv("RETIREJS_WORKER_TIMEOUT", "600"))

_RETIRE_BIN = shutil.which("retire") or "retire"

# Retire.js severity string → Briar SeverityLevel
_SEVERITY_MAP: Dict[str, SeverityLevel] = {
    "critical": SeverityLevel.critical,
    "high":     SeverityLevel.high,
    "medium":   SeverityLevel.medium,
    "low":      SeverityLevel.info,
    "none":     SeverityLevel.info,
}


class RetireJsWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="retirejs", queue_name="scan.probe.retirejs")
        self.timeout = WORKER_TIMEOUT

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [])

        # Gather all .js URLs from endpoints
        js_urls = list(dict.fromkeys(
            u for u in endpoints if ".js" in u.lower()
        ))

        if not js_urls:
            js_urls = await self._collect_js_from_target(target, auth_context)

        if not js_urls:
            logger.info("[retirejs] No JS files found — skipping")
            return []

        js_urls = js_urls[:MAX_JS_FILES]
        logger.info(f"[retirejs] Downloading {len(js_urls)} JS file(s) for retire.js analysis")

        headers = _build_headers(auth_context)

        # Download all JS files into a temp directory
        work_dir = tempfile.mkdtemp(prefix="retirejs_", dir="/tmp/retirejs")
        try:
            url_to_path = await self._download_js_files(js_urls, work_dir, headers)
            if not url_to_path:
                logger.warning("[retirejs] No JS files could be downloaded")
                return []

            logger.info(f"[retirejs] Downloaded {len(url_to_path)} file(s), running retire.js")
            retire_results = await self._run_retire(work_dir)
            findings = self._parse_retire_output(retire_results, url_to_path, target)

            logger.info(f"[retirejs] Complete — {len(findings)} vulnerability finding(s)")
            return findings

        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    # ── JS file collection ────────────────────────────────────────────────────

    async def _collect_js_from_target(
        self, target: str, auth_context: Dict[str, Any]
    ) -> List[str]:
        """Fallback: fetch target HTML and extract <script src> tags."""
        headers = _build_headers(auth_context)
        try:
            async with httpx.AsyncClient(
                headers=headers, verify=False, follow_redirects=True,
                timeout=httpx.Timeout(FETCH_TIMEOUT),
            ) as client:
                resp = await client.get(target)
                if resp.status_code != 200:
                    return []
                parsed = urlparse(target)
                base = f"{parsed.scheme}://{parsed.netloc}"
                src_re = re.compile(
                    r'<script[^>]+src=[\'"]([^\'"]+\.js[^\'"]*)[\'"]', re.IGNORECASE
                )
                urls = []
                for m in src_re.finditer(resp.text):
                    src = m.group(1)
                    if src.startswith("http"):
                        urls.append(src)
                    elif src.startswith("/"):
                        urls.append(base + src)
                return list(dict.fromkeys(urls))[:MAX_JS_FILES]
        except Exception as exc:
            logger.debug(f"[retirejs] Target JS collect failed: {exc}")
            return []

    # ── Download ──────────────────────────────────────────────────────────────

    async def _download_js_files(
        self,
        js_urls: List[str],
        work_dir: str,
        headers: Dict[str, str],
    ) -> Dict[str, str]:
        """Download JS files concurrently. Returns {url: local_path}."""
        semaphore = asyncio.Semaphore(CONCURRENCY)
        url_to_path: Dict[str, str] = {}
        lock = asyncio.Lock()

        async with httpx.AsyncClient(
            headers=headers,
            verify=False,
            follow_redirects=True,
            timeout=httpx.Timeout(FETCH_TIMEOUT),
        ) as client:

            async def fetch_one(url: str, index: int):
                async with semaphore:
                    try:
                        resp = await client.get(url)
                        if resp.status_code != 200:
                            return
                        if len(resp.content) > MAX_FILE_SIZE:
                            logger.debug(f"[retirejs] {url} too large ({len(resp.content)} bytes), skipping")
                            return
                        # Use index-based filename to avoid OS path collisions
                        # but preserve the original basename for retire.js detection
                        original_name = urlparse(url).path.split("/")[-1] or "file.js"
                        # Sanitize — retire.js uses the filename for library detection
                        safe_name = re.sub(r"[^\w.\-]", "_", original_name)
                        local_path = os.path.join(work_dir, f"{index:04d}_{safe_name}")
                        with open(local_path, "wb") as f:
                            f.write(resp.content)
                        async with lock:
                            url_to_path[url] = local_path
                    except Exception as exc:
                        logger.debug(f"[retirejs] Download failed for {url}: {exc}")

            await asyncio.gather(*[fetch_one(u, i) for i, u in enumerate(js_urls)])

        return url_to_path

    # ── Retire.js execution ───────────────────────────────────────────────────

    async def _run_retire(self, work_dir: str) -> List[Dict[str, Any]]:
        """Run retire --js against work_dir, return parsed JSON results list."""
        output_file = os.path.join(work_dir, "retire_output.json")

        cmd = [
            _RETIRE_BIN,
            "--js",
            "--path", work_dir,
            "--outputformat", "json",
            "--outputpath", output_file,
            "--severity", "low",   # include all severity levels
        ]

        logger.info(f"[retirejs] Running: {' '.join(cmd[:6])} ...")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=RETIRE_TIMEOUT
            )

            stdout = stdout_b.decode("utf-8", errors="ignore").strip()
            stderr = stderr_b.decode("utf-8", errors="ignore").strip()

            if stdout:
                logger.debug(f"[retirejs] stdout: {stdout[:500]}")
            if stderr:
                logger.debug(f"[retirejs] stderr: {stderr[:500]}")

            # retire exits with 0 (clean), 13 (vulnerabilities found in v3+),
            # or 1 (vulnerabilities found in older versions)
            if proc.returncode not in (0, 1, 13):
                logger.warning(f"[retirejs] Unexpected exit code {proc.returncode}")

        except asyncio.TimeoutError:
            logger.error(f"[retirejs] Timed out after {RETIRE_TIMEOUT}s")
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return []
        except Exception as exc:
            logger.error(f"[retirejs] Execution failed: {exc}", exc_info=True)
            return []

        if not os.path.exists(output_file):
            logger.info("[retirejs] No output file — retire found 0 vulnerabilities")
            return []

        try:
            with open(output_file, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            if not raw:
                return []
            data = json.loads(raw)
            # retire.js JSON output: list of file-result objects
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "data" in data:
                return data["data"]
            return []
        except Exception as exc:
            logger.error(f"[retirejs] Failed to parse output: {exc}")
            return []

    # ── Result parsing ────────────────────────────────────────────────────────

    def _parse_retire_output(
        self,
        retire_data: List[Dict[str, Any]],
        url_to_path: Dict[str, str],
        target: str,
    ) -> List[Dict[str, Any]]:
        """
        Convert retire.js JSON output into Briar scan findings.

        Retire.js output format (per file):
          {
            "file": "/tmp/retirejs_xxx/0001_jquery-3.4.0.min.js",
            "results": [
              {
                "component": "jquery",
                "version":   "3.4.0",
                "detection": "filename",
                "vulnerabilities": [
                  {
                    "severity": "medium",
                    "identifiers": {
                      "CVE":     ["CVE-2020-11022"],
                      "summary": "Passing HTML from untrusted sources..."
                    },
                    "info": ["https://..."]
                  }
                ]
              }
            ]
          }
        """
        # Reverse map: local path → original URL
        path_to_url: Dict[str, str] = {v: k for k, v in url_to_path.items()}

        findings: List[Dict[str, Any]] = []
        # Track (component, version, cve) to avoid duplicates across files
        seen: set = set()

        for file_entry in retire_data:
            local_path = file_entry.get("file", "")
            original_url = path_to_url.get(local_path, local_path)

            results = file_entry.get("results", [])
            for result in results:
                component = result.get("component", "unknown")
                version = result.get("version", "unknown")
                detection = result.get("detection", "unknown")
                vulns = result.get("vulnerabilities", [])

                if not vulns:
                    # Library detected but clean — no finding needed (jsscanner handles info)
                    continue

                for vuln in vulns:
                    severity_str = vuln.get("severity", "medium").lower()
                    identifiers = vuln.get("identifiers", {})
                    cves: List[str] = identifiers.get("CVE", [])
                    summary: str = identifiers.get("summary", "Known vulnerability in JS library")
                    info_urls: List[str] = vuln.get("info", [])

                    # Dedup by (component, version, first CVE or summary)
                    dedup_key = (component, version, cves[0] if cves else summary[:40])
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    sev = _SEVERITY_MAP.get(severity_str, SeverityLevel.medium)
                    cve_str = ", ".join(cves) if cves else "no CVE ID"
                    description = (
                        f"[retirejs] {component} {version} — {summary} "
                        f"({cve_str}) in {original_url}"
                    )

                    logger.info(
                        f"[retirejs] VULNERABLE: {component} {version} | "
                        f"{cve_str} | {severity_str.upper()} | {original_url}"
                    )

                    findings.append({
                        "url":      original_url,
                        "type":     "vulnerable_library",
                        "severity": sev,
                        "description": description,
                        "raw_output": {
                            "source":      "retirejs",
                            "component":   component,
                            "version":     version,
                            "detection":   detection,
                            "cves":        cves,
                            "severity":    severity_str,
                            "summary":     summary,
                            "info_urls":   info_urls,
                            "js_url":      original_url,
                            "target":      target,
                        },
                    })

        return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_headers(auth_context: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "User-Agent": "Mozilla/5.0 (compatible; Briar-RetireJS/1.0)",
    }
    headers.update(auth_context.get("headers", {}))
    cookies = auth_context.get("cookies", [])
    if cookies:
        headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    return headers


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    worker = RetireJsWorker()
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
