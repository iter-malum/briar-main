"""
Dalfox XSS Scanner Worker
==========================
Phase: DAST — XSS scanning

Dalfox is a fast and powerful open-source XSS scanner.
It supports reflected, DOM-based, and stored XSS detection.

Queue: scan.dast.dalfox
Worker timeout: 1800s
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List
from urllib.parse import urlparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("dalfox-worker")

DALFOX_WORKER  = int(os.getenv("DALFOX_WORKER", "10"))
DALFOX_TIMEOUT = int(os.getenv("DALFOX_TIMEOUT", "10"))
DALFOX_BLIND_URL = os.getenv("DALFOX_BLIND_URL", "")

WORK_DIR    = "/tmp/dalfox"
TARGETS_FILE = f"{WORK_DIR}/targets.txt"
OUTPUT_FILE  = f"{WORK_DIR}/output.txt"
TOTAL_TIMEOUT = 1800


class DalfoxWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="dalfox", queue_name="scan.dast.dalfox")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [])
        if not endpoints:
            logger.info("[dalfox] No endpoints provided — skipping")
            return []

        _STATIC_EXTS = frozenset({
            ".css", ".js", ".mjs", ".map",
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".mp3", ".mp4", ".webm", ".pdf", ".zip", ".gz",
        })

        def _has_params(url: str) -> bool:
            try:
                p = urlparse(url)
                ext = os.path.splitext(p.path.lower())[1]
                return bool(p.query) and ext not in _STATIC_EXTS
            except Exception:
                return False

        # Primary targets: GET URLs with query params (reflected XSS candidates)
        get_targets = [ep for ep in endpoints if _has_params(ep)]

        # Secondary targets: API/non-static endpoints without GET params.
        # Dalfox with --mining-dict probes common GET/POST parameter names,
        # discovering hidden inputs on REST endpoints that have no query string.
        def _is_api_endpoint(url: str) -> bool:
            try:
                p = urlparse(url)
                ext = os.path.splitext(p.path.lower())[1]
                # Skip known static files
                if ext in _STATIC_EXTS:
                    return False
                # Skip root and common navigation paths that serve SPA shells
                if p.path in ("/", "") or p.path in ("/login", "/register", "/home"):
                    return False
                # Include all non-static, non-SPA-shell endpoints:
                # REST/API paths, numeric ID paths (/product/42), search paths, etc.
                _SPA_ONLY_EXTS = frozenset({".html", ".htm", ".xml", ".txt", ".json", ".yaml"})
                if ext in _SPA_ONLY_EXTS:
                    return False
                return True
            except Exception:
                return False

        api_targets = [ep for ep in endpoints if not _has_params(ep) and _is_api_endpoint(ep)]
        # Increased cap: was 20, now 150 — Juice Shop has 100+ REST endpoints worth testing
        all_targets = list(dict.fromkeys(get_targets + api_targets[:150]))

        if not all_targets:
            logger.info("[dalfox] No testable endpoints found — XSS scan skipped")
            return []

        waf_bypass   = task_payload.get("waf_bypass", False)
        # Enable parameter mining by default — dalfox probes common GET/POST
        # parameter names, discovering hidden inputs not visible in the URL.
        # This is especially effective on REST APIs that accept undocumented params.
        mining_dict  = task_payload.get("mining_dict", True)
        blind_url    = task_payload.get("blind_url", DALFOX_BLIND_URL)

        os.makedirs(WORK_DIR, exist_ok=True)

        # Write endpoints to targets file
        with open(TARGETS_FILE, "w") as f:
            f.write("\n".join(all_targets) + "\n")

        logger.info(f"[dalfox] Scanning {len(all_targets)} endpoint(s) "
                    f"({len(get_targets)} GET-param + {min(len(api_targets), 150)} API)")

        # Build command
        cmd = [
            "dalfox",
            "file", TARGETS_FILE,
            "--worker", str(DALFOX_WORKER),
            "--timeout", str(DALFOX_TIMEOUT),
            "--output", OUTPUT_FILE,
            "--format", "json",
            "--no-color",
            "--silence",
        ]

        if blind_url:
            cmd.extend(["--blind", blind_url])

        if waf_bypass:
            cmd.append("--waf-evasion")

        if mining_dict:
            cmd.append("--mining-dict")

        # Auth cookies
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            cmd.extend(["--cookie", cookie_str])

        # Auth headers (skip Cookie header — handled above)
        for key, value in auth_context.get("headers", {}).items():
            if key.lower() == "cookie":
                continue
            cmd.extend(["--header", f"{key}: {value}"])

        # Remove stale output file before run
        if os.path.exists(OUTPUT_FILE):
            os.remove(OUTPUT_FILE)

        logger.info(f"[dalfox] Command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=WORK_DIR,
            )

            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(), timeout=TOTAL_TIMEOUT
            )

            if stderr_data:
                stderr_text = stderr_data.decode("utf-8", errors="ignore").strip()
                if stderr_text:
                    logger.debug(f"[dalfox] stderr: {stderr_text[:500]}")

        except asyncio.TimeoutError:
            logger.warning("[dalfox] Scan timed out")
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass
        except Exception as exc:
            logger.error(f"[dalfox] Error running dalfox: {exc}", exc_info=True)
            return []

        return _parse_dalfox_output(OUTPUT_FILE)


def _parse_dalfox_output(output_file: str) -> List[Dict[str, Any]]:
    """Parse dalfox JSON Lines output file.

    Dalfox JSON format per line:
      {
        "type": "V" | "G",
        "inject_type": "reflected" | "dom" | "stored",
        "poc": "<script>...",
        "data": {...},
        "param": "q",
        "url": "https://example.com/search?q=..."
      }

    "V" = verified XSS  -> high severity
    "G" = potential XSS -> medium severity
    """
    results: List[Dict[str, Any]] = []

    if not os.path.exists(output_file):
        logger.info("[dalfox] No output file found — no findings")
        return results

    with open(output_file, "r", errors="ignore") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.debug(f"[dalfox] Skipping non-JSON line {line_no}: {exc}")
                continue

            inject_type = finding.get("inject_type", "reflected")
            param       = finding.get("param", "")
            poc         = finding.get("poc", "")
            url         = finding.get("url", "")
            ftype       = finding.get("type", "G")

            severity = SeverityLevel.high if ftype == "V" else SeverityLevel.medium

            results.append({
                "url": url,
                "type": f"xss_{inject_type}",
                "description": (
                    f"XSS [{inject_type}] in param '{param}': "
                    f"{poc[:200]}"
                ),
                "severity": severity,
                "parameter": param,
                "poc": poc,
                "inject_type": inject_type,
                "raw_output": finding,
            })

    logger.info(f"[dalfox] Parsed {len(results)} finding(s) from output")
    return results


async def main():
    worker = DalfoxWorker()
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
