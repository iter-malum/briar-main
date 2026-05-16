"""
Nikto Web Server Scanner Worker
=================================
Phase: DAST
Queue: scan.dast.nikto

Nikto scans per-host (not per-endpoint), so it targets the primary host
derived from the first endpoint or the raw target URL. Results are parsed
from Nikto's JSON output and mapped to Briar SeverityLevel values.
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
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
logger = logging.getLogger("nikto-worker")


def _extract_base_url(target: str, endpoints: List[str]) -> str:
    """Return scheme://host from the target URL, falling back through endpoints."""
    for candidate in ([target] if target else []) + (endpoints or []):
        try:
            p = urlparse(candidate)
            if p.scheme in ("http", "https") and p.netloc:
                return f"{p.scheme}://{p.netloc}"
        except Exception:
            continue
    return target


def _map_severity(vuln: Dict[str, Any]) -> SeverityLevel:
    """
    Heuristic severity mapping based on Nikto vulnerability message and URL.

    Nikto does not emit native severity levels, so we infer from content:
    - XSS or SQL injection indicators in the message   → high
    - Admin panel or backup file indicators in the URL → medium
    - Everything else                                  → low
    """
    msg = (vuln.get("msg") or "").lower()
    url = (vuln.get("url") or "").lower()

    if "xss" in msg or "sql" in msg:
        return SeverityLevel.high
    if "admin" in url or "backup" in url:
        return SeverityLevel.medium
    return SeverityLevel.low


class NiktoWorker(BaseWorker):

    def __init__(self):
        super().__init__(tool_name="nikto", queue_name="scan.dast.nikto")
        self.timeout  = int(os.getenv("NIKTO_TIMEOUT",   "30"))
        self.max_time = int(os.getenv("NIKTO_MAX_TIME",  "600"))
        self.tuning   = os.getenv("NIKTO_TUNING",        "1,2,3,4,5,7,8,9")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [])
        # Nikto is a per-host scanner — extract scheme://host only.
        # Never pass a deep URL or static-file URL as the scan target.
        scan_target = _extract_base_url(target, endpoints)

        if not scan_target:
            logger.warning("[nikto] No valid target URL — skipping")
            return []

        work_dir = "/tmp/nikto"
        os.makedirs(work_dir, exist_ok=True)

        # Use a named temp file so Nikto can write structured JSON output.
        with tempfile.NamedTemporaryFile(
            dir=work_dir, suffix=".json", mode="w", delete=False
        ) as tf:
            output_file = tf.name

        logger.info(f"[nikto] Scanning target: {scan_target}")

        try:
            cmd = [
                "nikto",
                "-h",       scan_target,
                "-output",  output_file,
                "-Format",  "json",
                "-Tuning",  self.tuning,
                "-maxtime", f"{self.max_time}s",
                "-timeout", str(self.timeout),
            ]

            # Suppress SSL errors when caller opts out of SSL validation.
            no_ssl = task_payload.get("no_ssl_check", False)
            if no_ssl:
                cmd.append("-nossl")

            # Auth: inject a consistent user-agent when headers are present.
            headers: Dict[str, str] = auth_context.get("headers", {})
            cookies: List[Dict[str, str]] = auth_context.get("cookies", [])

            if headers:
                cmd.extend(["-useragent", "Mozilla/5.0"])

            if cookies:
                cookie_str = "; ".join(
                    f"{c['name']}={c['value']}" for c in cookies
                )
                cmd.extend(["-cookies", cookie_str])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
            )

            try:
                _, stderr_data = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.max_time + 30,  # slight buffer beyond -maxtime
                )
            except asyncio.TimeoutError:
                logger.error(f"[nikto] Process timed out after {self.max_time + 30}s")
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                return []

            if process.returncode not in (0, None):
                stderr_text = (stderr_data or b"").decode("utf-8", errors="ignore")
                logger.warning(
                    f"[nikto] Exited with code {process.returncode}. "
                    f"stderr: {stderr_text[:500]}"
                )

            return self._parse_output(output_file, scan_target)

        except Exception as exc:
            logger.error(f"[nikto] Execution failed: {exc}", exc_info=True)
            return []

        finally:
            try:
                os.unlink(output_file)
            except FileNotFoundError:
                pass

    # ── Output parsing ─────────────────────────────────────────────────────────

    def _parse_output(self, output_file: str, target: str) -> List[Dict[str, Any]]:
        """
        Parse Nikto's JSON output file.

        Expected structure:
            {
              "vulnerabilities": [
                {
                  "id": "...",
                  "method": "GET",
                  "url": "http://...",
                  "msg": "...",
                  "references": "...",
                  "osvdbid": "...",
                  "osvdblink": "..."
                },
                ...
              ]
            }
        """
        results: List[Dict[str, Any]] = []

        if not os.path.exists(output_file):
            logger.warning("[nikto] Output file not found — no results to parse")
            return results

        try:
            with open(output_file, "r", encoding="utf-8", errors="ignore") as fh:
                raw = fh.read().strip()

            if not raw:
                logger.info("[nikto] Output file is empty — no findings")
                return results

            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.error(f"[nikto] Failed to parse JSON output: {exc}")
            return results
        except OSError as exc:
            logger.error(f"[nikto] Cannot read output file: {exc}")
            return results

        vulnerabilities = data.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            logger.warning("[nikto] Unexpected JSON structure — 'vulnerabilities' is not a list")
            return results

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            severity = _map_severity(vuln)
            results.append({
                "url":         vuln.get("url", target),
                "type":        f"nikto_{vuln.get('id', 'finding')}",
                "description": vuln.get("msg", ""),
                "severity":    severity,
                "osvdb_id":    vuln.get("osvdbid"),
                "references":  vuln.get("references", ""),
                "raw_output":  vuln,
            })

        logger.info(f"[nikto] Parsed {len(results)} findings")
        return results


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    worker = NiktoWorker()
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
