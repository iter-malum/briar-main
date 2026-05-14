"""
SQLmap Exploitation Worker
===========================
Phase: EXPLOIT (Phase 4 — opt-in only)

Safety requirements:
  1. scan.config.exploit_enabled MUST be True (checked by PipelineManager before publishing).
  2. Only runs on endpoints where nuclei/zap detected a SQLi vulnerability.
  3. Uses --level=1 --risk=1 (minimal impact) by default.
  4. Hard timeout of 10 min per URL, 30 min total.
  5. Does NOT --dump data by default — only confirms injection and extracts DBMS info.
     Set SQLMAP_DUMP=true env to enable data extraction (use with explicit consent).

sqlmap is installed as a Python script under /opt/sqlmap/sqlmap.py.
"""

import asyncio
import json
import logging
import os
import re
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
logger = logging.getLogger("sqlmap-worker")

SQLMAP_BIN = os.getenv("SQLMAP_BIN", "/opt/sqlmap/sqlmap.py")
SQLMAP_DUMP = os.getenv("SQLMAP_DUMP", "false").lower() == "true"

# Per-URL and total timeouts (seconds)
PER_URL_TIMEOUT = int(os.getenv("SQLMAP_PER_URL_TIMEOUT", "600"))
TOTAL_TIMEOUT   = int(os.getenv("SQLMAP_TOTAL_TIMEOUT", "1800"))

# Safety: refuse obviously unrelated URLs (local, reserved)
_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


class SqlmapWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="sqlmap", queue_name="scan.exploit.sqlmap")
        self.level = int(os.getenv("SQLMAP_LEVEL", "1"))
        self.risk  = int(os.getenv("SQLMAP_RISK", "1"))

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        scan_id: str = task_payload.get("scan_id", "")
        source_tools: List[str] = task_payload.get("source_tools", ["nuclei", "zap"])

        # Load SQLi-positive endpoints from DB
        sqli_endpoints = await self._get_sqli_endpoints_from_db(scan_id, source_tools)

        if not sqli_endpoints:
            logger.info("[sqlmap] No SQLi-positive endpoints found — skipping")
            return []

        logger.info(f"[sqlmap] Will test {len(sqli_endpoints)} SQLi-positive endpoints")

        results: List[Dict[str, Any]] = []
        total_start = asyncio.get_event_loop().time()

        for url in sqli_endpoints[:10]:  # safety cap
            if asyncio.get_event_loop().time() - total_start > TOTAL_TIMEOUT:
                logger.warning("[sqlmap] Total timeout reached")
                break

            host = urlparse(url).hostname or ""
            if host in _BLOCKED_HOSTS:
                logger.warning(f"[sqlmap] Skipping blocked host: {url}")
                continue

            partial = await self._run_sqlmap(url, auth_context)
            results.extend(partial)

        logger.info(f"[sqlmap] Confirmed {len(results)} injection points")
        return results

    async def _run_sqlmap(
        self,
        url: str,
        auth_context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        work_dir = "/tmp/sqlmap"
        os.makedirs(work_dir, exist_ok=True)

        with tempfile.TemporaryDirectory(dir=work_dir) as out_dir:
            cmd = [
                "python3", SQLMAP_BIN,
                "-u", url,
                "--batch",               # no interactive prompts
                "--level", str(self.level),
                "--risk",  str(self.risk),
                "--output-dir", out_dir,
                "--forms",               # test form parameters too
                "--random-agent",        # vary User-Agent
                "--timeout", "30",
                "--retries", "1",
                "--threads", "3",
                "--technique", "BEUST",  # all common techniques
                "-v", "0",               # minimal verbosity
            ]

            if SQLMAP_DUMP:
                cmd.append("--dump")
                logger.warning("[sqlmap] DUMP mode enabled — extracting data")

            # Auth
            cookies = auth_context.get("cookies", [])
            if cookies:
                cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
                cmd.extend(["--cookie", cookie_str])

            for key, value in auth_context.get("headers", {}).items():
                cmd.extend(["-H", f"{key}: {value}"])

            logger.info(f"[sqlmap] Testing: {url}")

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=work_dir,
                )

                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=PER_URL_TIMEOUT
                )

                output = stdout_data.decode("utf-8", errors="ignore")
                return _parse_sqlmap_output(output, url)

            except asyncio.TimeoutError:
                logger.warning(f"[sqlmap] Timed out on {url}")
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                return []
            except Exception as exc:
                logger.error(f"[sqlmap] Error on {url}: {exc}", exc_info=True)
                return []


def _parse_sqlmap_output(output: str, url: str) -> List[Dict[str, Any]]:
    """Parse sqlmap terminal output for confirmed injection points."""
    results: List[Dict[str, Any]] = []

    # sqlmap prints lines like:
    # Parameter: id (GET)
    #     Type: boolean-based blind
    #     Title: AND boolean-based blind - WHERE or HAVING clause
    #     Payload: id=1 AND 5678=5678

    confirmed = False
    current_param = None
    current_type  = None
    current_payload = None
    dbms = None

    for line in output.splitlines():
        line = line.strip()

        # DBMS detection
        m = re.search(r"back-end DBMS:\s+(.+)", line, re.IGNORECASE)
        if m:
            dbms = m.group(1).strip()

        # Injection point header
        m = re.match(r"Parameter:\s+(.+?)\s+\((.+?)\)", line)
        if m:
            if current_param and confirmed:
                results.append(_make_result(url, current_param, current_type, current_payload, dbms))
            current_param   = m.group(1)
            current_type    = None
            current_payload = None
            confirmed = True

        if current_param:
            if line.startswith("Type:"):
                current_type = line.replace("Type:", "").strip()
            elif line.startswith("Payload:"):
                current_payload = line.replace("Payload:", "").strip()

    # flush last
    if current_param and confirmed:
        results.append(_make_result(url, current_param, current_type, current_payload, dbms))

    # Fallback: if sqlmap says "is vulnerable" but we didn't catch params
    if not results and "is vulnerable" in output.lower():
        results.append({
            "url": url,
            "type": "sql-injection",
            "description": f"SQLmap confirmed injection at {url}. DBMS: {dbms or 'unknown'}",
            "severity": SeverityLevel.critical,
            "raw_output": {"url": url, "dbms": dbms, "raw": output[:2000]},
        })

    return results


def _make_result(
    url: str,
    param: str,
    injection_type: str,
    payload: str,
    dbms: str,
) -> Dict[str, Any]:
    return {
        "url": url,
        "type": "sql-injection",
        "description": (
            f"Confirmed SQLi in parameter '{param}' "
            f"({injection_type or 'unknown type'}). "
            f"DBMS: {dbms or 'unknown'}. "
            f"Payload: {payload or 'see raw_output'}"
        ),
        "severity": SeverityLevel.critical,
        "raw_output": {
            "url": url,
            "parameter": param,
            "injection_type": injection_type,
            "payload": payload,
            "dbms": dbms,
        },
    }


async def main():
    worker = SqlmapWorker()
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
