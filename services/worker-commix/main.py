"""
Commix Command Injection Worker
================================
Phase: EXPLOIT (requires exploit_enabled=True)
Queue: scan.exploit.commix

Triggered by: finding_router when inspector emits cmdi_candidate

What this worker does
---------------------
commix (COMMand Injection eXploiter) is the reference tool for confirming
and exploiting OS command injection.  It tests all major injection contexts:
  - Classic (inline, chaining with ; | || &&)
  - Time-based blind (sleep-triggered)
  - File-based (write-and-read back marker)
  - Dynamic code evaluation (PHP eval etc.)

Safety controls
---------------
1. exploit_enabled gate enforced by PipelineManager.
2. Default mode: `--hostname` — extracts the server hostname ONLY.
   This confirms RCE without writing files, opening shells, or dumping data.
3. Full OS shell access disabled unless COMMIX_OS_CMD env var is explicitly set.
4. --batch flag ensures no interactive prompts / auto-choices.
5. --crawl=0 prevents commix from following links (we target one URL).
6. Per-URL timeout 5 min, total 20 min.

Finding router integration
--------------------------
Receives: target URL + inject_param + inject_method + inject_payload
Runs commix against that exact (URL, parameter) pair using the technique
already identified by the inspector (classic, time-based, etc.).
"""

import asyncio
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("commix-worker")

COMMIX_BIN      = os.getenv("COMMIX_BIN",     "/opt/commix/commix.py")
PER_URL_TIMEOUT = int(os.getenv("COMMIX_PER_URL_TIMEOUT", "300"))   # 5 min
TOTAL_TIMEOUT   = int(os.getenv("COMMIX_TOTAL_TIMEOUT",   "1200"))  # 20 min
# Gate: allow richer OS command if explicitly enabled
ALLOW_OS_CMD    = os.getenv("COMMIX_OS_CMD", "false").lower() not in ("false", "0", "no")
CONFIRM_CMD     = os.getenv("COMMIX_CONFIRM_CMD", "id")

_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

# ── commix output patterns ─────────────────────────────────────────────────────

_VULN_RE = re.compile(
    r"(?:is vulnerable|identified as injectable|seems to be injectable)",
    re.IGNORECASE,
)
_TECH_RE = re.compile(
    r"Injection Type:\s+(.+)",
    re.IGNORECASE,
)
_CMD_OUTPUT_RE = re.compile(
    r"(?:Command:\s*\n.+?\n)(.+?)(?:\n\[|$)",
    re.DOTALL,
)
_HOSTNAME_RE = re.compile(
    r"\[\+\] Hostname:\s+(\S+)",
    re.IGNORECASE,
)
_OS_RE = re.compile(
    r"Operating System:\s+(.+)",
    re.IGNORECASE,
)


class CommixWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="commix", queue_name="scan.exploit.commix")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        exploit_enabled: bool = task_payload.get("exploit_enabled", False)
        finding_triggered: bool = task_payload.get("finding_triggered", False)

        # ── Finding-triggered path (fast, precise) ─────────────────────────────
        if finding_triggered:
            url           = task_payload.get("target") or target
            inject_param  = task_payload.get("inject_param")
            inject_method = task_payload.get("inject_method", "GET").upper()
            evidence      = task_payload.get("evidence", "")
            if url and inject_param:
                logger.info(
                    f"[commix] Finding-triggered: {inject_method} {url} "
                    f"param={inject_param!r}"
                )
                return await self._test_url(
                    url, inject_param, inject_method,
                    auth_context, exploit_enabled,
                )

        # ── Phase-based fallback ───────────────────────────────────────────────
        scan_id: str = task_payload.get("scan_id", "")
        cmdi_endpoints = await self._get_cmdi_endpoints(scan_id)
        if not cmdi_endpoints:
            logger.info("[commix] No CMDi candidate endpoints found — skipping")
            return []

        logger.info(f"[commix] Phase-based: testing {len(cmdi_endpoints)} CMDi candidate(s)")

        results: List[Dict[str, Any]] = []
        start = asyncio.get_event_loop().time()

        for ep in cmdi_endpoints:
            if asyncio.get_event_loop().time() - start > TOTAL_TIMEOUT:
                logger.warning("[commix] Total timeout reached")
                break
            partial = await self._test_url(
                ep["url"],
                ep.get("parameter"),
                ep.get("method", "GET"),
                auth_context,
                exploit_enabled,
            )
            results.extend(partial)

        logger.info(f"[commix] Confirmed {len(results)} command injection point(s)")
        return results

    async def _get_cmdi_endpoints(self, scan_id: str) -> List[Dict[str, Any]]:
        """Load cmdi_candidate findings from DB for phase-based triggering."""
        if not scan_id:
            return []
        try:
            async with self.session_factory() as session:
                from shared.models import ScanResultORM
                from sqlalchemy import select
                from uuid import UUID
                stmt = select(ScanResultORM).where(
                    ScanResultORM.scan_id == UUID(scan_id),
                    ScanResultORM.vulnerability_type == "cmdi_candidate",
                )
                rows = await session.execute(stmt)
                findings = rows.scalars().all()
                result = []
                for f in findings:
                    raw = f.raw_output or {}
                    result.append({
                        "url":       f.url or "",
                        "parameter": raw.get("parameter"),
                        "method":    raw.get("method", "GET"),
                    })
                return result
        except Exception as exc:
            logger.warning(f"[commix] DB query failed: {exc}")
            return []

    async def _test_url(
        self,
        url: str,
        param: Optional[str],
        method: str,
        auth_context: Dict[str, Any],
        exploit_enabled: bool,
    ) -> List[Dict[str, Any]]:
        """Run commix against a single (url, param, method) target."""
        host = urlparse(url).hostname or ""
        if host in _BLOCKED_HOSTS:
            logger.warning(f"[commix] Skipping blocked host: {url}")
            return []

        work_dir = "/tmp/commix"
        os.makedirs(work_dir, exist_ok=True)

        cmd = [
            "python3", COMMIX_BIN,
            "-u", url,
            "--batch",          # no interactive prompts
            "--crawl=0",        # don't follow links
            "--timeout=30",
            "--retries=1",
            "--output-dir", work_dir,
        ]

        # Target specific parameter
        if param:
            cmd.extend(["--param", param])

        # POST data
        if method.upper() == "POST":
            cmd.extend(["--data", f"{param}=1" if param else "data=1"])

        # Mode: --hostname is safe (just extracts hostname via RCE to confirm)
        # Full OS command only when explicitly unlocked
        if exploit_enabled and ALLOW_OS_CMD:
            cmd.extend(["--os-cmd", CONFIRM_CMD])
            logger.info(f"[commix] OS command confirmation: {CONFIRM_CMD!r}")
        else:
            # --hostname triggers a single system('hostname') and proves RCE
            # without persistent changes, file writes, or interactive sessions
            cmd.append("--hostname")

        # Auth
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            cmd.extend(["--cookie", cookie_str])

        for key, value in auth_context.get("headers", {}).items():
            cmd.extend(["-H", f"{key}: {value}"])

        logger.info(f"[commix] Testing: {method} {url} param={param!r}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
            )
            try:
                stdout_data, _ = await asyncio.wait_for(
                    process.communicate(), timeout=PER_URL_TIMEOUT
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning(f"[commix] Timed out on {url}")
                return []

            output = stdout_data.decode("utf-8", errors="ignore")
            return _parse_commix_output(output, url, param, method)

        except FileNotFoundError:
            logger.error(f"[commix] Binary not found: {COMMIX_BIN}")
            return []
        except Exception as exc:
            logger.error(f"[commix] Error on {url}: {exc}", exc_info=True)
            return []


# ── Output parser ─────────────────────────────────────────────────────────────

def _parse_commix_output(
    output: str,
    url: str,
    param: Optional[str],
    method: str,
) -> List[Dict[str, Any]]:
    """
    Parse commix terminal output into structured findings.

    commix prints lines like:
      [+] Commix identified the following injection point(s):
        Parameter: cmd (GET)
        Injection Type: Results-based OS command injection technique
      ...
      [+] Hostname: webapp-prod-01
      [+] Operating System: Linux
    """
    if not _VULN_RE.search(output):
        return []

    technique = None
    m = _TECH_RE.search(output)
    if m:
        technique = m.group(1).strip()

    hostname = None
    m = _HOSTNAME_RE.search(output)
    if m:
        hostname = m.group(1).strip()

    os_type = None
    m = _OS_RE.search(output)
    if m:
        os_type = m.group(1).strip()

    # Try to capture any command output (when --os-cmd was used)
    cmd_output = ""
    m = _CMD_OUTPUT_RE.search(output)
    if m:
        cmd_output = m.group(1).strip()[:300]

    rce_confirmed = bool(hostname or cmd_output)
    severity = SeverityLevel.critical

    description = (
        f"OS command injection confirmed in parameter '{param}' via {method}. "
        f"Technique: {technique or 'unknown'}. "
    )
    if hostname:
        description += f"Hostname retrieved: {hostname!r}. "
    if os_type:
        description += f"OS: {os_type}. "
    if cmd_output:
        description += f"Command output: {cmd_output!r}"

    return [{
        "url":         url,
        "type":        "command-injection",
        "description": description,
        "severity":    severity,
        "raw_output": {
            "url":           url,
            "parameter":     param,
            "method":        method,
            "technique":     technique,
            "hostname":      hostname,
            "os_type":       os_type,
            "cmd_output":    cmd_output,
            "rce_confirmed": rce_confirmed,
            "raw":           output[:3000],
        },
    }]


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    worker = CommixWorker()
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
