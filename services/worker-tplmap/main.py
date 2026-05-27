"""
Tplmap SSTI Exploitation Worker
================================
Phase: EXPLOIT (requires exploit_enabled=True)
Queue: scan.exploit.tplmap

Triggered by: finding_router when inspector emits ssti_candidate

What this worker does
---------------------
tplmap is the definitive tool for Server-Side Template Injection (SSTI).
It detects the template engine (Jinja2, Twig, FreeMarker, Velocity, ERB,
Smarty, etc.), confirms remote code evaluation, and — when exploit mode is
on — can execute OS commands, read files, and spawn a bind/reverse shell.

Safety controls
---------------
1. scan.config.exploit_enabled checked by PipelineManager before publishing.
2. By default only confirms engine + evaluates {{7*7}} (no OS access).
3. OS command execution (`--os-cmd`) gated behind TPLMAP_OS_CMD env var.
4. Hard per-URL timeout (default 5 min) and total timeout (20 min).
5. Blocked hosts list prevents localhost / internal addresses.

Finding router integration
--------------------------
Payload received:
  target          – URL containing the injectable parameter
  inject_param    – parameter name (e.g. "tmpl", "template", "msg")
  inject_method   – HTTP method ("GET" | "POST")
  inject_payload  – original inspector evidence payload (for context)
  evidence        – human-readable description from inspector

tplmap is run directly against that specific (URL, param, method) triple
rather than crawling, so scans are fast and precise.
"""

import asyncio
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("tplmap-worker")

TPLMAP_BIN      = os.getenv("TPLMAP_BIN",     "/opt/tplmap/tplmap.py")
PER_URL_TIMEOUT = int(os.getenv("TPLMAP_PER_URL_TIMEOUT", "300"))   # 5 min
TOTAL_TIMEOUT   = int(os.getenv("TPLMAP_TOTAL_TIMEOUT",   "1200"))  # 20 min
# OS command to run when exploit_enabled is True — safe read-only command
CONFIRM_CMD     = os.getenv("TPLMAP_CONFIRM_CMD", "id")
# Gate: only send --os-cmd if this env var is set AND exploit_enabled
ALLOW_OS_CMD    = os.getenv("TPLMAP_OS_CMD", "false").lower() not in ("false", "0", "no")

_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

# ── tplmap output patterns ─────────────────────────────────────────────────────

_ENGINE_RE = re.compile(
    r"Engine:\s+([A-Za-z0-9_. ]+)",
)
_INJECTION_RE = re.compile(
    r"Injection:\s+(\S+)",
)
_CAPABILITY_RE = re.compile(
    r"Shell command execution:\s+(ok|no)",
    re.IGNORECASE,
)
_OS_RE = re.compile(
    r"OS:\s+(\S+)",
)
_OS_CMD_RE = re.compile(
    r">\s+(.+)",      # tplmap echoes OS command output after "> "
)
_IDENTIFIED_RE = re.compile(
    r"identified the following injection point",
    re.IGNORECASE,
)


class TplmapWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="tplmap", queue_name="scan.exploit.tplmap")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        exploit_enabled: bool = task_payload.get("exploit_enabled", False)
        finding_triggered: bool = task_payload.get("finding_triggered", False)
        endpoints: List[str] = task_payload.get("endpoints", [target])

        # When triggered by Finding Router, test the single known-injectable URL
        if finding_triggered:
            url         = task_payload.get("target") or target
            inject_param  = task_payload.get("inject_param")
            inject_method = task_payload.get("inject_method", "GET").upper()
            evidence      = task_payload.get("evidence", "")
            if url and inject_param:
                logger.info(
                    f"[tplmap] Finding-triggered: {inject_method} {url} "
                    f"param={inject_param!r}"
                )
                return await self._test_url(
                    url, inject_param, inject_method,
                    auth_context, exploit_enabled,
                )

        # Phase-based fallback: test all SSTI candidates from DB
        scan_id: str = task_payload.get("scan_id", "")
        ssti_endpoints = await self._get_ssti_endpoints(scan_id)
        if not ssti_endpoints:
            logger.info("[tplmap] No SSTI candidate endpoints found — skipping")
            return []

        logger.info(f"[tplmap] Phase-based: testing {len(ssti_endpoints)} SSTI candidate(s)")

        results: List[Dict[str, Any]] = []
        start = asyncio.get_event_loop().time()

        for ep in ssti_endpoints:
            if asyncio.get_event_loop().time() - start > TOTAL_TIMEOUT:
                logger.warning("[tplmap] Total timeout reached")
                break
            partial = await self._test_url(
                ep["url"],
                ep.get("parameter"),
                ep.get("method", "GET"),
                auth_context,
                exploit_enabled,
            )
            results.extend(partial)

        logger.info(f"[tplmap] Confirmed {len(results)} SSTI injection point(s)")
        return results

    async def _get_ssti_endpoints(self, scan_id: str) -> List[Dict[str, Any]]:
        """Load ssti_candidate findings from DB for phase-based triggering."""
        if not scan_id:
            return []
        try:
            async with self.db_session() as session:
                from shared.models import ScanResultORM
                from sqlalchemy import select
                from uuid import UUID
                stmt = select(ScanResultORM).where(
                    ScanResultORM.scan_id == UUID(scan_id),
                    ScanResultORM.vulnerability_type == "ssti_candidate",
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
            logger.warning(f"[tplmap] DB query failed: {exc}")
            return []

    async def _test_url(
        self,
        url: str,
        param: Optional[str],
        method: str,
        auth_context: Dict[str, Any],
        exploit_enabled: bool,
    ) -> List[Dict[str, Any]]:
        """Run tplmap against a single (url, param, method) target."""
        from urllib.parse import urlparse

        host = urlparse(url).hostname or ""
        if host in _BLOCKED_HOSTS:
            logger.warning(f"[tplmap] Skipping blocked host: {url}")
            return []

        work_dir = "/tmp/tplmap"
        os.makedirs(work_dir, exist_ok=True)

        cmd = [
            "python3", TPLMAP_BIN,
            "-u", url,
            "--level", "1",          # Minimal probe depth — fast + low-noise
        ]

        # Target specific parameter when known (much faster than auto-detect)
        if param:
            cmd.extend(["-p", param])

        # POST method
        if method.upper() == "POST":
            cmd.extend(["--data", f"{param}=1" if param else "data=1"])

        # Safe OS confirmation: only when exploit mode is fully unlocked
        if exploit_enabled and ALLOW_OS_CMD:
            cmd.extend(["--os-cmd", CONFIRM_CMD])
            logger.info(f"[tplmap] OS command confirmation enabled: {CONFIRM_CMD!r}")

        # Auth
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            cmd.extend(["-c", cookie_str])

        for key, value in auth_context.get("headers", {}).items():
            cmd.extend(["-H", f"{key}: {value}"])

        logger.info(f"[tplmap] Testing: {method} {url} param={param!r}")

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
                logger.warning(f"[tplmap] Timed out on {url}")
                return []

            output = stdout_data.decode("utf-8", errors="ignore")
            return _parse_tplmap_output(output, url, param, method)

        except FileNotFoundError:
            logger.error(f"[tplmap] Binary not found: {TPLMAP_BIN}")
            return []
        except Exception as exc:
            logger.error(f"[tplmap] Error on {url}: {exc}", exc_info=True)
            return []


# ── Output parser ─────────────────────────────────────────────────────────────

def _parse_tplmap_output(
    output: str,
    url: str,
    param: Optional[str],
    method: str,
) -> List[Dict[str, Any]]:
    """
    Parse tplmap's terminal output into structured findings.

    Example tplmap output:
      [+] Tplmap identified the following injection point:
        GET parameter: tmpl
        Engine: Jinja2
        Injection: {{*}}
        Context: text
        OS: posix-linux
        Technique: render
        Capabilities:
          Shell command execution: ok
          ...
    """
    if not _IDENTIFIED_RE.search(output):
        return []

    engine      = (_ENGINE_RE.search(output)     or type('', (), {'group': lambda s, n: None})()).group(1)
    injection   = (_INJECTION_RE.search(output)  or type('', (), {'group': lambda s, n: None})()).group(1)
    shell_ok    = bool(_CAPABILITY_RE.search(output) and
                       _CAPABILITY_RE.search(output).group(1).lower() == "ok")
    os_type     = (_OS_RE.search(output)         or type('', (), {'group': lambda s, n: None})()).group(1)

    # Capture OS command output (if --os-cmd was passed)
    cmd_output = ""
    m = _OS_CMD_RE.search(output)
    if m:
        cmd_output = m.group(1).strip()

    # Clean up engine name
    engine_str = (engine or "unknown").strip()
    severity   = SeverityLevel.critical if shell_ok else SeverityLevel.high

    description = (
        f"SSTI confirmed in parameter '{param}' via {method}. "
        f"Engine: {engine_str}. "
        f"Shell execution: {'YES — RCE confirmed' if shell_ok else 'no'}. "
        f"Injection syntax: {injection or 'see raw_output'}."
    )
    if cmd_output:
        description += f" OS command output: {cmd_output[:200]!r}"

    return [{
        "url":         url,
        "type":        "ssti-confirmed",
        "description": description,
        "severity":    severity,
        "raw_output": {
            "url":           url,
            "parameter":     param,
            "method":        method,
            "engine":        engine_str,
            "injection":     injection,
            "shell_capable": shell_ok,
            "os_type":       os_type,
            "cmd_output":    cmd_output,
            "raw":           output[:3000],
        },
    }]


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    worker = TplmapWorker()
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
