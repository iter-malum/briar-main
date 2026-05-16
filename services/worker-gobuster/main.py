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
        self.wordlist = os.getenv(
            "GOBUSTER_WORDLIST",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
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

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-x", extensions,
            "-t", str(threads),
            "--timeout", f"{timeout}s",
            "--no-progress",
            "--output", OUTPUT_FILE,
        ]

        # Inject auth headers
        for key, value in auth_context.get("headers", {}).items():
            cmd.extend(["-H", f"{key}: {value}"])

        # Inject cookies as a Cookie header
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            cmd.extend(["-H", f"Cookie: {cookie_str}"])

        logger.info(f"[gobuster] dir mode → {url}")
        await self._run_gobuster(cmd, timeout)

        return _parse_dir_output(OUTPUT_FILE, url)

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
