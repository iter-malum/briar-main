"""
FFUF Fuzzer Worker
==================
Fuzzes discovered endpoints from the PROBE phase (source: katana results).
Writes output to a temp JSON file for reliable parsing — FFUF's -json flag
emits a single JSON object at process exit, not streaming JSONL.
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
logger = logging.getLogger("ffuf-worker")


class FFUFWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="ffuf", queue_name="scan.fuzz.ffuf")
        self.timeout = int(os.getenv("FFUF_TIMEOUT", "1200"))
        self.rate    = int(os.getenv("FFUF_RATE", "500"))
        self.threads = int(os.getenv("FFUF_THREADS", "40"))
        self.wordlist = os.getenv(
            "FFUF_WORDLIST",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        )

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        # Determine base URLs to fuzz.
        # Use katana endpoints but deduplicate to unique base paths so we
        # don't launch FFUF once per discovered sub-page.
        endpoints: List[str] = task_payload.get("endpoints", [])
        base_urls = _unique_base_urls(endpoints, target)

        results: List[Dict[str, Any]] = []

        for base_url in base_urls[:20]:  # cap at 20 bases per scan to avoid explosion
            partial = await self._fuzz_one(base_url, auth_context)
            results.extend(partial)

        logger.info(f"[ffuf] Total discovered paths: {len(results)} across {len(base_urls)} base URLs")
        return results

    async def _fuzz_one(
        self,
        base_url: str,
        auth_context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        work_dir = "/tmp/ffuf"
        os.makedirs(work_dir, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            dir=work_dir, suffix=".json", delete=False
        ) as tf:
            out_file = tf.name

        try:
            cmd = [
                "ffuf",
                "-u", f"{base_url.rstrip('/')}/FUZZ",
                "-w", self.wordlist,
                "-o", out_file,
                "-of", "json",
                "-rate", str(self.rate),
                "-t", str(self.threads),
                "-mc", "200,204,301,302,307,401,403,405,500",
                "-recursion",
                "-recursion-depth", "2",
                "-s",  # silent — no progress bar
            ]

            # Auth headers
            for key, value in auth_context.get("headers", {}).items():
                cmd.extend(["-H", f"{key}: {value}"])

            cookies = auth_context.get("cookies", [])
            if cookies:
                cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
                cmd.extend(["-H", f"Cookie: {cookie_str}"])

            logger.info(f"[ffuf] Fuzzing {base_url} …")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
            )

            try:
                _, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning(f"[ffuf] Timed out fuzzing {base_url}")
                return []

            if process.returncode not in (0, None):
                err = stderr_data.decode("utf-8", errors="ignore").strip()
                if err:
                    logger.warning(f"[ffuf] exit {process.returncode}: {err[:300]}")

            return _parse_ffuf_output(out_file, base_url)

        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)


# ── Output parsing ─────────────────────────────────────────────────────────────

def _parse_ffuf_output(out_file: str, base_url: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    try:
        with open(out_file, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return results

    for item in data.get("results", []):
        url = item.get("url", "")
        if not url:
            # Reconstruct from base + input word
            word = (item.get("input") or {}).get("FUZZ", "")
            url = f"{base_url.rstrip('/')}/{word}" if word else ""
        if not url:
            continue

        status = item.get("status", 0)
        severity = _status_to_severity(status)

        results.append({
            "url": url,
            "type": "discovered_path",
            "description": (
                f"Fuzzer found: {url} "
                f"[status={status}, size={item.get('length', 0)}, "
                f"words={item.get('words', 0)}]"
            ),
            "severity": severity,
            "raw_output": {
                "url": url,
                "status": status,
                "length": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "content_type": item.get("content-type") or item.get("content_type"),
                "redirect": item.get("redirectlocation"),
                "host": item.get("host"),
                "duration_ms": item.get("duration"),
            },
        })

    return results


def _status_to_severity(status: int) -> SeverityLevel:
    if status == 500:
        return SeverityLevel.medium
    if status in (401, 403):
        return SeverityLevel.low
    return SeverityLevel.info


def _unique_base_urls(endpoints: List[str], fallback: str) -> List[str]:
    """Deduplicate to scheme+host+path-prefix combos."""
    if not endpoints:
        return [fallback] if fallback else []
    seen: set = set()
    out: List[str] = []
    for url in endpoints:
        try:
            p = urlparse(url)
            base = f"{p.scheme}://{p.netloc}"
            if base not in seen:
                seen.add(base)
                out.append(base)
        except Exception:
            continue
    return out if out else [fallback]


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    worker = FFUFWorker()
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
