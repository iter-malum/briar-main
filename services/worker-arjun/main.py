#!/usr/bin/env python3
"""Arjun HTTP Parameter Discovery Worker"""

import asyncio
import json
import logging
import os
import sys
from typing import Dict, Any, List
from urllib.parse import urlparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s')
logger = logging.getLogger("arjun-worker")

ARJUN_RATE = int(os.environ.get("ARJUN_RATE", 9999))
ARJUN_TIMEOUT = int(os.environ.get("ARJUN_TIMEOUT", 15))

_STATIC_EXTS = frozenset({
    ".css", ".js", ".mjs", ".ts", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".webm", ".ogg", ".wav",
    ".pdf", ".zip", ".gz", ".tar", ".rar",
})


def _is_scannable(url: str) -> bool:
    """Return True if the URL is worth scanning for hidden parameters."""
    try:
        path = urlparse(url).path.lower()
        ext = os.path.splitext(path)[1]
        return ext not in _STATIC_EXTS
    except Exception:
        return True


class ArjunWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="arjun", queue_name="scan.probe.arjun")
        self.timeout = 300
        self.rate = ARJUN_RATE
        self.arjun_timeout = ARJUN_TIMEOUT

    async def execute_tool(self, target: str, auth_context: Dict[str, Any], task_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        endpoints = task_payload.get("endpoints", [])
        if not endpoints and target and target.startswith('http'):
            endpoints = [target]

        normalized = []
        for ep in endpoints:
            ep = ep.strip()
            if not ep:
                continue
            if not ep.startswith(('http://', 'https://')):
                ep = f"https://{ep}"
            normalized.append(ep)

        unique_endpoints = list({ep for ep in normalized if _is_scannable(ep)})
        if not unique_endpoints:
            logger.warning("No scannable endpoints (all static files or empty)")
            return []

        logger.info(f"Running Arjun against {len(unique_endpoints)} endpoints")

        work_dir = "/tmp/arjun"
        os.makedirs(work_dir, exist_ok=True)

        targets_file = os.path.join(work_dir, "targets.txt")
        output_file = os.path.join(work_dir, "output.json")

        with open(targets_file, 'w') as f:
            f.write('\n'.join(unique_endpoints))

        # Build auth headers dict for arjun --headers
        headers_dict: Dict[str, str] = dict(auth_context.get("headers", {}))
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            headers_dict["Cookie"] = cookie_str

        # Determine HTTP methods
        method_param = task_payload.get("method", "GET").upper()
        methods: List[str] = []
        if "GET" in method_param:
            methods.append("GET")
        if "POST" in method_param:
            methods.append("POST")
        if not methods:
            methods = ["GET"]

        all_results: List[Dict[str, Any]] = []

        for method in methods:
            result = await self._run_arjun(
                targets_file=targets_file,
                output_file=output_file,
                method=method,
                headers_dict=headers_dict,
            )
            all_results.extend(result)

        # Deduplicate by (url, parameter)
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for r in all_results:
            key = (r["url"], tuple(sorted(r.get("parameters", []))))
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        logger.info(f"Arjun found {len(deduped)} parameter sets across {len(unique_endpoints)} endpoints")
        return deduped

    async def _run_arjun(
        self,
        targets_file: str,
        output_file: str,
        method: str,
        headers_dict: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        # Remove stale output file so we don't read old data
        if os.path.exists(output_file):
            os.remove(output_file)

        cmd = [
            "python3", "-m", "arjun",
            "-i", targets_file,
            "-o", output_file,
            "-q",
            "--rate-limit", str(self.rate),
            "--timeout", str(self.arjun_timeout),
            "-m", method,
        ]

        if headers_dict:
            cmd.extend(["--headers", json.dumps(headers_dict)])

        logger.info(f"Arjun command ({method}): {' '.join(cmd)}")

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp/arjun",
            )

            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout,
            )

            if process.returncode not in [0, None]:
                stderr_output = stderr_data.decode('utf-8', errors='ignore').strip()
                if stderr_output:
                    logger.warning(f"arjun exited {process.returncode} ({method}): {stderr_output[:300]}")
            else:
                logger.debug(f"arjun stdout ({method}): {stdout_data.decode('utf-8', errors='ignore')[:200]}")

            return self._parse_output(output_file, method)

        except asyncio.TimeoutError:
            logger.error(f"Arjun timed out after {self.timeout}s (method={method})")
            if process:
                process.kill()
                await process.wait()
            return []
        except Exception as e:
            logger.error(f"Arjun execution failed (method={method}): {e}", exc_info=True)
            return []

    def _parse_output(self, output_file: str, method: str) -> List[Dict[str, Any]]:
        if not os.path.exists(output_file):
            logger.warning(f"Arjun output file not found: {output_file}")
            return []

        try:
            with open(output_file, 'r') as f:
                raw = f.read().strip()

            if not raw:
                return []

            data = json.loads(raw)
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to read/parse arjun output: {e}")
            return []

        # Arjun outputs either a list of {"url": ..., "params": [...]} or a
        # single such dict. Normalise to a list.
        if isinstance(data, dict):
            entries = [data]
        elif isinstance(data, list):
            entries = data
        else:
            logger.warning(f"Unexpected arjun output type: {type(data)}")
            return []

        results: List[Dict[str, Any]] = []
        for entry in entries:
            url = entry.get("url", "")
            params = entry.get("params", [])
            if not url or not params:
                continue

            preview = ', '.join(params[:10])
            suffix = f" (+{len(params) - 10} more)" if len(params) > 10 else ""
            results.append({
                "url": url,
                "type": "discovered_parameter",
                "description": f"Discovered {len(params)} hidden parameters via {method}: {preview}{suffix}",
                "severity": SeverityLevel.info,
                "parameters": params,
                "method": method,
                "raw_output": entry,
            })

        return results


async def main():
    worker = ArjunWorker()
    try:
        await worker.start()
        while worker.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await worker.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
