"""
Nuclei Vulnerability Scanner Worker
=====================================
Phase: DAST
Sources:  katana + ffuf + httpx (ALL discovered endpoints)
Enhancement: reads WhatWeb tech tags and adds relevant -tags filter
             so only appropriate templates run.
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
from datetime import datetime
from typing import Any, Dict, List

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("nuclei-worker")

SEVERITY_MAP = {
    "critical": SeverityLevel.critical,
    "high":     SeverityLevel.high,
    "medium":   SeverityLevel.medium,
    "low":      SeverityLevel.low,
    "info":     SeverityLevel.info,
}


class NucleiWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="nuclei", queue_name="scan.dast.nuclei")
        self.timeout     = int(os.getenv("NUCLEI_TIMEOUT", "1800"))
        self.rate_limit  = int(os.getenv("NUCLEI_RATE_LIMIT", "100"))
        self.concurrency = int(os.getenv("NUCLEI_CONCURRENCY", "25"))

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [target])
        scan_id: str = task_payload.get("scan_id", "")

        # De-duplicate and write to targets file
        unique_endpoints = list(dict.fromkeys(ep for ep in endpoints if ep.startswith("http")))
        if not unique_endpoints:
            unique_endpoints = [target]

        work_dir = "/tmp/nuclei"
        os.makedirs(work_dir, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            dir=work_dir, suffix=".txt", mode="w", delete=False
        ) as tf:
            targets_file = tf.name
            tf.write("\n".join(unique_endpoints))

        logger.info(f"[nuclei] Scanning {len(unique_endpoints)} endpoints")

        try:
            cmd = [
                "nuclei",
                "-l", targets_file,       # multi-target list
                "-jsonl",
                "-silent",
                "-rate-limit", str(self.rate_limit),
                "-c", str(self.concurrency),
                "-timeout", "30",
                "-retries", "1",
            ]

            # Auth
            headers = auth_context.get("headers", {})
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

            cookies = auth_context.get("cookies", [])
            if cookies:
                cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
                cmd.extend(["-H", f"Cookie: {cookie_str}"])

            # Technology-based template selection
            if scan_id:
                tech_tags = await self.get_tech_tags(scan_id)
                if tech_tags:
                    cmd.extend(["-tags", ",".join(set(tech_tags))])
                    logger.info(f"[nuclei] Using tech tags: {tech_tags}")

            # Extra payload overrides
            if task_payload.get("templates"):
                cmd.extend(["-t", ",".join(task_payload["templates"])])

            if task_payload.get("severity_filter"):
                cmd.extend(["-s", task_payload["severity_filter"]])

            if task_payload.get("exclude_tags"):
                cmd.extend(["-exclude-tags", ",".join(task_payload["exclude_tags"])])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
            )

            results: List[Dict[str, Any]] = []
            stdout_task = asyncio.create_task(
                self._read_jsonl(process.stdout, results)
            )
            _, stderr_data = await asyncio.wait_for(
                asyncio.gather(
                    stdout_task,
                    process.wait(),
                ),
                timeout=self.timeout,
            )

            if process.returncode not in (0, None):
                logger.warning(f"[nuclei] exited with code {process.returncode}")

            logger.info(f"[nuclei] Found {len(results)} vulnerabilities")
            return results

        except asyncio.TimeoutError:
            logger.error(f"[nuclei] Timed out after {self.timeout}s")
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass
            return []

        except Exception as exc:
            logger.error(f"[nuclei] Execution failed: {exc}", exc_info=True)
            return []

        finally:
            if os.path.exists(targets_file):
                os.unlink(targets_file)

    async def _read_jsonl(self, stream, results: List[Dict[str, Any]]):
        while True:
            line = await stream.readline()
            if not line:
                break
            line_str = line.decode("utf-8", errors="ignore").strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                info = data.get("info", {})
                sev_str = info.get("severity", "info").lower()

                results.append({
                    "url": data.get("matched-at", ""),
                    "type": data.get("template-id", ""),
                    "description": info.get("name", ""),
                    "severity": SEVERITY_MAP.get(sev_str, SeverityLevel.info),
                    "raw_output": {
                        "template-id":       data.get("template-id"),
                        "template-path":     data.get("template-path"),
                        "info":              info,
                        "matcher-name":      data.get("matcher-name"),
                        "extracted-results": data.get("extracted-results"),
                        "curl-command":      data.get("curl-command"),
                        "timestamp":         data.get("timestamp", datetime.utcnow().isoformat()),
                    },
                })
            except json.JSONDecodeError:
                logger.debug(f"[nuclei] Unparseable line: {line_str[:120]}")


async def main():
    worker = NucleiWorker()
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
