"""
WhatWeb Technology Detection Worker
=====================================
Phase: RECON (runs in parallel with Katana)
Output: detected tech stack saved as scan_results with type="technology"
        These results are later read by NucleiWorker to select relevant templates.

WhatWeb aggression level 3 (--aggression 3) = active scan but not intrusive.
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("whatweb-worker")


class WhatWebWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="whatweb", queue_name="scan.recon.whatweb")
        self.timeout = int(os.getenv("WHATWEB_TIMEOUT", "120"))
        self.aggression = int(os.getenv("WHATWEB_AGGRESSION", "3"))

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        work_dir = "/tmp/whatweb"
        os.makedirs(work_dir, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            dir=work_dir, suffix=".json", delete=False
        ) as tf:
            out_file = tf.name

        try:
            cmd = [
                "whatweb",
                "--no-errors",
                f"--aggression={self.aggression}",
                f"--log-json={out_file}",
                # NOTE: do NOT add --quiet here — it suppresses --log-json output
                # in some WhatWeb versions and causes 0 results.
            ]

            # Auth headers → Cookie flag
            cookies = auth_context.get("cookies", [])
            if cookies:
                cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
                cmd.extend(["--header", f"Cookie: {cookie_str}"])

            for key, value in auth_context.get("headers", {}).items():
                cmd.extend(["--header", f"{key}: {value}"])

            cmd.append(target)

            logger.info(f"[whatweb] Detecting tech stack: {target}")
            logger.debug(f"[whatweb] Command: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning(f"[whatweb] Timed out after {self.timeout}s")
                return []

            if process.returncode not in (0, None):
                stderr_text = stderr_data.decode("utf-8", errors="ignore").strip()
                logger.warning(
                    f"[whatweb] Exited with code {process.returncode}. stderr: {stderr_text[:300]}"
                )

            # If log-json file is empty, fall back to parsing stdout
            result = _parse_whatweb_output(out_file, target)
            if not result:
                stdout_text = stdout_data.decode("utf-8", errors="ignore").strip()
                if stdout_text:
                    logger.debug(f"[whatweb] stdout (fallback parse): {stdout_text[:200]}")
                    result = _parse_whatweb_stdout(stdout_text, target)
            return result

        except Exception as exc:
            logger.error(f"[whatweb] Execution failed: {exc}", exc_info=True)
            return []
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)


def _build_result_from_entry(entry: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
    """Convert a single WhatWeb JSON entry into a Briar result dict."""
    url = entry.get("target", target)
    plugins = entry.get("plugins", {})
    if not plugins:
        return None

    technologies = list(plugins.keys())
    tech_with_versions: Dict[str, str] = {}
    for tech_name, tech_data in plugins.items():
        if not isinstance(tech_data, dict):
            tech_with_versions[tech_name] = ""
            continue
        # WhatWeb stores version strings in "string" or "version" keys
        versions = tech_data.get("string", []) or tech_data.get("version", [])
        version = versions[0] if isinstance(versions, list) and versions else ""
        tech_with_versions[tech_name] = version

    description_parts = [f"{n} {v}".strip() for n, v in tech_with_versions.items()]

    return {
        "url": url,
        "type": "technology",
        "description": "Detected: " + ", ".join(description_parts[:25]),
        "severity": SeverityLevel.info,
        "raw_output": {
            "technologies": technologies,
            "tech_with_versions": tech_with_versions,
            "http_status": entry.get("http_status"),
        },
    }


def _parse_whatweb_output(out_file: str, target: str) -> List[Dict[str, Any]]:
    try:
        with open(out_file, "r", errors="ignore") as f:
            content = f.read().strip()
        if not content:
            return []

        # WhatWeb --log-json writes one JSON object per line OR a JSON array
        entries: List[Dict[str, Any]] = []
        try:
            data = json.loads(content)
            entries = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            for line in content.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    except FileNotFoundError:
        return []

    results = [r for entry in entries if (r := _build_result_from_entry(entry, target)) is not None]
    logger.info(f"[whatweb] Detected {len(results)} tech entries for {target}")
    return results


def _parse_whatweb_stdout(stdout: str, target: str) -> List[Dict[str, Any]]:
    """
    Fallback: parse WhatWeb's human-readable stdout format.
    Example line:
      http://example.com [200 OK] Apache[2.4.41], Bootstrap[3.4.1], ...
    """
    results: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("http"):
            continue
        # Split off the URL
        parts = line.split(" ", 1)
        if len(parts) < 2:
            continue
        url = parts[0]
        rest = parts[1]
        # Extract technology names (comma-separated, ignore version details)
        import re
        techs = re.findall(r'(\w[\w\-\.]+)(?:\[.*?\])?', rest)
        if not techs:
            continue
        results.append({
            "url": url,
            "type": "technology",
            "description": "Detected: " + ", ".join(techs[:25]),
            "severity": SeverityLevel.info,
            "raw_output": {
                "technologies": techs,
                "tech_with_versions": {t: "" for t in techs},
                "http_status": None,
            },
        })
    return results


async def main():
    worker = WhatWebWorker()
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
