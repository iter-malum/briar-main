"""
OWASP ZAP Active Scanner Worker
=================================
Phase: DAST (parallel with Nuclei)
Sources: katana + ffuf + httpx endpoints

Fixes vs original:
- Health-check loop replaces bare sleep(15) for ZAP startup
- Correct ZAP REST API paths: /JSON/spider/ and /JSON/ascan/ (not "active_scan")
- Endpoints from previous phases are added to ZAP context before scanning
- auth cookies/headers properly loaded via ZAP replacer rules
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

import httpx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("zap-worker")

RISK_MAP = {
    "High":          SeverityLevel.high,
    "Medium":        SeverityLevel.medium,
    "Low":           SeverityLevel.low,
    "Informational": SeverityLevel.info,
}


class ZAPWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="zap", queue_name="scan.dast.zap")
        self.timeout      = int(os.getenv("ZAP_TIMEOUT", "3600"))
        self.zap_port     = int(os.getenv("ZAP_PORT", "8090"))
        self.api_key      = os.getenv("ZAP_API_KEY", "briar-zap-api-key-2024")
        self.max_duration = int(os.getenv("ZAP_MAX_DURATION", "30"))  # minutes

    # ── ZAP base URL ───────────────────────────────────────────────────────────

    @property
    def _base(self) -> str:
        return f"http://localhost:{self.zap_port}"

    async def _zap(self, client: httpx.AsyncClient, path: str, **params) -> dict:
        """Call the ZAP JSON API, always injecting the api key."""
        resp = await client.get(
            f"{self._base}/JSON/{path}",
            params={"apikey": self.api_key, **params},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    # ── Tool entry point ───────────────────────────────────────────────────────

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [target])
        if not endpoints:
            endpoints = [target]

        zap_process: Optional[asyncio.subprocess.Process] = None
        try:
            zap_process = await self._start_zap_daemon()
            await self._wait_for_zap_ready()

            async with httpx.AsyncClient() as client:
                # Load auth into ZAP
                await self._load_auth(client, auth_context)

                # Feed all discovered endpoints into ZAP's tree so ascan covers them
                for ep in endpoints[:500]:  # cap to avoid memory issues
                    try:
                        await self._zap(client, "core/action/accessUrl/", url=ep)
                    except Exception:
                        pass

                # Spider the primary target
                spider_id = await self._start_spider(client, target)
                await self._wait_scan(client, "spider", spider_id)

                # Active scan the primary target (ZAP will include discovered URLs)
                ascan_id = await self._start_ascan(client, target)
                await self._wait_scan(client, "ascan", ascan_id)

                return await self._collect_alerts(client, target)

        except Exception as exc:
            logger.error(f"[zap] Execution failed: {exc}", exc_info=True)
            return []
        finally:
            if zap_process:
                zap_process.terminate()
                try:
                    await asyncio.wait_for(zap_process.wait(), timeout=15)
                except asyncio.TimeoutError:
                    zap_process.kill()

    # ── ZAP daemon management ──────────────────────────────────────────────────

    async def _start_zap_daemon(self) -> asyncio.subprocess.Process:
        cmd = [
            "/zap/zap.sh",
            "-daemon",
            "-port", str(self.zap_port),
            "-host", "127.0.0.1",
            "-config", f"api.key={self.api_key}",
            "-config", "api.disablekey=false",
            "-config", f"scanner.maxDuration={self.max_duration}",
            "-config", "spider.maxDuration=5",
        ]
        logger.info(f"[zap] Starting ZAP daemon on port {self.zap_port}")
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return proc

    async def _wait_for_zap_ready(self, max_wait: int = 120):
        """Poll ZAP's API until it responds — much safer than a fixed sleep."""
        deadline = asyncio.get_event_loop().time() + max_wait
        while asyncio.get_event_loop().time() < deadline:
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        f"{self._base}/JSON/core/view/version/",
                        params={"apikey": self.api_key},
                        timeout=5,
                    )
                    if resp.status_code == 200:
                        version = resp.json().get("version", "?")
                        logger.info(f"[zap] Ready — version {version}")
                        return
            except Exception:
                pass
            await asyncio.sleep(3)
        raise TimeoutError("[zap] ZAP daemon did not start in time")

    # ── Auth loading ───────────────────────────────────────────────────────────

    async def _load_auth(self, client: httpx.AsyncClient, auth_context: Dict[str, Any]):
        """Add cookies and custom headers via ZAP's replacer API."""
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            try:
                await self._zap(
                    client,
                    "replacer/action/addRule/",
                    description="briar-auth-cookie",
                    enabled="true",
                    matchtype="REQ_HEADER",
                    matchregex="false",
                    matchstring="Cookie",
                    replacement=cookie_str,
                    initiators="",
                )
            except Exception as exc:
                logger.warning(f"[zap] Failed to set cookie: {exc}")

        for name, value in auth_context.get("headers", {}).items():
            try:
                await self._zap(
                    client,
                    "replacer/action/addRule/",
                    description=f"briar-header-{name}",
                    enabled="true",
                    matchtype="REQ_HEADER",
                    matchregex="false",
                    matchstring=name,
                    replacement=value,
                    initiators="",
                )
            except Exception as exc:
                logger.warning(f"[zap] Failed to set header {name}: {exc}")

    # ── Spider ─────────────────────────────────────────────────────────────────

    async def _start_spider(self, client: httpx.AsyncClient, target: str) -> str:
        data = await self._zap(client, "spider/action/scan/", url=target)
        scan_id = data.get("scan", "0")
        logger.info(f"[zap] Spider started, id={scan_id}")
        return scan_id

    # ── Active scan ────────────────────────────────────────────────────────────

    async def _start_ascan(self, client: httpx.AsyncClient, target: str) -> str:
        data = await self._zap(client, "ascan/action/scan/", url=target)
        scan_id = data.get("scan", "0")
        logger.info(f"[zap] Active scan started, id={scan_id}")
        return scan_id

    # ── Poll until done ────────────────────────────────────────────────────────

    async def _wait_scan(
        self, client: httpx.AsyncClient, scan_type: str, scan_id: str
    ):
        """
        Poll ZAP scan progress until 100 (complete).
        scan_type must be "spider" or "ascan" — these are the actual ZAP API namespaces.
        """
        deadline = asyncio.get_event_loop().time() + self.timeout
        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(10)
            try:
                data = await self._zap(
                    client, f"{scan_type}/view/status/", scanId=scan_id
                )
                progress = int(data.get("status", 0))
                logger.info(f"[zap] {scan_type} progress: {progress}%")
                if progress >= 100:
                    logger.info(f"[zap] {scan_type} complete")
                    return
            except Exception as exc:
                logger.warning(f"[zap] Status poll error ({scan_type}): {exc}")
        logger.warning(f"[zap] {scan_type} timed out after {self.timeout}s")

    # ── Collect results ────────────────────────────────────────────────────────

    async def _collect_alerts(
        self, client: httpx.AsyncClient, target: str
    ) -> List[Dict[str, Any]]:
        try:
            data = await self._zap(
                client, "core/view/alerts/", baseurl=target, start="0", count="5000"
            )
        except Exception as exc:
            logger.error(f"[zap] Failed to collect alerts: {exc}")
            return []

        results: List[Dict[str, Any]] = []
        for alert in data.get("alerts", []):
            results.append({
                "url":         alert.get("url", target),
                "type":        f"ZAP-{alert.get('pluginId', '')}",
                "description": alert.get("name", alert.get("description", "")),
                "severity":    RISK_MAP.get(alert.get("risk", ""), SeverityLevel.info),
                "raw_output": {
                    "name":        alert.get("name"),
                    "description": alert.get("description"),
                    "solution":    alert.get("solution"),
                    "reference":   alert.get("reference"),
                    "cweid":       alert.get("cweid"),
                    "wascid":      alert.get("wascid"),
                    "evidence":    alert.get("evidence"),
                    "param":       alert.get("param"),
                    "attack":      alert.get("attack"),
                    "pluginId":    alert.get("pluginId"),
                    "risk":        alert.get("risk"),
                },
            })

        logger.info(f"[zap] Collected {len(results)} alerts")
        return results


async def main():
    worker = ZAPWorker()
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
