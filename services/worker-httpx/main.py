#!/usr/bin/env python3
"""HTTPX Probe Worker - FINAL FIXED VERSION"""

import asyncio
import json
import logging
import os
import sys
from typing import Dict, Any, List

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s')
logger = logging.getLogger("httpx-worker")


class HTTPXWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="httpx", queue_name="scan.probe.httpx")
        self.timeout = 300
        self.threads = 50
        self.rate_limit = 200

    async def execute_tool(self, target: str, auth_context: Dict[str, Any], task_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Получаем эндпоинты
        endpoints = task_payload.get("endpoints", [])
        if not endpoints and target and target.startswith('http'):
            endpoints = [target]
        
        # Нормализуем
        normalized = []
        for ep in endpoints:
            ep = ep.strip()
            if not ep: continue
            if not ep.startswith(('http://', 'https://')):
                ep = f"https://{ep}"
            normalized.append(ep)
        
        unique_endpoints = list(set(normalized))
        if not unique_endpoints:
            logger.warning("No valid endpoints")
            return []
        
        logger.info(f"Probing {len(unique_endpoints)} endpoints")
        
        # Файл целей
        targets_file = "/tmp/httpx/targets.txt"
        os.makedirs(os.path.dirname(targets_file), exist_ok=True)
        with open(targets_file, 'w') as f:
            f.write('\n'.join(unique_endpoints))
        
        # Команда
        cmd = [
            "/usr/local/bin/httpx-pd",
            "-l", targets_file,
            "-json",
            "-silent",
            "-no-color",
            "-status-code",
            "-content-type",
            "-content-length",
            "-title",
            "-tech-detect",
            "-threads", str(self.threads),
            "-rate-limit", str(self.rate_limit),
            "-timeout", "10",
            "-follow-redirects",
            "-retries", "1",
            "-no-decode"
        ]
        
        # Заголовки
        for k, v in auth_context.get("headers", {}).items():
            cmd.extend(["-H", f"{k}: {v}"])
        
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            cmd.extend(["-H", f"Cookie: {cookie_header}"])
        
        logger.info(f"Command: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp/httpx"
            )
            
            results: List[Dict] = []
            
            # Читаем весь вывод сразу
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            # Парсим JSONL
            output = stdout_data.decode('utf-8', errors='ignore')
            for line in output.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    self._process_result(data, results)
                except json.JSONDecodeError as e:
                    logger.debug(f"Failed to parse: {line[:100]}... {e}")
                    continue
            
            # Логируем ошибки
            if process.returncode not in [0, None]:
                stderr_output = stderr_data.decode('utf-8', errors='ignore').strip()
                if stderr_output:
                    logger.warning(f"httpx-pd exited {process.returncode}: {stderr_output[:300]}")
            
            logger.info(f"Found {len(results)} results from {len(unique_endpoints)} endpoints")
            return results
            
        except asyncio.TimeoutError:
            logger.error(f"HTTPX timed out after {self.timeout}s")
            if process:
                process.kill()
                await process.wait()
            return []
        except Exception as e:
            logger.error(f"Execution failed: {e}", exc_info=True)
            return []

    # ✅ ИСПРАВЛЕННАЯ СИГНАТУРА: data: Dict[str, Any]
    def _process_result(self, data: Dict[str, Any], results_list: List):
        url = data.get("url") or data.get("input")
        if not url:
            return
        
        status = data.get("status_code", 0)
        severity = SeverityLevel.medium if status >= 500 else SeverityLevel.low if status in [401, 403, 407] else SeverityLevel.info
        
        results_list.append({
            "url": url,
            "type": "probe_result",
            "description": f"HTTP {status} - {data.get('title', '')[:80]}",
            "severity": severity,
            "status_code": status,
            "content_type": data.get("content_type", ""),
            "content_length": data.get("content_length", 0),
            "title": data.get("title", ""),
            "technologies": data.get("tech", []),
            "web_server": data.get("webserver", ""),
            "response_time_ms": data.get("response-time", 0),
            "raw_output": data
        })


async def main():
    worker = HTTPXWorker()
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