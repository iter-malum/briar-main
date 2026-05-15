"""Katana Crawler Worker"""

import asyncio
import json
import logging
import sys
import os
from typing import Dict, Any, List

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("katana-worker")

class KatanaWorker(BaseWorker):
    def __init__(self):
        super().__init__(
            tool_name="katana",
            queue_name="scan.crawl.katana"
        )
        self.timeout = int(os.getenv("KATANA_TIMEOUT", "600"))  # 10 минут
        self.depth = int(os.getenv("KATANA_DEPTH", "3"))
        self.concurrency = int(os.getenv("KATANA_CONCURRENCY", "10"))

    async def execute_tool(self, target: str, auth_context: Dict[str, Any], task_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Запуск Katana краулера"""
        
        cmd = [
            "/usr/local/bin/katana",
            "-u", target,
            "-jsonl",
            "-depth", str(self.depth),
            "-c", str(self.concurrency),
            "-silent",
            "-no-color",
            "-jc",          # Always enable JavaScript crawling
            "-fx",          # Form extraction
            "-aff",         # Automatic form fill for deeper discovery
            "-kf", "all",   # Known files (robots.txt, sitemap.xml, etc.)
            "-rl", "100",   # Rate limit (requests/second)
            "-timeout", "15",  # Per-request timeout
            "-retry", "1",
        ]
        
        # Добавляем заголовки аутентификации
        headers = auth_context.get("headers", {})
        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        
        # Cookies через файл (если есть)
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookies_file = "/tmp/katana/cookies.txt"
            os.makedirs(os.path.dirname(cookies_file), exist_ok=True)
            with open(cookies_file, 'w') as f:
                for c in cookies:
                    # Формат: domain\tflag\tpath\tsecure\texpiration\tname\tvalue
                    f.write(f"{c.get('domain','')}\tTRUE\t{c.get('path','/')}\tFALSE\t0\t{c['name']}\t{c['value']}\n")
            cmd.extend(["-H", f"@{cookies_file}"])
        
        # Дополнительные параметры из payload
        if task_payload.get("headless"):
            cmd.append("-headless")
            cmd.append("-no-sandbox")
        
        logger.info(f"Starting Katana crawl: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp/katana"
            )
            
            results = []
            # Читаем stdout и stderr параллельно
            stdout_future = self._read_stream(process.stdout, results, is_stderr=False)
            stderr_future = self._read_stream(process.stderr, None, is_stderr=True)
            
            await asyncio.wait_for(
                asyncio.gather(stdout_future, stderr_future, process.wait()),
                timeout=self.timeout
            )
            
            if process.returncode not in [0, None]:
                logger.warning(f"Katana exited with code {process.returncode}")
            
            logger.info(f"Katana found {len(results)} endpoints")
            return results
            
        except asyncio.TimeoutError:
            logger.error(f"Katana timed out after {self.timeout} seconds")
            if process:
                process.kill()
                await process.wait()
            return []
        except Exception as e:
            logger.error(f"Katana execution failed: {e}", exc_info=True)
            return []

    async def _read_stream(self, stream, results_list, is_stderr=False):
        """Чтение потока вывода Katana (JSONL формат) с увеличенным лимитом"""
        
        # ✅ Увеличиваем лимит до 10 МБ для обработки длинных JSON-строк
        MAX_LINE_LENGTH = 10 * 1024 * 1024  # 10 MB
        
        while True:
            try:
                line = await stream.readuntil(b'\n')
                line_str = line.decode('utf-8', errors='ignore').strip()
                
                if not line_str:
                    continue
                    
                if is_stderr:
                    # Логируем только важные ошибки
                    if any(kw in line_str.lower() for kw in ['error', 'failed', 'exception']):
                        logger.warning(f"Katana stderr: {line_str[:500]}")
                    continue
                
                # Парсим JSONL
                try:
                    data = json.loads(line_str)
                    
                    # Извлекаем URL из структуры Katana
                    request = data.get("request", {})
                    endpoint_url = request.get("endpoint") or request.get("url")
                    
                    if endpoint_url:
                        results_list.append({
                            "url": endpoint_url,
                            "type": "endpoint",
                            "description": f"Discovered via {request.get('method', 'GET')}",
                            "severity": SeverityLevel.info,
                            "method": request.get("method", "GET"),
                            "source": request.get("source", ""),
                            "tag": data.get("response", {}).get("headers", {}).get("content-type", ""),
                            "raw_output": {
                                "request": request,
                                "response": data.get("response", {}),
                                "timestamp": data.get("timestamp")
                            }
                        })
                except json.JSONDecodeError as e:
                    logger.debug(f"Failed to parse Katana JSONL: {line_str[:200]}... Error: {e}")
                    continue
                    
            except asyncio.exceptions.LimitOverrunError:
                # 🔄 Если линия слишком длинная — читаем и пропускаем (или логируем)
                logger.warning("Katana output line exceeded limit, skipping...")
                # Прочитаем и сбросим буфер до следующего \n
                try:
                    await stream.readuntil(b'\n')
                except:
                    break
            except asyncio.IncompleteReadError as e:
                # Конец потока
                if e.partial:
                    # Обработаем оставшиеся данные
                    line_str = e.partial.decode('utf-8', errors='ignore').strip()
                    if line_str:
                        try:
                            data = json.loads(line_str)
                            # ... та же логика обработки ...
                        except:
                            pass
                break
            except Exception as e:
                logger.error(f"Error reading Katana stream: {e}", exc_info=True)
                break

async def main():
    worker = KatanaWorker()
    await worker.start()
    
    try:
        # Блокируем выполнение до получения сигнала shutdown
        while worker.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    finally:
        await worker.shutdown()

if __name__ == "__main__":
    asyncio.run(main())