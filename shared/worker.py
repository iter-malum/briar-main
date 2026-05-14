# FILE: shared/worker.py
import asyncio
import json
import os
import sys
import logging
from typing import Dict, Any, List, Optional
from uuid import UUID
from enum import Enum

import aio_pika
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select

# Добавляем путь к shared, если запускается из подпапки
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.config import settings
from shared.models import ScanResultORM, SeverityLevel
from shared.rabbitmq import RabbitMQPublisher

logger = logging.getLogger("worker-base")

class BaseWorker:
    def __init__(self, tool_name: str, queue_name: str):
        self.tool_name = tool_name
        self.queue_name = queue_name
        self.publisher = RabbitMQPublisher()
        self.engine = create_async_engine(settings.db_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, class_=AsyncSession)
        
        # URL сервиса аутентификации
        self.auth_service_url = os.getenv("AUTH_SERVICE_URL", "http://auth-service:8000")

    async def start(self):
        logger.info(f"Starting {self.tool_name} worker...")
        await self.publisher.connect()
        
        # Подключение к RabbitMQ для потребления
        self.connection = await aio_pika.connect_robust(settings.rabbitmq_url)
        channel = await self.connection.channel()
        await channel.set_qos(prefetch_count=10)
        
        queue = await channel.declare_queue(self.queue_name, durable=True)
        await queue.consume(self.on_message)
        logger.info(f"Worker {self.tool_name} listening on {self.queue_name}")

    async def on_message(self, message: aio_pika.IncomingMessage):
        async with message.process():
            try:
                body = json.loads(message.body.decode())
                logger.info(f"[{self.tool_name}] Received task for scan: {body.get('scan_id')}")
                await self.run_task(body)
            except Exception as e:
                logger.error(f"[{self.tool_name}] Error processing message: {e}", exc_info=True)
                # В продакшене здесь можно отправить сообщение в DLQ (Dead Letter Queue)

    async def run_task(self, payload: Dict[str, Any]):
        scan_id = payload["scan_id"]
        target = payload.get("target", "")
        auth_session_id = payload.get("auth_session_id")
        
        # 1. Получение контекста аутентификации
        headers = await self.get_auth_headers(auth_session_id)
        
        # 2. Запуск инструмента
        results = await self.execute_tool(target, headers, payload.get("payload", {}))
        
        # 3. Сохранение результатов в БД
        await self.save_results(scan_id, results)
        
        # 4. Публикация результатов (опционально, для chaining)
        # await self.publisher.publish("scan.results", {"scan_id": scan_id, "results_count": len(results)})

    async def get_auth_headers(self, session_id: str) -> Dict[str, str]:
        if not session_id:
            return {}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self.auth_service_url}/api/v1/auth/sessions/{session_id}")
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("headers", {})
        except Exception as e:
            logger.warning(f"Failed to get auth session: {e}")
        return {}

    async def execute_tool(self, target: str, auth_headers: Dict[str, str], task_payload: Dict[str, Any]) -> List[Dict]:
        """
        Переопределяется в наследниках.
        Возвращает список найденных уязвимостей/эндпоинтов.
        """
        raise NotImplementedError

    async def save_results(self, scan_id: str, results: List[Dict]):
        async with self.session_factory() as session:
            for res in results:
                item = ScanResultORM(
                    scan_id=UUID(scan_id),
                    tool=self.tool_name,
                    severity=res.get("severity", "info"),
                    url=res.get("url"),
                    vulnerability_type=res.get("type"),
                    description=res.get("description"),
                    raw_output=res
                )
                session.add(item)
            await session.commit()
            logger.info(f"[{self.tool_name}] Saved {len(results)} results for scan {scan_id}")