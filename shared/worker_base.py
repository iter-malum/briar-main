"""
BaseWorker
==========
Abstract base class for all Briar scanner workers.

Key design:
- Consumes tasks from a dedicated RabbitMQ queue.
- After execution saves results to PostgreSQL.
- Publishes a `scan.step.completed` event so the Orchestrator's
  PipelineManager can trigger the next pipeline phase.
- Loads auth context (cookies / headers) from Auth Service on demand.
- Loads endpoints from previous-phase tools stored in PostgreSQL.
- Provides tech tag context from WhatWeb results for Nuclei.
"""

import asyncio
import json
import logging
import os
import signal
import sys
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

import aio_pika
import httpx
from prometheus_client import Counter, Gauge, Histogram
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.config import settings
from shared.models import ScanResultORM, ScanStatus, ScanStepORM, SeverityLevel
from shared.pipeline import TECH_TO_NUCLEI_TAGS

logger = logging.getLogger("worker-base")

# ── Per-worker Prometheus metrics (labels carry tool_name) ────────────────────

worker_tasks_total = Counter(
    "briar_worker_tasks_total",
    "Total tasks processed by each worker",
    ["tool", "status"],
)
worker_task_duration = Histogram(
    "briar_worker_task_duration_seconds",
    "Task processing duration per worker",
    ["tool"],
    buckets=[5, 10, 30, 60, 120, 300, 600, 1200, 1800, 3600],
)
worker_queue_depth = Gauge(
    "briar_queue_depth",
    "Approximate number of messages waiting in each worker queue",
    ["queue"],
)
vulns_found_total = Counter(
    "briar_vulns_found_total",
    "Total vulnerability findings saved by each worker",
    ["tool", "severity"],
)


class BaseWorker(ABC):

    def __init__(self, tool_name: str, queue_name: str):
        self.tool_name = tool_name
        self.queue_name = queue_name
        self.running = False

        self.auth_service_url = os.getenv("AUTH_SERVICE_URL", "http://auth-service:8000")

        # DB
        self.engine = create_async_engine(
            settings.db_url,
            pool_size=5,
            max_overflow=10,
            pool_recycle=3600,
        )
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

        # RabbitMQ handles — set in start()
        self._connection: Optional[aio_pika.abc.AbstractRobustConnection] = None
        self._channel: Optional[aio_pika.abc.AbstractChannel] = None
        self._queue: Optional[aio_pika.abc.AbstractQueue] = None
        self._pub_exchange: Optional[aio_pika.abc.AbstractExchange] = None

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def start(self):
        logger.info(f"[{self.tool_name}] Starting worker…")
        await self._connect_rabbitmq()
        self.running = True

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))
            except NotImplementedError:
                pass  # Windows

        logger.info(f"[{self.tool_name}] Ready. Listening on: {self.queue_name}")

    async def shutdown(self):
        logger.info(f"[{self.tool_name}] Shutting down…")
        self.running = False
        if self._connection and not self._connection.is_closed:
            await self._connection.close()
        await self.engine.dispose()

    # ── RabbitMQ setup ─────────────────────────────────────────────────────────

    async def _connect_rabbitmq(self):
        for attempt in range(1, 11):
            try:
                self._connection = await aio_pika.connect_robust(
                    settings.rabbitmq_url,
                    heartbeat=600,
                    blocked_connection_timeout=300,
                )
                self._channel = await self._connection.channel()
                await self._channel.set_qos(prefetch_count=1)

                exchange = await self._channel.declare_exchange(
                    "briar.scan", aio_pika.ExchangeType.DIRECT, durable=True
                )
                self._pub_exchange = exchange

                self._queue = await self._channel.declare_queue(
                    self.queue_name, durable=True,
                    arguments={"x-message-ttl": 86400000},
                )
                await self._queue.bind(exchange, routing_key=self.queue_name)

                # Also bind the completion queue so we can publish to it
                await self._channel.declare_queue(
                    "scan.step.completed", durable=True,
                    arguments={"x-message-ttl": 86400000},
                )

                await self._queue.consume(self._on_message)
                logger.info(f"[{self.tool_name}] Bound to queue '{self.queue_name}'")
                return

            except Exception as exc:
                wait = min(2 ** attempt, 30)
                logger.error(f"[{self.tool_name}] RabbitMQ attempt {attempt}/10 failed: {exc} — retry in {wait}s")
                await asyncio.sleep(wait)

        raise ConnectionError(f"[{self.tool_name}] Cannot connect to RabbitMQ after 10 attempts")

    # ── Message handling ───────────────────────────────────────────────────────

    async def _on_message(self, message: aio_pika.IncomingMessage):
        async with message.process(ignore_processed=True):
            try:
                body = json.loads(message.body.decode())
                scan_id = body.get("scan_id", "?")
                logger.info(f"[{self.tool_name}] Task received for scan {scan_id}")

                worker_timeout = int(os.getenv("WORKER_TIMEOUT", "3600"))
                await asyncio.wait_for(self._process_task(body), timeout=worker_timeout)

            except asyncio.TimeoutError:
                scan_id = json.loads(message.body.decode()).get("scan_id", "?")
                logger.error(f"[{self.tool_name}] Task timed out for scan {scan_id}")
                await self._update_step_status(scan_id, ScanStatus.failed)
                await self._publish_completion(scan_id, "failed")
            except Exception as exc:
                logger.error(f"[{self.tool_name}] Unhandled error: {exc}", exc_info=True)

    async def _process_task(self, payload: Dict[str, Any]):
        import time as _time
        scan_id = payload["scan_id"]
        target = payload.get("target", "")
        auth_session_id = payload.get("auth_session_id")
        task_payload = payload.get("payload", {})
        source_tools: List[str] = task_payload.get("source_tools", [])

        _task_start = _time.monotonic()
        try:
            await self._update_step_status(scan_id, ScanStatus.running)

            # Load endpoints from previous-phase tools
            endpoints: List[str] = []
            if source_tools:
                endpoints = await self._get_endpoints_from_db(scan_id, source_tools)
                logger.info(f"[{self.tool_name}] Loaded {len(endpoints)} endpoints from {source_tools}")

            # Fall back to the original target URL
            if not endpoints and target:
                endpoints = [target]

            task_payload["endpoints"] = endpoints

            # Inject scan_id so execute_tool implementations can query the DB
            task_payload["scan_id"] = scan_id

            # Resolve auth context
            auth_context = await self._get_auth_context(auth_session_id)

            # Execute the tool
            results = await self.execute_tool(target, auth_context, task_payload)

            # Persist results
            await self._save_results(scan_id, results)

            await self._update_step_status(scan_id, ScanStatus.completed)
            await self._publish_completion(scan_id, "completed")
            logger.info(f"[{self.tool_name}] Done — {len(results)} results for scan {scan_id}")

            # Prometheus
            worker_tasks_total.labels(tool=self.tool_name, status="completed").inc()
            worker_task_duration.labels(tool=self.tool_name).observe(_time.monotonic() - _task_start)

        except Exception as exc:
            logger.error(f"[{self.tool_name}] Task failed: {exc}", exc_info=True)
            await self._update_step_status(scan_id, ScanStatus.failed)
            await self._publish_completion(scan_id, "failed")
            worker_tasks_total.labels(tool=self.tool_name, status="failed").inc()
            worker_task_duration.labels(tool=self.tool_name).observe(_time.monotonic() - _task_start)

    # ── Completion event ───────────────────────────────────────────────────────

    async def _publish_completion(self, scan_id: str, status: str):
        """Notify the PipelineManager that this tool finished."""
        if not self._pub_exchange:
            return
        try:
            msg = aio_pika.Message(
                body=json.dumps({
                    "scan_id": scan_id,
                    "tool": self.tool_name,
                    "status": status,
                    "timestamp": datetime.utcnow().isoformat(),
                }).encode(),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            )
            await self._pub_exchange.publish(msg, routing_key="scan.step.completed")
            logger.debug(f"[{self.tool_name}] Published completion event for scan {scan_id}")
        except Exception as exc:
            logger.warning(f"[{self.tool_name}] Failed to publish completion: {exc}")

    # ── DB helpers ─────────────────────────────────────────────────────────────

    async def _get_endpoints_from_db(self, scan_id: str, source_tools: List[str]) -> List[str]:
        """Load unique URLs saved by the specified source tools."""
        try:
            async with self.session_factory() as session:
                stmt = (
                    select(ScanResultORM.url)
                    .where(
                        ScanResultORM.scan_id == UUID(scan_id),
                        ScanResultORM.tool.in_(source_tools),
                        ScanResultORM.url.isnot(None),
                        ScanResultORM.url != "",
                    )
                    .distinct()
                )
                result = await session.execute(stmt)
                return [url for (url,) in result.all() if url and url.startswith("http")]
        except Exception as exc:
            logger.error(f"[{self.tool_name}] _get_endpoints_from_db failed: {exc}")
            return []

    async def _get_sqli_endpoints_from_db(self, scan_id: str, source_tools: List[str]) -> List[str]:
        """Return only endpoints from source tools that have associated SQLi findings."""
        from shared.pipeline import SQLI_INDICATORS
        try:
            async with self.session_factory() as session:
                stmt = (
                    select(ScanResultORM.url)
                    .where(
                        ScanResultORM.scan_id == UUID(scan_id),
                        ScanResultORM.tool.in_(source_tools),
                        ScanResultORM.url.isnot(None),
                    )
                )
                result = await session.execute(stmt)
                rows = result.all()
                sqli_urls = set()
                for (url,) in rows:
                    if not url:
                        continue
                    # Check if there's a SQLi finding for this URL
                    vuln_stmt = select(ScanResultORM.vulnerability_type).where(
                        ScanResultORM.scan_id == UUID(scan_id),
                        ScanResultORM.url == url,
                        ScanResultORM.vulnerability_type.isnot(None),
                    )
                    vr = await session.execute(vuln_stmt)
                    for (vtype,) in vr.all():
                        if vtype and any(ind in vtype.lower() for ind in SQLI_INDICATORS):
                            sqli_urls.add(url)
                            break
                return list(sqli_urls)
        except Exception as exc:
            logger.error(f"[{self.tool_name}] _get_sqli_endpoints failed: {exc}")
            return []

    async def get_tech_tags(self, scan_id: str) -> List[str]:
        """Read WhatWeb results and map technologies to Nuclei template tags."""
        try:
            async with self.session_factory() as session:
                stmt = select(ScanResultORM.raw_output).where(
                    ScanResultORM.scan_id == UUID(scan_id),
                    ScanResultORM.tool == "whatweb",
                )
                result = await session.execute(stmt)
                tags: set = set()
                for (raw,) in result.all():
                    if not raw:
                        continue
                    techs = raw.get("technologies", [])
                    for tech in techs:
                        lower = tech.lower()
                        for key, tag_list in TECH_TO_NUCLEI_TAGS.items():
                            if key in lower:
                                tags.update(tag_list)
                return list(tags)
        except Exception as exc:
            logger.warning(f"[{self.tool_name}] Failed to read tech tags: {exc}")
            return []

    async def _update_step_status(self, scan_id: str, status: ScanStatus):
        try:
            async with self.session_factory() as session:
                stmt = select(ScanStepORM).where(
                    ScanStepORM.scan_id == UUID(scan_id),
                    ScanStepORM.tool == self.tool_name,
                )
                result = await session.execute(stmt)
                step = result.scalars().first()
                if step:
                    step.status = status
                    now = datetime.utcnow()
                    if status == ScanStatus.running and not step.started_at:
                        step.started_at = now
                    elif status in (ScanStatus.completed, ScanStatus.failed) and not step.finished_at:
                        step.finished_at = now
                    await session.commit()
        except Exception as exc:
            logger.error(f"[{self.tool_name}] _update_step_status failed: {exc}")

    async def _save_results(self, scan_id: str, results: List[Dict[str, Any]]):
        if not results:
            return
        async with self.session_factory() as session:
            items = [
                ScanResultORM(
                    scan_id=UUID(scan_id),
                    tool=self.tool_name,
                    severity=res.get("severity", SeverityLevel.info),
                    url=res.get("url"),
                    vulnerability_type=res.get("type"),
                    description=res.get("description", ""),
                    raw_output=res.get("raw_output", {}),
                )
                for res in results
            ]
            session.add_all(items)
            await session.commit()
            logger.info(f"[{self.tool_name}] Saved {len(items)} results for scan {scan_id}")

        # Prometheus: count findings by severity
        for item in items:
            vulns_found_total.labels(
                tool=self.tool_name,
                severity=item.severity.value if item.severity else "info",
            ).inc()

    # ── Auth context ───────────────────────────────────────────────────────────

    async def _get_auth_context(self, session_id: Optional[str]) -> Dict[str, Any]:
        if not session_id:
            return {"cookies": [], "headers": {}}
        try:
            # Always create a fresh client — don't reuse a closed one
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.auth_service_url}/api/v1/auth/sessions/{session_id}"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "cookies": data.get("cookies", []),
                        "headers": data.get("headers", {}),
                        "storage_state": data.get("storage_state", ""),
                    }
        except Exception as exc:
            logger.warning(f"[{self.tool_name}] Failed to get auth context: {exc}")
        return {"cookies": [], "headers": {}}

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Run the underlying tool and return a list of result dicts."""
