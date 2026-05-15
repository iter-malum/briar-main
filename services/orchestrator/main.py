"""
Briar Orchestrator
==================
Responsibilities:
  1. Accept POST /scans and persist scan + steps to PostgreSQL.
  2. Publish the RECON phase tools to RabbitMQ (pipeline entry point).
  3. Run a background PipelineManager that consumes `scan.step.completed`
     events from workers and triggers the next pipeline phase.
  4. Update scan.status lifecycle (pending → running → completed/failed).
"""

import sys
import os
import asyncio
import json
import logging
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import aio_pika
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload
from sqlalchemy import select

from shared.config import settings
from shared.models import (
    Base, ScanORM, ScanStepORM, ScanStatus,
    ScanCreateRequest, ScanResponse,
)
from shared.pipeline import (
    PHASES, TOOL_QUEUES,
    should_trigger_phase, is_scan_complete,
    get_tools_for_initial_publish, SQLI_INDICATORS,
)
from shared.rabbitmq import RabbitMQPublisher

# ── Prometheus metrics ─────────────────────────────────────────────────────────

scans_total = Counter(
    "briar_scans_total",
    "Total number of scans created",
    ["status"],
)
scan_duration_seconds = Histogram(
    "briar_scan_duration_seconds",
    "Scan end-to-end duration in seconds",
    buckets=[30, 60, 120, 300, 600, 900, 1800, 3600],
)
active_scans = Gauge(
    "briar_active_scans",
    "Number of scans currently in running state",
)
pipeline_events_total = Counter(
    "briar_pipeline_events_total",
    "Pipeline step-completion events processed",
    ["tool", "status"],
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("orchestrator")

app = FastAPI(title="Briar Orchestrator", version="0.2.0", root_path="/api/v1")

engine = create_async_engine(
    settings.db_url,
    echo=False,
    pool_size=10,
    max_overflow=20,
    pool_recycle=3600,
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
publisher = RabbitMQPublisher()


# ── DB dependency ──────────────────────────────────────────────────────────────

async def get_db():
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


# ── Pipeline Manager ───────────────────────────────────────────────────────────

class PipelineManager:
    """
    Consumes `scan.step.completed` messages published by workers and drives
    the scan pipeline forward phase by phase.
    """

    def __init__(self, pub: RabbitMQPublisher):
        self.publisher = pub
        self._connection: Optional[aio_pika.abc.AbstractRobustConnection] = None

    async def start(self):
        self._connection = await aio_pika.connect_robust(settings.rabbitmq_url)
        channel = await self._connection.channel()
        await channel.set_qos(prefetch_count=50)

        exchange = await channel.declare_exchange(
            "briar.scan", aio_pika.ExchangeType.DIRECT, durable=True
        )
        queue = await channel.declare_queue(
            "scan.step.completed", durable=True,
            arguments={"x-message-ttl": 86400000},
        )
        await queue.bind(exchange, routing_key="scan.step.completed")
        await queue.consume(self._on_message)
        logger.info("PipelineManager listening on scan.step.completed")

    async def _on_message(self, message: aio_pika.IncomingMessage):
        async with message.process():
            try:
                body = json.loads(message.body.decode())
                pipeline_events_total.labels(
                    tool=body.get("tool", "unknown"),
                    status=body.get("status", "unknown"),
                ).inc()
                await self._advance_pipeline(body)
            except Exception as exc:
                logger.error(f"PipelineManager error: {exc}", exc_info=True)

    async def _advance_pipeline(self, event: dict):
        scan_id = event.get("scan_id")
        completed_tool = event.get("tool")
        tool_status = event.get("status", "completed")

        if not scan_id or not completed_tool:
            return

        logger.info(f"[pipeline] step_completed: scan={scan_id} tool={completed_tool} status={tool_status}")

        async with async_session() as session:
            # Load scan
            stmt = (
                select(ScanORM)
                .options(selectinload(ScanORM.steps))
                .where(ScanORM.id == UUID(scan_id))
            )
            result = await session.execute(stmt)
            scan = result.scalars().first()
            if not scan:
                logger.warning(f"[pipeline] scan {scan_id} not found")
                return

            selected_tools = set(scan.config.get("tools", []))
            exploit_enabled = scan.config.get("exploit_enabled", False)

            # Mark scan as running on first completion event
            if scan.status == ScanStatus.pending:
                scan.status = ScanStatus.running
                scan.updated_at = datetime.utcnow()

            # Collect all terminal-state tools (completed OR failed)
            completed_tools = {
                s.tool for s in scan.steps
                if s.status in (ScanStatus.completed, ScanStatus.failed)
            }

            # Evaluate which phases are now unblocked
            for phase in PHASES:
                if not should_trigger_phase(phase, completed_tools, selected_tools):
                    continue

                # Extra guards for exploit phase
                if phase["requires_explicit"] and not exploit_enabled:
                    logger.info(f"[pipeline] skipping phase '{phase['id']}' — exploit not enabled")
                    continue

                if phase["requires_sqli"]:
                    has_sqli = await self._has_sqli_findings(scan_id, session)
                    if not has_sqli:
                        logger.info(f"[pipeline] skipping phase '{phase['id']}' — no SQLi findings")
                        continue

                await self._publish_phase(scan_id, scan, phase, selected_tools)

            # Check overall completion
            if is_scan_complete(selected_tools, completed_tools):
                any_failed = any(
                    s.status == ScanStatus.failed
                    for s in scan.steps
                    if s.tool in selected_tools
                )
                final_status = ScanStatus.failed if any_failed else ScanStatus.completed
                scan.status = final_status
                scan.updated_at = datetime.utcnow()
                logger.info(f"[pipeline] scan {scan_id} → {scan.status.value}")

                # Prometheus: record completion
                scans_total.labels(status=final_status.value).inc()
                active_scans.dec()

                # Record duration if we have timestamps
                if scan.created_at:
                    duration = (datetime.utcnow() - scan.created_at.replace(tzinfo=None)).total_seconds()
                    scan_duration_seconds.observe(duration)

            await session.commit()

    async def _publish_phase(self, scan_id, scan: ScanORM, phase: dict, selected_tools: set):
        tools = phase["tools"] & selected_tools
        for tool in tools:
            queue_name = TOOL_QUEUES.get(tool)
            if not queue_name:
                continue

            source_tools = phase["source_tools"].get(tool, [])

            payload = {
                "event": "scan.task.created",
                "scan_id": str(scan_id),
                "target": scan.target_url,
                "auth_session_id": scan.config.get("auth_session_id"),
                "payload": {
                    "source_tools": source_tools,
                    "phase": phase["id"],
                    "exploit_enabled": scan.config.get("exploit_enabled", False),
                },
            }
            await self.publisher.publish(queue_name, payload)
            logger.info(f"[pipeline] published {tool} (phase={phase['id']}) for scan {scan_id}")

    @staticmethod
    async def _has_sqli_findings(scan_id: str, session: AsyncSession) -> bool:
        from shared.models import ScanResultORM
        stmt = select(ScanResultORM.vulnerability_type).where(
            ScanResultORM.scan_id == UUID(scan_id),
            ScanResultORM.vulnerability_type.isnot(None),
        )
        result = await session.execute(stmt)
        for (vtype,) in result.all():
            if vtype and any(ind in vtype.lower() for ind in SQLI_INDICATORS):
                return True
        return False

    async def stop(self):
        if self._connection and not self._connection.is_closed:
            await self._connection.close()


pipeline_manager: Optional[PipelineManager] = None


# ── Lifecycle ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    global pipeline_manager

    logger.info("Creating PostgreSQL tables…")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await publisher.connect()

    pipeline_manager = PipelineManager(publisher)
    await pipeline_manager.start()

    logger.info("Orchestrator ready.")


@app.on_event("shutdown")
async def shutdown():
    if pipeline_manager:
        await pipeline_manager.stop()
    await publisher.close()
    await engine.dispose()


# ── REST API ───────────────────────────────────────────────────────────────────

@app.post("/scans", response_model=ScanResponse, status_code=201)
async def create_scan(payload: ScanCreateRequest, session: AsyncSession = Depends(get_db)):
    logger.info(f"New scan request: {payload.target_url} tools={payload.tools}")

    try:
        scan_id = uuid4()
        scan = ScanORM(
            id=scan_id,
            target_url=str(payload.target_url).rstrip("/"),
            config={
                "tools": payload.tools,
                "auth_session_id": str(payload.auth_session_id) if payload.auth_session_id else None,
                "exploit_enabled": payload.exploit_enabled,
            },
        )
        session.add(scan)
        await session.flush()

        for tool in payload.tools:
            session.add(ScanStepORM(scan_id=scan.id, tool=tool, status=ScanStatus.pending))

        await session.commit()

        # Reload with steps for response
        stmt = (
            select(ScanORM)
            .options(selectinload(ScanORM.steps))
            .where(ScanORM.id == scan_id)
        )
        result = await session.execute(stmt)
        scan_with_steps = result.scalars().first()

        # Publish ONLY the recon phase tools immediately
        recon_tools = get_tools_for_initial_publish(set(payload.tools))

        # If no recon tools selected, skip directly to the first eligible phase
        if not recon_tools:
            # Find the first phase that has selected tools and no deps
            for phase in PHASES:
                phase_tools = phase["tools"] & set(payload.tools)
                if phase_tools and not (phase["trigger_after"] & set(payload.tools)):
                    recon_tools = list(phase_tools)
                    break

        for tool in recon_tools:
            queue_name = TOOL_QUEUES.get(tool)
            if not queue_name:
                continue
            msg = {
                "event": "scan.task.created",
                "scan_id": str(scan_id),
                "target": str(payload.target_url).rstrip("/"),
                "auth_session_id": str(payload.auth_session_id) if payload.auth_session_id else None,
                "payload": {
                    "source_tools": [],
                    "phase": "recon",
                    "exploit_enabled": payload.exploit_enabled,
                },
            }
            await publisher.publish(queue_name, msg)
            logger.info(f"Published initial task: {tool} for scan {scan_id}")

        # Prometheus: scan created
        scans_total.labels(status="pending").inc()
        active_scans.inc()

        return scan_with_steps

    except HTTPException:
        raise
    except Exception as exc:
        await session.rollback()
        logger.error(f"Scan creation failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_db)):
    stmt = (
        select(ScanORM)
        .options(selectinload(ScanORM.steps))
        .where(ScanORM.id == scan_id)
    )
    result = await session.execute(stmt)
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, session: AsyncSession = Depends(get_db)):
    """Cancel a running or pending scan — marks it and all in-flight steps as failed."""
    try:
        stmt = (
            select(ScanORM)
            .options(selectinload(ScanORM.steps))
            .where(ScanORM.id == UUID(scan_id))
        )
        result = await session.execute(stmt)
        scan = result.scalars().first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.status in (ScanStatus.completed, ScanStatus.failed):
            raise HTTPException(status_code=400, detail=f"Scan already in terminal state: {scan.status.value}")

        scan.status = ScanStatus.failed
        scan.updated_at = datetime.utcnow()
        now = datetime.utcnow()
        for step in scan.steps:
            if step.status in (ScanStatus.pending, ScanStatus.running):
                step.status = ScanStatus.failed
                step.finished_at = now
        await session.commit()

        # Decrement active_scans gauge safely
        try:
            active_scans.dec()
        except Exception:
            pass

        logger.info(f"Scan {scan_id} cancelled by user request")
        return {"scan_id": scan_id, "status": "cancelled"}
    except HTTPException:
        raise
    except Exception as exc:
        await session.rollback()
        logger.error(f"Cancel failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "orchestrator"}
