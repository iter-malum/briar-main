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
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import aio_pika
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from fastapi.responses import Response, HTMLResponse, JSONResponse
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload
from sqlalchemy import select, text

from pathlib import Path
from shared.config import settings
from shared.tool_definitions import TOOL_DEFINITIONS, TOOLS_BY_ID
from shared.models import (
    Base, ScanORM, ScanStepORM, ScanStatus,
    ScanCreateRequest, ScanResponse,
)
from shared.pipeline import (
    PHASES, TOOL_QUEUES,
    should_trigger_phase, is_scan_complete,
    get_tools_for_initial_publish, SQLI_INDICATORS,
    detect_app_type,
)
from finding_router import FindingRouter
from shared.rabbitmq import RabbitMQPublisher
from result_processor import process_tool_results
from report_generator import generate_json_report, generate_html_report

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
        # M7: Finding Router — routes high-value findings to specialized tools
        self.finding_router = FindingRouter(pub.publish)

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

            # Guard: ignore stale completion events from workers that were still
            # running when the scan was cancelled or already completed.
            # run_tool re-opens the scan (sets it back to running) before publishing,
            # so legitimate re-runs from the UI are NOT blocked here.
            if scan.status in (ScanStatus.completed, ScanStatus.failed):
                logger.info(
                    f"[pipeline] scan {scan_id} already {scan.status.value} "
                    f"— ignoring late event from {completed_tool}"
                )
                return

            # user_tools = what the user explicitly selected (immutable).
            # selected_tools = same thing, used for phase triggering.
            # Dynamic tools added by finding_router / run-tool go into "tools"
            # but do NOT count for pipeline completion.
            user_tools = set(
                scan.config.get("user_tools") or scan.config.get("tools", [])
            )
            selected_tools = user_tools
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

            # M8: Detect app type from WhatWeb results (once after RECON completes)
            app_context = scan.config.get("app_context")
            if app_context is None and "whatweb" in completed_tools:
                app_context = await self._detect_app_context(scan_id, session)
                if app_context:
                    # Persist into scan config so we don't re-detect each event
                    scan.config = {**scan.config, "app_context": app_context}
                    logger.info(
                        f"[pipeline] App detected: {app_context.get('app_type')} "
                        f"/ {app_context.get('framework')} for scan {scan_id}"
                    )

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

                await self._publish_phase(scan_id, scan, phase, selected_tools, app_context or {})

            # M7: Route any newly-emitted high-value findings to specialized tools.
            # Runs after phase triggers so both paths are committed together.
            routed = await self.finding_router.route_new_findings(
                scan_id, scan, session
            )
            if routed > 0:
                logger.info(
                    f"[pipeline] finding-router: {routed} new routing(s) "
                    f"triggered for scan {scan_id}"
                )

            # M12: Quality Layer — dedup + confidence scoring for the just-completed tool.
            # Only runs on success (failed tools may emit partial/noisy results).
            if tool_status == "completed" and completed_tool:
                try:
                    processed = await process_tool_results(scan_id, completed_tool, session)
                    if processed:
                        logger.info(
                            f"[quality] processed {processed} results "
                            f"for tool={completed_tool} scan={scan_id}"
                        )
                except Exception as qe:
                    # Quality layer errors must never abort the pipeline.
                    logger.warning(
                        f"[quality] result_processor failed for "
                        f"tool={completed_tool} scan={scan_id}: {qe}",
                        exc_info=True,
                    )

            # Check overall completion — based on user_tools only.
            # finding_router / run-tool extras are supplementary and do NOT
            # block or influence scan completion.
            completed_tools = {
                s.tool for s in scan.steps
                if s.status in (ScanStatus.completed, ScanStatus.failed)
            }
            if is_scan_complete(user_tools, completed_tools):
                # A tool only counts as "failed" if it has NO completed step.
                # If a tool had a failed first attempt but a completed retry we
                # must not mark the whole scan as failed.
                def _tool_net_status(tool: str) -> str:
                    tool_steps = [s for s in scan.steps if s.tool == tool]
                    if any(s.status == ScanStatus.completed for s in tool_steps):
                        return "completed"
                    if any(s.status == ScanStatus.failed for s in tool_steps):
                        return "failed"
                    return "pending"

                any_failed = any(
                    _tool_net_status(t) == "failed"
                    for t in user_tools
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

    async def _publish_phase(
        self,
        scan_id,
        scan: ScanORM,
        phase: dict,
        selected_tools: set,
        app_context: dict = {},
    ):
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
                    # M8: app-type context for adaptive tool strategy
                    "app_type":  app_context.get("app_type", "unknown"),
                    "is_spa":    app_context.get("is_spa", False),
                    "framework": app_context.get("framework"),
                    "tech_stack": app_context.get("tech_stack", []),
                    # M11: second user context for BOLA cross-user testing (optional)
                    **({"second_auth_context": scan.config["second_auth_context"]}
                       if tool == "bola" and scan.config.get("second_auth_context")
                       else {}),
                },
            }
            await self.publisher.publish(queue_name, payload)
            logger.info(
                f"[pipeline] published {tool} (phase={phase['id']}, "
                f"app_type={app_context.get('app_type', 'unknown')}) for scan {scan_id}"
            )

    @staticmethod
    async def _detect_app_context(scan_id: str, session: AsyncSession) -> dict:
        """
        Read WhatWeb results for this scan from the DB and run app-type detection.
        Returns a dict like {app_type, is_spa, framework, tech_stack} or {}.
        """
        from shared.models import ScanResultORM
        try:
            stmt = select(ScanResultORM.raw_output).where(
                ScanResultORM.scan_id == UUID(scan_id),
                ScanResultORM.tool == "whatweb",
            )
            result = await session.execute(stmt)
            raw_outputs = [row[0] for row in result.all() if row[0]]
            if not raw_outputs:
                return {}
            return detect_app_type(raw_outputs)
        except Exception as exc:
            logger.warning(f"[pipeline] App-type detection failed: {exc}")
            return {}

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

async def _run_migrations(conn):
    """
    Idempotent schema migrations — each statement executed separately because
    asyncpg does not allow multiple commands in a single prepared statement.
    """
    statements = [
        # M8: request context columns
        """ALTER TABLE scan_results
               ADD COLUMN IF NOT EXISTS request_method  VARCHAR(10),
               ADD COLUMN IF NOT EXISTS request_body    VARCHAR(8192),
               ADD COLUMN IF NOT EXISTS request_params  JSONB""",
        # M6a: create vulnstatus enum type if it doesn't exist yet
        """DO $$
           BEGIN
               IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'vulnstatus') THEN
                   CREATE TYPE vulnstatus AS ENUM ('open', 'false_positive', 'accepted', 'fixed');
               END IF;
           END$$""",
        # M6a: vulnerability management columns
        """ALTER TABLE scan_results
               ADD COLUMN IF NOT EXISTS vuln_status   vulnstatus  NOT NULL DEFAULT 'open',
               ADD COLUMN IF NOT EXISTS analyst_note  TEXT,
               ADD COLUMN IF NOT EXISTS updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()""",
        # M6a: history table
        """CREATE TABLE IF NOT EXISTS vuln_status_history (
               id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
               result_id   UUID        NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
               old_status  VARCHAR(30),
               new_status  VARCHAR(30) NOT NULL,
               note        TEXT,
               changed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
           )""",
        "CREATE INDEX IF NOT EXISTS idx_vuln_history_result_id  ON vuln_status_history (result_id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_vuln_status ON scan_results (vuln_status)",
        # M7: Finding Router — tracks which findings have been routed to specialized tools
        """ALTER TABLE scan_results
               ADD COLUMN IF NOT EXISTS routed_at TIMESTAMPTZ""",
        # Index for the router's "unrouted candidates" query (hot path on every pipeline event)
        """CREATE INDEX IF NOT EXISTS idx_scan_results_routing
               ON scan_results (scan_id, vulnerability_type, routed_at)
               WHERE routed_at IS NULL""",
        # M12: Quality Layer — deduplication + confidence scoring columns
        """ALTER TABLE scan_results
               ADD COLUMN IF NOT EXISTS dedup_key   VARCHAR(16),
               ADD COLUMN IF NOT EXISTS confidence  INTEGER NOT NULL DEFAULT 50,
               ADD COLUMN IF NOT EXISTS confirmed_by JSONB""",
        # Index for bucket lookups in result_processor (hot path after every tool)
        """CREATE INDEX IF NOT EXISTS idx_scan_results_dedup_key
               ON scan_results (scan_id, dedup_key)
               WHERE dedup_key IS NOT NULL""",
        # Index to quickly find unprocessed rows (dedup_key IS NULL)
        """CREATE INDEX IF NOT EXISTS idx_scan_results_unprocessed
               ON scan_results (scan_id, tool)
               WHERE dedup_key IS NULL""",
    ]
    try:
        for stmt in statements:
            await conn.execute(text(stmt))
        logger.info("Schema migrations applied (or already up-to-date).")
    except Exception as exc:
        logger.error(f"Migration failed: {exc}", exc_info=True)
        raise


@app.on_event("startup")
async def startup():
    global pipeline_manager

    logger.info("Creating PostgreSQL tables…")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Run migrations in a separate clean transaction
    async with engine.begin() as conn:
        await _run_migrations(conn)

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
                # user_tools is the immutable set the user explicitly selected.
                # Pipeline completion is based ONLY on user_tools — dynamically
                # triggered tools (finding_router, run-tool) don't block or change
                # the scan's lifecycle.
                "user_tools": payload.tools,
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


class RunToolRequest(BaseModel):
    tool: str
    params: Dict[str, Any] = {}


@app.post("/scans/{scan_id}/run-tool")
async def run_tool(
    scan_id: str,
    payload: RunToolRequest,
    session: AsyncSession = Depends(get_db),
):
    """Launch a single tool against an existing scan, bypassing the normal pipeline."""
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

        tool = payload.tool
        queue_name = TOOL_QUEUES.get(tool)
        if not queue_name:
            raise HTTPException(status_code=400, detail=f"Unknown tool: {tool}")

        # Find or create the step for this tool
        existing_step = next((s for s in scan.steps if s.tool == tool), None)
        if existing_step:
            existing_step.status = ScanStatus.pending
            existing_step.started_at = None
            existing_step.finished_at = None
        else:
            session.add(ScanStepORM(scan_id=scan.id, tool=tool, status=ScanStatus.pending))
            # Track in "tools" (full history) but NOT in "user_tools" (user's
            # explicit selection).  Completion checking uses user_tools only,
            # so manually-run tools don't block or affect the scan lifecycle.
            tools = scan.config.get("tools", [])
            if tool not in tools:
                scan.config = {**scan.config, "tools": tools + [tool]}

        # Re-open scan if it was already closed
        if scan.status in (ScanStatus.completed, ScanStatus.failed):
            scan.status = ScanStatus.running
            active_scans.inc()

        scan.updated_at = datetime.utcnow()
        await session.commit()

        # Publish directly to the tool's queue
        msg = {
            "event": "scan.task.created",
            "scan_id": str(scan.id),
            "target": scan.target_url,
            "auth_session_id": scan.config.get("auth_session_id"),
            "payload": {
                "source_tools": [],
                "phase": "manual",
                "tool_params": payload.params,
            },
        }
        await publisher.publish(queue_name, msg)
        logger.info(f"[run-tool] Queued {tool} for scan {scan_id}")
        return {"scan_id": scan_id, "tool": tool, "status": "queued"}

    except HTTPException:
        raise
    except Exception as exc:
        await session.rollback()
        logger.error(f"Run-tool failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


TOOL_CONFIG_FILE = Path("/tmp/briar_tool_configs.json")


def _load_tool_configs() -> dict:
    try:
        if TOOL_CONFIG_FILE.exists():
            return json.loads(TOOL_CONFIG_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_tool_configs(configs: dict):
    try:
        TOOL_CONFIG_FILE.write_text(json.dumps(configs, indent=2))
    except Exception as e:
        logger.error(f"Failed to save tool configs: {e}")


@app.get("/tools")
async def list_tools():
    """Return all tool definitions merged with saved config overrides."""
    saved = _load_tool_configs()
    result = []
    for td in TOOL_DEFINITIONS:
        tool = dict(td)
        if td["id"] in saved:
            saved_params = saved[td["id"]].get("params", {})
            tool["params"] = [
                {**p, "value": saved_params.get(p["key"], p["default"])}
                for p in td["params"]
            ]
        result.append(tool)
    return result


@app.put("/tools/{tool_id}")
async def update_tool_config(tool_id: str, body: dict):
    """
    Save tool configuration.
    Body: { "params": { "param_key": value, ... } }
    """
    if tool_id not in TOOLS_BY_ID:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found")
    configs = _load_tool_configs()
    configs[tool_id] = {"params": body.get("params", {})}
    _save_tool_configs(configs)
    return {"saved": True, "tool_id": tool_id}


@app.get("/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    format: str = "json",   # noqa: A002  — "format" shadows builtin, intentional
    session: AsyncSession = Depends(get_db),
):
    """
    M13: Generate a security report for *scan_id*.

    Query params:
      format=json  (default) — structured JSON report
      format=html            — self-contained HTML report

    The report includes:
      • Scan metadata and tool list
      • Severity summary (critical/high/medium/low/info counts)
      • OWASP Top 10 2021 coverage matrix
      • Per-tool findings breakdown
      • Full findings table with confidence, dedup status, and OWASP category
    """
    from shared.models import ScanResultORM

    # Load scan
    stmt = (
        select(ScanORM)
        .options(selectinload(ScanORM.steps))
        .where(ScanORM.id == UUID(scan_id))
    )
    result = await session.execute(stmt)
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Load all results for this scan
    res_stmt = select(ScanResultORM).where(ScanResultORM.scan_id == UUID(scan_id))
    res_result = await session.execute(res_stmt)
    results = list(res_result.scalars().all())

    fmt = (format or "json").lower().strip()

    if fmt == "html":
        try:
            html = generate_html_report(scan, results)
            return HTMLResponse(content=html, status_code=200)
        except Exception as exc:
            logger.error(f"HTML report generation failed for scan {scan_id}: {exc}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")

    # Default: JSON
    try:
        report = generate_json_report(scan, results)
        return JSONResponse(content=report, status_code=200)
    except Exception as exc:
        logger.error(f"JSON report generation failed for scan {scan_id}: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "orchestrator"}
