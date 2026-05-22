"""
Scheduler service — manages cron-based recurring scans.
Stores schedules in PostgreSQL; APScheduler fires them at the right time
and calls the orchestrator to create a new scan.
"""
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, HTTPException
from pydantic import Field
from pydantic_settings import BaseSettings
from sqlalchemy import text, select, update
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.models import ScanScheduleORM, ScheduleCreate, ScheduleUpdate, ScheduleResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scheduler")


class Settings(BaseSettings):
    DB_USER: str = Field(default="briar")
    DB_PASSWORD: str = Field(default="secure_password_change_me")
    DB_HOST: str = Field(default="postgres")
    DB_PORT: str = Field(default="5432")
    DB_NAME: str = Field(default="briar_db")
    ORCHESTRATOR_URL: str = Field(default="http://orchestrator:8000")
    UI_SERVICE_URL: str = Field(default="http://ui-service:8000")

    @property
    def db_url(self) -> str:
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

engine = create_async_engine(settings.db_url, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
scheduler = AsyncIOScheduler(timezone="UTC")


# ── DB migration ──────────────────────────────────────────────────────────────

async def _run_migrations() -> None:
    async with engine.begin() as conn:
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS scan_schedules (
                id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                label           VARCHAR(255),
                target_url      VARCHAR(2048) NOT NULL,
                tools           JSON NOT NULL,
                auth_session_id UUID,
                cron_expression VARCHAR(100) NOT NULL,
                enabled         BOOLEAN NOT NULL DEFAULT TRUE,
                created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
                last_run_at     TIMESTAMPTZ,
                next_run_at     TIMESTAMPTZ,
                last_scan_id    UUID,
                prev_scan_id    UUID,
                run_count       INTEGER NOT NULL DEFAULT 0
            )
        """))
        # Idempotent column add for existing deployments
        await conn.execute(text(
            "ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS prev_scan_id UUID"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS idx_scan_schedules_enabled ON scan_schedules (enabled)"
        ))
    logger.info("Migrations OK")


# ── APScheduler helpers ───────────────────────────────────────────────────────

def _parse_cron(expr: str) -> CronTrigger:
    """Accept standard 5-field cron or a preset name."""
    PRESETS: Dict[str, str] = {
        "@hourly":   "0 * * * *",
        "@daily":    "0 0 * * *",
        "@weekly":   "0 0 * * 0",
        "@monthly":  "0 0 1 * *",
    }
    resolved = PRESETS.get(expr, expr)
    parts = resolved.split()
    if len(parts) != 5:
        raise ValueError(f"Invalid cron expression: {expr!r} — must have 5 fields")
    minute, hour, day, month, day_of_week = parts
    return CronTrigger(
        minute=minute, hour=hour, day=day,
        month=month, day_of_week=day_of_week,
        timezone="UTC",
    )


async def _fire_scan(schedule_id: str) -> None:
    """Called by APScheduler — creates a new scan via the orchestrator."""
    async with SessionLocal() as session:
        row = await session.get(ScanScheduleORM, UUID(schedule_id))
        if row is None or not row.enabled:
            return

        payload: Dict[str, Any] = {
            "target_url": row.target_url,
            "tools": row.tools,
        }
        if row.auth_session_id:
            payload["auth_session_id"] = str(row.auth_session_id)

        scan_id: Optional[str] = None
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{settings.ORCHESTRATOR_URL}/scans",
                    json=payload,
                )
                resp.raise_for_status()
                scan_id = resp.json().get("scan_id")
            logger.info("Schedule %s fired → scan %s", schedule_id, scan_id)
        except Exception as exc:
            logger.error("Schedule %s fire failed: %s", schedule_id, exc)

        now = datetime.now(timezone.utc)
        job = scheduler.get_job(schedule_id)
        next_run = job.next_run_time if job else None

        # Shift last → prev before storing the new scan_id
        await session.execute(
            update(ScanScheduleORM)
            .where(ScanScheduleORM.id == UUID(schedule_id))
            .values(
                last_run_at=now,
                next_run_at=next_run,
                prev_scan_id=ScanScheduleORM.last_scan_id,
                last_scan_id=UUID(scan_id) if scan_id else None,
                run_count=ScanScheduleORM.run_count + 1,
                updated_at=now,
            )
        )
        await session.commit()


def _register_job(schedule: ScanScheduleORM) -> None:
    """Add or replace an APScheduler job for the given schedule."""
    sid = str(schedule.id)
    if scheduler.get_job(sid):
        scheduler.remove_job(sid)
    if not schedule.enabled:
        return
    trigger = _parse_cron(schedule.cron_expression)
    scheduler.add_job(
        _fire_scan,
        trigger=trigger,
        id=sid,
        args=[sid],
        replace_existing=True,
        misfire_grace_time=3600,
    )
    job = scheduler.get_job(sid)
    logger.info("Registered job %s  next=%s", sid, job.next_run_time if job else None)


async def _load_all_jobs() -> None:
    """Reload all enabled schedules from DB into APScheduler on startup."""
    async with SessionLocal() as session:
        result = await session.execute(
            select(ScanScheduleORM).where(ScanScheduleORM.enabled == True)
        )
        rows = result.scalars().all()
    for row in rows:
        try:
            _register_job(row)
        except Exception as exc:
            logger.warning("Could not register schedule %s: %s", row.id, exc)
    logger.info("Loaded %d schedule(s) from DB", len(rows))


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await _run_migrations()
    scheduler.start()
    await _load_all_jobs()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="Briar Scheduler", lifespan=lifespan)


# ── Routes ────────────────────────────────────────────────────────────────────

def _to_response(row: ScanScheduleORM) -> ScheduleResponse:
    return ScheduleResponse(
        id=row.id,
        label=row.label,
        target_url=row.target_url,
        tools=row.tools,
        auth_session_id=row.auth_session_id,
        cron_expression=row.cron_expression,
        enabled=row.enabled,
        created_at=row.created_at,
        updated_at=row.updated_at,
        last_run_at=row.last_run_at,
        next_run_at=row.next_run_at,
        last_scan_id=row.last_scan_id,
        prev_scan_id=row.prev_scan_id,
        run_count=row.run_count,
    )


@app.get("/schedules", response_model=List[ScheduleResponse])
async def list_schedules():
    async with SessionLocal() as session:
        result = await session.execute(
            select(ScanScheduleORM).order_by(ScanScheduleORM.created_at.desc())
        )
        return [_to_response(r) for r in result.scalars().all()]


@app.post("/schedules", response_model=ScheduleResponse, status_code=201)
async def create_schedule(body: ScheduleCreate):
    # Validate cron before persisting
    try:
        _parse_cron(body.cron_expression)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    row = ScanScheduleORM(
        id=uuid4(),
        label=body.label,
        target_url=str(body.target_url),
        tools=body.tools,
        auth_session_id=body.auth_session_id,
        cron_expression=body.cron_expression,
        enabled=True,
    )

    # Set next_run_at from APScheduler before saving
    try:
        trigger = _parse_cron(body.cron_expression)
        from apscheduler.triggers.cron import CronTrigger
        next_fire = trigger.get_next_fire_time(None, datetime.now(timezone.utc))
        row.next_run_at = next_fire
    except Exception:
        pass

    async with SessionLocal() as session:
        session.add(row)
        await session.commit()
        await session.refresh(row)

    _register_job(row)
    # Update next_run_at from actual registered job
    job = scheduler.get_job(str(row.id))
    if job and job.next_run_time:
        async with SessionLocal() as session:
            await session.execute(
                update(ScanScheduleORM)
                .where(ScanScheduleORM.id == row.id)
                .values(next_run_at=job.next_run_time)
            )
            await session.commit()
        row.next_run_at = job.next_run_time

    return _to_response(row)


@app.get("/schedules/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(schedule_id: UUID):
    async with SessionLocal() as session:
        row = await session.get(ScanScheduleORM, schedule_id)
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _to_response(row)


@app.patch("/schedules/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(schedule_id: UUID, body: ScheduleUpdate):
    async with SessionLocal() as session:
        row = await session.get(ScanScheduleORM, schedule_id)
        if not row:
            raise HTTPException(status_code=404, detail="Schedule not found")

        if body.label is not None:
            row.label = body.label
        if body.tools is not None:
            row.tools = body.tools
        if body.auth_session_id is not None:
            row.auth_session_id = body.auth_session_id
        if body.cron_expression is not None:
            try:
                _parse_cron(body.cron_expression)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
            row.cron_expression = body.cron_expression
        if body.enabled is not None:
            row.enabled = body.enabled

        row.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(row)

    _register_job(row)
    job = scheduler.get_job(str(row.id))
    if job and job.next_run_time:
        async with SessionLocal() as session:
            await session.execute(
                update(ScanScheduleORM)
                .where(ScanScheduleORM.id == row.id)
                .values(next_run_at=job.next_run_time)
            )
            await session.commit()
        row.next_run_at = job.next_run_time

    return _to_response(row)


@app.delete("/schedules/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: UUID):
    async with SessionLocal() as session:
        row = await session.get(ScanScheduleORM, schedule_id)
        if not row:
            raise HTTPException(status_code=404, detail="Schedule not found")
        await session.delete(row)
        await session.commit()

    sid = str(schedule_id)
    if scheduler.get_job(sid):
        scheduler.remove_job(sid)


@app.post("/schedules/{schedule_id}/run-now", response_model=Dict[str, Any])
async def run_now(schedule_id: UUID):
    """Immediately trigger a scan for this schedule, ignoring the cron timing."""
    async with SessionLocal() as session:
        row = await session.get(ScanScheduleORM, schedule_id)
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")

    payload: Dict[str, Any] = {
        "target_url": row.target_url,
        "tools": row.tools,
    }
    if row.auth_session_id:
        payload["auth_session_id"] = str(row.auth_session_id)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{settings.ORCHESTRATOR_URL}/scans",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Orchestrator error: {exc}")

    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        await session.execute(
            update(ScanScheduleORM)
            .where(ScanScheduleORM.id == schedule_id)
            .values(
                last_run_at=now,
                prev_scan_id=ScanScheduleORM.last_scan_id,
                last_scan_id=UUID(data["scan_id"]),
                run_count=ScanScheduleORM.run_count + 1,
                updated_at=now,
            )
        )
        await session.commit()

    return {"scan_id": data["scan_id"], "status": data.get("status", "pending")}


@app.get("/schedules/{schedule_id}/diff")
async def get_schedule_diff(schedule_id: UUID):
    """
    Return the vulnerability diff between the last two scheduled runs.
    Proxies to the UI service diff endpoint so the caller doesn't need
    to know the scan IDs up-front.
    """
    async with SessionLocal() as session:
        row = await session.get(ScanScheduleORM, schedule_id)
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if not row.last_scan_id or not row.prev_scan_id:
        raise HTTPException(
            status_code=404,
            detail="Diff not available yet — need at least two completed runs",
        )

    url = (
        f"{settings.UI_SERVICE_URL}/api/v1/scans/{row.last_scan_id}"
        f"/diff?compare_to={row.prev_scan_id}"
    )
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"UI service error: {exc}")


@app.get("/health")
async def health():
    return {"status": "ok", "jobs": len(scheduler.get_jobs())}
