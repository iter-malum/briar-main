"""
Endpoint Cache  (warm-start for repeated scans)
================================================
When the same target is scanned more than once, the crawler (katana) would
re-discover all the same endpoints again.  This module makes the second (and
subsequent) scans start immediately at the PROBE phase by re-using the endpoint
list from the most recent successful katana run against the same target.

How it works
------------
  1. ``find_best_source_scan()`` — queries the DB for the most recent completed
     scan against *target_url* that produced katana results.

  2. ``inject_cached_endpoints()`` — copies those katana ``scan_results`` rows
     into *dest_scan_id*, stamping each with the new scan's UUID.
     The rows are identical in structure so all downstream workers
     (``_get_live_endpoints_from_db``, ``_get_endpoints_with_params``, etc.)
     read them exactly as if katana had just run.

  3. The orchestrator marks katana as ``completed`` in the new scan's step
     table and publishes the PROBE phase immediately — skipping the 15-30 min
     crawl latency entirely.

Cache freshness
---------------
By default the cache is considered stale after ``MAX_CACHE_AGE_HOURS`` hours.
A caller can pass ``max_age_hours=0`` to skip freshness checking and always
reuse the most recent scan regardless of age.

The cached scan MUST have ``status='completed'`` and its katana step must be
``status='completed'`` — partial / failed crawls are never reused.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from uuid import UUID, uuid4

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("endpoint_cache")

# Endpoints older than this are considered stale; set to 0 to disable.
MAX_CACHE_AGE_HOURS: int = 0    # 0 = no expiry — cache is always available

# Endpoint record types that carry real crawl/probe data.
# We include every type that workers downstream use for injection testing.
_ENDPOINT_TYPES = frozenset({
    "endpoint",
    "api_endpoint",
    "js_extracted_endpoint",
    "openapi_spec",
    "api_schema_endpoint",
    "graphql_endpoint",
    "graphql_field",
    "sensitive_path",
    "exposed_resource",
    "idor_candidate",
    "admin_panel",
})

# Finding types that must NOT be copied into the new scan.
# These are routing signals (swagger_found, graphql_found) that would
# cause the finding_router to fire twice — once on cache inject and
# once after the real tool runs.
_SKIP_TYPES = frozenset({
    "swagger_found",
    "graphql_found",
    "jwt_found",
    "credential_exposure",
})


async def find_best_source_scan(
    target_url: str,
    current_scan_id: UUID,
    session: AsyncSession,
    max_age_hours: int = MAX_CACHE_AGE_HOURS,
) -> Optional[Tuple[UUID, datetime, int]]:
    """
    Find the most recent completed scan for *target_url* whose katana step
    produced endpoints.

    Returns
    -------
    (source_scan_id, completed_at, endpoint_count)  or  None if no cache hit.
    """
    from shared.models import ScanORM, ScanStepORM, ScanResultORM, ScanStatus

    try:
        cutoff: Optional[datetime] = None
        if max_age_hours > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

        # Find completed scans for same target (exclude current scan)
        scan_q = select(ScanORM.id, ScanORM.updated_at).where(
            and_(
                ScanORM.target_url == target_url.rstrip("/"),
                ScanORM.status == ScanStatus.completed,
                ScanORM.id != current_scan_id,
            )
        ).order_by(ScanORM.updated_at.desc()).limit(10)

        rows = (await session.execute(scan_q)).all()
        if not rows:
            logger.debug(f"[endpoint_cache] No completed scans found for {target_url}")
            return None

        for scan_id, updated_at in rows:
            # Check freshness
            if cutoff and updated_at:
                # Make updated_at timezone-aware for comparison
                if updated_at.tzinfo is None:
                    updated_at_aware = updated_at.replace(tzinfo=timezone.utc)
                else:
                    updated_at_aware = updated_at
                if updated_at_aware < cutoff:
                    continue

            # Check that katana step was completed
            step_q = select(ScanStepORM.status).where(
                and_(
                    ScanStepORM.scan_id == scan_id,
                    ScanStepORM.tool == "katana",
                )
            )
            step_status = (await session.execute(step_q)).scalar_one_or_none()
            if step_status != ScanStatus.completed:
                continue

            # Count endpoint records from katana
            count_q = select(func.count()).select_from(ScanResultORM).where(
                and_(
                    ScanResultORM.scan_id == scan_id,
                    ScanResultORM.tool == "katana",
                    ScanResultORM.type.in_(_ENDPOINT_TYPES),
                )
            )
            count = (await session.execute(count_q)).scalar_one()
            if count < 5:  # not worth reusing a tiny/empty crawl
                logger.debug(
                    f"[endpoint_cache] Scan {scan_id} has only {count} katana endpoints — skipping"
                )
                continue

            logger.info(
                f"[endpoint_cache] Cache hit: scan={scan_id}, "
                f"endpoints={count}, age={updated_at}"
            )
            return (scan_id, updated_at, count)

        logger.info(f"[endpoint_cache] No usable cache found for {target_url}")
        return None

    except Exception as exc:
        logger.warning(f"[endpoint_cache] find_best_source_scan failed: {exc}")
        return None


async def inject_cached_endpoints(
    source_scan_id: UUID,
    dest_scan_id: UUID,
    session: AsyncSession,
) -> int:
    """
    Copy katana endpoint records from *source_scan_id* into *dest_scan_id*.

    Each row gets a fresh UUID and updated scan_id.  All other columns —
    url, type, description, severity, tool, raw_output, request_method,
    request_body, request_params, param names — are preserved verbatim so
    downstream workers see exactly the same data structure.

    Returns the number of rows copied.
    """
    from shared.models import ScanResultORM, SeverityLevel

    try:
        # Load source rows
        src_q = select(ScanResultORM).where(
            and_(
                ScanResultORM.scan_id == source_scan_id,
                ScanResultORM.tool == "katana",
                ScanResultORM.type.in_(_ENDPOINT_TYPES),
                ScanResultORM.type.notin_(_SKIP_TYPES),
            )
        )
        src_rows = (await session.execute(src_q)).scalars().all()

        if not src_rows:
            logger.warning(
                f"[endpoint_cache] No copyable rows in source scan {source_scan_id}"
            )
            return 0

        now = datetime.now(timezone.utc)
        copied = 0
        for row in src_rows:
            new_row = ScanResultORM(
                id=uuid4(),
                scan_id=dest_scan_id,
                tool="katana",
                url=row.url,
                type=row.type,
                description=row.description,
                severity=row.severity,
                vulnerability_type=row.vulnerability_type,
                has_params=row.has_params,
                raw_output=row.raw_output,
                request_method=row.request_method,
                request_body=row.request_body,
                request_params=row.request_params,
                # Reset pipeline metadata so it doesn't carry over
                routed_at=None,
                dedup_key=None,
                confidence=row.confidence,
                confirmed_by=None,
            )
            session.add(new_row)
            copied += 1

        await session.flush()
        logger.info(
            f"[endpoint_cache] Injected {copied} endpoint(s) from "
            f"scan {source_scan_id} → {dest_scan_id}"
        )
        return copied

    except Exception as exc:
        logger.error(f"[endpoint_cache] inject_cached_endpoints failed: {exc}", exc_info=True)
        return 0


async def get_cache_stats(
    target_url: str,
    session: AsyncSession,
    max_age_hours: int = MAX_CACHE_AGE_HOURS,
) -> dict:
    """
    Return cache availability info for *target_url* without modifying anything.
    Used by the UI/API to show whether a warm-start is available.

    Returns
    -------
    {
        "available": bool,
        "source_scan_id": str | None,
        "endpoint_count": int,
        "cached_at": str | None,     # ISO datetime
        "age_hours": float | None,
    }
    """
    # We need a dummy UUID just for the exclusion filter — use nil UUID
    dummy_id = UUID("00000000-0000-0000-0000-000000000000")
    result = await find_best_source_scan(target_url, dummy_id, session, max_age_hours)
    if result is None:
        return {
            "available": False,
            "source_scan_id": None,
            "endpoint_count": 0,
            "cached_at": None,
            "age_hours": None,
        }
    source_id, cached_at, count = result
    age = None
    if cached_at:
        ref = cached_at if cached_at.tzinfo else cached_at.replace(tzinfo=timezone.utc)
        age = round((datetime.now(timezone.utc) - ref).total_seconds() / 3600, 1)
    return {
        "available": True,
        "source_scan_id": str(source_id),
        "endpoint_count": count,
        "cached_at": cached_at.isoformat() if cached_at else None,
        "age_hours": age,
    }
