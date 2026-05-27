"""
services/orchestrator/result_processor.py — M12 Quality Layer
==============================================================
Post-processing logic executed after each tool's results land in the DB.

Responsibilities
----------------
1. For every new ScanResultORM that lacks a dedup_key, compute one and
   persist it together with an initial confidence score.
2. Group results within the same scan by dedup_key.  When multiple tools
   report the same (url, vuln_class, param) bucket:
   • Update confirmed_by on every row in the group.
   • Re-compute confidence using the cross-confirmation bonus and write it
     back to every row.
3. Mark lower-confidence duplicates as superseded: if a group already
   contains a row with confidence >= HIGH_CONFIDENCE_THRESHOLD, tag the
     weaker rows' vuln_status as 'false_positive' only when their tool
     base-score is <= SUPERSEDE_SCORE_CEILING.  (We never auto-close rows
     from high-signal tools like sqlmap / tplmap / dalfox.)

The function `process_tool_results` is designed to be awaited directly
inside the PipelineManager step-completion handler right before the final
session.commit().
"""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models import ScanResultORM, ScanStatus, VulnStatus, SeverityLevel
from shared.dedup import (
    compute_dedup_key,
    compute_confidence,
    tool_base_score,
    normalize_vuln_type,
    UNKNOWN_CLASS,
)

logger = logging.getLogger("result_processor")

# ── Thresholds ─────────────────────────────────────────────────────────────────

# A finding is considered "high-confidence confirmed" once it reaches this score.
HIGH_CONFIDENCE_THRESHOLD = 80

# Rows from tools at or below this base-score are candidates for auto-supersede
# when the same finding is already confirmed by a higher-signal tool.
SUPERSEDE_SCORE_CEILING = 55

# Tools whose findings must NEVER be auto-superseded regardless of score.
NEVER_SUPERSEDE_TOOLS = {"sqlmap", "tplmap", "commix", "dalfox", "jwt_tool"}

# Severity levels that are never info/noise — skip supersede for these too.
NEVER_SUPERSEDE_SEVERITIES = {SeverityLevel.critical, SeverityLevel.high}


# ── Helper: extract param from raw_output / request_params ────────────────────

def _extract_param(result: ScanResultORM) -> Optional[str]:
    """Try to extract a meaningful parameter name from the result row."""
    raw = result.raw_output or {}
    # Common keys emitted by workers
    for key in ("param", "parameter", "inject_param", "field"):
        val = raw.get(key)
        if val and isinstance(val, str):
            return val
    # Fallback: first key in request_params.get
    rp = result.request_params or {}
    get_params = rp.get("get") or {}
    if get_params and isinstance(get_params, dict):
        return next(iter(get_params), None)
    return None


# ── Core processing ────────────────────────────────────────────────────────────

async def process_tool_results(
    scan_id: str | UUID,
    tool: str,
    session: AsyncSession,
) -> int:
    """
    Process all results produced by *tool* for *scan_id* in the current session.

    Steps:
      1. Load all results for this scan+tool that don't yet have a dedup_key.
      2. Assign dedup_key + initial confidence to each.
      3. Load the sibling bucket (same scan, same dedup_key) for cross-tool analysis.
      4. Recompute confidence for every row in each affected bucket.
      5. Auto-supersede weak duplicates where appropriate.

    Returns the number of results processed.
    """
    scan_uuid = UUID(str(scan_id))

    # ── 1. Load unprocessed rows for this tool ─────────────────────────────────
    stmt = select(ScanResultORM).where(
        ScanResultORM.scan_id == scan_uuid,
        ScanResultORM.tool == tool,
        ScanResultORM.dedup_key.is_(None),
    )
    result = await session.execute(stmt)
    new_rows: list[ScanResultORM] = list(result.scalars().all())

    if not new_rows:
        return 0

    # ── 2. Assign dedup_key + initial confidence ───────────────────────────────
    affected_keys: set[str] = set()

    for row in new_rows:
        # Skip pure-info findings from recon tools — dedup adds no value
        if (
            row.severity == SeverityLevel.info
            and normalize_vuln_type(row.vulnerability_type) == UNKNOWN_CLASS
        ):
            continue

        param = _extract_param(row)
        key = compute_dedup_key(row.url, row.vulnerability_type, param)
        row.dedup_key = key
        row.confidence = tool_base_score(tool)
        row.confirmed_by = [tool]
        affected_keys.add(key)

    if not affected_keys:
        return len(new_rows)

    # ── 3. Load sibling buckets (same scan, same dedup_keys) ──────────────────
    stmt2 = select(ScanResultORM).where(
        ScanResultORM.scan_id == scan_uuid,
        ScanResultORM.dedup_key.in_(list(affected_keys)),
    )
    result2 = await session.execute(stmt2)
    all_bucket_rows: list[ScanResultORM] = list(result2.scalars().all())

    # Group by dedup_key
    buckets: dict[str, list[ScanResultORM]] = {}
    for row in all_bucket_rows:
        if row.dedup_key:
            buckets.setdefault(row.dedup_key, []).append(row)

    # ── 4. Recompute confidence + confirmed_by for each bucket ────────────────
    for key, rows in buckets.items():
        # Collect unique tool names across all rows in this bucket
        all_tools: list[str] = []
        for r in rows:
            if r.confirmed_by:
                all_tools.extend(r.confirmed_by)
            elif r.tool:
                all_tools.append(r.tool)
        # Deduplicate preserving order
        seen: set[str] = set()
        unique_tools: list[str] = []
        for t in all_tools:
            if t not in seen:
                seen.add(t)
                unique_tools.append(t)

        new_confidence = compute_confidence(unique_tools)

        for r in rows:
            r.confirmed_by = unique_tools
            r.confidence = new_confidence

        # ── 5. Auto-supersede weak duplicates ─────────────────────────────────
        if new_confidence >= HIGH_CONFIDENCE_THRESHOLD and len(rows) > 1:
            # Sort by confidence (individual tool base score) descending
            sorted_rows = sorted(
                rows,
                key=lambda r: tool_base_score(r.tool),
                reverse=True,
            )
            # The first row is the "primary" — leave it open
            primary = sorted_rows[0]
            for r in sorted_rows[1:]:
                if r is primary:
                    continue
                if r.tool in NEVER_SUPERSEDE_TOOLS:
                    continue
                if r.severity in NEVER_SUPERSEDE_SEVERITIES:
                    continue
                if tool_base_score(r.tool) <= SUPERSEDE_SCORE_CEILING:
                    if r.vuln_status == VulnStatus.open:
                        r.vuln_status = VulnStatus.false_positive
                        r.analyst_note = (
                            f"[auto] Superseded by higher-confidence finding "
                            f"from '{primary.tool}' (confidence={new_confidence}). "
                            f"Confirmed by: {', '.join(unique_tools)}."
                        )
                        logger.debug(
                            f"[dedup] Superseded result {r.id} "
                            f"(tool={r.tool}, score={tool_base_score(r.tool)}) "
                            f"in bucket {key}"
                        )

        logger.info(
            f"[dedup] bucket={key[:8]}… tools={unique_tools} "
            f"confidence={new_confidence} rows={len(rows)}"
        )

    # Flush changes into the session (caller commits)
    await session.flush()

    processed = len(new_rows)
    logger.info(
        f"[result_processor] scan={scan_id} tool={tool} "
        f"processed={processed} buckets={len(buckets)}"
    )
    return processed
