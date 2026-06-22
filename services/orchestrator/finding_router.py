"""
Finding Router  (M7)
====================
Watches scan_results for high-value injection candidates and immediately
triggers the appropriate specialized tool without waiting for the full
phase to complete.

Before M7  (phase-based):
  inspector emits sqli_candidate → orchestrator notices only after ALL
  phase tools finish → sqlmap starts ~15 min later

After M7   (finding-based):
  inspector emits sqli_candidate → router triggers sqlmap within seconds

Design
------
Called from _advance_pipeline() after every step-completion event.
Queries for unrouted findings (routed_at IS NULL), deduplicates by
(url, vulnerability_type, parameter), and publishes one task per unique
target.  All processed findings are stamped with routed_at so they are
never dispatched twice.

Graceful degradation
--------------------
If a route's target tool is not yet in TOOL_QUEUES (e.g. tplmap before
M9 is deployed), the finding is left unrouted and retried on the next
pipeline event.  This means adding a new worker in a future milestone
automatically picks up any accumulated candidates.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models import ScanResultORM, ScanStepORM, ScanORM, ScanStatus
from shared.pipeline import FINDING_ROUTES, TOOL_QUEUES

logger = logging.getLogger("finding-router")

# Severity ordering for picking the "best" representative finding in a group
_SEV_ORDER: Dict[str, int] = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
    "info":     4,
}

PublishFn = Callable[[str, Dict[str, Any]], Coroutine[Any, Any, None]]


class FindingRouter:
    """
    Deduplicates and routes high-value findings to specialized tools.
    One instance is held by PipelineManager and reused across all events.
    """

    def __init__(self, publish_fn: PublishFn):
        self._publish = publish_fn

    # ── Public API ─────────────────────────────────────────────────────────────

    async def route_new_findings(
        self,
        scan_id: str,
        scan: ScanORM,
        session: AsyncSession,
    ) -> int:
        """
        Process all unrouted candidate findings for this scan.

        Steps:
          1. Fetch findings whose vulnerability_type is in FINDING_ROUTES
             and routed_at IS NULL.
          2. Group by (url, vulnerability_type, parameter) to deduplicate —
             inspector + nuclei may both flag the same endpoint.
          3. For each unique group check routing rules (exploit gate, tool
             availability, existing in-progress step).
          4. Publish one task per unique group, create ScanStep if needed.
          5. Stamp all processed findings with routed_at.

        Returns the number of tool tasks published.
        """
        routable_types = list(FINDING_ROUTES.keys())
        if not routable_types:
            return 0

        # ── 1. Fetch unrouted findings ──────────────────────────────────────
        stmt = select(ScanResultORM).where(
            ScanResultORM.scan_id == UUID(scan_id),
            ScanResultORM.vulnerability_type.in_(routable_types),
            ScanResultORM.routed_at.is_(None),
        )
        rows = await session.execute(stmt)
        findings: List[ScanResultORM] = list(rows.scalars().all())

        if not findings:
            return 0

        # ── 2. Deduplicate ─────────────────────────────────────────────────
        # Group by (url, vulnerability_type, parameter).  Multiple tools can
        # report the same injectable endpoint — we route it only once.
        groups: Dict[Tuple[str, str, str], List[ScanResultORM]] = {}
        for f in findings:
            param = _extract_param(f)
            key = (f.url or "", f.vulnerability_type or "", param)
            groups.setdefault(key, []).append(f)

        routed_count = 0
        all_processed_ids: List[UUID] = []  # findings to stamp with routed_at

        # ── 3 & 4. Route each unique group ─────────────────────────────────
        for (url, vtype, param), group in groups.items():
            route = FINDING_ROUTES.get(vtype)

            # No route defined — mark as processed so we don't retry forever
            if not route:
                all_processed_ids.extend(f.id for f in group)
                continue

            tool = route["tool"]

            # Exploit gate: skip privileged tools when not explicitly enabled
            if route.get("requires_exploit", False) and not scan.config.get("exploit_enabled", False):
                logger.debug(
                    f"[router] {vtype} → {tool!r} skipped "
                    f"(exploit_enabled=False, url={url!r})"
                )
                all_processed_ids.extend(f.id for f in group)
                continue

            # Graceful degradation: tool not yet deployed
            if tool not in TOOL_QUEUES:
                logger.debug(
                    f"[router] {tool!r} not in TOOL_QUEUES yet — "
                    f"leaving {vtype} unrouted for retry"
                )
                # Do NOT add to all_processed_ids — retry on next event
                continue

            # Idempotency: don't trigger a tool that is already running/done
            existing_step = next((s for s in scan.steps if s.tool == tool), None)
            if existing_step and existing_step.status in (
                ScanStatus.running, ScanStatus.completed
            ):
                logger.debug(
                    f"[router] {tool!r} already {existing_step.status.value} "
                    f"— skipping re-trigger for {url!r}"
                )
                all_processed_ids.extend(f.id for f in group)
                continue

            # Pick the best (highest-severity) representative finding
            best = _pick_best(group)

            # Ensure a ScanStep exists so is_scan_complete() tracks this tool
            if not existing_step:
                new_step = ScanStepORM(
                    scan_id=UUID(scan_id),
                    tool=tool,
                    status=ScanStatus.pending,
                )
                session.add(new_step)
                # Append to in-memory list so further checks in this loop are correct
                scan.steps.append(new_step)
                # Add to "tools" (full tracking) but NOT to "user_tools" (the
                # user's explicit selection).  Completion checking uses user_tools
                # only, so router-triggered tools never block scan completion.
                tools_list = list(scan.config.get("tools", []))
                if tool not in tools_list:
                    scan.config = {**scan.config, "tools": tools_list + [tool]}
                logger.info(f"[router] Created step + triggered '{tool}' for scan {scan_id}")

            # Publish task to the tool's queue
            payload = self._build_payload(scan_id, scan, best, url, vtype, param, tool)
            try:
                await self._publish(TOOL_QUEUES[tool], payload)
                logger.info(
                    f"[router] ✓ {vtype} → {tool} | "
                    f"url={url!r} param={param!r} | "
                    f"evidence: {(best.description or '')[:100]}"
                )
                routed_count += 1
            except Exception as exc:
                logger.error(f"[router] Failed to publish to {TOOL_QUEUES[tool]!r}: {exc}")

            all_processed_ids.extend(f.id for f in group)

        # ── 5. Stamp processed findings ────────────────────────────────────
        if all_processed_ids:
            now = datetime.now(timezone.utc)
            await session.execute(
                update(ScanResultORM)
                .where(ScanResultORM.id.in_(all_processed_ids))
                .values(routed_at=now)
            )

        return routed_count

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_payload(
        scan_id: str,
        scan: ScanORM,
        finding: ScanResultORM,
        url: str,
        vtype: str,
        param: str,
        tool: str,
    ) -> Dict[str, Any]:
        """
        Construct the RabbitMQ task envelope for the routed tool.
        The payload shape mirrors the standard scan.task.created message so
        existing workers need no changes to their _process_task() methods.
        """
        raw = finding.raw_output or {}
        route_ctx = raw.get("route_context", {})
        app_ctx: Dict[str, Any] = scan.config.get("app_context") or {}

        payload: Dict[str, Any] = {
            # Standard pipeline fields
            "phase":           "exploit",
            "source_tools":    [finding.tool],
            "exploit_enabled": scan.config.get("exploit_enabled", False),
            # App-type context (M8)
            "app_type":        app_ctx.get("app_type", "unknown"),
            "is_spa":          app_ctx.get("is_spa", False),
            "framework":       app_ctx.get("framework"),
            "tech_stack":      app_ctx.get("tech_stack", []),
            # Finding-specific routing context
            "finding_triggered": True,
            "finding_id":        str(finding.id),
            "finding_type":      vtype,
            # Pre-validated endpoint for targeted exploitation
            "endpoints":       [url] if url else [],
            "inject_param":    param or route_ctx.get("param"),
            "inject_method":   route_ctx.get("method", "GET"),
            "inject_payload":  route_ctx.get("payload"),
            "evidence":        finding.description,
        }

        # ── M20: credential_exposure → playwright admin workflow ─────────────
        # When routing valid credentials to playwright, include email/password so
        # the admin workflow test can login programmatically via REST.
        if vtype == "credential_exposure" and tool == "playwright":
            payload["admin_email"]     = raw.get("email")
            payload["admin_password"]  = raw.get("password")
            payload["admin_login_url"] = url  # login endpoint URL

        return {
            "event":           "scan.task.created",
            "scan_id":         scan_id,
            "target":          url or scan.target_url,
            "auth_session_id": scan.config.get("auth_session_id"),
            "payload":         payload,
        }


# ── Module-level helpers ───────────────────────────────────────────────────────

def _extract_param(finding: ScanResultORM) -> str:
    """Extract the parameter name from a finding's raw_output, if present."""
    if finding.raw_output and isinstance(finding.raw_output, dict):
        return finding.raw_output.get("parameter") or ""
    return ""


def _pick_best(group: List[ScanResultORM]) -> ScanResultORM:
    """Return the highest-severity finding from a dedup group."""
    return min(
        group,
        key=lambda f: _SEV_ORDER.get(
            f.severity.value if f.severity else "info", 5
        ),
    )
