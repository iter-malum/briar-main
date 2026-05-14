"""
Briar Integration Service
=========================
Handles external integrations:
  - GitLab CI/CD webhook  → creates a scan automatically when a pipeline runs
  - SARIF v2.1.0 export   → converts scan results to GitLab Security Dashboard format
  - Prometheus metrics    → exposes /metrics for scraping

Environment variables
---------------------
GITLAB_WEBHOOK_TOKEN  — shared secret validated in X-Gitlab-Token header
ORCHESTRATOR_URL      — internal URL of the Briar orchestrator (default http://orchestrator:8000)
DB_*                  — PostgreSQL connection parameters (same as other services)
DEFAULT_SCAN_TOOLS    — comma-separated list of tools to use for webhook-triggered scans
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.config import settings
from shared.models import ScanORM, ScanResultORM, ScanStatus, SeverityLevel

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("integration-service")

# ── Config ─────────────────────────────────────────────────────────────────────

GITLAB_WEBHOOK_TOKEN = os.getenv("GITLAB_WEBHOOK_TOKEN", "")
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8000")
DEFAULT_SCAN_TOOLS = os.getenv(
    "DEFAULT_SCAN_TOOLS", "whatweb,katana,httpx,ffuf,nuclei,zap"
).split(",")

# ── Prometheus metrics ─────────────────────────────────────────────────────────

webhook_requests_total = Counter(
    "briar_webhook_requests_total",
    "Total GitLab webhook requests received",
    ["event_type", "status"],
)
sarif_exports_total = Counter(
    "briar_sarif_exports_total",
    "Total SARIF export requests",
    ["status"],
)
sarif_export_duration = Histogram(
    "briar_sarif_export_duration_seconds",
    "SARIF export latency",
    buckets=[0.05, 0.1, 0.25, 0.5, 1, 2, 5],
)
webhook_triggered_scans = Counter(
    "briar_webhook_triggered_scans_total",
    "Scans created via GitLab webhook",
)

# ── Database ───────────────────────────────────────────────────────────────────

engine = create_async_engine(
    settings.db_url,
    pool_size=5,
    max_overflow=10,
    pool_recycle=3600,
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Briar Integration Service",
    version="1.0.0",
    description="GitLab CI/CD webhook receiver and SARIF exporter",
)

# ── SARIF severity mapping ─────────────────────────────────────────────────────

SEVERITY_TO_SARIF_LEVEL = {
    SeverityLevel.critical: "error",
    SeverityLevel.high: "error",
    SeverityLevel.medium: "warning",
    SeverityLevel.low: "note",
    SeverityLevel.info: "none",
}

# Maps Briar severity → GitLab DAST severity label
SEVERITY_TO_GL_SEVERITY = {
    SeverityLevel.critical: "Critical",
    SeverityLevel.high: "High",
    SeverityLevel.medium: "Medium",
    SeverityLevel.low: "Low",
    SeverityLevel.info: "Info",
}

# Tool name → SARIF toolComponent name
TOOL_NAMES = {
    "whatweb": "WhatWeb",
    "katana": "Katana",
    "httpx": "HTTPX",
    "ffuf": "FFUF",
    "nuclei": "Nuclei",
    "zap": "OWASP ZAP",
    "sqlmap": "SQLmap",
}

# ── Helpers ────────────────────────────────────────────────────────────────────


def _validate_gitlab_token(x_gitlab_token: Optional[str]) -> None:
    """Validate X-Gitlab-Token header using constant-time comparison."""
    if not GITLAB_WEBHOOK_TOKEN:
        # Token validation disabled — warn but allow through (dev mode)
        logger.warning("GITLAB_WEBHOOK_TOKEN not set — skipping token validation")
        return
    if not x_gitlab_token:
        raise HTTPException(status_code=401, detail="Missing X-Gitlab-Token header")
    if not hmac.compare_digest(x_gitlab_token, GITLAB_WEBHOOK_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid X-Gitlab-Token")


def _extract_target_url(payload: Dict[str, Any]) -> Optional[str]:
    """
    Try to extract a target URL from various GitLab webhook payload shapes:
    - Pipeline hooks with variables (BRIAR_TARGET_URL)
    - Push hooks (repository.homepage)
    - Merge request hooks (object_attributes.url)
    """
    # Highest priority: explicit variable set in .gitlab-ci.yml
    variables = payload.get("variables") or {}
    if isinstance(variables, list):
        variables = {v.get("key"): v.get("value") for v in variables if isinstance(v, dict)}
    if target := variables.get("BRIAR_TARGET_URL"):
        return target

    # Pipeline hook: builds[].variables
    for build in payload.get("builds", []):
        for var in build.get("variables", []):
            if isinstance(var, dict) and var.get("key") == "BRIAR_TARGET_URL":
                return var.get("value")

    # Pipeline hook object_attributes.variables
    obj = payload.get("object_attributes", {})
    for var in obj.get("variables", []):
        if isinstance(var, dict) and var.get("key") == "BRIAR_TARGET_URL":
            return var.get("value")

    # Fallback: repository homepage
    repo = payload.get("repository") or payload.get("project", {})
    return repo.get("homepage") or repo.get("web_url")


async def _create_scan_via_orchestrator(
    target_url: str, tools: List[str], project_info: str
) -> Dict[str, Any]:
    """POST to orchestrator to create a scan and return the response."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"{ORCHESTRATOR_URL}/scans",
            json={
                "target_url": target_url,
                "tools": tools,
                "exploit_enabled": False,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"[webhook] Created scan {data.get('id')} for {target_url} ({project_info})")
        return data


# ── SARIF builder ──────────────────────────────────────────────────────────────


def _make_rule(result: ScanResultORM) -> Dict[str, Any]:
    rule_id = result.vulnerability_type or f"{result.tool}-finding"
    severity = SEVERITY_TO_SARIF_LEVEL.get(result.severity, "none")
    return {
        "id": rule_id,
        "name": rule_id.replace("-", " ").title(),
        "shortDescription": {"text": result.vulnerability_type or "Security Finding"},
        "fullDescription": {"text": result.description or ""},
        "defaultConfiguration": {"level": severity},
        "properties": {
            "tags": [result.tool, "security"],
            "security-severity": _cvss_from_severity(result.severity),
        },
    }


def _cvss_from_severity(severity: SeverityLevel) -> str:
    """Approximate CVSS score string for SARIF security-severity property."""
    return {
        SeverityLevel.critical: "9.0",
        SeverityLevel.high: "7.5",
        SeverityLevel.medium: "5.0",
        SeverityLevel.low: "2.5",
        SeverityLevel.info: "0.0",
    }.get(severity, "0.0")


def _build_sarif(scan: ScanORM, results: List[ScanResultORM]) -> Dict[str, Any]:
    """Convert Briar scan results into a SARIF v2.1.0 document."""

    # Group results by tool
    by_tool: Dict[str, List[ScanResultORM]] = {}
    for r in results:
        by_tool.setdefault(r.tool, []).append(r)

    runs = []
    for tool_name, tool_results in by_tool.items():
        # Deduplicate rules by rule_id
        rules_seen: Dict[str, Dict] = {}
        sarif_results = []

        for r in tool_results:
            rule_id = r.vulnerability_type or f"{r.tool}-finding"
            if rule_id not in rules_seen:
                rules_seen[rule_id] = _make_rule(r)

            level = SEVERITY_TO_SARIF_LEVEL.get(r.severity, "none")
            location = {}
            if r.url:
                location = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": r.url, "uriBaseId": "%SRCROOT%"}
                    }
                }

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": r.description or r.vulnerability_type or "Finding"},
                    "locations": [location] if location else [],
                    "properties": {
                        "severity": SEVERITY_TO_GL_SEVERITY.get(r.severity, "Info"),
                        "tool": tool_name,
                        "url": r.url or "",
                    },
                }
            )

        runs.append(
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAMES.get(tool_name, tool_name),
                        "version": "1.0.0",
                        "informationUri": "https://github.com/briar-dast/briar",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                        if scan.created_at
                        else None,
                        "endTimeUtc": scan.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                        if scan.updated_at
                        else None,
                    }
                ],
                "automationDetails": {
                    "id": f"briar/{scan.id}/{tool_name}",
                    "description": {
                        "text": f"Briar DAST scan {scan.id} — {tool_name} phase"
                    },
                },
                "properties": {
                    "scan_id": str(scan.id),
                    "target_url": scan.target_url,
                    "scan_status": scan.status.value,
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


# ── Routes ─────────────────────────────────────────────────────────────────────


@app.post("/api/v1/integrations/gitlab/webhook", status_code=202)
async def gitlab_webhook(
    request: Request,
    x_gitlab_token: Optional[str] = Header(default=None, alias="X-Gitlab-Token"),
    x_gitlab_event: Optional[str] = Header(default=None, alias="X-Gitlab-Event"),
):
    """
    Receive a GitLab webhook call and trigger a DAST scan.

    Configure in GitLab: Settings → Webhooks → Pipeline events / Push events.
    Set the secret token to match GITLAB_WEBHOOK_TOKEN env var.
    Pass BRIAR_TARGET_URL as a CI/CD variable or pipeline variable.
    """
    _validate_gitlab_token(x_gitlab_token)

    try:
        payload = await request.json()
    except Exception:
        webhook_requests_total.labels(
            event_type=x_gitlab_event or "unknown", status="error"
        ).inc()
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    event_type = x_gitlab_event or payload.get("object_kind", "unknown")
    logger.info(f"[webhook] Received event: {event_type}")

    # Only process pipeline / push / merge_request hooks
    supported_events = {"Pipeline Hook", "Push Hook", "Merge Request Hook", "pipeline", "push", "merge_request"}
    if event_type not in supported_events:
        webhook_requests_total.labels(event_type=event_type, status="skipped").inc()
        return {"status": "skipped", "reason": f"event_type={event_type} not supported"}

    target_url = _extract_target_url(payload)
    if not target_url:
        webhook_requests_total.labels(event_type=event_type, status="no_target").inc()
        return {
            "status": "skipped",
            "reason": "No target URL found. Set BRIAR_TARGET_URL variable.",
        }

    project_info = (
        payload.get("project", {}).get("path_with_namespace")
        or payload.get("repository", {}).get("name", "unknown")
    )

    try:
        scan_data = await _create_scan_via_orchestrator(
            target_url=target_url,
            tools=DEFAULT_SCAN_TOOLS,
            project_info=project_info,
        )
        webhook_triggered_scans.inc()
        webhook_requests_total.labels(event_type=event_type, status="success").inc()

        scan_id = scan_data.get("id")
        return {
            "status": "accepted",
            "scan_id": scan_id,
            "target_url": target_url,
            "project": project_info,
            "sarif_url": f"/api/v1/integrations/gitlab/sarif/{scan_id}",
        }

    except httpx.HTTPStatusError as exc:
        logger.error(f"[webhook] Orchestrator returned error: {exc.response.text}")
        webhook_requests_total.labels(event_type=event_type, status="error").inc()
        raise HTTPException(status_code=502, detail="Failed to create scan")
    except Exception as exc:
        logger.error(f"[webhook] Unexpected error: {exc}", exc_info=True)
        webhook_requests_total.labels(event_type=event_type, status="error").inc()
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/integrations/gitlab/sarif/{scan_id}")
async def get_sarif(
    scan_id: str,
    min_severity: Optional[str] = Query(
        default=None,
        description="Filter: only include findings at or above this severity (critical/high/medium/low/info)",
    ),
):
    """
    Export scan results as SARIF v2.1.0 for GitLab Security Dashboard.

    Download and upload as a DAST artifact in .gitlab-ci.yml:

        artifacts:
          reports:
            dast: gl-dast-report.sarif
    """
    start = time.monotonic()
    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        sarif_exports_total.labels(status="bad_request").inc()
        raise HTTPException(status_code=400, detail="Invalid scan_id format")

    severity_order = [
        SeverityLevel.info,
        SeverityLevel.low,
        SeverityLevel.medium,
        SeverityLevel.high,
        SeverityLevel.critical,
    ]
    min_idx = 0
    if min_severity:
        try:
            min_idx = severity_order.index(SeverityLevel(min_severity.lower()))
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid min_severity. Use one of: {[s.value for s in severity_order]}",
            )

    async with async_session() as session:
        # Load scan
        scan_result = await session.execute(
            select(ScanORM).where(ScanORM.id == scan_uuid)
        )
        scan = scan_result.scalars().first()
        if not scan:
            sarif_exports_total.labels(status="not_found").inc()
            raise HTTPException(status_code=404, detail="Scan not found")

        # Load results
        stmt = select(ScanResultORM).where(ScanResultORM.scan_id == scan_uuid)
        results_result = await session.execute(stmt)
        all_results = list(results_result.scalars().all())

    # Filter by severity if requested
    if min_severity:
        allowed = set(s.value for s in severity_order[min_idx:])
        all_results = [r for r in all_results if r.severity.value in allowed]

    sarif_doc = _build_sarif(scan, all_results)

    elapsed = time.monotonic() - start
    sarif_export_duration.observe(elapsed)
    sarif_exports_total.labels(status="success").inc()

    return Response(
        content=json.dumps(sarif_doc, indent=2, default=str),
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": f'attachment; filename="briar-sarif-{scan_id}.json"',
            "X-Scan-Status": scan.status.value,
            "X-Finding-Count": str(len(all_results)),
        },
    )


@app.get("/api/v1/integrations/gitlab/scans/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Lightweight status check — useful for polling from CI/CD pipelines."""
    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan_id")

    async with async_session() as session:
        result = await session.execute(
            select(ScanORM.id, ScanORM.status, ScanORM.target_url, ScanORM.updated_at).where(
                ScanORM.id == scan_uuid
            )
        )
        row = result.first()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Count findings by severity
        findings_result = await session.execute(
            select(ScanResultORM.severity).where(ScanResultORM.scan_id == scan_uuid)
        )
        severity_counts: Dict[str, int] = {}
        for (sev,) in findings_result.all():
            severity_counts[sev.value] = severity_counts.get(sev.value, 0) + 1

    return {
        "scan_id": str(row.id),
        "status": row.status.value,
        "target_url": row.target_url,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "findings": severity_counts,
        "sarif_url": f"/api/v1/integrations/gitlab/sarif/{scan_id}",
    }


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "integration-service"}


@app.on_event("startup")
async def startup():
    logger.info("Integration service started")


@app.on_event("shutdown")
async def shutdown():
    await engine.dispose()
    logger.info("Integration service stopped")
