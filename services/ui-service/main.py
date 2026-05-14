"""Briar UI Service — REST API + Neo4j sync + WebSocket real-time updates"""

import sys
import os
import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from neo4j import AsyncGraphDatabase, AsyncDriver
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from shared.config import settings
from shared.models import ScanORM, ScanResultORM, ScanStepORM, ScanStatus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ui-service")

app = FastAPI(title="Briar UI Service", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Database ──────────────────────────────────────────────────────────────────

engine = create_async_engine(settings.db_url, pool_size=5, max_overflow=10, pool_recycle=3600)
session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# ── Neo4j ─────────────────────────────────────────────────────────────────────

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "briar_neo4j_password")

neo4j_driver: Optional[AsyncDriver] = None


async def get_neo4j() -> Optional[AsyncDriver]:
    return neo4j_driver


# ── WebSocket manager ─────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, scan_id: str, ws: WebSocket):
        await ws.accept()
        self._connections.setdefault(scan_id, []).append(ws)

    def disconnect(self, scan_id: str, ws: WebSocket):
        conns = self._connections.get(scan_id, [])
        if ws in conns:
            conns.remove(ws)

    async def broadcast(self, scan_id: str, payload: dict):
        for ws in list(self._connections.get(scan_id, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                pass


manager = ConnectionManager()


# ── Lifecycle ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    global neo4j_driver
    try:
        neo4j_driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        async with neo4j_driver.session() as s:
            await s.run("RETURN 1")
        # Create indexes
        async with neo4j_driver.session() as s:
            await s.run("CREATE INDEX endpoint_url IF NOT EXISTS FOR (e:Endpoint) ON (e.url, e.scan_id)")
            await s.run("CREATE INDEX vuln_id IF NOT EXISTS FOR (v:Vulnerability) ON (v.id)")
        logger.info("Connected to Neo4j")
    except Exception as exc:
        logger.warning(f"Neo4j unavailable at startup (will retry on demand): {exc}")
        neo4j_driver = None


@app.on_event("shutdown")
async def shutdown():
    if neo4j_driver:
        await neo4j_driver.close()
    await engine.dispose()


# ── Neo4j Sync ────────────────────────────────────────────────────────────────

async def sync_scan_to_neo4j(scan_id: str) -> bool:
    """Push scan results from Postgres into Neo4j graph."""
    driver = await get_neo4j()
    if not driver:
        return False

    try:
        async with session_factory() as db:
            stmt = select(ScanResultORM).where(
                ScanResultORM.scan_id == UUID(scan_id),
                ScanResultORM.url.isnot(None),
            )
            res = await db.execute(stmt)
            rows = res.scalars().all()

        async with driver.session() as neo:
            for row in rows:
                sev = row.severity.value if hasattr(row.severity, "value") else str(row.severity)
                if row.tool in ("katana", "httpx"):
                    await neo.run(
                        """
                        MERGE (e:Endpoint {url: $url, scan_id: $scan_id})
                        SET e.method = $method, e.discovered_by = $tool, e.updated_at = datetime()
                        """,
                        url=row.url,
                        scan_id=scan_id,
                        method=row.raw_output.get("method", "GET"),
                        tool=row.tool,
                    )
                elif row.url:
                    await neo.run(
                        """
                        MERGE (v:Vulnerability {id: $id})
                        SET v.type = $type, v.severity = $severity, v.tool = $tool, v.scan_id = $scan_id,
                            v.description = $desc
                        WITH v
                        MERGE (e:Endpoint {url: $url, scan_id: $scan_id})
                        MERGE (e)-[r:HAS_VULN]->(v)
                        SET r.timestamp = datetime()
                        """,
                        id=str(row.id),
                        type=row.vulnerability_type or "Unknown",
                        severity=sev,
                        tool=row.tool,
                        scan_id=scan_id,
                        desc=row.description or "",
                        url=row.url,
                    )

        logger.info(f"Synced {len(rows)} results for scan {scan_id} to Neo4j")
        return True

    except Exception as exc:
        logger.error(f"Neo4j sync failed for scan {scan_id}: {exc}", exc_info=True)
        return False


# ── Helper: graph from Postgres fallback ──────────────────────────────────────

async def _graph_from_postgres(scan_id: str) -> dict:
    async with session_factory() as db:
        stmt = select(ScanResultORM).where(ScanResultORM.scan_id == UUID(scan_id))
        res = await db.execute(stmt)
        rows = res.scalars().all()

    nodes: list = []
    links: list = []
    seen_urls: set = set()

    for row in rows:
        if not row.url:
            continue
        sev = row.severity.value if hasattr(row.severity, "value") else str(row.severity)
        if row.url not in seen_urls:
            seen_urls.add(row.url)
            nodes.append({
                "id": row.url,
                "label": row.url.split("/")[-1] or "/",
                "url": row.url,
                "type": "endpoint" if row.tool in ("katana", "httpx") else "vulnerability",
                "discovered_by": row.tool,
                "severity": sev,
                "vuln_count": 0,
            })
        if row.tool not in ("katana", "httpx"):
            vuln_node_id = f"vuln-{row.id}"
            nodes.append({
                "id": vuln_node_id,
                "label": row.vulnerability_type or "Unknown",
                "type": "vulnerability",
                "severity": sev,
                "tool": row.tool,
                "url": row.url,
            })
            links.append({"source": row.url, "target": vuln_node_id})

    return {"nodes": nodes, "links": links}


# ── REST API ──────────────────────────────────────────────────────────────────

@app.get("/api/v1/scans")
async def list_scans(limit: int = Query(50, ge=1, le=200)):
    async with session_factory() as db:
        stmt = (
            select(ScanORM)
            .options(selectinload(ScanORM.steps))
            .order_by(ScanORM.created_at.desc())
            .limit(limit)
        )
        res = await db.execute(stmt)
        scans = res.scalars().all()

    return [
        {
            "id": str(s.id),
            "target_url": s.target_url,
            "status": s.status.value,
            "created_at": s.created_at.isoformat(),
            "updated_at": s.updated_at.isoformat(),
            "tools": s.config.get("tools", []),
            "steps": [
                {"tool": st.tool, "status": st.status.value}
                for st in s.steps
            ],
        }
        for s in scans
    ]


@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str):
    async with session_factory() as db:
        stmt = (
            select(ScanORM)
            .options(selectinload(ScanORM.steps))
            .where(ScanORM.id == UUID(scan_id))
        )
        res = await db.execute(stmt)
        scan = res.scalars().first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "id": str(scan.id),
        "target_url": scan.target_url,
        "status": scan.status.value,
        "created_at": scan.created_at.isoformat(),
        "updated_at": scan.updated_at.isoformat(),
        "tools": scan.config.get("tools", []),
        "steps": [
            {
                "tool": s.tool,
                "status": s.status.value,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            }
            for s in scan.steps
        ],
    }


@app.get("/api/v1/scans/{scan_id}/graph")
async def get_scan_graph(scan_id: str):
    """Returns graph data for React-Force-Graph: { nodes, links }"""
    await sync_scan_to_neo4j(scan_id)

    driver = await get_neo4j()
    if not driver:
        return await _graph_from_postgres(scan_id)

    nodes: list = []
    links: list = []

    try:
        async with driver.session() as neo:
            # Endpoint nodes with aggregated vuln info
            endpoint_res = await neo.run(
                """
                MATCH (e:Endpoint {scan_id: $scan_id})
                OPTIONAL MATCH (e)-[:HAS_VULN]->(v:Vulnerability)
                RETURN e.url AS url, e.method AS method, e.discovered_by AS discovered_by,
                       count(v) AS vuln_count,
                       collect(DISTINCT v.severity) AS severities
                """,
                scan_id=scan_id,
            )
            async for rec in endpoint_res:
                sevs = [s for s in rec["severities"] if s]
                nodes.append({
                    "id": rec["url"],
                    "label": rec["url"].split("/")[-1] or "/",
                    "url": rec["url"],
                    "type": "endpoint",
                    "method": rec["method"] or "GET",
                    "discovered_by": rec["discovered_by"] or "unknown",
                    "vuln_count": rec["vuln_count"] or 0,
                    "has_critical": "critical" in sevs,
                    "has_high": "high" in sevs,
                })

            # Vulnerability nodes + edges
            vuln_res = await neo.run(
                """
                MATCH (e:Endpoint {scan_id: $scan_id})-[:HAS_VULN]->(v:Vulnerability)
                RETURN v.id AS id, v.type AS type, v.severity AS severity,
                       v.tool AS tool, v.description AS description, e.url AS endpoint_url
                """,
                scan_id=scan_id,
            )
            async for rec in vuln_res:
                vuln_id = f"vuln-{rec['id']}"
                nodes.append({
                    "id": vuln_id,
                    "label": rec["type"] or "Unknown",
                    "type": "vulnerability",
                    "severity": rec["severity"],
                    "tool": rec["tool"],
                    "description": rec["description"] or "",
                })
                links.append({"source": rec["endpoint_url"], "target": vuln_id})

        return {"nodes": nodes, "links": links}

    except Exception as exc:
        logger.error(f"Neo4j graph query failed: {exc}", exc_info=True)
        return await _graph_from_postgres(scan_id)


@app.get("/api/v1/vulnerabilities")
async def list_vulnerabilities(
    scan_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    tool: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    async with session_factory() as db:
        stmt = select(ScanResultORM).where(ScanResultORM.tool.notin_(["katana", "httpx"]))
        if scan_id:
            stmt = stmt.where(ScanResultORM.scan_id == UUID(scan_id))
        if severity:
            stmt = stmt.where(ScanResultORM.severity == severity)
        if tool:
            stmt = stmt.where(ScanResultORM.tool == tool)
        stmt = stmt.order_by(ScanResultORM.created_at.desc()).limit(limit)
        res = await db.execute(stmt)
        vulns = res.scalars().all()

    return [
        {
            "id": str(v.id),
            "scan_id": str(v.scan_id),
            "tool": v.tool,
            "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
            "url": v.url,
            "vulnerability_type": v.vulnerability_type,
            "description": v.description,
            "created_at": v.created_at.isoformat(),
        }
        for v in vulns
    ]


@app.post("/api/v1/scans/{scan_id}/sync")
async def trigger_sync(scan_id: str):
    asyncio.create_task(sync_scan_to_neo4j(scan_id))
    return {"message": "Sync triggered", "scan_id": scan_id}


# ── WebSocket real-time updates ───────────────────────────────────────────────

@app.websocket("/ws/scans/{scan_id}")
async def ws_scan_updates(websocket: WebSocket, scan_id: str):
    await manager.connect(scan_id, websocket)

    try:
        # Initial snapshot
        async with session_factory() as db:
            stmt = (
                select(ScanORM)
                .options(selectinload(ScanORM.steps), selectinload(ScanORM.results))
                .where(ScanORM.id == UUID(scan_id))
            )
            res = await db.execute(stmt)
            scan = res.scalars().first()

        if scan:
            await websocket.send_json({
                "event": "initial_state",
                "scan": {
                    "id": str(scan.id),
                    "status": scan.status.value,
                    "steps": [{"tool": s.tool, "status": s.status.value} for s in scan.steps],
                    "endpoint_count": sum(1 for r in scan.results if r.tool in ("katana", "httpx")),
                    "vuln_count": sum(1 for r in scan.results if r.tool not in ("katana", "httpx")),
                },
            })

        # Polling loop — push diffs to client
        last_step_states: Dict[str, str] = {}
        last_counts = (-1, -1)

        while True:
            await asyncio.sleep(3)

            async with session_factory() as db:
                stmt = (
                    select(ScanORM)
                    .options(selectinload(ScanORM.steps), selectinload(ScanORM.results))
                    .where(ScanORM.id == UUID(scan_id))
                )
                res = await db.execute(stmt)
                scan = res.scalars().first()

            if not scan:
                break

            for step in scan.steps:
                key = step.tool
                if last_step_states.get(key) != step.status.value:
                    last_step_states[key] = step.status.value
                    await websocket.send_json({
                        "event": "step_update",
                        "tool": step.tool,
                        "status": step.status.value,
                        "progress": _calc_progress(scan.steps),
                    })

            ep_count = sum(1 for r in scan.results if r.tool in ("katana", "httpx"))
            vl_count = sum(1 for r in scan.results if r.tool not in ("katana", "httpx"))

            if (ep_count, vl_count) != last_counts:
                last_counts = (ep_count, vl_count)
                await websocket.send_json({
                    "event": "stats_update",
                    "scan_status": scan.status.value,
                    "endpoint_count": ep_count,
                    "vuln_count": vl_count,
                })

            if scan.status in (ScanStatus.completed, ScanStatus.failed):
                await websocket.send_json({"event": "scan_complete", "status": scan.status.value})
                break

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.error(f"WebSocket error for scan {scan_id}: {exc}", exc_info=True)
    finally:
        manager.disconnect(scan_id, websocket)


def _calc_progress(steps) -> int:
    if not steps:
        return 0
    done = sum(1 for s in steps if s.status in (ScanStatus.completed, ScanStatus.failed))
    return int(done / len(steps) * 100)


@app.get("/health")
async def health():
    neo4j_ok = neo4j_driver is not None
    return {"status": "healthy", "service": "ui-service", "neo4j": neo4j_ok}
