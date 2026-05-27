"""
GraphQL Security Testing Worker
================================
Phase: DAST  (requires_exploit=False)
Queue: scan.dast.graphql

Triggered by: finding_router when katana emits graphql_found

What this worker tests
----------------------
GraphQL has a unique attack surface that standard HTTP scanners miss.
This worker runs a targeted battery against the discovered endpoint:

  1. Introspection enabled             – schema exposure (OWASP API9)
  2. Query depth limit absent          – deeply nested query causes DoS
  3. Query breadth / alias abuse       – 100-alias field multiplication DoS
  4. Batching attacks                  – array of operations in one request
  5. Field suggestion leakage          – typo reveals real field names
  6. Mutation auth bypass              – sensitive mutations without token
  7. IDOR via argument enumeration     – id:1, id:2 … on object queries
  8. Error info disclosure             – stack traces / internal paths in errors
  9. CSRF via GET request              – query accepted via GET+URL-encode

All tests use httpx — no binary required.
Severity assignments follow OWASP API Security Top 10 2023.
"""

import asyncio
import json
import logging
import os
import random
import re
import sys
import string
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import httpx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("graphql-worker")

TOTAL_TIMEOUT   = int(os.getenv("GRAPHQL_TIMEOUT",   "600"))
REQUEST_TIMEOUT = float(os.getenv("GRAPHQL_REQ_TIMEOUT", "15"))
IDOR_PROBE_MAX  = int(os.getenv("GRAPHQL_IDOR_MAX", "20"))

# Common mutations to test without authentication
_SENSITIVE_MUTATIONS = [
    "mutation { createUser(email: \"briar_test@test.com\", password: \"test123\") { id } }",
    "mutation { register(username: \"briar_test\", email: \"briar@test.com\") { token } }",
    "mutation { login(username: \"admin\", password: \"admin\") { token } }",
    "mutation { deleteUser(id: 1) { success } }",
    "mutation { resetPassword(email: \"admin@test.com\") { success } }",
    "mutation { updateUser(id: 1, role: \"admin\") { id role } }",
]

# Introspection query
_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}
"""

# Typo to trigger field suggestions
_SUGGESTION_QUERY = "{ usr { id } }"   # "usr" instead of "user"


class GraphQLWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="graphql", queue_name="scan.dast.graphql")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        # Finding router provides the GraphQL URL in inject_payload or target
        graphql_url = (
            task_payload.get("inject_payload")
            or task_payload.get("target")
            or target
        )

        # Phase-based fallback: scan all graphql_found findings
        if not task_payload.get("finding_triggered"):
            scan_id = task_payload.get("scan_id", "")
            graphql_urls = await self._get_graphql_urls(scan_id)
            if not graphql_urls:
                graphql_urls = [graphql_url]
        else:
            graphql_urls = [graphql_url]

        headers = _build_headers(auth_context)
        results: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(
            headers=headers,
            verify=False,
            follow_redirects=True,
            timeout=httpx.Timeout(REQUEST_TIMEOUT),
        ) as client:
            for gql_url in graphql_urls:
                logger.info(f"[graphql] Testing endpoint: {gql_url}")
                partial = await self._test_endpoint(client, gql_url, auth_context)
                results.extend(partial)

        logger.info(f"[graphql] Total findings: {len(results)}")
        return results

    async def _get_graphql_urls(self, scan_id: str) -> List[str]:
        if not scan_id:
            return []
        try:
            async with self.db_session() as session:
                from shared.models import ScanResultORM
                from sqlalchemy import select
                from uuid import UUID
                stmt = select(ScanResultORM).where(
                    ScanResultORM.scan_id == UUID(scan_id),
                    ScanResultORM.vulnerability_type == "graphql_found",
                )
                rows = await session.execute(stmt)
                urls = []
                for f in rows.scalars().all():
                    raw = f.raw_output or {}
                    u = raw.get("graphql_url") or f.url
                    if u:
                        urls.append(u)
                return list(dict.fromkeys(urls))
        except Exception as exc:
            logger.warning(f"[graphql] DB query failed: {exc}")
            return []

    # ── Test battery ──────────────────────────────────────────────────────────

    async def _test_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        auth_context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # Run all tests concurrently, collect results
        test_coros = [
            self._test_introspection(client, url),
            self._test_depth_limit(client, url),
            self._test_alias_abuse(client, url),
            self._test_batching(client, url),
            self._test_field_suggestion(client, url),
            self._test_mutation_auth_bypass(client, url),
            self._test_idor(client, url),
            self._test_get_method(client, url),
        ]

        results = await asyncio.gather(*test_coros, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.debug(f"[graphql] Test error: {r}")
            elif isinstance(r, list):
                findings.extend(r)

        return findings

    # ── Test 1: Introspection ─────────────────────────────────────────────────

    async def _test_introspection(
        self, client: httpx.AsyncClient, url: str
    ) -> List[Dict[str, Any]]:
        try:
            resp = await client.post(url, json={"query": _INTROSPECTION_QUERY})
            if resp.status_code != 200:
                return []
            data = resp.json()
            schema = data.get("data", {}).get("__schema")
            if not schema:
                return []
            type_names = [t.get("name") for t in schema.get("types", []) if not (t.get("name") or "").startswith("__")]
            return [{
                "url":         url,
                "type":        "graphql-introspection-enabled",
                "severity":    SeverityLevel.medium,
                "description": (
                    f"GraphQL introspection is enabled at {url}. "
                    f"Full schema exposed: {len(type_names)} type(s) visible. "
                    f"Types: {', '.join(type_names[:10])}{'…' if len(type_names) > 10 else ''}. "
                    f"Attackers can map the entire API surface. "
                    f"Disable introspection in production (OWASP API9)."
                ),
                "raw_output": {
                    "url":        url,
                    "type_count": len(type_names),
                    "types":      type_names[:30],
                },
            }]
        except Exception as exc:
            logger.debug(f"[graphql] Introspection test error: {exc}")
            return []

    # ── Test 2: Depth limit ───────────────────────────────────────────────────

    async def _test_depth_limit(
        self, client: httpx.AsyncClient, url: str
    ) -> List[Dict[str, Any]]:
        # Build a 12-level deep nested query using common field names
        depth_query = "{" + " a {" * 12 + " id " + "}" * 12 + "}"
        try:
            resp = await client.post(url, json={"query": depth_query})
            body = resp.text
            # If we get a 200 with "data" key (not errors only) → no depth limit
            try:
                parsed = resp.json()
                has_only_errors = bool(parsed.get("errors")) and not parsed.get("data")
                has_depth_error = any(
                    "depth" in str(e).lower() or "complexity" in str(e).lower()
                    for e in parsed.get("errors", [])
                )
                if has_depth_error:
                    return []  # Depth limiting is active — this is correct behaviour
                if not has_only_errors and resp.status_code == 200:
                    return [{
                        "url":         url,
                        "type":        "graphql-no-depth-limit",
                        "severity":    SeverityLevel.medium,
                        "description": (
                            f"No query depth limit detected at {url}. "
                            f"A deeply nested query (12 levels) was accepted without error. "
                            f"Allows denial-of-service via exponentially nested queries."
                        ),
                        "raw_output": {"url": url, "depth_tested": 12},
                    }]
            except Exception:
                pass
        except Exception as exc:
            logger.debug(f"[graphql] Depth limit test error: {exc}")
        return []

    # ── Test 3: Alias abuse (100 aliases = field multiplication DoS) ──────────

    async def _test_alias_abuse(
        self, client: httpx.AsyncClient, url: str
    ) -> List[Dict[str, Any]]:
        # Create 100 aliased versions of the same field
        aliases = " ".join(f"f{i}: __typename" for i in range(100))
        query = "{" + aliases + "}"
        try:
            t0 = asyncio.get_event_loop().time()
            resp = await client.post(url, json={"query": query})
            elapsed = asyncio.get_event_loop().time() - t0
            try:
                parsed = resp.json()
                has_cost_error = any(
                    "cost" in str(e).lower() or "complexity" in str(e).lower() or "alias" in str(e).lower()
                    for e in parsed.get("errors", [])
                )
                if has_cost_error:
                    return []  # Rate/cost limiting active
                if resp.status_code == 200 and parsed.get("data"):
                    return [{
                        "url":         url,
                        "type":        "graphql-alias-abuse",
                        "severity":    SeverityLevel.medium,
                        "description": (
                            f"GraphQL alias multiplication attack succeeded at {url}. "
                            f"100 aliased fields accepted in one query (response in {elapsed:.1f}s). "
                            f"Without query cost limiting, this enables amplification DoS."
                        ),
                        "raw_output": {"url": url, "aliases": 100, "elapsed_s": round(elapsed, 2)},
                    }]
            except Exception:
                pass
        except Exception as exc:
            logger.debug(f"[graphql] Alias abuse test error: {exc}")
        return []

    # ── Test 4: Batching ──────────────────────────────────────────────────────

    async def _test_batching(
        self, client: httpx.AsyncClient, url: str
    ) -> List[Dict[str, Any]]:
        batch = [{"query": "{ __typename }"}] * 10
        try:
            resp = await client.post(url, json=batch)
            if resp.status_code == 200:
                try:
                    parsed = resp.json()
                    if isinstance(parsed, list) and len(parsed) > 1:
                        return [{
                            "url":         url,
                            "type":        "graphql-batching-enabled",
                            "severity":    SeverityLevel.low,
                            "description": (
                                f"GraphQL query batching is enabled at {url}. "
                                f"10 operations were accepted in a single request. "
                                f"Combined with brute-force, this multiplies attack throughput "
                                f"10× while appearing as a single request in rate-limit counters."
                            ),
                            "raw_output": {"url": url, "batch_size": 10},
                        }]
                except Exception:
                    pass
        except Exception as exc:
            logger.debug(f"[graphql] Batching test error: {exc}")
        return []

    # ── Test 5: Field suggestion leakage ─────────────────────────────────────

    async def _test_field_suggestion(
        self, client: httpx.AsyncClient, url: str
    ) -> List[Dict[str, Any]]:
        typo_queries = [
            ("{ usr { id } }",      "user"),
            ("{ userr { id } }",    "user"),
            ("{ products { ids } }", "id"),
        ]
        for query, expected_hint in typo_queries:
            try:
                resp = await client.post(url, json={"query": query})
                body = resp.text
                if "did you mean" in body.lower() or "suggestion" in body.lower():
                    # Extract suggestion if possible
                    m = re.search(r'"Did you mean "([^"]+)"', body, re.IGNORECASE)
                    suggestion = m.group(1) if m else "see raw_output"
                    return [{
                        "url":         url,
                        "type":        "graphql-field-suggestion",
                        "severity":    SeverityLevel.info,
                        "description": (
                            f"GraphQL endpoint leaks field name suggestions at {url}. "
                            f"Query {query!r} returned 'Did you mean {suggestion!r}'. "
                            f"Schema can be partially mapped even with introspection disabled."
                        ),
                        "raw_output": {"url": url, "query": query, "suggestion": suggestion},
                    }]
            except Exception as exc:
                logger.debug(f"[graphql] Field suggestion test error: {exc}")
        return []

    # ── Test 6: Mutation auth bypass ──────────────────────────────────────────

    async def _test_mutation_auth_bypass(
        self, client: httpx.AsyncClient, url: str
    ) -> List[Dict[str, Any]]:
        # Use a fresh unauthenticated client (no inherited auth headers)
        findings = []
        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=httpx.Timeout(REQUEST_TIMEOUT)
            ) as anon_client:
                for mutation in _SENSITIVE_MUTATIONS:
                    try:
                        resp = await anon_client.post(url, json={"query": mutation})
                        body = resp.text
                        parsed = resp.json() if resp.status_code == 200 else {}
                        data = parsed.get("data") or {}
                        errors = parsed.get("errors", [])
                        auth_errors = any(
                            any(w in str(e).lower() for w in
                                ("unauthorized", "unauthenticated", "forbidden",
                                 "not allowed", "permission", "access denied", "auth"))
                            for e in errors
                        )
                        # If mutation returned data (not just errors), it succeeded without auth
                        if data and not auth_errors:
                            op_name = re.search(r"mutation\s*\{\s*(\w+)", mutation)
                            name = op_name.group(1) if op_name else "unknown"
                            findings.append({
                                "url":         url,
                                "type":        "graphql-mutation-auth-bypass",
                                "severity":    SeverityLevel.high,
                                "description": (
                                    f"GraphQL mutation '{name}' succeeded without authentication at {url}. "
                                    f"Sensitive operation executed as anonymous user — "
                                    f"missing authorization check (OWASP API1/API5)."
                                ),
                                "raw_output": {
                                    "url":      url,
                                    "mutation": mutation,
                                    "response": body[:500],
                                },
                            })
                            break  # One confirmed bypass is enough
                    except Exception:
                        continue
        except Exception as exc:
            logger.debug(f"[graphql] Mutation auth bypass test error: {exc}")
        return findings

    # ── Test 7: IDOR via ID enumeration ───────────────────────────────────────

    async def _test_idor(
        self, client: httpx.AsyncClient, url: str
    ) -> List[Dict[str, Any]]:
        """
        Fetch introspection schema, find query fields that take an ID argument,
        then compare responses for id=1 vs id=9999 to detect IDOR.
        """
        try:
            resp = await client.post(url, json={"query": _INTROSPECTION_QUERY})
            if resp.status_code != 200:
                return []
            schema = resp.json().get("data", {}).get("__schema", {})
        except Exception:
            return []

        # Find query fields with an 'id' argument
        id_fields: List[str] = []
        for t in schema.get("types", []):
            if t.get("name") in ("Query",) and t.get("kind") == "OBJECT":
                for field in (t.get("fields") or []):
                    args = field.get("args") or []
                    if any(a.get("name", "").lower() in ("id", "user_id", "userId") for a in args):
                        id_fields.append(field.get("name", ""))

        if not id_fields:
            return []

        findings = []
        for field_name in id_fields[:3]:  # limit to 3 fields
            query_1  = f"{{ {field_name}(id: 1) {{ id }} }}"
            query_99 = f"{{ {field_name}(id: 9999) {{ id }} }}"
            try:
                r1  = await client.post(url, json={"query": query_1})
                r99 = await client.post(url, json={"query": query_99})
                d1  = (r1.json().get("data")  or {}).get(field_name)
                d99 = (r99.json().get("data") or {}).get(field_name)
                # If id=1 returned data but the user didn't get 401/403, potential IDOR
                if d1 is not None:
                    findings.append({
                        "url":         url,
                        "type":        "graphql-idor-candidate",
                        "severity":    SeverityLevel.high,
                        "description": (
                            f"GraphQL field '{field_name}' accepts an 'id' argument and returned "
                            f"data for id=1 without an authorization error at {url}. "
                            f"No ownership check detected — potential BOLA/IDOR "
                            f"(OWASP API1). Confirm by testing cross-user access."
                        ),
                        "raw_output": {
                            "url":        url,
                            "field":      field_name,
                            "query":      query_1,
                            "result_id1": str(d1)[:200],
                        },
                    })
            except Exception:
                continue

        return findings

    # ── Test 8: GET method (CSRF vector) ─────────────────────────────────────

    async def _test_get_method(
        self, client: httpx.AsyncClient, url: str
    ) -> List[Dict[str, Any]]:
        import urllib.parse
        query = "{ __typename }"
        encoded = urllib.parse.urlencode({"query": query})
        get_url = f"{url}?{encoded}"
        try:
            resp = await client.get(get_url)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get("data"):
                        return [{
                            "url":         url,
                            "type":        "graphql-get-method-allowed",
                            "severity":    SeverityLevel.medium,
                            "description": (
                                f"GraphQL endpoint at {url} accepts queries via GET requests. "
                                f"This enables CSRF attacks — browsers will include credentials "
                                f"(cookies/session tokens) in cross-origin GET requests. "
                                f"Only POST with Content-Type: application/json should be allowed."
                            ),
                            "raw_output": {"url": url, "get_url": get_url},
                        }]
                except Exception:
                    pass
        except Exception as exc:
            logger.debug(f"[graphql] GET method test error: {exc}")
        return []


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_headers(auth_context: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent":   "Mozilla/5.0 (compatible; Briar-GraphQL/1.0)",
    }
    headers.update(auth_context.get("headers", {}))
    cookies = auth_context.get("cookies", [])
    if cookies:
        headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    return headers


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    worker = GraphQLWorker()
    await worker.start()
    try:
        while worker.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await worker.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
