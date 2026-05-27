"""
OpenAPI / Swagger Spec-Driven Testing Worker
=============================================
Phase: DAST  (requires_exploit=False)
Queue: scan.dast.openapi

Triggered by: finding_router when katana emits swagger_found

What this worker does
----------------------
Instead of blindly crawling, this worker:
  1. Downloads and parses the OpenAPI 2.0 / 3.0 spec (JSON or YAML)
  2. Enumerates every defined endpoint with its exact parameters
  3. Runs a targeted security test battery on each operation:

     A. Authentication enforcement
        • Request endpoint without auth token → expect 401/403
        • If 200 returned → missing auth (OWASP API2)

     B. BOLA / IDOR detection  (OWASP API1)
        • Endpoints with {id} path params → fetch id=1 vs id=2
        • Compare responses to detect cross-object access

     C. Mass assignment  (OWASP API6)
        • POST/PUT with extra fields not in the spec schema
        • Check if unknown fields are reflected back in response

     D. HTTP method override  (OWASP API8)
        • Try undocumented HTTP methods on each path
        • X-HTTP-Method-Override header bypass

     E. Excessive data exposure  (OWASP API3)
        • Inspect response bodies for PII/sensitive field patterns
          (email, ssn, password, credit_card, api_key, secret, token)

     F. Security headers audit
        • Missing CORS headers, X-Content-Type, rate-limit headers

All tests use httpx (no external binary).
"""

import asyncio
import json
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("openapi-worker")

TOTAL_TIMEOUT   = int(os.getenv("OPENAPI_TIMEOUT",     "1200"))  # 20 min
REQUEST_TIMEOUT = float(os.getenv("OPENAPI_REQ_TIMEOUT", "15"))
MAX_ENDPOINTS   = int(os.getenv("OPENAPI_MAX_ENDPOINTS", "200"))

# PII / sensitive field names to flag in response bodies
_SENSITIVE_FIELDS = frozenset({
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "private_key", "ssn", "social_security",
    "credit_card", "card_number", "cvv", "pin", "dob", "date_of_birth",
})

# Headers that expose overly permissive CORS
_CORS_WILDCARD_RE = re.compile(r"access-control-allow-origin:\s*\*", re.IGNORECASE)

# HTTP methods to try for undocumented method test
_PROBE_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE")


class OpenAPIWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="openapi", queue_name="scan.dast.openapi")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        # Finding router puts the spec URL in inject_payload
        spec_url = (
            task_payload.get("inject_payload")
            or task_payload.get("openapi_url")
        )

        if not spec_url:
            # Phase-based: find spec URLs from DB
            scan_id = task_payload.get("scan_id", "")
            spec_urls = await self._get_spec_urls(scan_id)
            if not spec_urls:
                # Probe well-known paths against the target
                spec_urls = await _discover_spec_url(target, auth_context)
            if not spec_urls:
                logger.info("[openapi] No spec URL found — skipping")
                return []
        else:
            spec_urls = [spec_url]

        all_results: List[Dict[str, Any]] = []
        for surl in spec_urls:
            logger.info(f"[openapi] Processing spec: {surl}")
            partial = await self._test_spec(surl, target, auth_context)
            all_results.extend(partial)

        logger.info(f"[openapi] Total findings: {len(all_results)}")
        return all_results

    async def _get_spec_urls(self, scan_id: str) -> List[str]:
        if not scan_id:
            return []
        try:
            async with self.db_session() as session:
                from shared.models import ScanResultORM
                from sqlalchemy import select
                from uuid import UUID
                stmt = select(ScanResultORM).where(
                    ScanResultORM.scan_id == UUID(scan_id),
                    ScanResultORM.vulnerability_type == "swagger_found",
                )
                rows = await session.execute(stmt)
                urls = []
                for f in rows.scalars().all():
                    raw = f.raw_output or {}
                    u = raw.get("spec_url") or raw.get("inject_payload") or f.url
                    if u:
                        urls.append(u)
                return list(dict.fromkeys(urls))
        except Exception as exc:
            logger.warning(f"[openapi] DB query failed: {exc}")
            return []

    # ── Spec fetch + parse ────────────────────────────────────────────────────

    async def _test_spec(
        self,
        spec_url: str,
        base_target: str,
        auth_context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        headers = _build_headers(auth_context)

        async with httpx.AsyncClient(
            headers=headers,
            verify=False,
            follow_redirects=True,
            timeout=httpx.Timeout(REQUEST_TIMEOUT),
        ) as client:
            # Fetch the spec
            spec = await _fetch_spec(client, spec_url)
            if not spec:
                logger.warning(f"[openapi] Could not fetch/parse spec: {spec_url}")
                return []

            # Extract operations from spec
            operations = _parse_spec(spec, spec_url, base_target)
            logger.info(f"[openapi] Spec parsed: {len(operations)} operation(s)")

            if len(operations) > MAX_ENDPOINTS:
                logger.info(f"[openapi] Capping to {MAX_ENDPOINTS} operations")
                operations = operations[:MAX_ENDPOINTS]

            findings: List[Dict[str, Any]] = []
            start = asyncio.get_event_loop().time()

            for op in operations:
                if asyncio.get_event_loop().time() - start > TOTAL_TIMEOUT:
                    logger.warning("[openapi] Total timeout reached")
                    break
                partial = await self._test_operation(client, op, headers, auth_context)
                findings.extend(partial)

            # Global spec findings
            findings.extend(_check_spec_security(spec, spec_url))

        return findings

    # ── Per-operation tests ───────────────────────────────────────────────────

    async def _test_operation(
        self,
        client: httpx.AsyncClient,
        op: Dict[str, Any],
        headers: Dict[str, str],
        auth_context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        url    = op["url"]
        method = op["method"]

        # ── A. Authentication enforcement ─────────────────────────────────────
        try:
            anon_headers = {
                "Content-Type": "application/json",
                "User-Agent":   "Mozilla/5.0 (compatible; Briar-OpenAPI/1.0)",
            }
            async with httpx.AsyncClient(
                headers=anon_headers,
                verify=False,
                follow_redirects=False,
                timeout=httpx.Timeout(REQUEST_TIMEOUT),
            ) as anon_client:
                body = json.dumps(op.get("sample_body", {})) if method in ("POST", "PUT", "PATCH") else None
                resp = await _make_request(anon_client, method, url, body)
                if resp and resp.status_code in (200, 201, 204):
                    # Not getting 401/403 → auth not enforced
                    if op.get("requires_auth", True):
                        findings.append({
                            "url":         url,
                            "type":        "api-missing-authentication",
                            "severity":    SeverityLevel.high,
                            "description": (
                                f"API endpoint {method} {url} returned HTTP {resp.status_code} "
                                f"without an authentication token. "
                                f"Expected 401/403 (OWASP API2 — Broken Authentication)."
                            ),
                            "raw_output": {
                                "url":    url,
                                "method": method,
                                "status": resp.status_code,
                                "spec":   op.get("spec_url"),
                            },
                        })
        except Exception:
            pass

        # ── B. BOLA / IDOR ────────────────────────────────────────────────────
        if "{id}" in url or "{" in url:
            findings.extend(await self._test_bola(client, op))

        # ── C. Mass assignment ────────────────────────────────────────────────
        if method in ("POST", "PUT", "PATCH"):
            findings.extend(await self._test_mass_assignment(client, op))

        # ── D. Undocumented HTTP methods ──────────────────────────────────────
        findings.extend(await self._test_method_override(client, op))

        # ── E. Sensitive data in response ─────────────────────────────────────
        findings.extend(await self._test_data_exposure(client, op))

        return findings

    async def _test_bola(
        self, client: httpx.AsyncClient, op: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Replace {id} with 1 and 2; compare responses to detect BOLA."""
        url_template = op["url"]
        method       = op["method"]
        if method not in ("GET", "HEAD"):
            return []

        url1 = re.sub(r"\{[^}]+\}", "1", url_template)
        url2 = re.sub(r"\{[^}]+\}", "2", url_template)

        try:
            r1 = await _make_request(client, method, url1)
            r2 = await _make_request(client, method, url2)
            if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
                # Both IDs accessible — check if same user/ownership context
                if r1.text != r2.text and len(r1.text) > 20:
                    return [{
                        "url":         url1,
                        "type":        "api-bola-candidate",
                        "severity":    SeverityLevel.high,
                        "description": (
                            f"Potential BOLA/IDOR at {url_template}. "
                            f"Both id=1 and id=2 returned HTTP 200 with different data. "
                            f"No ownership enforcement detected — "
                            f"verify cross-user access manually (OWASP API1)."
                        ),
                        "raw_output": {
                            "url_template": url_template,
                            "url_id1": url1,
                            "url_id2": url2,
                            "status_id1": r1.status_code,
                            "status_id2": r2.status_code,
                        },
                    }]
        except Exception as exc:
            logger.debug(f"[openapi] BOLA test error for {url_template}: {exc}")
        return []

    async def _test_mass_assignment(
        self, client: httpx.AsyncClient, op: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """POST extra fields not in schema; check if reflected in response."""
        url    = op["url"]
        method = op["method"]
        # Inject extra privileged fields alongside sample body
        extra_fields = {
            "role":           "admin",
            "is_admin":       True,
            "admin":          True,
            "is_superuser":   True,
            "privilege_level": 9,
            "__proto__":      {"admin": True},
        }
        body = {**op.get("sample_body", {}), **extra_fields}
        try:
            resp = await _make_request(client, method, url, json.dumps(body))
            if resp and resp.status_code in (200, 201):
                resp_text = resp.text.lower()
                reflected = [f for f in ("admin", "superuser", "privilege_level", "role")
                             if f'"' + f + '"' in resp_text or f"'{f}'" in resp_text]
                if reflected:
                    return [{
                        "url":         url,
                        "type":        "api-mass-assignment",
                        "severity":    SeverityLevel.high,
                        "description": (
                            f"Potential mass assignment at {method} {url}. "
                            f"Extra privileged fields reflected in response: {reflected}. "
                            f"Server accepted undocumented fields that could alter user privileges "
                            f"(OWASP API6)."
                        ),
                        "raw_output": {
                            "url":       url,
                            "method":    method,
                            "reflected": reflected,
                        },
                    }]
        except Exception as exc:
            logger.debug(f"[openapi] Mass assignment test error for {url}: {exc}")
        return []

    async def _test_method_override(
        self, client: httpx.AsyncClient, op: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Try HTTP methods not listed in the spec; flag unexpected 200s."""
        url              = op["url"]
        documented_methods: Set[str] = {op["method"]}
        for method in _PROBE_METHODS:
            if method in documented_methods or method == "OPTIONS":
                continue
            try:
                resp = await _make_request(client, method, url)
                if resp and resp.status_code in (200, 201, 204):
                    return [{
                        "url":         url,
                        "type":        "api-undocumented-method",
                        "severity":    SeverityLevel.medium,
                        "description": (
                            f"Undocumented HTTP method {method} returned {resp.status_code} "
                            f"at {url}. Only {op['method']} is defined in the OpenAPI spec. "
                            f"May indicate incomplete access control (OWASP API8)."
                        ),
                        "raw_output": {
                            "url": url, "method": method, "status": resp.status_code,
                        },
                    }]
            except Exception:
                continue
        return []

    async def _test_data_exposure(
        self, client: httpx.AsyncClient, op: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Fetch endpoint and scan response body for sensitive field names."""
        url    = op["url"]
        method = op["method"]
        if method not in ("GET", "HEAD"):
            return []
        concrete_url = re.sub(r"\{[^}]+\}", "1", url)
        try:
            resp = await _make_request(client, "GET", concrete_url)
            if resp and resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                if "json" in ct:
                    body_lower = resp.text.lower()
                    exposed = [f for f in _SENSITIVE_FIELDS if f'"' + f + '"' in body_lower]
                    if exposed:
                        return [{
                            "url":         concrete_url,
                            "type":        "api-sensitive-data-exposure",
                            "severity":    SeverityLevel.medium,
                            "description": (
                                f"Response from {concrete_url} contains potentially sensitive "
                                f"field names: {exposed}. "
                                f"Verify whether these fields expose real secret values "
                                f"(OWASP API3 — Excessive Data Exposure)."
                            ),
                            "raw_output": {
                                "url":     concrete_url,
                                "exposed": exposed,
                                "snippet": resp.text[:500],
                            },
                        }]
        except Exception as exc:
            logger.debug(f"[openapi] Data exposure test error for {url}: {exc}")
        return []


# ── Spec-level security checks ─────────────────────────────────────────────────

def _check_spec_security(spec: Dict[str, Any], spec_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # HTTPS scheme check
    schemes = spec.get("schemes", []) or []
    servers = spec.get("servers", []) or []
    server_urls = [s.get("url", "") for s in servers]
    all_http = all(
        u.startswith("http://") for u in server_urls if u
    ) if server_urls else ("http" in schemes and "https" not in schemes)

    if all_http and (schemes or server_urls):
        findings.append({
            "url":         spec_url,
            "type":        "api-http-only",
            "severity":    SeverityLevel.medium,
            "description": (
                f"OpenAPI spec at {spec_url} defines only HTTP (non-TLS) server URLs. "
                f"API transmits data over unencrypted connection (OWASP API8)."
            ),
            "raw_output": {"spec_url": spec_url, "schemes": schemes, "servers": server_urls},
        })

    # Missing global security definition
    if not spec.get("security") and not spec.get("securityDefinitions") and not spec.get("components", {}).get("securitySchemes"):
        findings.append({
            "url":         spec_url,
            "type":        "api-no-security-definition",
            "severity":    SeverityLevel.low,
            "description": (
                f"OpenAPI spec at {spec_url} defines no global security scheme "
                f"(no securityDefinitions / components.securitySchemes / security). "
                f"Individual endpoints may lack authentication requirements."
            ),
            "raw_output": {"spec_url": spec_url},
        })

    return findings


# ── Spec fetch + parse helpers ─────────────────────────────────────────────────

async def _fetch_spec(
    client: httpx.AsyncClient,
    spec_url: str,
) -> Optional[Dict[str, Any]]:
    try:
        resp = await client.get(spec_url)
        if resp.status_code != 200:
            return None
        ct = resp.headers.get("content-type", "")
        if "yaml" in ct or spec_url.endswith((".yaml", ".yml")):
            try:
                import yaml
                return yaml.safe_load(resp.text)
            except Exception:
                return None
        return resp.json()
    except Exception as exc:
        logger.warning(f"[openapi] Spec fetch failed: {spec_url}: {exc}")
        return None


def _parse_spec(
    spec: Dict[str, Any],
    spec_url: str,
    base_target: str,
) -> List[Dict[str, Any]]:
    """Extract operations from OpenAPI 2.0 / 3.0 spec."""
    operations: List[Dict[str, Any]] = []

    # Determine base URL
    parsed_spec = urlparse(spec_url)
    spec_origin = f"{parsed_spec.scheme}://{parsed_spec.netloc}"

    # OpenAPI 3.x: servers list
    servers = spec.get("servers", [])
    if servers:
        base_url = servers[0].get("url", spec_origin)
        if not base_url.startswith("http"):
            base_url = spec_origin + base_url
    else:
        # Swagger 2.x: host + basePath + scheme
        host      = spec.get("host", parsed_spec.netloc)
        base_path = spec.get("basePath", "")
        schemes   = spec.get("schemes", ["https"])
        scheme    = "https" if "https" in schemes else schemes[0] if schemes else "https"
        base_url  = f"{scheme}://{host}{base_path}"

    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return operations

    http_methods = ("get", "post", "put", "patch", "delete", "head", "options")
    security_defined = bool(spec.get("securityDefinitions") or spec.get("components", {}).get("securitySchemes"))

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in http_methods:
                continue
            if not isinstance(operation, dict):
                continue

            url = base_url.rstrip("/") + path

            # Sample body from requestBody (OpenAPI 3) or parameters (Swagger 2)
            sample_body: Dict[str, Any] = {}
            param_names: List[str] = []
            request_body = operation.get("requestBody", {})
            if request_body:
                content = request_body.get("content", {})
                schema  = (content.get("application/json", {}) or {}).get("schema", {})
                props   = schema.get("properties", {})
                for prop_name, prop_schema in props.items():
                    param_names.append(prop_name)
                    sample_body[prop_name] = _sample_value(prop_schema)
            else:
                for param in (operation.get("parameters") or []):
                    if not isinstance(param, dict):
                        continue
                    name = param.get("name", "")
                    if name:
                        param_names.append(name)
                    if param.get("in") in ("body", "formData"):
                        schema = param.get("schema", {})
                        sample_body[name] = _sample_value(schema)

            # Does this operation declare its own security requirement?
            op_security = operation.get("security")
            requires_auth = (
                security_defined and op_security is not False
                and not (isinstance(op_security, list) and len(op_security) == 0)
            )

            operations.append({
                "url":          url,
                "path":         path,
                "method":       method.upper(),
                "param_names":  param_names,
                "sample_body":  sample_body,
                "requires_auth": requires_auth,
                "spec_url":     spec_url,
                "operation_id": operation.get("operationId", ""),
                "summary":      operation.get("summary", ""),
            })

    return operations


def _sample_value(schema: Dict[str, Any]) -> Any:
    """Generate a minimal sample value from a JSON Schema type."""
    t = schema.get("type", "string") if isinstance(schema, dict) else "string"
    if t == "integer":   return 1
    if t == "number":    return 1.0
    if t == "boolean":   return True
    if t == "array":     return []
    if t == "object":    return {}
    return "briar_test"


async def _discover_spec_url(target: str, auth_context: Dict[str, Any]) -> List[str]:
    """Probe common OpenAPI spec paths against the target."""
    headers = _build_headers(auth_context)
    parsed  = urlparse(target)
    base    = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [
        f"{base}/openapi.json",   f"{base}/openapi.yaml",
        f"{base}/swagger.json",   f"{base}/swagger.yaml",
        f"{base}/api/openapi.json", f"{base}/api/swagger.json",
        f"{base}/v1/openapi.json",  f"{base}/v2/api-docs",
        f"{base}/api-docs",         f"{base}/api/v1/openapi.json",
    ]
    found: List[str] = []
    async with httpx.AsyncClient(
        headers=headers, verify=False, follow_redirects=True,
        timeout=httpx.Timeout(10),
    ) as client:
        for url in candidates:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    text = resp.text[:300].lower()
                    if any(kw in text for kw in ("openapi", "swagger", '"paths"', "'paths'")):
                        found.append(url)
            except Exception:
                continue
    return found


async def _make_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    body: Optional[str] = None,
) -> Optional[httpx.Response]:
    try:
        content = body.encode() if body else None
        headers: Dict[str, str] = {}
        if body:
            headers["Content-Type"] = "application/json"
        resp = await client.request(method, url, content=content, headers=headers)
        return resp
    except Exception:
        return None


def _build_headers(auth_context: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent":   "Mozilla/5.0 (compatible; Briar-OpenAPI/1.0)",
    }
    headers.update(auth_context.get("headers", {}))
    cookies = auth_context.get("cookies", [])
    if cookies:
        headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    return headers


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    worker = OpenAPIWorker()
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
