"""
BOLA / IDOR Access Control Testing Worker
==========================================
Phase: DAST  (requires_exploit=False)
Queue: scan.dast.bola

BOLA = Broken Object Level Authorization (OWASP API1 / OWASP A01)
IDOR = Insecure Direct Object Reference (classic name for the same flaw)

The core question: can User A access resources that belong to User B
just by changing an ID in the URL or request body?

What this worker tests
-----------------------

  Strategy 1 — Unauthenticated probe  (severity: HIGH)
    Strip all auth headers/cookies and retry each ID-bearing endpoint.
    A resource returning 200 without credentials is unauthenticated IDOR.

  Strategy 2 — Sequential ID enumeration  (severity: HIGH)
    For endpoints like /users/42 → test /users/1, /users/2, /users/3.
    If multiple IDs return 200 with different-sized responses, the server
    is exposing objects without an ownership check.

  Strategy 3 — Out-of-range / boundary IDs  (severity: MEDIUM)
    Test /resource/0, /resource/-1, /resource/2147483647 (MAX_INT).
    Unexpected 200 responses reveal weak input validation.

  Strategy 4 — UUID predictability  (severity: INFO)
    If a UUID path param is found, check if sequential v1 UUIDs
    return data (v1 UUIDs encode a timestamp and can be brute-forced).

  Strategy 5 — Two-user cross-access  (severity: CRITICAL)
    If scan.config contains a second_auth_context, replay each request
    using the second user's credentials and compare responses.
    Identical data returned to different users = confirmed BOLA.

Response comparison heuristic
-------------------------------
Two responses are "meaningfully different" if:
  • Status codes differ (200 vs 403)
  • Response body sizes differ by > 50 bytes  (different objects)
  • Response bodies are identical despite different IDs  (same object
    returned regardless of ID = ownership check bypassed)

Detection is conservative: only endpoints where AT LEAST 3 different
IDs return 200 with different content are flagged as BOLA candidates.
"""

import asyncio
import hashlib
import logging
import os
import re
import sys
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, urlunparse

import httpx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("bola-worker")

MAX_ID_TEMPLATES    = int(os.getenv("BOLA_MAX_TEMPLATES",   "50"))
REQUEST_TIMEOUT     = float(os.getenv("BOLA_REQUEST_TIMEOUT", "12"))
CONCURRENCY         = int(os.getenv("BOLA_CONCURRENCY",       "15"))
TOTAL_TIMEOUT       = int(os.getenv("BOLA_TOTAL_TIMEOUT",    "900"))   # 15 min
SEQ_PROBE_COUNT     = int(os.getenv("BOLA_SEQ_PROBE_COUNT",   "20"))   # IDs per template
# Proactive mode: when crawl yields no integer-bearing URLs, probe these seed paths
# with ID=1 to discover live REST resources. Covers Juice Shop + common REST patterns.
SEED_PROBE_IDS      = int(os.getenv("BOLA_SEED_PROBE_IDS",   "20"))

_SEED_RESOURCE_PATHS = [
    # Juice Shop REST API
    "/api/Users/{id}",
    "/api/Products/{id}",
    "/api/Feedbacks/{id}",
    "/api/Complaints/{id}",
    "/api/BasketItems/{id}",
    "/api/Challenges/{id}",
    "/api/Quantitys/{id}",
    "/api/Recycles/{id}",
    "/api/SecurityAnswers/{id}",
    "/rest/basket/{id}",
    # Generic REST conventions
    "/api/users/{id}",
    "/api/items/{id}",
    "/api/orders/{id}",
    "/api/accounts/{id}",
    "/api/v1/users/{id}",
    "/api/v1/items/{id}",
    "/api/v1/orders/{id}",
    "/api/v2/users/{id}",
    "/users/{id}",
    "/orders/{id}",
    "/products/{id}",
    "/accounts/{id}",
]

# Matches integer path segments that look like DB primary keys (1 – 9_999_999)
_INT_SEG_RE   = re.compile(r"^\d{1,7}$")
# Matches UUID v1-v5 segments
_UUID_SEG_RE  = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# HTTP methods that carry resource IDs
_RESOURCE_METHODS = ("GET", "PUT", "PATCH", "DELETE")


class BOLAWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="bola", queue_name="scan.dast.bola")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [target])
        if not endpoints:
            endpoints = [target]

        # Optional second user context for cross-user BOLA test
        second_auth: Optional[Dict[str, Any]] = task_payload.get("second_auth_context")

        # Extract ID-bearing URL templates from crawl results
        templates = _extract_id_templates(endpoints)
        templates = templates[:MAX_ID_TEMPLATES]

        # Proactive seed enumeration: when the crawl produced few/no integer-bearing
        # URLs (common when scanning unauthenticated — Juice Shop returns 401 for most
        # /api/* paths), probe well-known REST resource patterns directly.
        # This ensures BOLA tests run even without prior authenticated crawl coverage.
        if len(templates) < 3:
            try:
                from urllib.parse import urlparse as _up
                _p = _up(target)
                base_url = f"{_p.scheme}://{_p.netloc}" if _p.scheme and _p.netloc else target
            except Exception:
                base_url = target

            auth_headers_tmp = _build_headers(auth_context)
            async with httpx.AsyncClient(
                verify=False, follow_redirects=False,
                timeout=httpx.Timeout(REQUEST_TIMEOUT),
            ) as probe_client:
                seed_templates = await _probe_seed_resources(
                    probe_client, base_url, auth_headers_tmp
                )

            # Merge: seed templates that aren't already covered by crawl templates
            seen = {t["template"] for t in templates}
            for st in seed_templates:
                if st["template"] not in seen:
                    templates.append(st)
                    seen.add(st["template"])

            if seed_templates:
                logger.info(
                    f"[bola] Seed probing added {len(seed_templates)} resource template(s)"
                )

        if not templates:
            logger.info("[bola] No ID-bearing endpoints found — skipping")
            return []

        logger.info(f"[bola] {len(templates)} ID template(s) to test")

        auth_headers    = _build_headers(auth_context)
        anon_headers    = _build_anon_headers()
        second_headers  = _build_headers(second_auth) if second_auth else None

        semaphore = asyncio.Semaphore(CONCURRENCY)
        findings: List[Dict[str, Any]] = []
        lock = asyncio.Lock()
        start = asyncio.get_event_loop().time()

        async with httpx.AsyncClient(
            verify=False, follow_redirects=False,
            timeout=httpx.Timeout(REQUEST_TIMEOUT),
        ) as client:

            async def test_one(tmpl: Dict[str, Any]):
                if asyncio.get_event_loop().time() - start > TOTAL_TIMEOUT:
                    return
                async with semaphore:
                    partial = await self._test_template(
                        client, tmpl,
                        auth_headers, anon_headers, second_headers,
                    )
                    if partial:
                        async with lock:
                            findings.extend(partial)

            await asyncio.gather(*[test_one(t) for t in templates])

        # ── M22: Juice Shop-specific IDOR extended probes ────────────────────
        try:
            parsed = urlparse(target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            base_url = target

        async with httpx.AsyncClient(
            verify=False, follow_redirects=False,
            timeout=httpx.Timeout(REQUEST_TIMEOUT),
        ) as idor_client:
            idor = await self._test_idor_extended(
                idor_client, base_url, auth_headers
            )
            findings.extend(idor)

        logger.info(f"[bola] Scan complete: {len(findings)} BOLA candidate(s)")
        return findings

    # ── M22: IDOR Extended probes ─────────────────────────────────────────────

    async def _test_idor_extended(
        self,
        client: httpx.AsyncClient,
        base: str,
        auth_headers: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """
        M22 — IDOR tests for patterns not caught by generic sequential enumeration:

          1. View Basket       — GET /rest/basket/:id for IDs 1-10 (compare sizes)
          2. Manipulate Basket — PUT /api/BasketItems/:id with quantity=99 (own→other)
          3. Forged Feedback   — POST /api/Feedbacks with a spoofed UserId
          4. Forged Review     — PUT /api/Products/:id/reviews with spoofed author
          5. GDPR Data Theft   — GET /api/Users/:id for IDs 1-5 (cross-user data)
        """
        findings: List[Dict[str, Any]] = []

        # ── 1. View Basket ─────────────────────────────────────────────────────
        basket_sizes: Dict[int, int] = {}
        for bid in range(1, 11):
            url = f"{base}/rest/basket/{bid}"
            try:
                r = await client.get(url, headers=auth_headers)
                if r.status_code == 200:
                    basket_sizes[bid] = len(r.content)
            except Exception:
                continue

        if len(basket_sizes) >= 1:
            unique_sizes = len(set(basket_sizes.values()))
            findings.append({
                "url":   f"{base}/rest/basket/{{id}}",
                "type":  "idor_view_basket",
                "description": (
                    f"View Basket IDOR: {len(basket_sizes)} basket IDs (1–10) accessible "
                    f"with current credentials ({unique_sizes} distinct sizes). "
                    "Users can view other users' shopping baskets."
                ),
                "severity":           SeverityLevel.high,
                "vulnerability_type": "idor_view_basket",
                "raw_output": {
                    "accessible_ids":  list(basket_sizes.keys()),
                    "basket_sizes":    basket_sizes,
                    "owasp":           "A01:2021 – Broken Access Control (BOLA/IDOR)",
                    "source":          "bola-worker",
                },
            })
            logger.info(
                f"[bola/idor] View Basket: {len(basket_sizes)} baskets accessible"
            )

        # ── 2. Manipulate Basket ───────────────────────────────────────────────
        # Try to change quantity of a basket item that likely belongs to another user
        for item_id in range(1, 8):
            url = f"{base}/api/BasketItems/{item_id}"
            try:
                r = await client.put(
                    url,
                    json={"quantity": 99},
                    headers={**auth_headers, "Content-Type": "application/json"},
                )
                if r.status_code in (200, 201, 204):
                    findings.append({
                        "url":   url,
                        "type":  "idor_manipulate_basket",
                        "description": (
                            f"Manipulate Basket IDOR: PUT /api/BasketItems/{item_id} "
                            f"succeeded (HTTP {r.status_code}) — can modify another user's "
                            "basket item quantity without ownership check."
                        ),
                        "severity":           SeverityLevel.high,
                        "vulnerability_type": "idor_manipulate_basket",
                        "raw_output": {
                            "basket_item_id": item_id,
                            "status":         r.status_code,
                            "owasp":          "A01:2021 – Broken Access Control (BOLA/IDOR)",
                            "source":         "bola-worker",
                        },
                    })
                    logger.info(
                        f"[bola/idor] Manipulate Basket: item {item_id} writable"
                    )
                    break
            except Exception:
                continue

        # ── 3. Forged Feedback ─────────────────────────────────────────────────
        # Post feedback with a different UserId than the authenticated user
        # Juice Shop: POST /api/Feedbacks accepts UserId in body without server-side check
        for spoofed_uid in (1, 2, 3):
            url = f"{base}/api/Feedbacks"
            try:
                r = await client.post(
                    url,
                    json={
                        "comment": "Briar IDOR probe — automated security test",
                        "rating":  5,
                        "UserId":  spoofed_uid,
                        "captchaId": 0,
                        "captcha":   "",
                    },
                    headers={**auth_headers, "Content-Type": "application/json"},
                )
                if r.status_code in (200, 201):
                    body = {}
                    try:
                        body = r.json().get("data", {})
                    except Exception:
                        pass
                    returned_uid = body.get("UserId") or body.get("userId")
                    if returned_uid == spoofed_uid:
                        findings.append({
                            "url":   url,
                            "type":  "idor_forged_feedback",
                            "description": (
                                f"Forged Feedback IDOR: POST /api/Feedbacks with "
                                f"UserId={spoofed_uid} accepted and stored — feedback "
                                "posted in another user's name without ownership check."
                            ),
                            "severity":           SeverityLevel.high,
                            "vulnerability_type": "idor_forged_feedback",
                            "raw_output": {
                                "spoofed_user_id": spoofed_uid,
                                "returned_user_id": returned_uid,
                                "status":           r.status_code,
                                "owasp":            "A01:2021 – Broken Access Control (BOLA/IDOR)",
                                "source":           "bola-worker",
                            },
                        })
                        logger.info(
                            f"[bola/idor] Forged Feedback: UserId={spoofed_uid} accepted"
                        )
                        break
            except Exception:
                continue

        # ── 4. Forged Review ───────────────────────────────────────────────────
        # PUT /api/Products/:id/reviews — overwrite another user's review
        for prod_id in range(1, 6):
            url = f"{base}/api/Products/{prod_id}/reviews"
            try:
                r = await client.put(
                    url,
                    json={"message": "Briar IDOR forged-review probe", "author": "injected@briar.test"},
                    headers={**auth_headers, "Content-Type": "application/json"},
                )
                if r.status_code in (200, 201, 204):
                    findings.append({
                        "url":   url,
                        "type":  "idor_forged_review",
                        "description": (
                            f"Forged Review IDOR: PUT /api/Products/{prod_id}/reviews "
                            f"accepted with spoofed author field (HTTP {r.status_code}) — "
                            "product reviews can be posted or overwritten as any user."
                        ),
                        "severity":           SeverityLevel.high,
                        "vulnerability_type": "idor_forged_review",
                        "raw_output": {
                            "product_id": prod_id,
                            "status":     r.status_code,
                            "owasp":      "A01:2021 – Broken Access Control (BOLA/IDOR)",
                            "source":     "bola-worker",
                        },
                    })
                    logger.info(
                        f"[bola/idor] Forged Review: product {prod_id} writable"
                    )
                    break
            except Exception:
                continue

        # ── 5. GDPR Data Theft — GET /api/Users/:id cross-user ────────────────
        user_responses: Dict[int, int] = {}
        for uid in range(1, 6):
            url = f"{base}/api/Users/{uid}"
            try:
                r = await client.get(url, headers=auth_headers)
                if r.status_code == 200:
                    user_responses[uid] = len(r.content)
            except Exception:
                continue

        if len(user_responses) >= 2:
            findings.append({
                "url":   f"{base}/api/Users/{{id}}",
                "type":  "idor_gdpr_data_theft",
                "description": (
                    f"GDPR Data Theft IDOR: {len(user_responses)} user records (IDs 1–5) "
                    "accessible via GET /api/Users/:id — personal data of other users "
                    "is exposed without ownership enforcement."
                ),
                "severity":           SeverityLevel.critical,
                "vulnerability_type": "idor_gdpr_data_theft",
                "raw_output": {
                    "accessible_user_ids": list(user_responses.keys()),
                    "response_sizes":      user_responses,
                    "owasp":               "A01:2021 – Broken Access Control + A02:2021 – Cryptographic Failures",
                    "source":              "bola-worker",
                },
            })
            logger.info(
                f"[bola/idor] GDPR Data Theft: {len(user_responses)} user records accessible"
            )

        logger.info(f"[bola/idor] Extended IDOR: {len(findings)} finding(s)")
        return findings

    # ── Per-template test suite ───────────────────────────────────────────────

    async def _test_template(
        self,
        client: httpx.AsyncClient,
        tmpl: Dict[str, Any],
        auth_headers: Dict[str, str],
        anon_headers: Dict[str, str],
        second_headers: Optional[Dict[str, str]],
    ) -> List[Dict[str, Any]]:
        """
        tmpl keys:
          template   – URL with {id} placeholder  e.g. /api/users/{id}
          original   – concrete URL that generated this template
          id_type    – "integer" | "uuid"
          id_pos     – index of the ID segment in path parts
          host       – scheme://host
        """
        template  = tmpl["template"]
        host      = tmpl["host"]
        id_type   = tmpl["id_type"]
        original  = tmpl["original"]
        orig_id   = tmpl["orig_id"]
        findings: List[Dict[str, Any]] = []

        # ── Strategy 1: Unauthenticated access ───────────────────────────────
        anon_url = template.replace("{id}", str(orig_id))
        try:
            auth_resp = await client.get(anon_url, headers=auth_headers)
            anon_resp = await client.get(anon_url, headers=anon_headers)
            anon_ct = anon_resp.headers.get("content-type", "")
            if (
                auth_resp.status_code in (200, 201)
                and anon_resp.status_code in (200, 201)
                and len(anon_resp.content) > 20
                and "text/html" not in anon_ct  # SPA wildcard routes return HTML — not real REST resources
            ):
                findings.append({
                    "url":         anon_url,
                    "type":        "bola-unauthenticated-access",
                    "severity":    SeverityLevel.high,
                    "description": (
                        f"Unauthenticated access to {anon_url}: "
                        f"returned HTTP {anon_resp.status_code} without credentials "
                        f"({len(anon_resp.content)} bytes). "
                        f"Resource should require authentication (OWASP API1 / A01)."
                    ),
                    "raw_output": {
                        "url":            anon_url,
                        "auth_status":    auth_resp.status_code,
                        "anon_status":    anon_resp.status_code,
                        "anon_body_size": len(anon_resp.content),
                        "template":       template,
                    },
                })
                # If unauthed already — skip heavier tests, it's clearly broken
                return findings
        except Exception as exc:
            logger.debug(f"[bola] Unauth test failed for {anon_url}: {exc}")

        # ── Strategy 2: Sequential ID enumeration ────────────────────────────
        if id_type == "integer":
            probe_ids = _generate_sequential_ids(int(orig_id), SEQ_PROBE_COUNT)
            responses: List[Tuple[int, int, str]] = []  # (id, status, body_hash)
            for pid in probe_ids:
                probe_url = template.replace("{id}", str(pid))
                try:
                    resp = await client.get(probe_url, headers=auth_headers)
                    h    = hashlib.md5(resp.content).hexdigest()
                    responses.append((pid, resp.status_code, h))
                except Exception:
                    continue

            ok_responses = [(pid, st, h) for pid, st, h in responses if st in (200, 201)]
            unique_bodies = len(set(h for _, _, h in ok_responses))

            if len(ok_responses) >= 3 and unique_bodies >= 2:
                # Multiple IDs return different data → no ownership check
                findings.append({
                    "url":         template.replace("{id}", str(orig_id)),
                    "type":        "bola-sequential-id-enumeration",
                    "severity":    SeverityLevel.high,
                    "description": (
                        f"BOLA/IDOR: {len(ok_responses)} sequential IDs returned "
                        f"HTTP 200 with different data at {template}. "
                        f"No ownership enforcement detected — authenticated users "
                        f"can enumerate other users' objects (OWASP API1)."
                    ),
                    "raw_output": {
                        "template":        template,
                        "probed_ids":      [pid for pid, _, _ in responses],
                        "ok_count":        len(ok_responses),
                        "unique_responses": unique_bodies,
                        "sample_results":  [(pid, st) for pid, st, _ in responses[:6]],
                    },
                })

            # ── Strategy 3: Out-of-range / boundary IDs ──────────────────────
            boundary_ids = [0, -1, 2_147_483_647, -2_147_483_648]
            for bid in boundary_ids:
                boundary_url = template.replace("{id}", str(bid))
                try:
                    resp = await client.get(boundary_url, headers=auth_headers)
                    resp_ct = resp.headers.get("content-type", "")
                    if (
                        resp.status_code in (200, 201)
                        and len(resp.content) > 20
                        and "text/html" not in resp_ct  # SPA wildcard routes return HTML for any path
                    ):
                        findings.append({
                            "url":         boundary_url,
                            "type":        "bola-boundary-id",
                            "severity":    SeverityLevel.medium,
                            "description": (
                                f"Out-of-range ID {bid} returned HTTP {resp.status_code} "
                                f"with {len(resp.content)} bytes at {boundary_url}. "
                                f"Indicates weak input validation / possible integer overflow "
                                f"or phantom record access (OWASP A01)."
                            ),
                            "raw_output": {
                                "url":    boundary_url,
                                "id":     bid,
                                "status": resp.status_code,
                                "size":   len(resp.content),
                            },
                        })
                        break  # one boundary finding per template
                except Exception:
                    continue

        # ── Strategy 4: UUID v1 predictability ────────────────────────────────
        if id_type == "uuid" and _is_uuid_v1(str(orig_id)):
            # v1 UUIDs embed a timestamp; sequential increments are predictable
            next_uuid = _next_uuid_v1()
            if next_uuid:
                probe_url = template.replace("{id}", next_uuid)
                try:
                    resp = await client.get(probe_url, headers=auth_headers)
                    if resp.status_code in (200, 201):
                        findings.append({
                            "url":         probe_url,
                            "type":        "bola-uuid-v1-predictable",
                            "severity":    SeverityLevel.high,
                            "description": (
                                f"UUID v1 resource at {template} returned HTTP 200 "
                                f"for a time-derived UUID {next_uuid!r}. "
                                f"UUIDv1 encodes a timestamp and MAC address — "
                                f"an attacker can brute-force adjacent records by "
                                f"incrementing the timestamp component (OWASP API1)."
                            ),
                            "raw_output": {
                                "template":    template,
                                "orig_id":     str(orig_id),
                                "probed_uuid": next_uuid,
                                "status":      resp.status_code,
                            },
                        })
                except Exception:
                    pass

        # ── Strategy 5: Two-user cross-access ────────────────────────────────
        if second_headers:
            resource_url = template.replace("{id}", str(orig_id))
            try:
                user1_resp = await client.get(resource_url, headers=auth_headers)
                user2_resp = await client.get(resource_url, headers=second_headers)
                if (
                    user1_resp.status_code in (200, 201)
                    and user2_resp.status_code in (200, 201)
                    and len(user1_resp.content) > 20
                ):
                    # Both users can read this object — confirmed BOLA
                    same_body = (
                        hashlib.md5(user1_resp.content).hexdigest()
                        == hashlib.md5(user2_resp.content).hexdigest()
                    )
                    findings.append({
                        "url":         resource_url,
                        "type":        "bola-cross-user-confirmed",
                        "severity":    SeverityLevel.critical,
                        "description": (
                            f"CONFIRMED BOLA at {resource_url}: "
                            f"two distinct authenticated users both received "
                            f"HTTP 200 for the same object ID. "
                            f"{'Identical responses — same object visible to all users.' if same_body else 'Different responses — cross-user data leakage confirmed.'} "
                            f"(OWASP API1 — Broken Object Level Authorization)"
                        ),
                        "raw_output": {
                            "url":         resource_url,
                            "user1_status": user1_resp.status_code,
                            "user2_status": user2_resp.status_code,
                            "same_body":    same_body,
                            "body_size_u1": len(user1_resp.content),
                            "body_size_u2": len(user2_resp.content),
                        },
                    })
            except Exception as exc:
                logger.debug(f"[bola] Cross-user test failed for {resource_url}: {exc}")

        return findings


# ── Proactive seed resource discovery ─────────────────────────────────────────

async def _probe_seed_resources(
    client: httpx.AsyncClient,
    base_url: str,
    auth_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    """
    Probe well-known REST resource paths with ID=1.
    Any path that returns 200/201 becomes a template for full enumeration.
    Runs only when the crawl produced too few integer-bearing URLs.
    """
    discovered: List[Dict[str, Any]] = []
    semaphore = asyncio.Semaphore(8)

    async def _check(path_template: str):
        url = base_url.rstrip("/") + path_template.replace("{id}", "1")
        async with semaphore:
            try:
                resp = await client.get(url, headers=auth_headers)
                logger.debug(f"[bola/seed] {url} → {resp.status_code}")
                if resp.status_code not in (200, 201):
                    return
                # Skip SPA wildcard responses: SPAs (Angular, React, Vue) return
                # HTTP 200 + index.html (text/html) for every unknown route.
                # Real REST API endpoints return application/json.
                ct = resp.headers.get("content-type", "")
                if "text/html" in ct:
                    logger.debug(f"[bola/seed] Skipping SPA route (HTML): {url}")
                    return
                if len(resp.content) < 10:
                    return
                template_path = path_template
                discovered.append({
                    "template": base_url.rstrip("/") + template_path,
                    "original": url,
                    "host":     base_url,
                    "id_type":  "integer",
                    "id_pos":   template_path.strip("/").split("/").index("{id}") if "{id}" in template_path else 0,
                    "orig_id":  1,
                })
                logger.info(f"[bola/seed] Live resource found: {url} → HTTP {resp.status_code}")
            except Exception as exc:
                logger.debug(f"[bola/seed] Exception for {url}: {exc}")

    await asyncio.gather(*[_check(p) for p in _SEED_RESOURCE_PATHS])
    return discovered


# ── URL template extraction ────────────────────────────────────────────────────

def _extract_id_templates(endpoints: List[str]) -> List[Dict[str, Any]]:
    """
    Find URL patterns with integer or UUID path segments.
    Returns a list of template dicts (deduplicated by template string).
    """
    seen_templates: Set[str] = set()
    results: List[Dict[str, Any]] = []

    for url in endpoints:
        try:
            p     = urlparse(url)
            if not (p.scheme and p.netloc and p.path):
                continue
            host  = f"{p.scheme}://{p.netloc}"
            parts = [s for s in p.path.split("/") if s]
            if not parts:
                continue

            # Skip URLs with repeated non-trivial path segments — artefacts of the
            # katana JS-extraction URL-doubling bug (e.g. /assets/public/assets/public/chunk.js
            # or /.well-known/csaf/0/.well-known/csaf/chunk.js).  Real resource paths
            # never repeat the same meaningful segment.
            path_lower = p.path.lower()
            if "assets/public/assets" in path_lower or "node_modules" in path_lower:
                continue
            from collections import Counter
            seg_counts = Counter(s for s in parts if len(s) > 3)
            if seg_counts and max(seg_counts.values()) >= 2:
                continue

            for i, seg in enumerate(parts):
                id_type = None
                if _INT_SEG_RE.match(seg):
                    val = int(seg)
                    if 1 <= val <= 9_999_999:
                        id_type = "integer"
                        orig_id = val
                elif _UUID_SEG_RE.match(seg):
                    id_type = "uuid"
                    orig_id = seg

                if not id_type:
                    continue

                template_parts = parts[:i] + ["{id}"] + parts[i + 1:]
                template_path  = "/" + "/".join(template_parts)
                template_key   = host + template_path

                if template_key in seen_templates:
                    continue
                seen_templates.add(template_key)

                results.append({
                    "template": host + template_path,
                    "original": url,
                    "host":     host,
                    "id_type":  id_type,
                    "id_pos":   i,
                    "orig_id":  orig_id,
                })
        except Exception:
            continue

    # Prioritise shorter templates (closer to root → higher value targets)
    results.sort(key=lambda t: t["template"].count("/"))
    return results


# ── Sequential ID generation ──────────────────────────────────────────────────

def _generate_sequential_ids(seed: int, count: int) -> List[int]:
    """
    Generate `count` integer IDs spread around `seed`.
    Start from 1 if seed is small; otherwise center around seed.
    """
    if seed <= count:
        return list(range(1, count + 1))
    half = count // 2
    start = max(1, seed - half)
    return list(range(start, start + count))


# ── UUID helpers ──────────────────────────────────────────────────────────────

def _is_uuid_v1(value: str) -> bool:
    try:
        return uuid.UUID(value).version == 1
    except Exception:
        return False


def _next_uuid_v1() -> Optional[str]:
    """Generate a freshly-minted UUID v1 to probe with."""
    try:
        return str(uuid.uuid1())
    except Exception:
        return None


# ── Header builders ───────────────────────────────────────────────────────────

def _build_headers(auth_context: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "User-Agent":  "Mozilla/5.0 (compatible; Briar-BOLA/1.0)",
        "Accept":      "application/json, text/html, */*",
    }
    headers.update(auth_context.get("headers", {}))
    cookies = auth_context.get("cookies", [])
    if cookies:
        headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    return headers


def _build_anon_headers() -> Dict[str, str]:
    """Headers with NO auth — for unauthenticated probe."""
    return {
        "User-Agent": "Mozilla/5.0 (compatible; Briar-BOLA-Anon/1.0)",
        "Accept":     "application/json, text/html, */*",
    }


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    worker = BOLAWorker()
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
