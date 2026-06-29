"""
Playwright DOM XSS Worker
==========================
Phase: DAST (non-exploitative)
Queue: scan.dast.playwright

Why this worker exists
-----------------------
HTTP-only scanners (dalfox, ZAP, Inspector) test server HTTP responses for
reflected XSS.  DOM-based XSS happens entirely in the browser:

  1. User visits /#/search?q=<payload>
  2. Angular reads the hash fragment via window.location (no HTTP request)
  3. Angular passes the value to [innerHTML] / document.write / eval
  4. XSS executes — the HTTP response body is untouched

Standard HTTP scanners will never see this because the payload never reaches
the server.  Only a real browser can detect it.

What this worker does
----------------------
  1. Launches a headless Chromium via Playwright
  2. Overrides window.alert / confirm / prompt to catch classic payloads
  3. Tests a set of Angular SPA seed routes known to accept user input
     (search, product IDs, tracking tokens, etc.)
  4. Also tests any crawled URL that has querystring parameters
  5. Reports dom_xss findings for each confirmed trigger
"""

import asyncio
import logging
import os
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx as _httpx
from playwright.async_api import (
    async_playwright,
    Dialog,
    BrowserContext,
)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("playwright-worker")

CONCURRENCY        = int(os.getenv("PLAYWRIGHT_XSS_CONCURRENCY", "2"))
PAGE_TIMEOUT_MS    = int(os.getenv("PLAYWRIGHT_PAGE_TIMEOUT",    "10000"))  # 10 s
WAIT_RENDER_MS     = int(os.getenv("PLAYWRIGHT_WAIT_RENDER",     "3000"))   # 3 s for Angular
MAX_PARAM_URLS     = int(os.getenv("PLAYWRIGHT_MAX_PARAM_URLS",  "40"))
TOTAL_TIMEOUT_S    = int(os.getenv("PLAYWRIGHT_TOTAL_TIMEOUT",   "900"))    # 15 min
HTTP_TIMEOUT       = float(os.getenv("PLAYWRIGHT_HTTP_TIMEOUT",  "8"))

# ── XSS payloads ─────────────────────────────────────────────────────────────
#
# These trigger window.alert() so our dialog handler fires.
# The payload list is kept short — we stop on first hit per URL.

_XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(2)>",
    "<svg onload=alert(3)>",
    "<iframe src=javascript:alert(4)>",
    "\">'><img src=x onerror=alert(5)>",
    "'><svg onload=alert(6)>",
    "<details open ontoggle=alert(7)>",
    "<body onload=alert(8)>",
    # URL-context DOM sinks: location.href = <input>, open(<input>)
    "javascript:alert(9)",
    "data:text/html,<script>alert(10)</script>",
]

# ── Angular SPA seed routes ───────────────────────────────────────────────────
#
# These Angular hash-fragment routes accept user input that may be passed
# directly to a DOM sink.  The HTTP response is always the same (index.html);
# only the browser-rendered DOM changes based on the hash.
#
# Format: (path_suffix_with_param, human_description)
# The {payload} placeholder is replaced during testing.

_ANGULAR_SEED_ROUTES: List[Tuple[str, str]] = [
    # Juice Shop: search term in /#/search?q= is reflected in the DOM
    ("/#/search?q={payload}",              "Angular search (q param)"),
    # Juice Shop: product details route — id param may be reflected
    ("/#/product/{payload}",               "Angular product ID route"),
    # Juice Shop: order tracking — id reflected in confirmation message
    ("/#/track-result?id={payload}",       "Angular order tracking ID"),
    # Common Angular SPA patterns in other apps
    ("/#/category/{payload}",              "Angular category route"),
    ("/#/page/{payload}",                  "Angular page route"),
    ("/?q={payload}",                      "Root search q param"),
    ("/?search={payload}",                 "Root search param"),
    ("/?query={payload}",                  "Root query param"),
    ("/?id={payload}",                     "Root id param"),
    ("/?redirect={payload}",               "Root redirect param"),
    ("/?next={payload}",                   "Root next param"),
    ("/?url={payload}",                    "Root url param"),
    ("/?token={payload}",                  "Root token param"),
    ("/?name={payload}",                   "Root name param"),
    ("/?message={payload}",                "Root message param"),
]

# ── Stored XSS patterns ───────────────────────────────────────────────────────
#
# Each pattern: POST canary to a storage endpoint, then visit the render page
# with Playwright and check whether the stored payload triggers a dialog.
#
# {id}     — replaced with each entity ID from the `ids` list
# {payload} — replaced with _STORED_XSS_PAYLOAD

_STORED_XSS_PAYLOAD = '<iframe src="javascript:alert(1)">'

_STORED_XSS_PATTERNS: List[Dict[str, Any]] = [
    # ── Juice Shop: product reviews ──────────────────────────────────────────
    # POST /api/Products/:id/reviews {"message": "<payload>"}
    # Rendered at /#/product/:id — Angular uses [innerHTML] binding
    {
        "desc":        "product review (Juice Shop)",
        "post_path":   "/api/Products/{id}/reviews",
        "post_body":   {"message": "{payload}"},
        "render_path": "/#/product/{id}",
        "ids":         list(range(1, 8)),
        "method":      "POST",
    },
    # ── Juice Shop: customer feedback ────────────────────────────────────────
    # Visible at /#/administration (admin session required to see it rendered)
    {
        "desc":        "customer feedback (Juice Shop)",
        "post_path":   "/api/Feedbacks",
        "post_body":   {"comment": "{payload}", "rating": 5,
                        "captchaId": 0, "captcha": ""},
        "render_path": "/#/administration",
        "ids":         [None],
        "method":      "POST",
    },
    # ── Juice Shop: user profile username field (stored XSS via username) ───────
    # PUT /rest/user/whoami requires auth; profile rendered at /#/profile
    # Angular {{username}} interpolation in profile page can execute injected JS
    {
        "desc":        "user profile username (Juice Shop)",
        "post_path":   "/rest/users/me",
        "post_body":   {"username": "{payload}"},
        "render_path": "/#/profile",
        "ids":         [None],
        "method":      "PUT",
    },
    # ── Generic patterns for non-Juice-Shop targets ──────────────────────────
    {
        "desc":        "generic /api/comments",
        "post_path":   "/api/comments",
        "post_body":   {"body": "{payload}", "content": "{payload}"},
        "render_path": "/comments",
        "ids":         [None],
        "method":      "POST",
    },
    {
        "desc":        "generic /api/reviews",
        "post_path":   "/api/reviews",
        "post_body":   {"comment": "{payload}", "text": "{payload}", "rating": 5},
        "render_path": "/reviews",
        "ids":         [None],
        "method":      "POST",
    },
]

# ── Helper: inject payload into all query params of a URL ────────────────────

def _inject_all_params(url: str, payload: str) -> str:
    """Return URL with every query param value replaced by payload."""
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    if not qs:
        return url
    new_qs = {k: [payload] for k in qs}
    return urlunparse(p._replace(query=urlencode(new_qs, doseq=True)))


def _base_origin(url: str) -> str:
    """Return scheme://host:port with no trailing slash."""
    p = urlparse(url)
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname}{port}"


_FINDING_DESCRIPTIONS = {
    "dom_xss":    "DOM-based XSS: browser triggered alert with payload",
    "stored_xss": "Stored XSS: injected payload executed when render page was visited",
}

def _make_finding(
    url: str,
    payload: str,
    evidence: str,
    finding_type: str = "dom_xss",
) -> Dict[str, Any]:
    desc = _FINDING_DESCRIPTIONS.get(finding_type, "XSS")
    return {
        "url":              url,
        "type":             finding_type,
        "description":      f"{desc}: {payload!r}",
        "severity":         SeverityLevel.high,
        "vulnerability_type": finding_type,
        "has_params":       True,
        "raw_output": {
            "payload":    payload,
            "evidence":   evidence,
            "source":     "playwright",
            "owasp":      "A03:2021 – Injection",
            "detection":  "dialog-triggered",
        },
    }


class PlaywrightWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="playwright", queue_name="scan.dast.playwright")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [target])
        cookies: List[Dict]  = auth_context.get("cookies", [])
        headers: Dict[str, str] = {
            k: v for k, v in auth_context.get("headers", {}).items()
            if k.lower() != "cookie"
        }

        origin = _base_origin(target)
        results: List[Dict[str, Any]] = []

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                    ],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=headers,
                )
                if cookies:
                    try:
                        pw_cookies = []
                        for c in cookies:
                            if not isinstance(c, dict) or not c.get("name"):
                                continue
                            entry: Dict[str, Any] = {
                                "name":   c["name"],
                                "value":  c.get("value", ""),
                                "domain": c.get("domain", urlparse(origin).hostname),
                                "path":   c.get("path", "/"),
                            }
                            if c.get("httpOnly"):
                                entry["httpOnly"] = True
                            if c.get("secure"):
                                entry["secure"] = True
                            pw_cookies.append(entry)
                        if pw_cookies:
                            await context.add_cookies(pw_cookies)
                    except Exception as e:
                        logger.warning(f"[playwright] Failed to set cookies: {e}")

                try:
                    # ── 1. Test Angular seed routes ───────────────────────────
                    logger.info(
                        f"[playwright] Testing {len(_ANGULAR_SEED_ROUTES)} seed routes "
                        f"on {origin}"
                    )
                    for route_tpl, desc in _ANGULAR_SEED_ROUTES:
                        for payload in _XSS_PAYLOADS:
                            path = route_tpl.replace("{payload}", urllib.parse.quote(payload))
                            url = origin + path
                            hit = await self._test_xss(context, url)
                            if hit:
                                logger.info(
                                    f"[playwright] DOM XSS found: {url!r} — {hit!r}"
                                )
                                results.append(_make_finding(url, payload, hit))
                                break  # first triggering payload per route is enough

                    # ── 2. Test crawled URLs with query params ────────────────
                    param_urls = [
                        ep for ep in endpoints
                        if "?" in ep and ep.startswith(("http://", "https://"))
                    ][:MAX_PARAM_URLS]

                    logger.info(
                        f"[playwright] Testing {len(param_urls)} crawled param URLs"
                    )
                    for base_url in param_urls:
                        for payload in _XSS_PAYLOADS:
                            injected = _inject_all_params(base_url, payload)
                            hit = await self._test_xss(context, injected)
                            if hit:
                                logger.info(
                                    f"[playwright] DOM XSS found: {injected!r} — {hit!r}"
                                )
                                results.append(_make_finding(injected, payload, hit))
                                break

                    # ── 3. Stored XSS probe ───────────────────────────────────
                    stored = await self._probe_stored_xss(
                        context, origin, cookies, headers
                    )
                    results.extend(stored)

                    # ── 4. Redirect chain testing (M19) ───────────────────────
                    redir = await self._test_redirect_chains(context, origin)
                    results.extend(redir)

                    # ── 5. Admin workflow (M20) — only when finding-triggered ─
                    admin_email    = task_payload.get("admin_email")
                    admin_password = task_payload.get("admin_password")
                    admin_login_url = task_payload.get("admin_login_url")
                    if (
                        task_payload.get("finding_type") == "credential_exposure"
                        and admin_email and admin_password
                    ):
                        admin_findings = await self._test_admin_workflow(
                            context, origin, admin_email, admin_password,
                            admin_login_url or (origin + "/rest/user/login"),
                        )
                        results.extend(admin_findings)

                finally:
                    await browser.close()

        except Exception as e:
            logger.error(f"[playwright] Browser error: {e}")

        logger.info(f"[playwright] Done — {len(results)} DOM XSS finding(s)")
        return results

    async def _probe_stored_xss(
        self,
        context: BrowserContext,
        origin: str,
        cookies: List[Dict],
        headers: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """
        POST XSS canary to known storage endpoints, then visit the render page
        with Playwright to check whether the payload was stored and executed.

        Uses a short iframe payload known to trigger alert() when rendered via
        [innerHTML] without Angular DOMSanitizer protection (Juice Shop pattern).
        """
        results: List[Dict[str, Any]] = []
        payload = _STORED_XSS_PAYLOAD

        cookie_header = "; ".join(
            f"{c['name']}={c['value']}" for c in cookies if c.get("name")
        )
        req_headers: Dict[str, str] = {
            **{k: v for k, v in headers.items() if k.lower() != "cookie"},
            "Content-Type": "application/json",
        }
        if cookie_header:
            req_headers["Cookie"] = cookie_header

        logger.info(f"[playwright/stored] Probing {len(_STORED_XSS_PATTERNS)} stored XSS pattern(s)")

        async with _httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=HTTP_TIMEOUT,
        ) as client:
            for pattern in _STORED_XSS_PATTERNS:
                ids = pattern.get("ids") or [None]
                found_this_pattern = False

                for entity_id in ids:
                    if found_this_pattern:
                        break

                    post_path = pattern["post_path"]
                    render_path = pattern["render_path"]
                    if entity_id is not None:
                        post_path = post_path.replace("{id}", str(entity_id))
                        render_path = render_path.replace("{id}", str(entity_id))

                    body = {
                        k: v.replace("{payload}", payload)
                        for k, v in pattern["post_body"].items()
                    }
                    post_url = origin + post_path

                    try:
                        resp = await client.request(
                            pattern.get("method", "POST"),
                            post_url,
                            json=body,
                            headers=req_headers,
                        )
                        # Only continue if endpoint accepted the data
                        if resp.status_code not in (200, 201, 204):
                            logger.debug(
                                f"[playwright/stored] {post_url} → {resp.status_code} skip"
                            )
                            continue
                    except Exception as e:
                        logger.debug(f"[playwright/stored] POST {post_url} failed: {e}")
                        continue

                    render_url = origin + render_path
                    logger.info(
                        f"[playwright/stored] Injected into {post_url}, "
                        f"visiting {render_url}"
                    )
                    hit = await self._test_xss(context, render_url)
                    if hit:
                        logger.info(
                            f"[playwright/stored] Stored XSS confirmed: "
                            f"{pattern['desc']} — {hit!r}"
                        )
                        results.append(
                            _make_finding(render_url, payload, hit, "stored_xss")
                        )
                        found_this_pattern = True

        return results

    # ── M19: Redirect chain testing ───────────────────────────────────────────

    async def _test_redirect_chains(
        self,
        context: BrowserContext,
        origin: str,
    ) -> List[Dict[str, Any]]:
        """
        Test known redirect-capable endpoints via headless Chromium.

        Injects a canary external URL into common redirect params and follows
        the full browser redirect chain (including JS-based meta-redirects and
        Angular router redirects that httpx cannot see).  Reports:
          - open_redirect_confirmed  (high) — browser actually landed on external domain
          - allowlist_bypass          (medium) — redirect to path on allow-listed domain
        """
        findings: List[Dict[str, Any]] = []
        canary_host   = "briar-evil-redirect-canary.example.com"
        canary_url    = f"https://{canary_host}/"
        origin_host   = urlparse(origin).hostname or ""

        redirect_probes = [
            # Juice Shop dedicated redirect endpoint
            f"{origin}/redirect?to={urllib.parse.quote(canary_url)}",
            f"{origin}/redirect?to={urllib.parse.quote('//' + canary_host + '/')}",
            f"{origin}/redirect?to={urllib.parse.quote(canary_url)}&lang=en",
            # Generic params
            f"{origin}?redirect={urllib.parse.quote(canary_url)}",
            f"{origin}?next={urllib.parse.quote(canary_url)}",
            f"{origin}?url={urllib.parse.quote(canary_url)}",
            f"{origin}?to={urllib.parse.quote(canary_url)}",
            f"{origin}?return_to={urllib.parse.quote(canary_url)}",
            # API-style
            f"{origin}/api/redirect?url={urllib.parse.quote(canary_url)}",
            f"{origin}/rest/redirect?to={urllib.parse.quote(canary_url)}",
        ]

        for probe_url in redirect_probes:
            page = await context.new_page()
            final_url: Optional[str] = None
            redirect_chain: List[str] = []

            try:
                # Track every navigation (including JS / meta redirects)
                page.on(
                    "framenavigated",
                    lambda f: redirect_chain.append(f.url) if f.is_main_frame() else None,
                )

                try:
                    await page.goto(
                        probe_url,
                        timeout=PAGE_TIMEOUT_MS,
                        wait_until="domcontentloaded",
                    )
                    await page.wait_for_timeout(1500)
                except Exception:
                    pass

                final_url = page.url

                if final_url and canary_host in final_url:
                    findings.append({
                        "url":   probe_url,
                        "type":  "open_redirect_confirmed",
                        "description": (
                            f"Browser-confirmed open redirect: {probe_url!r} → "
                            f"final URL {final_url!r} (external domain reached)"
                        ),
                        "severity":            SeverityLevel.high,
                        "vulnerability_type":  "open_redirect_confirmed",
                        "has_params":          True,
                        "raw_output": {
                            "probe_url":      probe_url,
                            "final_url":      final_url,
                            "redirect_chain": redirect_chain,
                            "detection":      "playwright-redirect-chain",
                            "owasp":          "A01:2021 – Broken Access Control (Open Redirect)",
                            "source":         "playwright",
                        },
                    })
                    break  # one confirmed redirect per origin is enough

                # Check redirect chain for external hops (allowlist bypass scenario)
                for hop in redirect_chain:
                    hop_host = urlparse(hop).hostname or ""
                    if hop_host and hop_host != origin_host and canary_host not in hop_host:
                        # Intermediate hop to unknown external domain during redirect chain
                        findings.append({
                            "url":   probe_url,
                            "type":  "open_redirect_chain",
                            "description": (
                                f"Redirect chain passes through external domain {hop_host!r}: "
                                f"{probe_url!r} → {hop!r} (intermediate hop)"
                            ),
                            "severity":           SeverityLevel.medium,
                            "vulnerability_type": "open_redirect_chain",
                            "raw_output": {
                                "probe_url":      probe_url,
                                "external_hop":   hop,
                                "redirect_chain": redirect_chain,
                                "owasp":          "A01:2021 – Broken Access Control",
                                "source":         "playwright",
                            },
                        })
                        break

            except Exception as e:
                logger.debug(f"[playwright/redirect] Error on {probe_url}: {e}")
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

        if findings:
            logger.info(
                f"[playwright/redirect] {len(findings)} redirect finding(s) on {origin}"
            )
        return findings

    # ── M20: Admin workflow automation ────────────────────────────────────────

    async def _test_admin_workflow(
        self,
        context: BrowserContext,
        origin: str,
        admin_email: str,
        admin_password: str,
        login_url: str,
    ) -> List[Dict[str, Any]]:
        """
        After valid admin credentials are found (by creds worker):
          1. Authenticate via REST API, inject JWT into browser context
          2. Navigate to /#/administration — confirm admin panel access
          3. Test Five-Star Feedback DELETE (silence negative reviews)
          4. Test Product Tampering (edit name/description via PUT /api/Products/:id)
          5. Test Forged Coupon application via /rest/basket/applyCoupon
        """
        findings: List[Dict[str, Any]] = []

        # ── Step 1: Login and get JWT ─────────────────────────────────────────
        jwt_token: Optional[str] = None
        try:
            async with _httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=HTTP_TIMEOUT
            ) as client:
                resp = await client.post(
                    login_url,
                    json={"email": admin_email, "password": admin_password},
                    headers={"Content-Type": "application/json"},
                )
                data = resp.json() if resp.status_code == 200 else {}
                # Juice Shop: {"authentication": {"token": "...", ...}}
                jwt_token = (
                    data.get("authentication", {}).get("token")
                    or data.get("token")
                    or data.get("access_token")
                    or data.get("accessToken")
                )
        except Exception as e:
            logger.warning(f"[playwright/admin] Login failed for {admin_email}: {e}")
            return []

        if not jwt_token:
            logger.info(f"[playwright/admin] No JWT extracted for {admin_email}")
            return []

        logger.info(
            f"[playwright/admin] JWT obtained for {admin_email}, "
            f"starting admin workflow on {origin}"
        )

        # Set auth header in the browser context for all subsequent requests
        await context.set_extra_http_headers({
            "Authorization": f"Bearer {jwt_token}"
        })

        # ── Step 2: Navigate to /#/administration ─────────────────────────────
        admin_page = await context.new_page()
        admin_accessible = False
        try:
            await admin_page.goto(
                f"{origin}/#/administration",
                timeout=PAGE_TIMEOUT_MS,
                wait_until="load",
            )
            await admin_page.wait_for_timeout(WAIT_RENDER_MS)

            # Juice Shop: admin panel has user/feedback management tables
            content = await admin_page.content()
            if any(kw in content.lower() for kw in (
                "mat-table", "user-management", "feedback", "orderId",
                "administration", "registered users", "all feedback",
            )):
                admin_accessible = True
                findings.append({
                    "url":   f"{origin}/#/administration",
                    "type":  "admin_panel_access",
                    "description": (
                        f"Admin panel at /#/administration is accessible "
                        f"with credentials {admin_email!r} — "
                        "Five-Star Feedback, user management, order details exposed"
                    ),
                    "severity":           SeverityLevel.critical,
                    "vulnerability_type": "admin_panel_access",
                    "has_params":         True,
                    "raw_output": {
                        "admin_email":  admin_email,
                        "admin_url":    f"{origin}/#/administration",
                        "detection":    "playwright-admin-workflow",
                        "owasp":        "A01:2021 – Broken Access Control",
                        "source":       "playwright",
                    },
                })
                logger.info(f"[playwright/admin] /#/administration ACCESSIBLE")
        except Exception as e:
            logger.debug(f"[playwright/admin] admin page error: {e}")
        finally:
            try:
                await admin_page.close()
            except Exception:
                pass

        if not admin_accessible:
            return findings

        # ── Step 3: Five-Star Feedback DELETE ─────────────────────────────────
        try:
            async with _httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=HTTP_TIMEOUT,
                headers={"Authorization": f"Bearer {jwt_token}",
                         "Content-Type": "application/json"},
            ) as client:
                # Get feedback list
                fb_resp = await client.get(f"{origin}/api/Feedbacks")
                if fb_resp.status_code == 200:
                    feedbacks = fb_resp.json().get("data", [])
                    five_star = [f for f in feedbacks if f.get("rating") == 5]
                    one_star  = [f for f in feedbacks if f.get("rating") == 1]

                    # Try to delete a one-star feedback (admins should not be able to do this)
                    for fb in one_star[:2]:
                        del_resp = await client.delete(
                            f"{origin}/api/Feedbacks/{fb['id']}"
                        )
                        if del_resp.status_code in (200, 204):
                            findings.append({
                                "url":   f"{origin}/api/Feedbacks/{fb['id']}",
                                "type":  "five_star_feedback_delete",
                                "description": (
                                    f"Admin can DELETE user feedback (id={fb['id']}) — "
                                    "Five-Star Feedback challenge: silencing 1-star reviews "
                                    "violates data integrity / business logic"
                                ),
                                "severity":           SeverityLevel.high,
                                "vulnerability_type": "five_star_feedback_delete",
                                "raw_output": {
                                    "feedback_id": fb["id"],
                                    "rating":      fb.get("rating"),
                                    "detection":   "playwright-admin-workflow",
                                    "owasp":       "A04:2021 – Insecure Design",
                                    "source":      "playwright",
                                },
                            })
                            logger.info(
                                f"[playwright/admin] Five-Star Feedback DELETE confirmed "
                                f"(feedback_id={fb['id']})"
                            )
                            break

                # ── Step 4: Product Tampering ─────────────────────────────────
                prod_resp = await client.get(f"{origin}/api/Products?offset=0&limit=10")
                if prod_resp.status_code == 200:
                    products = prod_resp.json().get("data", [])
                    if products:
                        prod = products[0]
                        original_name = prod.get("name", "")
                        tamper_name   = original_name + " [BRIAR-TAMPER-TEST]"
                        put_resp = await client.put(
                            f"{origin}/api/Products/{prod['id']}",
                            json={"name": tamper_name},
                        )
                        if put_resp.status_code in (200, 204):
                            # Restore original name
                            await client.put(
                                f"{origin}/api/Products/{prod['id']}",
                                json={"name": original_name},
                            )
                            findings.append({
                                "url":   f"{origin}/api/Products/{prod['id']}",
                                "type":  "product_tampering",
                                "description": (
                                    f"Admin can tamper product data via PUT /api/Products/{prod['id']} — "
                                    "name/description/price modification possible without audit trail"
                                ),
                                "severity":           SeverityLevel.high,
                                "vulnerability_type": "product_tampering",
                                "raw_output": {
                                    "product_id":    prod["id"],
                                    "original_name": original_name,
                                    "detection":     "playwright-admin-workflow",
                                    "owasp":         "A04:2021 – Insecure Design",
                                    "source":        "playwright",
                                },
                            })
                            logger.info(
                                f"[playwright/admin] Product Tampering confirmed "
                                f"(product_id={prod['id']})"
                            )

                # ── Step 5: Forged Coupon ─────────────────────────────────────
                # Try known Juice Shop coupon codes via REST
                known_coupons = ["WMNSDY2019", "ORANGE2020", "SUMMER2020", "FESTIVE", "JUIC3S0P"]
                for coupon in known_coupons:
                    basket_resp = await client.get(f"{origin}/rest/basket/1/coupon/{coupon}")
                    if basket_resp.status_code == 200:
                        findings.append({
                            "url":   f"{origin}/rest/basket/1/coupon/{coupon}",
                            "type":  "forged_coupon",
                            "description": (
                                f"Valid coupon code {coupon!r} accepted — "
                                "coupon code enumeration / forged coupon possible"
                            ),
                            "severity":           SeverityLevel.medium,
                            "vulnerability_type": "forged_coupon",
                            "raw_output": {
                                "coupon":    coupon,
                                "detection": "playwright-admin-workflow",
                                "owasp":     "A04:2021 – Insecure Design",
                                "source":    "playwright",
                            },
                        })
                        logger.info(f"[playwright/admin] Forged Coupon: {coupon!r} accepted")
                        break

        except Exception as e:
            logger.warning(f"[playwright/admin] Admin API tests error: {e}")

        logger.info(
            f"[playwright/admin] Done — {len(findings)} admin workflow finding(s)"
        )
        return findings

    async def _test_xss(self, context: BrowserContext, url: str) -> Optional[str]:
        """
        Load URL in a new browser page, return dialog message if XSS triggered.

        Uses Playwright's dialog event (fires for alert/confirm/prompt in any
        frame, including cross-frame iframes) — most reliable DOM XSS signal.
        Also checks page JS state for workers that call alert via overridden window.
        """
        page = await context.new_page()
        triggered: Optional[str] = None

        async def _on_dialog(dialog: Dialog) -> None:
            nonlocal triggered
            triggered = dialog.message or "triggered"
            logger.debug(f"[playwright] Dialog: {triggered!r} on {url}")
            try:
                await dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", _on_dialog)

        # Inject sentinel into the page before any navigation so dynamically
        # injected script tags from Angular can use it too.
        await page.add_init_script("""
            window.__briar_xss = null;
            const _orig_alert = window.alert;
            window.alert = function(v) {
                window.__briar_xss = String(v);
                _orig_alert && _orig_alert.call(window, v);
            };
        """)

        try:
            await page.goto(url, timeout=PAGE_TIMEOUT_MS, wait_until="load")
            # Give Angular / React / Vue time to hydrate and execute injected scripts
            await page.wait_for_timeout(WAIT_RENDER_MS)

            # Check JS sentinel in case dialog event fired before we could catch it
            if not triggered:
                sentinel = await page.evaluate("window.__briar_xss")
                if sentinel:
                    triggered = f"window.__briar_xss={sentinel!r}"

        except Exception as e:
            logger.debug(f"[playwright] page.goto error ({url}): {e}")
        finally:
            try:
                await page.close()
            except Exception:
                pass

        return triggered


if __name__ == "__main__":
    worker = PlaywrightWorker()
    asyncio.run(worker.start())
