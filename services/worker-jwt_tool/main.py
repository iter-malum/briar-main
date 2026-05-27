"""
JWT Tool Security Worker
=========================
Phase: DAST (non-exploitative — requires_exploit=False)
Queue: scan.dast.jwt_tool

Triggered by: finding_router when inspector emits jwt_found

What this worker does
---------------------
jwt_tool runs a comprehensive battery of JWT security tests against a live
application.  It does NOT require exploit_enabled because:
  - Algorithm confusion (RS256 → HS256) is a *verification* of misconfiguration
  - "none" algorithm acceptance is purely a logic flaw — no data is destroyed
  - Weak-secret cracking uses offline wordlist — no active exploitation

Attack categories tested (jwt_tool -M pb  "playbook" mode)
-----------------------------------------------------------
  1. None algorithm ("alg":"none") — server accepts unsigned tokens
  2. Algorithm confusion — RS256 key used as HS256 HMAC secret
  3. Null signature — empty signature bytes accepted
  4. JWKS injection — `kid` / `jku` / `x5u` header injection
  5. Embedded JWK — attacker-controlled public key in token header
  6. SQL injection in JWT claims (user_id, sub, etc.)
  7. Weak secret brute-force (offline, using built-in wordlist)

Inputs (from finding_router payload)
--------------------------------------
  inject_payload   – the JWT token string itself (inspector stores in raw_output)
  target           – URL to replay the forged tokens against
  inject_method    – HTTP method to use for replay
  inject_param     – header name or cookie that carries the JWT (for replay)

JWT detection in inspector
--------------------------
The inspector emits jwt_found when it observes a JWT-format token in:
  - Authorization: Bearer <JWT> request header (from auth_context)
  - Set-Cookie response header containing a JWT-format value
  - Response body containing a JWT at a JSON key like "token", "access_token"
"""

import asyncio
import json
import logging
import os
import re
import sys
import tempfile
from typing import Any, Dict, List, Optional

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("jwt_tool-worker")

JWT_TOOL_BIN    = os.getenv("JWT_TOOL_BIN",    "/opt/jwt_tool/jwt_tool.py")
PER_JWT_TIMEOUT = int(os.getenv("JWT_TOOL_TIMEOUT", "180"))    # 3 min per token
TOTAL_TIMEOUT   = int(os.getenv("JWT_TOOL_TOTAL_TIMEOUT", "900"))  # 15 min total
WORDLIST        = os.getenv(
    "JWT_TOOL_WORDLIST",
    "/opt/jwt_tool/jwt-common.txt",
)

# Matches a valid JWT: header.payload.signature (all base64url segments)
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
    re.ASCII,
)

# ── jwt_tool output patterns ─────────────────────────────────────────────────

_EXPLOIT_RE = re.compile(
    r"EXPLOIT!!!|STATUS: EXPLOIT|Attack worked!",
    re.IGNORECASE,
)
_TEST_RE = re.compile(
    r"\[\+\]\s+Test:\s+(.+)",
)
_STATUS_RE = re.compile(
    r"STATUS:\s+(\S+)",
    re.IGNORECASE,
)
_FORGED_RE = re.compile(
    r"Injecting.+?\n.+?eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
    re.DOTALL,
)
_CRACKED_RE = re.compile(
    r"(?:Key found|Secret found|Found key|HMAC Secret):\s+(.+)",
    re.IGNORECASE,
)


class JWTToolWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="jwt_tool", queue_name="scan.dast.jwt_tool")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        finding_triggered: bool = task_payload.get("finding_triggered", False)

        # ── Finding-triggered: test the specific JWT found by inspector ────────
        if finding_triggered:
            token         = task_payload.get("inject_payload", "")
            url           = task_payload.get("target") or target
            inject_param  = task_payload.get("inject_param", "Authorization")
            inject_method = task_payload.get("inject_method", "GET").upper()

            if not token or not _JWT_RE.match(token):
                # Fallback: scan auth context for a JWT
                token = _extract_jwt_from_auth(auth_context)

            if not token:
                logger.warning("[jwt_tool] No JWT found in payload or auth_context")
                return []

            logger.info(
                f"[jwt_tool] Testing JWT for {url} "
                f"(token: {token[:40]}…)"
            )
            return await self._test_jwt(token, url, inject_param, inject_method, auth_context)

        # ── Phase-based fallback: scan all jwt_found findings ─────────────────
        scan_id: str = task_payload.get("scan_id", "")
        jwt_findings = await self._get_jwt_findings(scan_id)

        # Also check if auth context itself has a JWT
        auth_jwt = _extract_jwt_from_auth(auth_context)
        if auth_jwt:
            jwt_findings.append({
                "token":  auth_jwt,
                "url":    target,
                "param":  "Authorization",
                "method": "GET",
            })

        # Deduplicate by token value
        seen_tokens = set()
        unique: List[Dict] = []
        for jf in jwt_findings:
            t = jf.get("token", "")
            if t and t not in seen_tokens:
                seen_tokens.add(t)
                unique.append(jf)

        if not unique:
            logger.info("[jwt_tool] No JWT tokens found — skipping")
            return []

        logger.info(f"[jwt_tool] Testing {len(unique)} unique JWT token(s)")

        results: List[Dict[str, Any]] = []
        start = asyncio.get_event_loop().time()

        for jf in unique:
            if asyncio.get_event_loop().time() - start > TOTAL_TIMEOUT:
                logger.warning("[jwt_tool] Total timeout reached")
                break
            partial = await self._test_jwt(
                jf["token"],
                jf.get("url", target),
                jf.get("param", "Authorization"),
                jf.get("method", "GET"),
                auth_context,
            )
            results.extend(partial)

        logger.info(f"[jwt_tool] Found {len(results)} JWT vulnerability(ies)")
        return results

    async def _get_jwt_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Load jwt_found findings from DB."""
        if not scan_id:
            return []
        try:
            async with self.db_session() as session:
                from shared.models import ScanResultORM
                from sqlalchemy import select
                from uuid import UUID
                stmt = select(ScanResultORM).where(
                    ScanResultORM.scan_id == UUID(scan_id),
                    ScanResultORM.vulnerability_type == "jwt_found",
                )
                rows = await session.execute(stmt)
                findings = rows.scalars().all()
                result = []
                for f in findings:
                    raw = f.raw_output or {}
                    token = raw.get("token") or raw.get("jwt") or ""
                    if token and _JWT_RE.match(token):
                        result.append({
                            "token":  token,
                            "url":    f.url or "",
                            "param":  raw.get("param", "Authorization"),
                            "method": raw.get("method", "GET"),
                        })
                return result
        except Exception as exc:
            logger.warning(f"[jwt_tool] DB query failed: {exc}")
            return []

    async def _test_jwt(
        self,
        token: str,
        url: str,
        inject_param: str,
        method: str,
        auth_context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Run jwt_tool playbook against a single token + replay URL.

        jwt_tool -M pb runs the full attack playbook:
          none algorithm, algorithm confusion, null signature,
          kid/jku/x5u injection, embedded JWK, and secret cracking.
        """
        work_dir = "/tmp/jwt_tool"
        os.makedirs(work_dir, exist_ok=True)

        # Determine whether the param is a header or a cookie
        is_cookie     = inject_param.lower() not in ("authorization", "auth", "bearer")
        param_is_auth = inject_param.lower() in ("authorization", "bearer")

        # jwt_tool requires a targetted URL for replay (-t) so it can send the
        # forged tokens and check whether the server accepts them.
        cmd = [
            "python3", JWT_TOOL_BIN,
            token,
            "-M", "pb",          # Full playbook
            "-t", url,
            "-np",               # No progress spinner (cleaner output)
        ]

        # Specify how to inject the token into the request
        if param_is_auth:
            cmd.extend(["-rh", f"Authorization: Bearer {token}"])
        elif is_cookie:
            cmd.extend(["-rc", f"{inject_param}={token}"])
        else:
            cmd.extend(["-rh", f"{inject_param}: {token}"])

        # Use the request method
        if method.upper() == "POST":
            cmd.extend(["-pd", ""])  # empty POST data (jwt_tool will inject token)

        # Brute-force weak HMAC secret if wordlist exists
        if os.path.exists(WORDLIST):
            cmd.extend(["-C", "-d", WORDLIST])

        # Propagate existing auth headers (for multi-step auth flows)
        for key, value in auth_context.get("headers", {}).items():
            if key.lower() not in ("authorization",):  # jwt_tool handles auth itself
                cmd.extend(["-rh", f"{key}: {value}"])

        cookies = auth_context.get("cookies", [])
        if cookies:
            for c in cookies:
                cmd.extend(["-rc", f"{c['name']}={c['value']}"])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
            )
            try:
                stdout_data, _ = await asyncio.wait_for(
                    process.communicate(), timeout=PER_JWT_TIMEOUT
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning(f"[jwt_tool] Timed out on {url}")
                return []

            output = stdout_data.decode("utf-8", errors="ignore")
            logger.debug(f"[jwt_tool] Output length: {len(output)} chars")
            return _parse_jwt_tool_output(output, token, url, inject_param)

        except FileNotFoundError:
            logger.error(f"[jwt_tool] Binary not found: {JWT_TOOL_BIN}")
            return []
        except Exception as exc:
            logger.error(f"[jwt_tool] Error on {url}: {exc}", exc_info=True)
            return []


# ── Output parser ─────────────────────────────────────────────────────────────

def _parse_jwt_tool_output(
    output: str,
    token: str,
    url: str,
    param: str,
) -> List[Dict[str, Any]]:
    """
    Parse jwt_tool playbook output.

    jwt_tool -M pb prints a table of tests with statuses like:
      [+] Test: Algorithm confusion using Public Key
      [+] Injecting...
      STATUS: EXPLOIT!!! Attempted algorithm confusion attack

      [+] Test: "none" Algorithm
      STATUS: EXPLOIT!!! Server accepted unsigned token
    """
    results: List[Dict[str, Any]] = []

    # Walk through test blocks
    current_test = None
    for line in output.splitlines():
        line = line.strip()

        m = _TEST_RE.match(line)
        if m:
            current_test = m.group(1).strip()
            continue

        if _EXPLOIT_RE.search(line) and current_test:
            severity = _vuln_severity(current_test)
            description = _vuln_description(current_test, url, param)
            results.append({
                "url":         url,
                "type":        _vuln_type(current_test),
                "description": description,
                "severity":    severity,
                "raw_output": {
                    "url":        url,
                    "param":      param,
                    "test_name":  current_test,
                    "token":      token[:80] + "…" if len(token) > 80 else token,
                    "raw_line":   line[:300],
                },
            })
            current_test = None  # reset so we don't double-report

    # Cracked secret is reported separately
    m = _CRACKED_RE.search(output)
    if m:
        secret = m.group(1).strip()
        results.append({
            "url":         url,
            "type":        "jwt-weak-secret",
            "description": (
                f"JWT HMAC secret cracked via dictionary attack: {secret!r}. "
                f"Attacker can forge arbitrary tokens for any user."
            ),
            "severity":    SeverityLevel.critical,
            "raw_output": {
                "url":    url,
                "param":  param,
                "secret": secret,
                "token":  token[:80] + "…" if len(token) > 80 else token,
            },
        })

    if results:
        logger.info(f"[jwt_tool] {len(results)} vulnerability(ies) confirmed at {url}")
    return results


def _vuln_type(test_name: str) -> str:
    """Map jwt_tool test name to a canonical vulnerability type."""
    t = test_name.lower()
    if "none" in t:
        return "jwt-none-algorithm"
    if "confusion" in t or "algorithm" in t:
        return "jwt-algorithm-confusion"
    if "null" in t or "empty signature" in t:
        return "jwt-null-signature"
    if "kid" in t or "jku" in t or "x5u" in t:
        return "jwt-header-injection"
    if "jwk" in t or "embedded" in t:
        return "jwt-embedded-jwk"
    if "sql" in t:
        return "jwt-sqli-in-claims"
    return "jwt-vulnerability"


def _vuln_severity(test_name: str) -> SeverityLevel:
    t = test_name.lower()
    # Authentication bypass = critical
    if any(k in t for k in ("none", "confusion", "null", "jwk", "embedded")):
        return SeverityLevel.critical
    if any(k in t for k in ("kid", "jku", "x5u", "sql")):
        return SeverityLevel.high
    return SeverityLevel.medium


def _vuln_description(test_name: str, url: str, param: str) -> str:
    t = test_name.lower()
    base = f"JWT vulnerability confirmed at {url} (token in {param!r}). "
    if "none" in t:
        return base + (
            "Server accepts tokens with alg='none' — no signature verification. "
            "Attacker can forge tokens for any user without knowing the secret."
        )
    if "confusion" in t:
        return base + (
            "Algorithm confusion: RS256 public key accepted as HS256 HMAC secret. "
            "Attacker can sign arbitrary tokens using the public key."
        )
    if "null" in t or "empty signature" in t:
        return base + (
            "Server accepts tokens with an empty/null signature — signature not validated."
        )
    if "kid" in t:
        return base + (
            "JWT 'kid' header parameter injection: attacker controls key lookup path."
        )
    if "jku" in t or "x5u" in t:
        return base + (
            "JWT 'jku'/'x5u' header injection: server fetches attacker-controlled JWKS URL."
        )
    if "embedded" in t or "jwk" in t:
        return base + (
            "Server accepts embedded JWK public key from token header — "
            "attacker supplies their own key."
        )
    return base + f"Test: {test_name}."


# ── Auth context JWT extractor ─────────────────────────────────────────────────

def _extract_jwt_from_auth(auth_context: Dict[str, Any]) -> str:
    """
    Find a JWT token in the current auth_context.
    Checks: Authorization Bearer header, cookies with JWT-format values.
    """
    headers = auth_context.get("headers", {})
    # Authorization: Bearer <JWT>
    auth_header = headers.get("Authorization") or headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if _JWT_RE.match(token):
            return token

    # Cookies
    for c in auth_context.get("cookies", []):
        val = c.get("value", "")
        if _JWT_RE.match(val):
            return val

    return ""


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    worker = JWTToolWorker()
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
