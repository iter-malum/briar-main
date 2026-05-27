"""
CORS Misconfiguration Scanner Worker
======================================
Phase: DAST  (requires_exploit=False)
Queue: scan.dast.cors

What this worker tests
----------------------
Cross-Origin Resource Sharing (CORS) misconfigurations are among the most
common access-control flaws.  A misconfigured CORS policy allows a
malicious website to make credentialed cross-origin requests to the target
and read the response — effectively bypassing the Same-Origin Policy.

This worker probes every discovered endpoint with 7 attack-class Origin
headers and classifies the server's response:

  CRITICAL
    1. Reflected Origin + Credentials
       → Access-Control-Allow-Origin mirrors attacker origin, ACAO-Credentials: true
       → Attacker site can exfiltrate any authenticated response

    2. Null Origin + Credentials
       → ACAO: null, ACAC: true
       → Sandboxed iframe on attacker domain bypasses SOP

  HIGH
    3. Subdomain prefix bypass  (evil.target.com accepted)
       → Weak "startsWith(target)" check; any target subdomain is trusted
       → Subdomain takeover → full read access

    4. Post-domain suffix bypass  (target.com.evil.com accepted)
       → Weak "endsWith(.target.com)" check
       → Attacker registers target.com.evil.com and gains full read access

    5. HTTP downgrade on HTTPS endpoint  (http://target.com accepted)
       → Allows MITM over plain HTTP to steal CORS-carried credentials

  MEDIUM
    6. Wildcard + Credentials  (technically spec-invalid, some servers do it)
       → ACAO: *, ACAC: true

  LOW / INFO
    7. Wildcard without Credentials
       → ACAO: * (acceptable for public APIs, risky for anything auth-gated)

Each test is a single HTTP request with a crafted Origin header.
Responses are scored by (ACAO reflected, ACAC: true, ACRM present).
Only endpoints with a meaningful CORS response are reported.
"""

import asyncio
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
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
logger = logging.getLogger("cors-worker")

MAX_ENDPOINTS   = int(os.getenv("CORS_MAX_ENDPOINTS",   "300"))
REQUEST_TIMEOUT = float(os.getenv("CORS_REQUEST_TIMEOUT", "10"))
CONCURRENCY     = int(os.getenv("CORS_CONCURRENCY",       "20"))
TOTAL_TIMEOUT   = int(os.getenv("CORS_TOTAL_TIMEOUT",    "900"))   # 15 min

# Static assets don't have CORS policies worth testing
_STATIC_EXTS = frozenset({
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf",
})


class CORSWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="cors", queue_name="scan.dast.cors")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [target])
        if not endpoints:
            endpoints = [target]

        # Deduplicate: test each unique path once (ignore query string for CORS)
        seen: Set[str] = set()
        unique: List[str] = []
        for ep in endpoints:
            try:
                p = urlparse(ep)
                ext = os.path.splitext(p.path.lower())[1]
                if ext in _STATIC_EXTS:
                    continue
                key = f"{p.scheme}://{p.netloc}{p.path}"
                if key not in seen:
                    seen.add(key)
                    unique.append(ep)
            except Exception:
                continue

        unique = unique[:MAX_ENDPOINTS]
        logger.info(f"[cors] Testing {len(unique)} unique endpoint(s)")

        # Build probe Origins from the target domain
        target_origins = _build_probe_origins(target)

        semaphore = asyncio.Semaphore(CONCURRENCY)
        findings: List[Dict[str, Any]] = []
        lock = asyncio.Lock()
        start = asyncio.get_event_loop().time()

        headers = _build_headers(auth_context)

        async with httpx.AsyncClient(
            headers=headers,
            verify=False,
            follow_redirects=True,
            timeout=httpx.Timeout(REQUEST_TIMEOUT),
        ) as client:

            async def test_one(url: str):
                if asyncio.get_event_loop().time() - start > TOTAL_TIMEOUT:
                    return
                async with semaphore:
                    partial = await _test_endpoint(client, url, target_origins)
                    if partial:
                        async with lock:
                            findings.extend(partial)

            await asyncio.gather(*[test_one(u) for u in unique])

        logger.info(f"[cors] Scan complete: {len(findings)} CORS issue(s) found")
        return findings


# ── CORS probe logic ───────────────────────────────────────────────────────────

def _build_probe_origins(target: str) -> Dict[str, str]:
    """
    Build the 7 probe Origin values for a given target URL.
    Returns {probe_name: origin_header_value}.
    """
    try:
        p     = urlparse(target)
        host  = p.netloc.split(":")[0]   # strip port
        scheme = p.scheme or "https"
    except Exception:
        host   = target
        scheme = "https"

    return {
        "reflected":       f"https://briar-cors-probe.evil.com",
        "null":            "null",
        "subdomain-pre":   f"https://briar-evil.{host}",
        "subdomain-post":  f"https://{host}.briar-evil.com",
        "http-downgrade":  f"http://{host}",
        "wildcard-creds":  f"https://briar-wildcard.evil.com",   # used to detect * with ACAC
    }


async def _test_endpoint(
    client: httpx.AsyncClient,
    url: str,
    probe_origins: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Run all CORS probes against a single endpoint."""
    findings: List[Dict[str, Any]] = []

    # First probe the endpoint without an Origin to establish baseline
    baseline_has_cors = False
    try:
        baseline = await client.get(url)
        if baseline.headers.get("access-control-allow-origin"):
            baseline_has_cors = True
    except Exception:
        return []

    for probe_name, origin_value in probe_origins.items():
        try:
            resp = await client.get(
                url,
                headers={"Origin": origin_value},
            )
        except Exception:
            continue

        finding = _analyse_cors_response(url, probe_name, origin_value, resp)
        if finding:
            findings.append(finding)
            # Don't repeat findings for the same endpoint once critical is found
            if finding["severity"] == SeverityLevel.critical:
                break

    return findings


def _analyse_cors_response(
    url: str,
    probe_name: str,
    origin_sent: str,
    resp: httpx.Response,
) -> Optional[Dict[str, Any]]:
    """
    Analyse a CORS response.  Return a finding dict or None.

    Decision logic:
      1. ACAO must be non-empty and non-wildcard to be interesting for
         reflected/null/subdomain probes.
      2. ACAC: true dramatically increases severity (credentialed reads).
      3. Wildcard + credentials is a separate (spec-invalid) critical case.
    """
    acao = resp.headers.get("access-control-allow-origin", "").strip()
    acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()
    acrm = resp.headers.get("access-control-allow-methods", "").strip()

    with_credentials = (acac == "true")

    # ── 1. Wildcard + credentials (spec-invalid, some servers allow it) ────────
    if acao == "*" and with_credentials:
        return _make_finding(
            url=url,
            probe=probe_name,
            origin_sent=origin_sent,
            acao=acao,
            with_credentials=True,
            severity=SeverityLevel.critical,
            vuln_type="cors-wildcard-with-credentials",
            description=(
                f"CORS wildcard with credentials enabled at {url}. "
                f"Access-Control-Allow-Origin: * combined with "
                f"Access-Control-Allow-Credentials: true is spec-invalid, "
                f"but accepted by some browsers. Any origin can read "
                f"credentialed responses (OWASP A01)."
            ),
        )

    # ── 2. Wildcard without credentials (informational) ───────────────────────
    if acao == "*" and not with_credentials:
        return _make_finding(
            url=url,
            probe=probe_name,
            origin_sent=origin_sent,
            acao=acao,
            with_credentials=False,
            severity=SeverityLevel.info,
            vuln_type="cors-wildcard",
            description=(
                f"CORS wildcard at {url}: Access-Control-Allow-Origin: *. "
                f"Any origin can read unauthenticated responses. "
                f"Acceptable for public APIs; risky if endpoint can return "
                f"sensitive data with cached/implicit auth."
            ),
        )

    # For non-wildcard responses, only flag if the server reflected our crafted origin
    if not acao or acao == "*":
        return None

    origin_reflected = (acao.lower() == origin_sent.lower())
    if not origin_reflected:
        return None   # Server returned a fixed origin — not our probe

    # ── 3. Null origin + credentials ──────────────────────────────────────────
    if probe_name == "null" and origin_sent == "null" and with_credentials:
        return _make_finding(
            url=url, probe=probe_name, origin_sent=origin_sent, acao=acao,
            with_credentials=True, severity=SeverityLevel.critical,
            vuln_type="cors-null-origin",
            description=(
                f"CORS null origin accepted with credentials at {url}. "
                f"Origin: null is sent by sandboxed iframes — an attacker "
                f"can load the target from a sandboxed iframe on any domain "
                f"and read the credentialed response (OWASP A01)."
            ),
        )

    # ── 4. Arbitrary reflected origin + credentials ───────────────────────────
    if probe_name == "reflected" and with_credentials:
        return _make_finding(
            url=url, probe=probe_name, origin_sent=origin_sent, acao=acao,
            with_credentials=True, severity=SeverityLevel.critical,
            vuln_type="cors-reflected-origin",
            description=(
                f"CORS reflects arbitrary Origin with credentials at {url}. "
                f"The server echoed back Origin: {origin_sent!r} with "
                f"Access-Control-Allow-Credentials: true. "
                f"Any malicious website can steal authenticated data "
                f"from this endpoint (OWASP A01)."
            ),
        )

    # Reflected without credentials — still noteworthy (high)
    if probe_name == "reflected" and not with_credentials:
        return _make_finding(
            url=url, probe=probe_name, origin_sent=origin_sent, acao=acao,
            with_credentials=False, severity=SeverityLevel.medium,
            vuln_type="cors-reflected-origin-no-credentials",
            description=(
                f"CORS reflects arbitrary Origin at {url} (no credentials flag). "
                f"The server echoes any Origin header value. "
                f"Unsafe for endpoints that return sensitive data, "
                f"or that rely on implicit auth (cookies) — confirm "
                f"whether ACAC can be forced to true via another header."
            ),
        )

    # ── 5. Subdomain prefix bypass ────────────────────────────────────────────
    if probe_name == "subdomain-pre":
        sev = SeverityLevel.high if with_credentials else SeverityLevel.medium
        return _make_finding(
            url=url, probe=probe_name, origin_sent=origin_sent, acao=acao,
            with_credentials=with_credentials, severity=sev,
            vuln_type="cors-subdomain-bypass",
            description=(
                f"CORS subdomain bypass at {url}: "
                f"Origin {origin_sent!r} (arbitrary subdomain of target) was accepted. "
                f"A subdomain takeover on any subdomain grants full cross-origin "
                f"read access{' with credentials' if with_credentials else ''} (OWASP A01)."
            ),
        )

    # ── 6. Post-domain suffix bypass ─────────────────────────────────────────
    if probe_name == "subdomain-post":
        sev = SeverityLevel.high if with_credentials else SeverityLevel.medium
        return _make_finding(
            url=url, probe=probe_name, origin_sent=origin_sent, acao=acao,
            with_credentials=with_credentials, severity=sev,
            vuln_type="cors-domain-suffix-bypass",
            description=(
                f"CORS domain-suffix bypass at {url}: "
                f"Origin {origin_sent!r} was accepted. "
                f"Weak endsWith() check — attacker registers a domain ending "
                f"in the target's name to bypass the origin check "
                f"(OWASP A01)."
            ),
        )

    # ── 7. HTTP downgrade ────────────────────────────────────────────────────
    if probe_name == "http-downgrade" and with_credentials:
        return _make_finding(
            url=url, probe=probe_name, origin_sent=origin_sent, acao=acao,
            with_credentials=True, severity=SeverityLevel.high,
            vuln_type="cors-http-downgrade",
            description=(
                f"CORS HTTP origin accepted on HTTPS endpoint at {url}. "
                f"Origin: {origin_sent!r} (HTTP) accepted with credentials. "
                f"An active MITM on the network can intercept the plain-HTTP "
                f"request and steal the credentialed CORS response."
            ),
        )

    return None


def _make_finding(
    url: str,
    probe: str,
    origin_sent: str,
    acao: str,
    with_credentials: bool,
    severity: SeverityLevel,
    vuln_type: str,
    description: str,
) -> Dict[str, Any]:
    return {
        "url":         url,
        "type":        vuln_type,
        "severity":    severity,
        "description": description,
        "raw_output": {
            "url":             url,
            "probe":           probe,
            "origin_sent":     origin_sent,
            "acao":            acao,
            "with_credentials": with_credentials,
        },
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_headers(auth_context: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "User-Agent": "Mozilla/5.0 (compatible; Briar-CORS/1.0)",
    }
    headers.update(auth_context.get("headers", {}))
    cookies = auth_context.get("cookies", [])
    if cookies:
        headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    return headers


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    worker = CORSWorker()
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
