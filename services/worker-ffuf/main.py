"""
FFUF Smart Fuzzer Worker
========================
Three-strategy fuzzing engine that runs after httpx has validated live endpoints:

  ROOT       – brute-force every discovered host root (/FUZZ) with a broad path
               wordlist (common.txt).  Finds admin panels, backup files, hidden
               dirs that katana never linked to.

  API PREFIX – extract shared path prefixes from discovered endpoints and fuzz
               each with an API-focused wordlist.  E.g. if katana found
               /api/v1/users and /api/v1/orders, we fuzz /api/v1/FUZZ to find
               /api/v1/admin, /api/v1/export, etc.

  IDOR       – detect integer path segments in live URLs and replace them with
               FUZZ to enumerate adjacent object IDs.  E.g. /api/products/7
               becomes /api/products/FUZZ with a 1-2000 numeric wordlist.

All three strategies run concurrently (asyncio.gather).

Wordlists (configurable via environment variables):
  FFUF_WORDLIST_ROOT  – broad path discovery  (default: common.txt)
  FFUF_WORDLIST_API   – API endpoint names    (default: api-endpoints-res.txt)
  IDOR wordlist is generated in-memory (1-2000) — no external file needed.
"""

import asyncio
import json
import logging
import os
import re
import sys
import tempfile
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel
from shared.app_strategies import get_strategy

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ffuf-worker")

WORK_DIR = "/tmp/ffuf"

# ── Tuning constants ───────────────────────────────────────────────────────────

# Max API prefixes to fuzz per host (avoid combinatorial explosion)
MAX_API_PREFIXES = 10
# Max IDOR templates to fuzz total
MAX_IDOR_TARGETS = 20
# IDs to enumerate for IDOR strategy
IDOR_RANGE = 2000

# ── Patterns ───────────────────────────────────────────────────────────────────

# Path prefixes that look like API mount points
_API_MOUNT_RE = re.compile(
    r"^/(?:api|v\d+|rest|graphql|gql|ws|rpc|soap|service|services|"
    r"internal|external|public|private|backend|gateway|proxy|json|xml)"
    r"(?:/|$)",
    re.IGNORECASE,
)

# A path segment that is a bare integer (IDOR candidate)
_INT_SEG_RE = re.compile(r"^\d{1,10}$")


# ── Worker ─────────────────────────────────────────────────────────────────────

class FFUFWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="ffuf", queue_name="scan.fuzz.ffuf")
        # Per-strategy per-target timeout in seconds
        self.strategy_timeout = int(os.getenv("FFUF_STRATEGY_TIMEOUT", "600"))
        self.rate     = int(os.getenv("FFUF_RATE",    "300"))
        self.threads  = int(os.getenv("FFUF_THREADS", "40"))

        self.wordlist_root = os.getenv(
            "FFUF_WORDLIST_ROOT",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        )
        # API-focused wordlist — fall back to common.txt if not present
        self.wordlist_api = os.getenv(
            "FFUF_WORDLIST_API",
            "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt",
        )

    # ── Main entry ─────────────────────────────────────────────────────────────

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [])
        if not endpoints and target:
            endpoints = [target]

        os.makedirs(WORK_DIR, exist_ok=True)

        # M8: app-type adaptive strategy
        # ── Resolve which strategies to run ───────────────────────────────────
        app_type  = task_payload.get("app_type", "unknown")
        framework = task_payload.get("framework")
        strategy  = get_strategy(app_type, "ffuf", framework)

        # Caller can pass "strategies" list explicitly; fallback to app-type strategy;
        # fallback to all three strategies if neither is specified.
        enabled_strategies: List[str] = (
            task_payload.get("strategies")
            or strategy.get("strategies")
            or ["root", "api_prefix", "idor"]
        )

        # Wordlist override: strategy > payload > env default
        wl_root = (
            strategy.get("wordlist_override")
            or task_payload.get("wordlist_root")
            or self.wordlist_root
        )
        wl_api = self.wordlist_api if os.path.exists(self.wordlist_api) else wl_root

        if strategy:
            logger.info(
                f"[ffuf] M8 strategy for app_type={app_type!r}: "
                f"enabled={enabled_strategies}, wordlist={wl_root!r}"
            )

        # Build all fuzzing tasks across enabled strategies
        tasks: List[asyncio.Task] = []
        task_labels: List[str] = []

        # ── Strategy 1: ROOT ──────────────────────────────────────────────────
        root_hosts = _unique_hosts(endpoints, target)
        if "root" in enabled_strategies:
            logger.info(f"[ffuf] ROOT strategy: {len(root_hosts)} host(s)")
            for host in root_hosts:
                tasks.append(asyncio.create_task(
                    self._fuzz(
                        url_template=f"{host}/FUZZ",
                        wordlist=wl_root,
                        auth_context=auth_context,
                        strategy="root",
                        label=host,
                    )
                ))
                task_labels.append(f"ROOT:{host}")
        else:
            logger.info(f"[ffuf] ROOT strategy skipped (app_type={app_type!r})")

        # ── Strategy 2: API PREFIX ────────────────────────────────────────────
        api_targets = _extract_api_prefixes(endpoints) if "api_prefix" in enabled_strategies else []
        if "api_prefix" in enabled_strategies:
            logger.info(f"[ffuf] API PREFIX strategy: {len(api_targets)} prefix(es)")
            for host, prefix in api_targets:
                tasks.append(asyncio.create_task(
                    self._fuzz(
                        url_template=f"{host}{prefix}/FUZZ",
                        wordlist=wl_api,
                        auth_context=auth_context,
                        strategy="api_prefix",
                        label=f"{host}{prefix}",
                    )
                ))
                task_labels.append(f"API:{host}{prefix}")
        else:
            logger.info(f"[ffuf] API PREFIX strategy skipped (app_type={app_type!r})")

        # ── Strategy 3: IDOR ──────────────────────────────────────────────────
        idor_targets = _extract_idor_targets(endpoints) if "idor" in enabled_strategies else []
        if "idor" in enabled_strategies:
            logger.info(f"[ffuf] IDOR strategy: {len(idor_targets)} template(s)")
        else:
            logger.info(f"[ffuf] IDOR strategy skipped (app_type={app_type!r})")
        idor_wl: str = ""
        if idor_targets:
            idor_wl = await _write_idor_wordlist(IDOR_RANGE)
            for host, template in idor_targets:
                tasks.append(asyncio.create_task(
                    self._fuzz(
                        url_template=f"{host}{template}",  # template already has FUZZ
                        wordlist=idor_wl,
                        auth_context=auth_context,
                        strategy="idor",
                        label=f"{host}{template}",
                        mc="200,201,204,301,302,307,401,403,405",  # tighter for IDOR
                    )
                ))
                task_labels.append(f"IDOR:{host}{template}")

        if not tasks:
            logger.warning("[ffuf] No fuzzing targets derived — skipping")
            return []

        # Run all strategies concurrently
        results_nested = await asyncio.gather(*tasks, return_exceptions=True)

        all_results: List[Dict[str, Any]] = []
        for label, outcome in zip(task_labels, results_nested):
            if isinstance(outcome, Exception):
                logger.warning(f"[ffuf] {label} failed: {outcome}")
            elif isinstance(outcome, list):
                logger.info(f"[ffuf] {label} → {len(outcome)} finding(s)")
                all_results.extend(outcome)

        # Clean up IDOR wordlist temp file (only created when there are IDOR targets)
        if idor_wl:
            try:
                os.unlink(idor_wl)
            except OSError:
                pass

        # Deduplicate by URL
        seen_urls: Set[str] = set()
        deduped: List[Dict[str, Any]] = []
        for r in all_results:
            if r["url"] not in seen_urls:
                seen_urls.add(r["url"])
                deduped.append(r)

        logger.info(
            f"[ffuf] Total: {len(deduped)} unique paths "
            f"(strategies={enabled_strategies}, "
            f"ROOT={len([l for l in task_labels if l.startswith('ROOT:')])} "
            f"API={len(api_targets)} IDOR={len(idor_targets)})"
        )
        return deduped

    # ── Core fuzzer ────────────────────────────────────────────────────────────

    async def _fuzz(
        self,
        url_template: str,
        wordlist: str,
        auth_context: Dict[str, Any],
        strategy: str,
        label: str,
        mc: str = "200,204,301,302,307,308,401,403,405,500",
    ) -> List[Dict[str, Any]]:
        """Run a single ffuf invocation with given URL template and wordlist."""

        with tempfile.NamedTemporaryFile(
            dir=WORK_DIR, suffix=".json", delete=False
        ) as tf:
            out_file = tf.name

        cmd = [
            "ffuf",
            "-u", url_template,
            "-w", wordlist,
            "-o", out_file,
            "-of", "json",
            "-rate", str(self.rate),
            "-t", str(self.threads),
            "-mc", mc,
            "-s",          # silent mode — no progress bar to stdout
            "-maxtime", str(self.strategy_timeout),  # hard wall-clock limit
        ]

        # Auth headers
        for key, val in auth_context.get("headers", {}).items():
            cmd.extend(["-H", f"{key}: {val}"])
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            cmd.extend(["-H", f"Cookie: {cookie_str}"])

        logger.info(f"[ffuf/{strategy}] {label}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=WORK_DIR,
            )
            # Python-level timeout = ffuf -maxtime + generous buffer
            try:
                _, stderr_data = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.strategy_timeout + 60,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning(f"[ffuf/{strategy}] Python timeout: {label}")
                return _parse_ffuf_output(out_file, strategy)

            if process.returncode not in (0, None):
                err = stderr_data.decode("utf-8", errors="ignore").strip()
                if err:
                    logger.warning(f"[ffuf/{strategy}] exit {process.returncode}: {err[:300]}")

            return _parse_ffuf_output(out_file, strategy)

        except FileNotFoundError:
            logger.error("[ffuf] 'ffuf' binary not found in PATH")
            return []
        except Exception as exc:
            logger.error(f"[ffuf/{strategy}] {label}: {exc}", exc_info=True)
            return []
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass


# ── Endpoint analysis helpers ──────────────────────────────────────────────────

def _unique_hosts(endpoints: List[str], fallback: str) -> List[str]:
    """Deduplicate to unique scheme://host values."""
    seen: Set[str] = set()
    out: List[str] = []
    for url in (endpoints or []) + ([fallback] if fallback else []):
        try:
            p = urlparse(url)
            if p.scheme and p.netloc:
                host = f"{p.scheme}://{p.netloc}"
                if host not in seen:
                    seen.add(host)
                    out.append(host)
        except Exception:
            continue
    return out


def _extract_api_prefixes(endpoints: List[str]) -> List[Tuple[str, str]]:
    """
    From a list of discovered endpoints, extract (host, prefix_path) pairs
    that are worth fuzzing for hidden API routes.

    A prefix qualifies if:
    - It matches a known API mount point pattern  (/api, /v1, /rest, …), OR
    - At least 2 discovered endpoints share the same immediate parent path
      (meaning the directory exists and may have siblings we haven't found)

    Returns at most MAX_API_PREFIXES pairs per host, ordered by child count
    descending (most productive prefix first).
    """
    # host → { parent_path → child_count }
    by_host: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for url in endpoints:
        try:
            p = urlparse(url)
            if not (p.scheme and p.netloc and p.path):
                continue
            host = f"{p.scheme}://{p.netloc}"
            parts = [s for s in p.path.split("/") if s]
            if not parts:
                continue

            # Immediate parent of this endpoint (the dir it lives in)
            if len(parts) >= 2:
                parent = "/" + "/".join(parts[:-1])
                by_host[host][parent] += 1

            # Any API-mount prefix at any depth (regardless of child count)
            for depth in range(1, len(parts) + 1):
                prefix = "/" + "/".join(parts[:depth])
                if _API_MOUNT_RE.match(prefix) or _API_MOUNT_RE.match(prefix + "/"):
                    # setdefault so we don't overwrite a legitimate count
                    by_host[host].setdefault(prefix, 0)
        except Exception:
            continue

    results: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    for host, prefix_map in by_host.items():
        # Most children first, then longest prefix (most specific)
        sorted_pfx = sorted(
            prefix_map.items(),
            key=lambda kv: (-kv[1], -len(kv[0])),
        )
        added = 0
        for prefix, count in sorted_pfx:
            if added >= MAX_API_PREFIXES:
                break
            is_api_mount = bool(_API_MOUNT_RE.match(prefix)) or bool(_API_MOUNT_RE.match(prefix + "/"))
            if count >= 2 or is_api_mount:
                key = (host, prefix)
                if key not in seen:
                    seen.add(key)
                    results.append(key)
                    added += 1

    return results


def _extract_idor_targets(endpoints: List[str]) -> List[Tuple[str, str]]:
    """
    Find URL patterns where a path segment is a bare integer.
    Returns (host, url_template) pairs where the integer is replaced with FUZZ.

    Example: /api/products/7/reviews  →  ("https://host", "/api/products/FUZZ/reviews")
             /users/42               →  ("https://host", "/users/FUZZ")

    Deduplicates templates so repeated IDs in different discovered URLs don't
    generate redundant fuzz runs.  Capped at MAX_IDOR_TARGETS.
    """
    seen: Set[Tuple[str, str]] = set()
    results: List[Tuple[str, str]] = []

    for url in endpoints:
        try:
            p = urlparse(url)
            if not (p.scheme and p.netloc and p.path):
                continue
            host = f"{p.scheme}://{p.netloc}"
            parts = [s for s in p.path.split("/") if s]
            if not parts:
                continue

            for i, seg in enumerate(parts):
                if not _INT_SEG_RE.match(seg):
                    continue
                # Sanity: only IDs that look like DB primary keys (1-999999)
                try:
                    if not (1 <= int(seg) <= 999_999):
                        continue
                except ValueError:
                    continue

                # Build template — keep prefix and suffix around the integer
                template_parts = parts[:i] + ["FUZZ"] + parts[i + 1:]
                template = "/" + "/".join(template_parts)
                key = (host, template)
                if key not in seen:
                    seen.add(key)
                    results.append(key)
                    if len(results) >= MAX_IDOR_TARGETS:
                        return results
        except Exception:
            continue

    return results


async def _write_idor_wordlist(n: int) -> str:
    """Write 1..n to a temp file and return the path."""
    with tempfile.NamedTemporaryFile(
        dir=WORK_DIR, suffix=".txt", delete=False, mode="w"
    ) as tf:
        tf.write("\n".join(str(i) for i in range(1, n + 1)))
        return tf.name


# ── Output parsing ─────────────────────────────────────────────────────────────

def _parse_ffuf_output(out_file: str, strategy: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    try:
        with open(out_file, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return results

    for item in data.get("results", []):
        url = item.get("url", "")
        if not url:
            word = (item.get("input") or {}).get("FUZZ", "")
            url = word  # ffuf sometimes omits url field when -s is active
        if not url:
            continue

        status = item.get("status", 0)
        results.append({
            "url": url,
            "type": "discovered_path",
            "description": (
                f"[ffuf/{strategy}] {url} "
                f"[status={status}, size={item.get('length', 0)}, "
                f"words={item.get('words', 0)}]"
            ),
            "severity": _status_to_severity(status),
            "raw_output": {
                "url": url,
                "status": status,
                "length": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "content_type": item.get("content-type") or item.get("content_type"),
                "redirect": item.get("redirectlocation"),
                "strategy": strategy,
                "duration_ms": item.get("duration"),
            },
        })

    return results


def _status_to_severity(status: int) -> SeverityLevel:
    if status == 500:
        return SeverityLevel.medium
    if status in (401, 403):
        return SeverityLevel.low
    return SeverityLevel.info


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    worker = FFUFWorker()
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
