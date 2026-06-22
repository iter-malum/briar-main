"""
JavaScript Secrets Scanner Worker
===================================
Phase: PROBE  (runs after katana, alongside httpx)
Queue: scan.probe.jsscanner

This worker fetches every .js file discovered by katana and scans its
content for hard-coded secrets using a comprehensive regex pattern library.

Why a dedicated worker instead of doing this inside katana?
  - Katana's _extract_js_endpoints already downloads JS files for path
    extraction; secrets scanning is a separate concern (different output type,
    different false-positive profile, much richer pattern set).
  - Running in the PROBE phase means secrets are reported before DAST
    starts, so nuclei/ZAP can be skipped on hosts already known-compromised.

Secret categories covered
--------------------------
  CRITICAL
    • Cloud provider keys   – AWS AKIA*, GCP AIza*, Azure subscription IDs
    • Private keys          – RSA/EC PEM blocks, SSH private keys
    • Stripe live keys      – sk_live_*, rk_live_*

  HIGH
    • Generic API tokens    – api_key, apikey, api-key with high-entropy value
    • OAuth / Bearer tokens – access_token, bearer, id_token
    • Database URLs         – postgres://, mysql://, mongodb://, redis://
    • JWT tokens            – eyJ...eyJ...

  MEDIUM
    • GitHub tokens         – ghp_*, github_pat_*, ghs_*
    • Twilio / SendGrid     – SK*, SG.xxx
    • Slack tokens          – xox[bpars]-*
    • Generic secrets       – password/passwd/secret/pwd with non-trivial value
    • Internal IPs          – 10.x, 172.16-31.x, 192.168.x in credentials context

All patterns are compiled once at module load.  False-positive suppression:
  - Minimum entropy check for token-like patterns (avoids test/placeholder values)
  - Values matching obvious placeholders skipped (YOUR_KEY, CHANGE_ME, xxx, etc.)
  - Max 3 findings per JS file to avoid flooding reports
"""

import asyncio
import logging
import math
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel
from shared.js_fingerprint import fingerprint_js, aggregate_tech_stack, LibraryMatch  # type: ignore[attr-defined]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("jsscanner-worker")

MAX_JS_FILES    = int(os.getenv("JSSCANNER_MAX_FILES", "100"))
MAX_FILE_SIZE   = int(os.getenv("JSSCANNER_MAX_FILE_BYTES", str(2 * 1024 * 1024)))  # 2 MB
FETCH_TIMEOUT   = float(os.getenv("JSSCANNER_FETCH_TIMEOUT", "15"))
CONCURRENCY     = int(os.getenv("JSSCANNER_CONCURRENCY", "10"))
MAX_PER_FILE    = int(os.getenv("JSSCANNER_MAX_PER_FILE", "3"))
TOTAL_TIMEOUT   = int(os.getenv("JSSCANNER_TOTAL_TIMEOUT", "600"))

# ── Secret patterns ────────────────────────────────────────────────────────────
# Each entry: (name, regex, severity, description_template)

_PATTERNS: List[Tuple[str, re.Pattern, SeverityLevel, str]] = []


def _add(name: str, pattern: str, severity: SeverityLevel, description: str, flags: int = 0):
    _PATTERNS.append((name, re.compile(pattern, flags | re.MULTILINE), severity, description))


# CRITICAL
_add("aws-access-key",     r"AKIA[0-9A-Z]{16}",                                 SeverityLevel.critical, "AWS Access Key ID")
_add("aws-secret-key",     r"""(?:aws_secret|aws_secret_access_key|AWS_SECRET)[^\w\n]{0,10}([A-Za-z0-9/+=]{40})""", SeverityLevel.critical, "AWS Secret Access Key")
_add("gcp-api-key",        r"AIza[0-9A-Za-z\-_]{35}",                           SeverityLevel.critical, "Google Cloud / Firebase API Key")
_add("private-key-pem",    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY", SeverityLevel.critical, "Private Key (PEM block)")
_add("stripe-live-key",    r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}",                  SeverityLevel.critical, "Stripe Live Secret Key")
_add("twilio-account-sid", r"AC[a-z0-9]{32}",                                   SeverityLevel.critical, "Twilio Account SID")

# HIGH
_add("generic-api-key",    r"""(?:api[_\-]?key|apikey|api[_\-]?secret)['\"\s:=]+([A-Za-z0-9\-_]{20,80})""",  SeverityLevel.high, "Generic API Key/Secret")
_add("oauth-token",        r"""(?:access[_\-]?token|bearer[_\-]?token|id[_\-]?token)['\"\s:=]+([A-Za-z0-9\-_.]{20,})""", SeverityLevel.high, "OAuth/Bearer Token")
_add("database-url",       r"""(?:postgres|mysql|mongodb|redis|mssql|oracle)://[^\s'\"<>]+""",               SeverityLevel.high, "Database Connection URL")
_add("jwt-token",          r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",                        SeverityLevel.high, "JSON Web Token (JWT)")
_add("github-token",       r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}",                                      SeverityLevel.high, "GitHub Personal Access Token")
_add("github-pat",         r"github_pat_[A-Za-z0-9_]{82}",                                                   SeverityLevel.high, "GitHub Fine-Grained PAT")

# MEDIUM
_add("sendgrid-key",       r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",     SeverityLevel.medium, "SendGrid API Key")
_add("slack-token",        r"xox[bpars]\-[0-9a-zA-Z\-]{10,}",                  SeverityLevel.medium, "Slack OAuth Token")
_add("heroku-api-key",     r"[hH]eroku[^\w\n]{0,10}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", SeverityLevel.medium, "Heroku API Key")
_add("generic-password",   r"""(?:password|passwd|pwd)['\"\s:=]+(?!['\"]{0,1}(?:YOUR|CHANGE|EXAMPLE|TEST|PLACEHOLDER|xxx|null|undefined|false|\*+))([A-Za-z0-9!@#$%^&*\-_]{8,})""", SeverityLevel.medium, "Hard-coded Password")
_add("generic-secret",     r"""(?:secret|private_key|client_secret)['\"\s:=]+(?!(?:YOUR|CHANGE|xxx|null))([A-Za-z0-9!@#$%^&*\-_]{10,})""", SeverityLevel.medium, "Hard-coded Secret")
_add("internal-ip-cred",   r"""(?:host|server|endpoint)['\"\s:=]+['\"]((?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+)['\"]\s*[,;]""", SeverityLevel.medium, "Internal IP in Credentials Context")

# Placeholder values to skip (prevent false positives)
_PLACEHOLDER_RE = re.compile(
    r"^(?:YOUR[_\-]?|CHANGE[_\-]?ME|EXAMPLE|TEST|PLACEHOLDER|INSERT|ENTER|"
    r"xxx|null|undefined|false|true|0{8,}|1{8,}|none|n/a|placeholder|"
    r"<[^>]+>|\$\{[^}]+\}|%[A-Z_]+%|\{\{[^}]+\}\})$",
    re.IGNORECASE,
)

# Minimum entropy threshold for token-like values (bits per character)
_MIN_ENTROPY = 3.5


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values())


def _is_likely_real(value: str) -> bool:
    """Return False for obvious placeholder / low-entropy values."""
    if not value or len(value) < 6:
        return False
    if _PLACEHOLDER_RE.match(value.strip()):
        return False
    # High-entropy check for long token-like values
    if len(value) >= 16 and _shannon_entropy(value) < _MIN_ENTROPY:
        return False
    return True


# ── Supply-chain helpers ───────────────────────────────────────────────────────

_KNOWN_COMPROMISED: Dict[str, Dict[str, str]] = {
    "event-stream":         {"desc": "Malicious 2018 supply-chain attack injecting bitcoin stealer", "severity": SeverityLevel.critical, "advisory": "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident"},
    "flatmap-stream":       {"desc": "Injected by event-stream compromise (bitcoin stealer)", "severity": SeverityLevel.critical, "advisory": "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident"},
    "colors":               {"desc": "Author sabotaged v1.4.44-liberty-2 with infinite loop", "severity": SeverityLevel.high, "advisory": "https://github.com/Marak/colors.js/issues/285"},
    "faker":                {"desc": "Author sabotaged v6.6.6 (same actor as colors)", "severity": SeverityLevel.high, "advisory": "https://github.com/marak/Faker.js/issues/1046"},
    "node-ipc":             {"desc": "Author added wiper payload targeting Russian/Belarusian IPs (v10.1.1-v10.1.2)", "severity": SeverityLevel.critical, "advisory": "https://github.com/RIAEvangelist/node-ipc/issues/233"},
    "ua-parser-js":         {"desc": "NPM account compromised; malicious versions 0.7.29, 0.8.0, 1.0.1 published", "severity": SeverityLevel.critical, "advisory": "https://github.com/faisalman/ua-parser-js/issues/536"},
    "coa":                  {"desc": "NPM account compromised; crypto-miner injected (2.0.3, 2.0.4)", "severity": SeverityLevel.critical, "advisory": "https://github.com/veged/coa/issues/99"},
    "rc":                   {"desc": "NPM account compromised; crypto-miner injected (1.2.9)", "severity": SeverityLevel.critical, "advisory": "https://github.com/dominictarr/rc/issues/131"},
    "eslint-scope":         {"desc": "Compromised to steal npm credentials (3.7.2)", "severity": SeverityLevel.high, "advisory": "https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/"},
    "getcookies":           {"desc": "Compromised cookie-stealing module injected via mailparser", "severity": SeverityLevel.critical, "advisory": "https://blog.npmjs.org/post/173526807575/reported-malicious-module-getcookies"},
    "bootstrap-sass":       {"desc": "Backdoor injected in 3.2.0.3 (remote code execution)", "severity": SeverityLevel.critical, "advisory": "https://www.rubysec.com/advisories/CVE-2019-10842/"},
    "left-pad":             {"desc": "Package was unpublished causing massive breakage (reliability risk)", "severity": SeverityLevel.medium, "advisory": "https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm"},
    "crossenv":             {"desc": "Typosquatting cross-env — data exfiltration", "severity": SeverityLevel.high, "advisory": "https://github.com/nicolo-ribaudo/chokidar/issues/858"},
    "lodash":               {"desc": "CVE-2021-23337 command injection / CVE-2020-8203 prototype pollution (pin >=4.17.21)", "severity": SeverityLevel.medium, "advisory": "https://github.com/lodash/lodash/issues/5261"},
    "axios":                {"desc": "SSRF via CVE-2023-45857 if <1.6.0", "severity": SeverityLevel.medium, "advisory": "https://github.com/axios/axios/issues/6027"},
}

_POPULAR_PACKAGES: List[str] = [
    "react", "react-dom", "vue", "angular", "svelte",
    "lodash", "underscore", "ramda",
    "express", "koa", "fastify", "hapi",
    "axios", "node-fetch", "got", "superagent",
    "webpack", "rollup", "vite", "esbuild", "parcel",
    "babel-core", "typescript", "eslint", "prettier",
    "jest", "mocha", "chai", "sinon",
    "cross-env", "dotenv", "moment", "dayjs",
    "uuid", "nanoid", "chalk", "debug",
    "socket.io", "ws", "mqtt", "amqplib",
    "sequelize", "mongoose", "pg", "redis",
    "passport", "jsonwebtoken", "bcrypt", "crypto-js",
    "inquirer", "commander", "yargs", "minimist",
    "sharp", "jimp", "puppeteer", "playwright",
    "multer", "formidable", "busboy",
    "helmet", "cors", "compression", "morgan",
    "nodemailer", "twilio", "stripe", "aws-sdk",
]


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance — returns early if distance > 2 for speed."""
    if abs(len(a) - len(b)) > 2:
        return 3
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if a[i - 1] == b[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]


def _find_typosquat(pkg: str) -> Optional[str]:
    """Return the legitimate package name if pkg looks like a typosquat, else None."""
    pkg_l = pkg.lower()
    if pkg_l in _POPULAR_PACKAGES:
        return None
    for pop in _POPULAR_PACKAGES:
        if _edit_distance(pkg_l, pop) == 1:
            return pop
    return None


# ── Worker ─────────────────────────────────────────────────────────────────────

class JsScannerWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="jsscanner", queue_name="scan.probe.jsscanner")

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        endpoints: List[str] = task_payload.get("endpoints", [])

        # Collect .js URLs — include vendor files for fingerprinting (but skip for secrets)
        all_js_urls = list(dict.fromkeys(
            u for u in endpoints if ".js" in u.lower()
        ))
        non_vendor_urls = [u for u in all_js_urls if not _is_static_vendor(u)]

        if not all_js_urls:
            all_js_urls = await self._collect_js_urls_from_target(target, auth_context)
            non_vendor_urls = [u for u in all_js_urls if not _is_static_vendor(u)]

        if not all_js_urls:
            logger.info("[jsscanner] No JS files found — skipping")
            return []

        # Fingerprinting covers all JS including vendor CDN files (version detection
        # needs e.g. jquery-3.6.0.min.js from cdnjs).  Secrets scanning skips vendor.
        fingerprint_urls = all_js_urls[:MAX_JS_FILES]
        secrets_urls = non_vendor_urls[:MAX_JS_FILES]

        logger.info(
            f"[jsscanner] {len(fingerprint_urls)} JS file(s) for fingerprinting, "
            f"{len(secrets_urls)} for secrets scanning"
        )

        headers = _build_headers(auth_context)
        semaphore = asyncio.Semaphore(CONCURRENCY)
        findings: List[Dict[str, Any]] = []
        lib_matches: List[LibraryMatch] = []
        findings_lock = asyncio.Lock()
        lib_lock = asyncio.Lock()
        start = asyncio.get_event_loop().time()

        async with httpx.AsyncClient(
            headers=headers,
            verify=False,
            follow_redirects=True,
            timeout=httpx.Timeout(FETCH_TIMEOUT),
        ) as client:

            async def process_one(js_url: str):
                if asyncio.get_event_loop().time() - start > TOTAL_TIMEOUT:
                    return
                async with semaphore:
                    content = await self._fetch_js(client, js_url)
                    if content is None:
                        return

                    # Library fingerprinting — runs on all JS files
                    matches = fingerprint_js(js_url, content)
                    if matches:
                        async with lib_lock:
                            lib_matches.extend(matches)

                    # Secrets scanning — skip vendor/CDN files
                    if js_url in secrets_urls:
                        secrets = self._scan_content(js_url, content)
                        if secrets:
                            async with findings_lock:
                                findings.extend(secrets)

            await asyncio.gather(*[process_one(u) for u in fingerprint_urls])

        # Convert library matches to findings
        lib_findings = _build_library_findings(lib_matches, target)
        findings.extend(lib_findings)

        # Emit a single tech_stack_detected finding that aggregates all libraries —
        # consumers can use this to enrich app_type context without iterating findings.
        if lib_matches:
            tech_stack = aggregate_tech_stack(lib_matches)
            findings.append({
                "url":      target,
                "type":     "tech_stack_detected",
                "severity": SeverityLevel.info,
                "description": (
                    f"[jsscanner] JS library fingerprinting detected {len(tech_stack)} "
                    f"libraries: "
                    + ", ".join(f"{k} {v}" for k, v in sorted(tech_stack.items()))
                ),
                "raw_output": {
                    "source":     "js_fingerprint",
                    "tech_stack": tech_stack,
                    "js_files_scanned": len(fingerprint_urls),
                },
            })
            logger.info(
                f"[jsscanner] Library fingerprinting: "
                + ", ".join(f"{k}={v}" for k, v in sorted(tech_stack.items()))
            )

        # ── M17: Supply chain + typosquatting analysis ────────────────────────
        sc_findings = await self._probe_supply_chain(target, _build_headers(auth_context))
        findings.extend(sc_findings)

        logger.info(
            f"[jsscanner] Complete — {len(findings)} finding(s) total "
            f"({len(lib_findings)} library, "
            f"{len(sc_findings)} supply-chain, "
            f"{len(findings) - len(lib_findings) - len(sc_findings) - (1 if lib_matches else 0)} secrets)"
        )
        return findings

    async def _probe_supply_chain(
        self, target: str, headers: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """
        Download backup package.json files exposed on the server, parse
        dependencies, and check for:
          1. Known compromised / malicious packages (hardcoded list)
          2. Typosquatting — package names within edit-distance 1 of top packages
        """
        findings: List[Dict[str, Any]] = []
        pkg_paths = [
            "/ftp/package.json.bak",
            "/ftp/package.json",
            "/package.json",
            "/package.json.bak",
            "/backup/package.json",
        ]
        parsed = urlparse(target)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(
            headers=headers, verify=False, follow_redirects=True,
            timeout=httpx.Timeout(10)
        ) as client:
            for path in pkg_paths:
                url = origin + path
                try:
                    resp = await client.get(url)
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                except Exception:
                    continue

                logger.info(f"[jsscanner/supply-chain] Found package.json at {url}")

                deps: Dict[str, str] = {}
                for section in ("dependencies", "devDependencies", "peerDependencies"):
                    deps.update(data.get(section, {}))

                if not deps:
                    continue

                # ── Check 1: known compromised packages ───────────────────────
                for pkg_name in deps:
                    vuln = _KNOWN_COMPROMISED.get(pkg_name.lower())
                    if vuln:
                        findings.append({
                            "url":  url,
                            "type": "supply_chain_attack",
                            "description": (
                                f"Supply chain risk: package {pkg_name!r} — {vuln['desc']}"
                            ),
                            "severity": vuln["severity"],
                            "vulnerability_type": "supply_chain_attack",
                            "raw_output": {
                                "package": pkg_name,
                                "version": deps[pkg_name],
                                "advisory": vuln["advisory"],
                                "source": "jsscanner-supply-chain",
                                "owasp": "A06:2021 – Vulnerable and Outdated Components",
                            },
                        })

                # ── Check 2: typosquatting ─────────────────────────────────────
                for pkg_name in deps:
                    squatter = _find_typosquat(pkg_name)
                    if squatter:
                        findings.append({
                            "url":  url,
                            "type": "typosquatting",
                            "description": (
                                f"Possible typosquatting: {pkg_name!r} looks like {squatter!r}"
                            ),
                            "severity": SeverityLevel.medium,
                            "vulnerability_type": "typosquatting",
                            "raw_output": {
                                "package":    pkg_name,
                                "legitimate": squatter,
                                "version":    deps[pkg_name],
                                "source":     "jsscanner-supply-chain",
                                "owasp":      "A06:2021 – Vulnerable and Outdated Components",
                            },
                        })

        return findings

    async def _collect_js_urls_from_target(
        self, target: str, auth_context: Dict[str, Any]
    ) -> List[str]:
        """Fetch target HTML and extract <script src> references as fallback."""
        headers = _build_headers(auth_context)
        try:
            async with httpx.AsyncClient(
                headers=headers, verify=False, follow_redirects=True,
                timeout=httpx.Timeout(FETCH_TIMEOUT)
            ) as client:
                resp = await client.get(target)
                if resp.status_code != 200:
                    return []
                parsed = urlparse(target)
                base   = f"{parsed.scheme}://{parsed.netloc}"
                src_re = re.compile(r'<script[^>]+src=[\'"]([^\'"]+\.js[^\'"]*)[\'"]', re.IGNORECASE)
                urls   = []
                for m in src_re.finditer(resp.text):
                    src = m.group(1)
                    if src.startswith("http"):
                        urls.append(src)
                    elif src.startswith("/"):
                        urls.append(base + src)
                    else:
                        urls.append(urljoin(target, src))
                return list(dict.fromkeys(urls))[:MAX_JS_FILES]
        except Exception as exc:
            logger.debug(f"[jsscanner] Target JS collect failed: {exc}")
            return []

    async def _fetch_js(
        self,
        client: httpx.AsyncClient,
        js_url: str,
    ) -> Optional[str]:
        """Download a JS file and return its text content, or None on failure."""
        try:
            resp = await client.get(js_url)
            if resp.status_code != 200:
                return None
            if len(resp.content) > MAX_FILE_SIZE:
                logger.debug(f"[jsscanner] File too large ({len(resp.content)} bytes): {js_url}")
                return None
            return resp.text
        except Exception as exc:
            logger.debug(f"[jsscanner] Fetch failed for {js_url}: {exc}")
            return None

    def _scan_content(
        self,
        js_url: str,
        content: str,
    ) -> List[Dict[str, Any]]:
        """Scan already-fetched JS content for hard-coded secrets."""
        findings: List[Dict[str, Any]] = []

        for name, pattern, severity, desc_template in _PATTERNS:
            if len(findings) >= MAX_PER_FILE:
                break
            for m in pattern.finditer(content):
                matched_value = (m.group(1) if m.lastindex else m.group(0)).strip()
                if not _is_likely_real(matched_value):
                    continue
                start_pos = max(0, m.start() - 40)
                end_pos   = min(len(content), m.end() + 40)
                context   = content[start_pos:end_pos].replace("\n", " ").strip()
                redacted  = matched_value[:8] + "…" if len(matched_value) > 8 else matched_value
                findings.append({
                    "url":         js_url,
                    "type":        f"secret-{name}",
                    "severity":    severity,
                    "description": (
                        f"[jsscanner] {desc_template} found in {js_url}. "
                        f"Value (redacted): {redacted!r}. "
                        f"Context: {context[:120]!r}"
                    ),
                    "raw_output": {
                        "url":            js_url,
                        "secret_type":    name,
                        "value_redacted": redacted,
                        "context":        context[:200],
                        "pattern":        pattern.pattern[:80],
                    },
                })
                if len(findings) >= MAX_PER_FILE:
                    break

        if findings:
            logger.info(f"[jsscanner] {js_url}: {len(findings)} secret(s) found")
        return findings


# ── Library finding builder ───────────────────────────────────────────────────

def _build_library_findings(
    matches: List[LibraryMatch],
    target: str,
) -> List[Dict[str, Any]]:
    """Convert LibraryMatch objects to informational js_library findings.

    One finding per unique library (deduped by key — best detection method wins).
    These are purely informational: they enrich the app tech-stack report.
    CVE analysis is delegated to worker-retirejs.
    """
    # Prefer detections with a real version string over "unknown"/"detected"
    _method_rank = {"filename": 3, "banner": 2, "version_var": 2}
    _has_version = lambda m: m.version not in ("unknown", "detected")

    best: Dict[str, LibraryMatch] = {}
    for m in matches:
        existing = best.get(m.library_key)
        if existing is None:
            best[m.library_key] = m
        elif _has_version(m) and not _has_version(existing):
            best[m.library_key] = m
        elif _method_rank.get(m.detection_method, 0) > _method_rank.get(existing.detection_method, 0):
            best[m.library_key] = m

    findings: List[Dict[str, Any]] = []
    for lib_key in sorted(best):
        m = best[lib_key]
        ver_display = m.version if m.version not in ("unknown",) else "version unknown"
        findings.append({
            "url":      m.js_url,
            "type":     "js_library",
            "severity": SeverityLevel.info,
            "description": (
                f"[jsscanner] {m.display_name} {ver_display} detected in {m.js_url} "
                f"(via {m.detection_method})"
            ),
            "raw_output": {
                "source":           "js_fingerprint",
                "library":          m.library_key,
                "display_name":     m.display_name,
                "version":          m.version,
                "detection_method": m.detection_method,
                "js_url":           m.js_url,
                "nuclei_tags":      m.nuclei_tags,
                "target":           target,
            },
        })
        logger.info(
            f"[jsscanner/fingerprint] {m.display_name} {ver_display} "
            f"via {m.detection_method} in {m.js_url}"
        )

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_static_vendor(url: str) -> bool:
    """Skip known vendor/CDN JS files — they contain no app secrets."""
    lower = url.lower()
    return any(v in lower for v in (
        "jquery", "bootstrap", "react.min", "angular.min", "vue.min",
        "lodash", "moment", "polyfill", "cdn.jsdelivr", "cdnjs.cloudflare",
        "unpkg.com", "ajax.googleapis", "fontawesome", "d3.min",
    ))


def _build_headers(auth_context: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "User-Agent": "Mozilla/5.0 (compatible; Briar-JsScanner/1.0)",
    }
    headers.update(auth_context.get("headers", {}))
    cookies = auth_context.get("cookies", [])
    if cookies:
        headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    return headers


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    worker = JsScannerWorker()
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
