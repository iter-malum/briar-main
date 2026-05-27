"""
shared/dedup.py — M12 Quality Layer
====================================
Deduplication engine and confidence scoring for scan results.

Dedup key
---------
  SHA-256( normalize(url) + "|" + vuln_class + "|" + normalize(param) )

Confidence score (0-100)
------------------------
  Base score = TOOL_BASE_SCORES[tool]
  Cross-confirmation bonus:
    • 2 independent tools confirm the same finding  → +20
    • 3+ independent tools confirm the same finding → +30
  Score is capped at 100.
"""

import hashlib
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse


# ── Canonical vulnerability classes ───────────────────────────────────────────

# Maps tool-specific vulnerability_type strings → canonical class name.
# Matching is done case-insensitively with substring/regex logic in
# `normalize_vuln_type()`.
VULN_CLASS_MAP: list[tuple[re.Pattern, str]] = [
    # SQL Injection
    (re.compile(r"sql.?inject|sqli|blind.?sql|error.?based.?sql|time.?based.?sql|union.?based", re.I), "sqli"),
    # Cross-Site Scripting
    (re.compile(r"\bxss\b|cross.?site.?script|reflected.?xss|stored.?xss|dom.?xss", re.I), "xss"),
    # Server-Side Template Injection
    (re.compile(r"ssti|template.?inject", re.I), "ssti"),
    # Command Injection
    (re.compile(r"cmdi|command.?inject|os.?command|rce|remote.?code", re.I), "cmdi"),
    # Broken Object-Level Authorization
    (re.compile(r"bola|idor|broken.?object|insecure.?direct", re.I), "bola"),
    # CORS misconfiguration
    (re.compile(r"cors|cross.?origin", re.I), "cors"),
    # JWT vulnerabilities
    (re.compile(r"jwt|json.?web.?token|alg.?none|weak.?secret|hs256|rs256", re.I), "jwt"),
    # Authentication / Authorization bypass
    (re.compile(r"auth.?bypass|unauth|missing.?auth|broken.?auth|access.?control", re.I), "auth"),
    # Sensitive data exposure / secrets
    (re.compile(r"secret|api.?key|credential|token.?leak|sensitive.?data|exposure", re.I), "secrets"),
    # GraphQL-specific
    (re.compile(r"graphql|introspect|batching|alias.?abuse", re.I), "graphql"),
    # Path/directory traversal
    (re.compile(r"path.?traversal|directory.?traversal|lfi|local.?file", re.I), "lfi"),
    # Open redirect
    (re.compile(r"open.?redirect|unvalidated.?redirect", re.I), "redirect"),
    # XXE
    (re.compile(r"\bxxe\b|xml.?external", re.I), "xxe"),
    # SSRF
    (re.compile(r"\bssrf\b|server.?side.?request", re.I), "ssrf"),
    # Mass assignment
    (re.compile(r"mass.?assign|over.?post|parameter.?pollution", re.I), "mass_assignment"),
    # Information disclosure (catch-all for info leaks)
    (re.compile(r"info.?disclosure|information.?leak|stack.?trace|debug", re.I), "info_disclosure"),
]

UNKNOWN_CLASS = "other"


def normalize_vuln_type(vuln_type: Optional[str]) -> str:
    """Return the canonical vulnerability class for *vuln_type*, or 'other'."""
    if not vuln_type:
        return UNKNOWN_CLASS
    for pattern, cls in VULN_CLASS_MAP:
        if pattern.search(vuln_type):
            return cls
    return UNKNOWN_CLASS


# ── URL normalisation ──────────────────────────────────────────────────────────

# Path segments that are clearly IDs — replace with a placeholder so that
# /api/users/42/orders and /api/users/99/orders deduplicate to the same key.
_ID_SEGMENT_RE = re.compile(
    r"^(?:"
    r"\d+"                                          # pure integer
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUID
    r"|[0-9a-f]{24,}"                               # ObjectID / long hex
    r")$",
    re.I,
)


def normalize_url(url: Optional[str]) -> str:
    """
    Normalize a URL for dedup purposes:
    • lowercase scheme + host
    • replace numeric / UUID path segments with '{id}'
    • strip query string and fragment
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip())
        path_parts = parsed.path.split("/")
        normalized_parts = [
            "{id}" if _ID_SEGMENT_RE.match(seg) else seg
            for seg in path_parts
        ]
        normalized_path = "/".join(normalized_parts)
        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            normalized_path,
            "", "", "",          # strip params / query / fragment
        ))
    except Exception:
        return url.lower().split("?")[0]


def normalize_param(param: Optional[str]) -> str:
    """Lower-case and strip whitespace from a parameter name."""
    return (param or "").strip().lower()


# ── Dedup key ──────────────────────────────────────────────────────────────────

def compute_dedup_key(
    url: Optional[str],
    vuln_type: Optional[str],
    param: Optional[str] = None,
) -> str:
    """
    Return a 16-character hex dedup key (first 64 bits of SHA-256).

    Components:
      • normalized URL (path segments, no query)
      • canonical vulnerability class
      • parameter name (optional; empty string if absent)
    """
    vuln_class = normalize_vuln_type(vuln_type)
    raw = "|".join([
        normalize_url(url),
        vuln_class,
        normalize_param(param),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Confidence scoring ─────────────────────────────────────────────────────────

# Base confidence score per tool (0-100).
# Higher = tool produces more precise, low-FP results for confirmed vulns.
TOOL_BASE_SCORES: dict[str, int] = {
    # Exploit workers — highest confidence (tool actually exploited the vuln)
    "sqlmap":   95,
    "tplmap":   90,
    "commix":   90,
    # Active DAST with payload-based proof
    "dalfox":   85,
    "jwt_tool": 80,
    "cors":     80,
    # Spec-driven / structured tests
    "openapi":  65,
    "graphql":  70,
    # Passive scanner + active scanner
    "nuclei":   70,
    "zap":      65,
    "nikto":    60,
    # Behaviour-based
    "bola":     60,
    # Light scanners
    "arjun":    55,
    "jsscanner": 60,
    # Inspector is heuristic-based
    "inspector": 50,
    # Recon tools — low confidence for vuln findings
    "katana":   40,
    "httpx":    40,
    "ffuf":     45,
    "gobuster": 40,
    "whatweb":  35,
}

_DEFAULT_BASE_SCORE = 45

# Cross-confirmation bonus: extra points when multiple independent tools
# agree on the same (url, vuln_class, param) combination.
_CONFIRMATION_BONUSES: dict[int, int] = {
    2: 20,   # 2 tools confirming
    3: 30,   # 3+ tools confirming
}


def compute_confidence(tools: list[str]) -> int:
    """
    Compute the aggregate confidence score for a finding confirmed by *tools*.

    Algorithm:
      1. Take the maximum base score among all contributing tools.
      2. Add the cross-confirmation bonus based on how many tools confirmed.
      3. Cap at 100.

    *tools* should be a non-empty list of tool names (duplicates are fine but
    will be deduplicated internally).
    """
    unique_tools = list(dict.fromkeys(t for t in tools if t))  # dedupe, preserve order
    if not unique_tools:
        return _DEFAULT_BASE_SCORE

    base = max(TOOL_BASE_SCORES.get(t, _DEFAULT_BASE_SCORE) for t in unique_tools)

    n = len(unique_tools)
    if n >= 3:
        bonus = _CONFIRMATION_BONUSES[3]
    elif n == 2:
        bonus = _CONFIRMATION_BONUSES[2]
    else:
        bonus = 0

    return min(100, base + bonus)


def tool_base_score(tool: str) -> int:
    """Return the base confidence score for a single tool."""
    return TOOL_BASE_SCORES.get(tool, _DEFAULT_BASE_SCORE)
