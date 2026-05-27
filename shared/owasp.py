"""
shared/owasp.py — OWASP Top 10 2021 Mapping
=============================================
Maps Briar's canonical vulnerability classes to OWASP Top 10 2021 categories
and builds a coverage matrix from a scan's results.
"""

from __future__ import annotations
from typing import Optional

# ── OWASP Top 10 2021 ─────────────────────────────────────────────────────────

OWASP_CATEGORIES: dict[str, dict] = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": (
            "Access control enforces policy so that users cannot act outside "
            "their intended permissions. Failures lead to unauthorized data "
            "access, modification, or destruction."
        ),
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": (
            "Failures related to cryptography (or lack thereof) that often "
            "lead to exposure of sensitive data or system compromise."
        ),
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "description": (
            "User-supplied data is not validated, filtered, or sanitized. "
            "Covers SQL, NoSQL, OS command, LDAP, template, and other injections."
        ),
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": (
            "Missing or ineffective control design. Distinct from implementation "
            "failures — the controls were never built, or are fundamentally flawed."
        ),
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": (
            "Missing appropriate security hardening, permissive cloud permissions, "
            "default credentials, overly informative error messages, and similar."
        ),
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": (
            "Using components with known vulnerabilities, unsupported versions, "
            "or without checking compatibility of security implications."
        ),
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": (
            "Weaknesses in authentication, session management, or credential "
            "handling that allow attackers to compromise passwords, keys, or tokens."
        ),
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": (
            "Code and infrastructure that does not protect against integrity "
            "violations, including insecure deserialization and CI/CD pipeline issues."
        ),
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": (
            "Without logging and monitoring, breaches cannot be detected. "
            "Covers missing audit trails, unmonitored log pipelines, and more."
        ),
        "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery",
        "description": (
            "SSRF flaws occur when a web application fetches a remote resource "
            "without validating the user-supplied URL."
        ),
        "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/",
    },
}

# ── Vuln class → OWASP category mapping ───────────────────────────────────────

VULN_CLASS_TO_OWASP: dict[str, str] = {
    # A01: Broken Access Control
    "bola":            "A01",
    "auth":            "A01",
    "redirect":        "A01",
    # A02: Cryptographic Failures
    "secrets":         "A02",
    # A03: Injection
    "sqli":            "A03",
    "cmdi":            "A03",
    "ssti":            "A03",
    "lfi":             "A03",
    "xxe":             "A03",
    # A05: Security Misconfiguration
    "cors":            "A05",
    "graphql":         "A05",
    "info_disclosure": "A05",
    # A07: Identification and Authentication Failures
    "jwt":             "A07",
    "xss":             "A07",   # XSS enables session hijacking → A07 secondary; primary listing below
    # A08: Software and Data Integrity Failures
    "mass_assignment": "A08",
    # A10: Server-Side Request Forgery
    "ssrf":            "A10",
    # XSS is most commonly listed under A03 Injection in practice
    # (override the A07 entry above)
}
# XSS maps to A03 in OWASP Top 10 2021
VULN_CLASS_TO_OWASP["xss"] = "A03"


def get_owasp_category(vuln_class: str) -> Optional[str]:
    """Return the OWASP category key (e.g. 'A01') for a canonical vuln class."""
    return VULN_CLASS_TO_OWASP.get(vuln_class)


def get_owasp_info(vuln_class: str) -> Optional[dict]:
    """Return the full OWASP category dict for a vuln class, or None."""
    key = get_owasp_category(vuln_class)
    return OWASP_CATEGORIES.get(key) if key else None


# ── Coverage matrix builder ────────────────────────────────────────────────────

def build_coverage_matrix(results: list) -> dict[str, dict]:
    """
    Build an OWASP Top 10 coverage matrix from a list of ScanResultORM (or dicts
    with ``vulnerability_type`` and ``severity`` keys).

    Returns a dict keyed by OWASP category id ("A01"…"A10"), each value:
    {
        "category":  <OWASP category dict>,
        "covered":   bool,             # True if at least one finding maps here
        "findings":  [                 # list of matching findings (brief)
            {"url", "vulnerability_type", "severity", "confidence", "tool"}
        ],
        "severity_counts": {"critical": n, "high": n, "medium": n, "low": n, "info": n},
        "max_severity": str,           # highest severity found (or None)
        "confirmed_count": int,        # findings with confidence >= 70
    }
    """
    from shared.dedup import normalize_vuln_type

    # Initialise matrix
    matrix: dict[str, dict] = {}
    for key, cat in OWASP_CATEGORIES.items():
        matrix[key] = {
            "category": cat,
            "covered": False,
            "findings": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "max_severity": None,
            "confirmed_count": 0,
        }

    _SEV_ORDER = ["critical", "high", "medium", "low", "info"]

    def _sev(r) -> str:
        return (getattr(r, "severity", None) or (r.get("severity") if isinstance(r, dict) else None) or "info").lower()

    def _field(r, attr: str):
        return getattr(r, attr, None) or (r.get(attr) if isinstance(r, dict) else None)

    for r in results:
        vtype = _field(r, "vulnerability_type")
        vuln_class = normalize_vuln_type(vtype)
        owasp_key = get_owasp_category(vuln_class)
        if not owasp_key or owasp_key not in matrix:
            continue

        cell = matrix[owasp_key]
        cell["covered"] = True

        sev = _sev(r)
        if sev in cell["severity_counts"]:
            cell["severity_counts"][sev] += 1

        # Track max severity
        cur_max = cell["max_severity"]
        if cur_max is None or _SEV_ORDER.index(sev) < _SEV_ORDER.index(cur_max):
            cell["max_severity"] = sev

        confidence = _field(r, "confidence") or 50
        if confidence >= 70:
            cell["confirmed_count"] += 1

        cell["findings"].append({
            "url":              _field(r, "url") or "",
            "vulnerability_type": vtype or "",
            "severity":         sev,
            "confidence":       confidence,
            "tool":             _field(r, "tool") or "",
        })

    return matrix
