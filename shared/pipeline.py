"""
Briar Pipeline Definition
=========================
Defines the 4-phase pentesting pipeline and helpers for the orchestrator's
event-driven state machine.

Pipeline flow:
  Phase 1 – RECON:   whatweb + katana                       (start immediately, parallel)
  Phase 2 – PROBE:   httpx + ffuf + gobuster + arjun        (after katana, parallel)
  Phase 3 – DAST:    nuclei + zap + nikto + dalfox          (after all probe tools, parallel)
  Phase 4 – EXPLOIT: sqlmap                                 (after nuclei/zap, only if SQLi found
                                                             AND scan.config.exploit_enabled=true)

Phases whose trigger tools are not in the scan's selected set are skipped
automatically, so e.g. selecting ["katana","nuclei"] works correctly.
The trigger_after check only counts tools that were actually selected for the scan.
"""

from typing import Dict, List, Optional, Set

# ── Queue routing table ────────────────────────────────────────────────────────

TOOL_QUEUES: Dict[str, str] = {
    "whatweb":  "scan.recon.whatweb",
    "katana":   "scan.crawl.katana",
    "httpx":    "scan.probe.httpx",
    "ffuf":     "scan.fuzz.ffuf",
    "gobuster": "scan.probe.gobuster",
    "arjun":    "scan.probe.arjun",
    "nuclei":   "scan.dast.nuclei",
    "zap":      "scan.dast.zap",
    "nikto":    "scan.dast.nikto",
    "dalfox":   "scan.dast.dalfox",
    "sqlmap":   "scan.exploit.sqlmap",
}

# ── Technology → Nuclei template tags ─────────────────────────────────────────

TECH_TO_NUCLEI_TAGS: Dict[str, List[str]] = {
    "wordpress":   ["wordpress", "cms"],
    "joomla":      ["joomla", "cms"],
    "drupal":      ["drupal", "cms"],
    "apache":      ["apache"],
    "nginx":       ["nginx"],
    "php":         ["php"],
    "mysql":       ["mysql", "sqli"],
    "postgresql":  ["postgresql", "sqli"],
    "mssql":       ["mssql", "sqli"],
    "tomcat":      ["apache", "java"],
    "iis":         ["iis", "microsoft"],
    "django":      ["django", "python"],
    "laravel":     ["laravel", "php"],
    "spring":      ["spring", "java"],
    "nodejs":      ["nodejs", "javascript"],
    "react":       ["xss", "javascript"],
    "angular":     ["xss", "javascript"],
    "jquery":      ["jquery", "javascript"],
}

# ── SQLi template / alert patterns for exploit trigger ────────────────────────

SQLI_INDICATORS = [
    "sql", "sqli", "sql-injection", "injection",
    "error-based", "time-based", "boolean-based",
    "mysql-error", "postgre-error", "mssql-error",
]

# ── Pipeline phase definitions ─────────────────────────────────────────────────
#
# Each phase:
#   id              – human-readable phase name
#   tools           – set of tools that belong to this phase
#   trigger_after   – set of tools whose completion unlocks this phase
#                     (empty = start immediately)
#   source_tools    – dict[tool → list of tools that provide endpoints]
#   requires_explicit – must be opt-in via scan.config.exploit_enabled
#   requires_sqli   – phase only runs if SQLi findings exist

PHASES: List[Dict] = [
    {
        "id": "recon",
        "tools": {"whatweb", "katana"},
        "trigger_after": set(),          # Start immediately
        "source_tools": {},              # Use original target URL
        "requires_explicit": False,
        "requires_sqli": False,
    },
    {
        "id": "probe",
        "tools": {"httpx", "ffuf", "gobuster", "arjun"},
        "trigger_after": {"katana"},     # Unlock when katana done
        "source_tools": {
            "httpx":    ["katana"],
            "ffuf":     ["katana"],
            "gobuster": ["katana"],
            "arjun":    ["katana"],  # Uses crawled endpoints; httpx/ffuf run in parallel
        },
        "requires_explicit": False,
        "requires_sqli": False,
    },
    {
        "id": "dast",
        "tools": {"nuclei", "zap", "nikto", "dalfox"},
        "trigger_after": {"httpx", "ffuf", "gobuster", "arjun"},  # Unlock when all probe tools done
        "source_tools": {
            # Use ALL discovered endpoints: katana + ffuf + gobuster + httpx
            "nuclei":  ["katana", "ffuf", "gobuster", "httpx"],
            "zap":     ["katana", "ffuf", "gobuster", "httpx"],
            "nikto":   ["katana", "httpx"],  # Nikto works per-host
            "dalfox":  ["katana", "ffuf", "gobuster", "httpx", "arjun"],  # Needs params
        },
        "requires_explicit": False,
        "requires_sqli": False,
    },
    {
        "id": "exploit",
        "tools": {"sqlmap"},
        "trigger_after": {"nuclei", "zap"},
        "source_tools": {
            "sqlmap": ["nuclei", "zap"],     # Only SQLi-positive endpoints
        },
        "requires_explicit": True,           # scan.config.exploit_enabled = true
        "requires_sqli": True,               # Must have confirmed SQLi
    },
]


# ── Helper functions ───────────────────────────────────────────────────────────

def get_phase(tool: str) -> Optional[Dict]:
    """Return the phase dict that contains this tool, or None."""
    for phase in PHASES:
        if tool in phase["tools"]:
            return phase
    return None


def should_trigger_phase(
    phase: Dict,
    completed_tools: Set[str],
    selected_tools: Set[str],
) -> bool:
    """
    Returns True if this phase should be published now.

    Rules:
    - At least one of its tools is in selected_tools
    - None of its tools have been completed yet (not already started)
    - All trigger_after tools that are in selected_tools have completed
    """
    phase_tools = phase["tools"] & selected_tools
    if not phase_tools:
        return False  # Nothing from this phase was selected

    # Already started: some phase tool has completed or is running
    if phase_tools & completed_tools:
        return False

    # Evaluate dependencies — only count triggers that were actually selected
    deps = phase["trigger_after"] & selected_tools
    if deps and not deps.issubset(completed_tools):
        return False  # Still waiting

    return True


def is_scan_complete(selected_tools: Set[str], completed_tools: Set[str]) -> bool:
    """True when every selected tool has a terminal status (completed or failed)."""
    return selected_tools.issubset(completed_tools)


def get_tools_for_initial_publish(selected_tools: Set[str]) -> List[str]:
    """Returns the tools from the recon phase that are in selected_tools."""
    phase = PHASES[0]  # recon
    return list(phase["tools"] & selected_tools)
