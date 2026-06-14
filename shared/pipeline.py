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

M8: App-type auto-detection
  After RECON, WhatWeb results are inspected.  A detected technology stack
  (SPA framework, language, CMS, API, etc.) is embedded in every subsequent
  task payload so workers can tune their strategy accordingly.
"""

from typing import Dict, List, Optional, Set

# ── Queue routing table ────────────────────────────────────────────────────────

TOOL_QUEUES: Dict[str, str] = {
    "whatweb":   "scan.recon.whatweb",
    "katana":    "scan.crawl.katana",
    "httpx":     "scan.probe.httpx",
    "gobuster":  "scan.probe.gobuster",
    "ffuf":      "scan.fuzz.ffuf",
    "arjun":     "scan.probe.arjun",
    "inspector": "scan.inspect.inspector",
    "nuclei":    "scan.dast.nuclei",
    "zap":       "scan.dast.zap",
    "nikto":     "scan.dast.nikto",
    "dalfox":    "scan.dast.dalfox",
    "sqlmap":    "scan.exploit.sqlmap",
    # ── M9: New exploit / verification workers ────────────────────────────────
    "tplmap":   "scan.exploit.tplmap",
    "commix":   "scan.exploit.commix",
    "jwt_tool": "scan.dast.jwt_tool",
    # ── M10: Discovery intelligence ────────────────────────────────────────────
    "graphql":    "scan.dast.graphql",
    "openapi":    "scan.dast.openapi",
    "jsscanner":  "scan.probe.jsscanner",
    # ── M11: Access control testing ────────────────────────────────────────────
    "cors":       "scan.dast.cors",
    "bola":       "scan.dast.bola",
}

# ── M7: Finding Router — finding type → tool routing table ────────────────────
#
# Each entry maps a vulnerability_type emitted by a worker to the tool that
# should be triggered immediately when that finding appears.
#
# requires_exploit = True  → only route when scan.config.exploit_enabled = True
# requires_exploit = False → always route (confirmation/verification tools)
#
# M9: tplmap, commix, jwt_tool deployed.
# M10: graphql, openapi, jsscanner deployed.
# The router silently skips entries whose tool is not yet in TOOL_QUEUES,
# accumulating candidates that are dispatched once the worker comes online.

FINDING_ROUTES: Dict[str, Dict] = {
    # ── Inspector / DAST candidates → exploitation ───────────────────────────
    "sqli_candidate": {
        "tool":             "sqlmap",
        "requires_exploit": True,
        "description":      "SQL injection surface → sqlmap exploitation",
    },
    # ── Inspector candidates → verification (non-exploitative) ───────────────
    "xss_candidate": {
        "tool":             "dalfox",
        "requires_exploit": False,
        "description":      "XSS reflection surface → dalfox payload crafting",
    },
    # ── M9: SSTI + CMDi exploitation ─────────────────────────────────────────
    "ssti_candidate": {
        "tool":             "tplmap",
        "requires_exploit": True,
        "description":      "SSTI surface → tplmap engine detection + RCE confirmation",
    },
    "cmdi_candidate": {
        "tool":             "commix",
        "requires_exploit": True,
        "description":      "Command injection surface → commix confirmation",
    },
    # ── M9: JWT security testing (non-exploitative) ───────────────────────────
    "jwt_found": {
        "tool":             "jwt_tool",
        "requires_exploit": False,
        "description":      "JWT token detected → jwt_tool security tests",
    },
    # ── M10: API discovery intelligence ──────────────────────────────────────
    "graphql_found": {
        "tool":             "graphql",
        "requires_exploit": False,
        "description":      "GraphQL endpoint → introspection + 8-test security battery",
    },
    "swagger_found": {
        "tool":             "openapi",
        "requires_exploit": False,
        "description":      "OpenAPI spec found → spec-driven auth/BOLA/mass-assignment testing",
    },
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
    # ZAP active scan rule IDs for SQL injection variants
    "zap-40018",   # SQL Injection
    "zap-40019",   # SQL Injection - MySQL
    "zap-40020",   # SQL Injection - Hypersonic SQL
    "zap-40021",   # SQL Injection - Oracle
    "zap-40022",   # SQL Injection - PostgreSQL
    "zap-40024",   # SQL Injection - SQLite
    "40018", "40019", "40020", "40021", "40022", "40024",
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
    # ── Phase 1: RECON ────────────────────────────────────────────────────────
    # katana discovers all endpoints (SPA crawl + passive gau + JS extraction).
    # whatweb fingerprints the tech stack for adaptive strategy in later phases.
    # Both run immediately in parallel.
    {
        "id": "recon",
        "tools": {"whatweb", "katana"},
        "trigger_after": set(),
        "source_tools": {},              # Use original scan target URL
        "requires_explicit": False,
        "requires_sqli": False,
    },

    # ── Phase 2: PROBE (URL validation) ──────────────────────────────────────
    # httpx probes every URL katana and gobuster found, stamping each with an
    # HTTP status code.  This creates the "live endpoint" list that ffuf, arjun,
    # and all DAST tools filter from.
    # gobuster brute-forces directory paths in parallel with httpx — both run
    # as soon as katana finishes (gobuster doesn't need live-URL filtering;
    # it works against the base host).
    {
        "id": "probe",
        "tools": {"httpx", "gobuster", "jsscanner"},
        "trigger_after": {"katana"},
        "source_tools": {
            "httpx":     ["katana"],
            "gobuster":  ["katana"],
            # M10: jsscanner gets .js URLs from katana for secret detection
            "jsscanner": ["katana"],
        },
        "requires_explicit": False,
        "requires_sqli": False,
    },

    # ── Phase 3: SMART FUZZ ───────────────────────────────────────────────────
    # ffuf and arjun both run AFTER httpx so they operate on httpx-confirmed
    # live endpoints (2xx/3xx) only — not raw katana/gobuster URLs that may
    # include thousands of 404s.
    #
    # ffuf runs three strategies in parallel:
    #   ROOT       – /FUZZ on every host (broad directory discovery)
    #   API PREFIX – extract API mount points from live URLs, fuzz each prefix
    #   IDOR       – replace integer segments with FUZZ, enumerate 1-2000
    #
    # arjun discovers hidden HTTP parameters on live endpoints.
    # source_tools includes httpx so the live-endpoint filter activates.
    {
        "id": "fuzz",
        "tools": {"ffuf", "arjun"},
        "trigger_after": {"httpx", "gobuster"},
        "source_tools": {
            "ffuf":  ["katana", "gobuster", "httpx"],  # httpx triggers live filter
            "arjun": ["katana", "httpx"],               # httpx triggers live filter
        },
        "requires_explicit": False,
        "requires_sqli": False,
    },

    # ── Phase 4: INSPECT ──────────────────────────────────────────────────────
    # Smart pre-exploitation triage.  Runs AFTER arjun has discovered hidden
    # parameters.  Inspector sends lightweight canary payloads to each
    # (endpoint, parameter) pair and emits structured candidates:
    #   sqli_candidate   → sqlmap
    #   ssti_candidate   → tplmap
    #   cmdi_candidate   → commix
    #   path_traversal   → nuclei (targeted)
    #   open_redirect    → nuclei (targeted)
    #   xss_candidate    → dalfox (targeted)
    #
    # DAST tools (phase 5) run in PARALLEL with inspect — they do broad
    # coverage; inspector does targeted depth.  Both feed the exploit phase.
    {
        "id": "inspect",
        "tools": {"inspector"},
        "trigger_after": {"arjun"},
        "source_tools": {
            # httpx triggers live-endpoint filter; arjun provides discovered params
            "inspector": ["katana", "httpx", "ffuf", "gobuster", "arjun"],
        },
        "requires_explicit": False,
        "requires_sqli": False,
    },

    # ── Phase 5: DAST ─────────────────────────────────────────────────────────
    # Broad active scanning runs in parallel with the inspect phase.
    # DAST tools have the most complete, validated endpoint list.
    # source_tools covers every discovery source so the live-URL filter can
    # pick the best confirmed-alive subset for each tool.
    #
    # jwt_tool is non-exploitative (requires_exploit=False in FINDING_ROUTES)
    # and runs in DAST phase.  It probes the target for JWT exposure and
    # tests algorithm-confusion + "none" alg + weak-secret flaws.  Juice Shop
    # and most modern Node apps use JWT — jwt_tool provides real coverage here.
    {
        "id": "dast",
        "tools": {"nuclei", "zap", "nikto", "dalfox", "cors", "bola", "jwt_tool"},
        "trigger_after": {"httpx", "ffuf", "gobuster"},
        "source_tools": {
            "nuclei":   ["katana", "ffuf", "gobuster", "httpx"],
            "zap":      ["katana", "ffuf", "gobuster", "httpx"],
            "nikto":    ["katana", "httpx"],
            "dalfox":   ["katana", "ffuf", "gobuster", "httpx", "arjun"],
            "cors":     ["katana", "ffuf", "gobuster", "httpx"],
            "bola":     ["katana", "ffuf", "gobuster", "httpx", "arjun"],
            # jwt_tool needs the live endpoint list to find JWT-bearing responses
            "jwt_tool": ["katana", "httpx"],
            # graphql/openapi are finding-triggered (via finding_router), not phase-triggered
        },
        "requires_explicit": False,
        "requires_sqli": False,
    },

    # ── Phase 6: EXPLOIT ──────────────────────────────────────────────────────
    # Triggered by confirmed findings from DAST + Inspector.
    #
    # sqlmap — SQL injection exploitation (requires SQLi finding in DB).
    # tplmap — SSTI exploitation (requires ssti_candidate finding).
    # commix — OS command injection (requires cmdi_candidate finding).
    #
    # All three require exploit_enabled=True.
    # The requires_sqli guard is intentionally applied to the entire phase to
    # prevent exploit tools from running on clean scans — tplmap/commix will
    # simply find no applicable endpoints from their source tools if no
    # candidates were emitted by inspector, so the cost is only one empty run.
    {
        "id": "exploit",
        "tools": {"sqlmap", "tplmap", "commix"},
        "trigger_after": {"nuclei", "zap", "inspector"},
        "source_tools": {
            "sqlmap": ["nuclei", "zap", "inspector"],
            # tplmap + commix get their specific target from the finding_router
            # payload injected by _publish_phase → they use inspector findings
            "tplmap":  ["inspector"],
            "commix":  ["inspector"],
        },
        "requires_explicit": True,
        "requires_sqli": False,   # sqlmap checks SQLi itself; tplmap/commix have own guards
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


# ── M8: App-type auto-detection ───────────────────────────────────────────────
#
# Maps technology keyword (lowercased) → detected capabilities.
# "app_type" can be one of: "spa", "api", "cms", "traditional", "unknown"
# "is_spa" drives headless depth / AJAX spider decisions in workers.

APP_TYPE_SIGNATURES: Dict[str, Dict] = {
    # SPA frameworks — must enable headless/AJAX strategies
    "react":          {"app_type": "spa", "is_spa": True,  "framework": "React"},
    "vue.js":         {"app_type": "spa", "is_spa": True,  "framework": "Vue.js"},
    "vuejs":          {"app_type": "spa", "is_spa": True,  "framework": "Vue.js"},
    "angular":        {"app_type": "spa", "is_spa": True,  "framework": "Angular"},
    "next.js":        {"app_type": "spa", "is_spa": True,  "framework": "Next.js"},
    "nuxt.js":        {"app_type": "spa", "is_spa": True,  "framework": "Nuxt.js"},
    "svelte":         {"app_type": "spa", "is_spa": True,  "framework": "Svelte"},
    "ember.js":       {"app_type": "spa", "is_spa": True,  "framework": "Ember.js"},
    "backbone.js":    {"app_type": "spa", "is_spa": True,  "framework": "Backbone.js"},
    "gatsby":         {"app_type": "spa", "is_spa": True,  "framework": "Gatsby"},
    # API backends — focus on endpoint fuzzing + auth testing
    "graphql":        {"app_type": "api", "is_spa": False, "framework": "GraphQL"},
    "rest":           {"app_type": "api", "is_spa": False, "framework": "REST"},
    "swagger":        {"app_type": "api", "is_spa": False, "framework": "OpenAPI"},
    "openapi":        {"app_type": "api", "is_spa": False, "framework": "OpenAPI"},
    "fastapi":        {"app_type": "api", "is_spa": False, "framework": "FastAPI"},
    "django rest":    {"app_type": "api", "is_spa": False, "framework": "DRF"},
    "spring boot":    {"app_type": "api", "is_spa": False, "framework": "Spring Boot"},
    # CMS — template-driven with known vuln patterns
    "wordpress":      {"app_type": "cms", "is_spa": False, "framework": "WordPress"},
    "joomla":         {"app_type": "cms", "is_spa": False, "framework": "Joomla"},
    "drupal":         {"app_type": "cms", "is_spa": False, "framework": "Drupal"},
    "magento":        {"app_type": "cms", "is_spa": False, "framework": "Magento"},
    "shopify":        {"app_type": "cms", "is_spa": False, "framework": "Shopify"},
    # Node.js / Express ecosystem — treat as SPA+API target
    # Juice Shop and many modern apps expose Express + Angular together.
    # Detecting Express as `app_type=spa` ensures headless AJAX crawling,
    # correct nuclei tags (nodejs/express), and no traditional-spider explosions.
    "express":        {"app_type": "spa", "is_spa": True,  "framework": "Express"},
    "node.js":        {"app_type": "spa", "is_spa": True,  "framework": "Node.js"},
    "socket.io":      {"app_type": "spa", "is_spa": True,  "framework": "Node.js"},
    "connect.sid":    {"app_type": "spa", "is_spa": True,  "framework": "Express"},
    # Traditional MVC — server-rendered, good for standard DAST
    "php":            {"app_type": "traditional", "is_spa": False, "lang": "PHP"},
    "laravel":        {"app_type": "traditional", "is_spa": False, "framework": "Laravel"},
    "symfony":        {"app_type": "traditional", "is_spa": False, "framework": "Symfony"},
    "codeigniter":    {"app_type": "traditional", "is_spa": False, "framework": "CodeIgniter"},
    "asp.net":        {"app_type": "traditional", "is_spa": False, "lang": "ASP.NET"},
    "ruby on rails":  {"app_type": "traditional", "is_spa": False, "framework": "Rails"},
    "django":         {"app_type": "traditional", "is_spa": False, "framework": "Django"},
    "flask":          {"app_type": "traditional", "is_spa": False, "framework": "Flask"},
}


def detect_app_type(whatweb_raw_outputs: List[Dict]) -> Dict:
    """
    Inspect a list of WhatWeb result dicts (raw_output fields from scan_results)
    and return a classification dict:

      {
        "app_type":   "spa" | "api" | "cms" | "traditional" | "unknown",
        "is_spa":     bool,
        "framework":  str | None,
        "tech_stack": [str, ...],   # all detected tech keywords
      }
    """
    tech_stack: List[str] = []

    for result in whatweb_raw_outputs:
        # WhatWeb raw_output may be a dict with plugin names as keys
        if isinstance(result, dict):
            for key in result:
                tech_stack.append(key.lower())
                # Also check string values for version hints
                val = result[key]
                if isinstance(val, str):
                    tech_stack.append(val.lower())
                elif isinstance(val, list):
                    for v in val:
                        if isinstance(v, str):
                            tech_stack.append(v.lower())

            # New WhatWebWorker format stores categorized tech in a nested structure.
            # Read language, frontend library, and server names from it so that
            # Node.js / Angular / Express detected there are visible to the keyword matcher.
            categorized = result.get("categorized")
            if isinstance(categorized, dict):
                for section in ("languages", "frontend_libs", "server"):
                    for entry in categorized.get(section, []):
                        if isinstance(entry, dict):
                            name = entry.get("name", "")
                            if name:
                                tech_stack.append(name.lower())
                title = categorized.get("title")
                if isinstance(title, str) and title:
                    tech_stack.append(title.lower())

    tech_text = " ".join(tech_stack)

    # Highest-priority match wins
    # Order matters: SPA > API > CMS > Traditional
    for keyword, classification in APP_TYPE_SIGNATURES.items():
        if keyword in tech_text:
            return {
                "app_type":  classification["app_type"],
                "is_spa":    classification["is_spa"],
                "framework": classification.get("framework") or classification.get("lang"),
                "tech_stack": list(set(tech_stack))[:30],  # cap for payload size
            }

    return {
        "app_type":  "unknown",
        "is_spa":    False,
        "framework": None,
        "tech_stack": list(set(tech_stack))[:30],
    }
