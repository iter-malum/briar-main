"""
App-Type Strategy Matrix  (M8)
==============================
Centralises per-app-type and per-framework configuration overrides for
every tool worker.  Workers call get_strategy() to receive a dict of
overrides that are MERGED on top of their own defaults — missing keys
mean "use the tool's built-in default".

Usage example (in a worker's execute_tool):
    from shared.app_strategies import get_strategy

    strategy = get_strategy(
        app_type  = task_payload.get("app_type",  "unknown"),
        tool      = "ffuf",
        framework = task_payload.get("framework"),
    )
    wordlist = strategy.get("wordlist_override") or self.wordlist_root

Why centralise here instead of per-worker env vars?
    Because the *same* WhatWeb detection drives *all* tools.  Having the
    mapping in one place ensures consistency and makes it trivial to add
    new app types without touching every worker.
"""

import re
from typing import Any, Dict, List, Optional

# ── Per-app-type strategies ─────────────────────────────────────────────────────
#
# Keys must match the "app_type" values emitted by detect_app_type():
#   "spa" | "api" | "cms" | "traditional" | "unknown"

STRATEGIES: Dict[str, Dict[str, Any]] = {

    # ── Single-Page Applications (React / Vue / Angular / Svelte …) ───────────
    "spa": {
        "katana": {
            "headless":       True,
            "headless_depth": 8,          # deep JS route traversal
            "strategy":       "breadth-first",
        },
        "zap": {
            "run_ajax_spider":        True,
            "ajax_timeout":           300,  # longer for full route discovery
            "run_traditional_spider": True,
            "run_openapi_import":     False,
        },
        "ffuf": {
            # SPAs rarely expose extension-based paths — root wordlist is best
            "strategies":            ["root"],
            "wordlist_override":     None,
        },
        "nuclei": {
            "extra_tags":      ["xss", "cors", "csp", "clickjacking", "dom"],
            "template_paths":  [],
        },
        "inspector": {
            "priority_types":  ["xss_candidate", "open_redirect"],
        },
        "gobuster": {
            "extensions": "html,js,json",
            "no_extension": True,         # SPA routes have no file extension
        },
        "arjun": {
            "methods": ["GET", "POST"],
        },
    },

    # ── REST / JSON APIs (no frontend, pure backend) ──────────────────────────
    "api": {
        "katana": {
            "headless":       False,      # no DOM to render
            "depth":          3,
        },
        "zap": {
            "run_ajax_spider":        False,   # no JS SPA — wastes time
            "run_traditional_spider": False,
            "run_openapi_import":     True,    # if spec found, use it
            "ajax_timeout":           60,
        },
        "ffuf": {
            "wordlist_override":
                "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt",
            "strategies":            ["root", "api_prefix", "idor"],
        },
        "nuclei": {
            "extra_tags":      ["api", "rest", "swagger", "auth", "token", "jwt", "ssrf"],
            "template_paths":  [],
        },
        "inspector": {
            "priority_types":  ["sqli_candidate", "cmdi_candidate", "open_redirect"],
            "inject_methods":  ["GET", "POST", "PUT", "DELETE", "PATCH"],
        },
        "gobuster": {
            "extensions": "json,yaml,xml,txt",
            "wordlist_extra":
                "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt",
        },
        "arjun": {
            "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
        },
    },

    # ── GraphQL endpoints ─────────────────────────────────────────────────────
    "graphql": {
        "katana": {
            "headless": False,
            "depth":    2,
        },
        "zap": {
            "run_ajax_spider":        False,
            "run_traditional_spider": False,
            "run_graphql_scan":       True,
            "run_openapi_import":     False,
        },
        "ffuf": {
            "wordlist_override":
                "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt",
            "strategies":            ["root", "api_prefix"],
        },
        "nuclei": {
            "extra_tags":      ["graphql", "api", "introspection"],
            "template_paths":  [],
        },
        "inspector": {
            "priority_types":  ["sqli_candidate", "cmdi_candidate"],
        },
        "gobuster": {
            "extensions": "json,graphql",
        },
        "arjun": {
            "methods": ["GET", "POST"],
        },
    },

    # ── CMS (WordPress, Drupal, Joomla, Magento …) ───────────────────────────
    "cms": {
        "katana": {
            "headless": False,
            "depth":    4,
        },
        "zap": {
            "run_ajax_spider":        True,
            "ajax_timeout":           120,
            "run_traditional_spider": True,
        },
        "ffuf": {
            "strategies": ["root"],
        },
        "nuclei": {
            "extra_tags":      ["cms", "cve", "sqli", "lfi", "auth-bypass"],
            "template_paths":  ["cms/"],
        },
        "inspector": {
            "priority_types":  ["sqli_candidate", "xss_candidate", "path_traversal"],
        },
        "gobuster": {
            "extensions": "php,html,js,txt,bak,old,zip,tar.gz,sql,log",
        },
        "arjun": {
            "methods": ["GET", "POST"],
        },
    },

    # ── Traditional server-rendered apps (PHP/MVC/ASP.NET/Rails …) ───────────
    "traditional": {
        "katana": {
            "headless": False,
            "depth":    4,
        },
        "zap": {
            "run_ajax_spider":        True,
            "ajax_timeout":           120,
            "run_traditional_spider": True,
        },
        "ffuf": {
            "strategies": ["root", "api_prefix", "idor"],
        },
        "nuclei": {
            "extra_tags":      ["sqli", "lfi", "rfi", "ssti", "rce", "injection"],
            "template_paths":  [],
        },
        "inspector": {
            "priority_types":  ["sqli_candidate", "ssti_candidate", "path_traversal"],
        },
        "gobuster": {
            # Mix of common server-side extensions — trimmed at runtime by language
            "extensions": "php,html,js,txt,aspx,jsp,do,action,xml,json,bak,old",
        },
        "arjun": {
            "methods": ["GET", "POST"],
        },
    },
}


# ── Per-framework overrides ─────────────────────────────────────────────────────
# Applied ON TOP of the app_type strategy.  Use for framework-specific tuning
# that differs meaningfully from the generic app_type defaults.
#
# Keys are normalised framework names (lowercase, no dots/spaces).
# See _normalise_framework() below.

FRAMEWORK_OVERRIDES: Dict[str, Dict[str, Any]] = {

    # ── CMS ───────────────────────────────────────────────────────────────────
    "wordpress": {
        "nuclei":   {"extra_tags": ["wordpress", "wp-plugin", "wp-theme", "cve", "cms"]},
        "gobuster": {"extensions": "php,html,js,txt,bak,old,zip,tar.gz,sql,wpress,log"},
    },
    "drupal": {
        "nuclei":   {"extra_tags": ["drupal", "cms", "cve", "sqli"]},
        "gobuster": {"extensions": "php,html,js,txt,module,install,info,yml"},
    },
    "joomla": {
        "nuclei":   {"extra_tags": ["joomla", "cms", "cve"]},
        "gobuster": {"extensions": "php,html,js,txt,xml,log"},
    },
    "magento": {
        "nuclei":   {"extra_tags": ["magento", "cms", "cve", "sqli"]},
        "gobuster": {"extensions": "php,html,js,txt,phtml"},
    },

    # ── PHP frameworks ────────────────────────────────────────────────────────
    "laravel": {
        "nuclei":    {"extra_tags": ["laravel", "php", "sqli", "lfi", "env"]},
        "gobuster":  {"extensions": "php,html,js,env,log,git,blade.php"},
        "inspector": {"priority_types": ["sqli_candidate", "ssti_candidate", "path_traversal"]},
    },
    "symfony": {
        "nuclei":    {"extra_tags": ["symfony", "php", "sqli", "lfi"]},
        "gobuster":  {"extensions": "php,html,js,env,log,yaml,yml"},
        "inspector": {"priority_types": ["sqli_candidate", "ssti_candidate"]},
    },
    "codeigniter": {
        "nuclei":    {"extra_tags": ["php", "sqli", "xss"]},
        "gobuster":  {"extensions": "php,html,js,txt"},
        "inspector": {"priority_types": ["sqli_candidate", "xss_candidate"]},
    },

    # ── Python frameworks ─────────────────────────────────────────────────────
    "django": {
        "nuclei":    {"extra_tags": ["django", "python", "ssti", "sqli"]},
        "gobuster":  {"extensions": "py,html,js,txt,log"},
        "inspector": {"priority_types": ["ssti_candidate", "sqli_candidate"]},
    },
    "flask": {
        "nuclei":    {"extra_tags": ["flask", "python", "ssti"]},
        "gobuster":  {"extensions": "py,html,js,txt"},
        "inspector": {"priority_types": ["ssti_candidate", "sqli_candidate"]},
    },
    "fastapi": {
        "nuclei":    {"extra_tags": ["fastapi", "python", "api", "swagger", "jwt"]},
        "gobuster":  {"extensions": "json,yaml"},
        "inspector": {"priority_types": ["sqli_candidate", "cmdi_candidate"]},
    },

    # ── Java frameworks ───────────────────────────────────────────────────────
    "spring": {
        "nuclei":    {"extra_tags": ["spring", "java", "actuator", "rce", "deserialization"]},
        "gobuster":  {"extensions": "jsp,do,action,html,js,json,xml,properties"},
        "inspector": {"priority_types": ["sqli_candidate", "cmdi_candidate", "ssti_candidate"]},
    },
    "springboot": {
        "nuclei":    {"extra_tags": ["spring", "java", "actuator", "rce", "cve"]},
        "gobuster":  {"extensions": "jsp,do,action,html,js,json,xml,yaml,properties"},
        "inspector": {"priority_types": ["sqli_candidate", "cmdi_candidate"]},
    },

    # ── .NET ──────────────────────────────────────────────────────────────────
    "aspnet": {
        "nuclei":    {"extra_tags": ["aspnet", "iis", "microsoft", "sqli"]},
        "gobuster":  {"extensions": "aspx,asp,ashx,asmx,html,js,txt,bak,config,web.config"},
        "inspector": {"priority_types": ["sqli_candidate", "xss_candidate"]},
    },

    # ── Ruby ──────────────────────────────────────────────────────────────────
    "rails": {
        "nuclei":    {"extra_tags": ["rails", "ruby", "sqli", "ssti"]},
        "gobuster":  {"extensions": "rb,html,js,txt,json,erb"},
        "inspector": {"priority_types": ["sqli_candidate", "ssti_candidate"]},
    },

    # ── SPA frameworks (additional depth, same base as "spa" type) ───────────
    "react": {
        "katana":    {"headless": True, "headless_depth": 8},
        "inspector": {"priority_types": ["xss_candidate", "open_redirect"]},
    },
    "angular": {
        "katana":    {"headless": True, "headless_depth": 8},
        "inspector": {"priority_types": ["xss_candidate", "open_redirect"]},
    },
    "vuejs": {
        "katana":    {"headless": True, "headless_depth": 8},
        "inspector": {"priority_types": ["xss_candidate", "open_redirect"]},
    },
    "nextjs": {
        "katana":    {"headless": True, "headless_depth": 8},
        "nuclei":    {"extra_tags": ["xss", "cors", "nextjs"]},
    },
}


# ── Public API ──────────────────────────────────────────────────────────────────

def get_strategy(
    app_type:  str,
    tool:      str,
    framework: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return the merged strategy config for (app_type, tool, framework).

    Merge order (later wins):
      1. Tool defaults (not handled here — done by the worker itself)
      2. app_type strategy
      3. Framework override (if framework is known)

    Returns {} if no strategy / override is defined for the combination —
    workers interpret this as "use your own defaults".

    Example:
        get_strategy("traditional", "gobuster", "Django")
        → {"extensions": "php,html,..."}   ← from traditional
          merged with
          {"extensions": "py,html,..."}    ← from django override
          = {"extensions": "py,html,..."}  ← django wins
    """
    base: Dict[str, Any] = dict(
        STRATEGIES.get(app_type or "unknown", {}).get(tool, {})
    )

    if framework:
        fw_key = _normalise_framework(framework)
        # Try progressively shorter variants so "Spring Boot" finds "spring"
        candidates = _framework_key_variants(fw_key, framework)
        for key in candidates:
            override = FRAMEWORK_OVERRIDES.get(key, {}).get(tool, {})
            if override:
                # Deep-merge lists (extra_tags, template_paths)
                merged: Dict[str, Any] = dict(base)
                for k, v in override.items():
                    if (
                        k in merged
                        and isinstance(merged[k], list)
                        and isinstance(v, list)
                    ):
                        # Union of lists (e.g. extra_tags)
                        merged[k] = list(dict.fromkeys(merged[k] + v))
                    else:
                        merged[k] = v
                return merged

    return base


def get_nuclei_tags(
    app_type:   str,
    framework:  Optional[str],
    tech_stack: Optional[List[str]] = None,
) -> List[str]:
    """
    Convenience helper — returns the full Nuclei tag list for a scan,
    combining app_type strategy tags, framework override tags, and
    tech_stack keywords mapped via TECH_TO_NUCLEI_TAGS.

    Always includes OWASP Top-10 critical categories as a baseline.
    """
    from shared.pipeline import TECH_TO_NUCLEI_TAGS

    tags: set = {"xss", "sqli", "rce", "ssrf", "lfi", "idor", "xxe"}

    strategy = get_strategy(app_type, "nuclei", framework)
    tags.update(strategy.get("extra_tags", []))

    if tech_stack:
        for kw in tech_stack:
            kw_lower = kw.lower()
            for key, tag_list in TECH_TO_NUCLEI_TAGS.items():
                if key in kw_lower:
                    tags.update(tag_list)

    return sorted(tags)


# ── Internal helpers ────────────────────────────────────────────────────────────

def _normalise_framework(framework: str) -> str:
    """
    Normalise a framework name for dict lookup.
    "Spring Boot" → "springboot",  "Vue.js" → "vuejs",  "ASP.NET" → "aspnet"
    """
    return re.sub(r"[^a-z0-9]", "", framework.lower())


def _framework_key_variants(normalised: str, original: str) -> List[str]:
    """
    Return a list of key candidates to try for the framework override lookup.
    Ordered from most-specific to least-specific.
    """
    candidates = [normalised]
    # Underscore variant: "spring_boot"
    under = re.sub(r"[^a-z0-9]", "_", original.lower()).strip("_")
    if under not in candidates:
        candidates.append(under)
    # First word only: "spring boot" → "spring"
    first = original.lower().split()[0] if original.split() else ""
    first_clean = re.sub(r"[^a-z0-9]", "", first)
    if first_clean and first_clean not in candidates:
        candidates.append(first_clean)
    return candidates
