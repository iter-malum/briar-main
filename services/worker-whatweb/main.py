"""
WhatWeb Technology Detection Worker
=====================================
Phase: RECON (runs in parallel with Katana)
Output: detected tech stack saved as scan_results with type="technology"
        These results are later read by NucleiWorker to select relevant templates
        and by the UI service /app-info endpoint to build the Application Card.

WhatWeb aggression level 3 (--aggression 3) = active scan but not intrusive.

App Info Card output format (raw_output fields):
  technologies         - flat list of plugin names
  tech_with_versions   - {name: version_string}
  categorized          - structured dict for the App Info card:
    server             - [{name, version}]
    languages          - [{name, version}]
    frontend_libs      - [{name, version}]
    cms                - [{name, version}]
    waf                - [{name}]
    cdn                - [{name}]
    interesting_headers- {header: value}
    ip                 - str or null
    title              - str or null
    http_status        - int or null
    country            - str or null
"""

import asyncio
import json
import logging
import os
import re
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("whatweb-worker")

# ── Technology classification tables ─────────────────────────────────────────
# Keys are lowercased WhatWeb plugin names (or substrings of them).
# Order within each category matters: more specific patterns first.

_SERVER_PLUGINS = {
    "nginx":           "Nginx",
    "apache":          "Apache",
    "microsoft-iis":   "IIS",
    "iis":             "IIS",
    "tomcat":          "Tomcat",
    "jetty":           "Jetty",
    "litespeed":       "LiteSpeed",
    "caddy":           "Caddy",
    "openresty":       "OpenResty",
    "gunicorn":        "Gunicorn",
    "werkzeug":        "Werkzeug",
    "hypercorn":       "Hypercorn",
    "uvicorn":         "Uvicorn",
    "kestrel":         "Kestrel",
    "weblogic":        "WebLogic",
    "websphere":       "WebSphere",
    "httpserver":      None,   # uses raw version string, handled separately
}

_LANG_PLUGINS = {
    "php":             "PHP",
    "ruby-on-rails":   "Ruby on Rails",
    "ruby":            "Ruby",
    "python":          "Python",
    "asp.net":         "ASP.NET",
    "asp":             "ASP",
    "java":            "Java",
    "node.js":         "Node.js",
    "nodejs":          "Node.js",
    "perl":            "Perl",
    "coldfusion":      "ColdFusion",
    "go":              "Go",
    "rust":            "Rust",
}

_FRONTEND_PLUGINS = {
    "jquery":          "jQuery",
    "bootstrap":       "Bootstrap",
    "react":           "React",
    "vue.js":          "Vue.js",
    "vuejs":           "Vue.js",
    "angular":         "Angular",
    "angularjs":       "AngularJS",
    "next.js":         "Next.js",
    "nuxt.js":         "Nuxt.js",
    "svelte":          "Svelte",
    "ember.js":        "Ember.js",
    "backbone.js":     "Backbone.js",
    "mootools":        "MooTools",
    "prototype":       "Prototype",
    "dojo":            "Dojo",
    "extjs":           "ExtJS",
    "knockout.js":     "Knockout.js",
    "modernizr":       "Modernizr",
    "lodash":          "Lodash",
    "underscore.js":   "Underscore.js",
    "axios":           "Axios",
    "font-awesome":    "Font Awesome",
    "tailwind":        "Tailwind CSS",
    "foundation":      "Foundation",
    "materialize":     "Materialize",
    "semantic-ui":     "Semantic UI",
    "bulma":           "Bulma",
    "htmx":            "htmx",
    "alpine.js":       "Alpine.js",
    "alpinejs":        "Alpine.js",
    "d3.js":           "D3.js",
    "chart.js":        "Chart.js",
    "three.js":        "Three.js",
    "gsap":            "GSAP",
    "select2":         "Select2",
    "moment.js":       "Moment.js",
    "typescript":      "TypeScript",
}

_CMS_PLUGINS = {
    "wordpress":       "WordPress",
    "joomla":          "Joomla",
    "drupal":          "Drupal",
    "typo3":           "TYPO3",
    "magento":         "Magento",
    "prestashop":      "PrestaShop",
    "opencart":        "OpenCart",
    "shopify":         "Shopify",
    "wix":             "Wix",
    "squarespace":     "Squarespace",
    "dotnetnuke":      "DotNetNuke",
    "sitecore":        "Sitecore",
    "concrete5":       "Concrete5",
    "craft-cms":       "Craft CMS",
    "ghost":           "Ghost",
    "contentful":      "Contentful",
    "strapi":          "Strapi",
    "directus":        "Directus",
    "umbraco":         "Umbraco",
    "kentico":         "Kentico",
}

_WAF_PLUGINS = {
    "cloudflare":      "Cloudflare",
    "modsecurity":     "ModSecurity",
    "sucuri":          "Sucuri",
    "imperva":         "Imperva",
    "akamai":          "Akamai",
    "f5-big-ip":       "F5 BIG-IP",
    "bigip":           "F5 BIG-IP",
    "barracuda":       "Barracuda",
    "aws-waf":         "AWS WAF",
    "wordfence":       "Wordfence",
    "naxsi":           "NAXSI",
    "incapsula":       "Incapsula",
}

_CDN_PLUGINS = {
    "amazon-cloudfront": "Amazon CloudFront",
    "cloudfront":      "Amazon CloudFront",
    "fastly":          "Fastly",
    "keycdn":          "KeyCDN",
    "bunnycdn":        "BunnyCDN",
    "jsdelivr":        "jsDelivr",
    "cdnjs":           "cdnjs",
    "unpkg":           "unpkg",
}

# Headers whose value is interesting for an analyst
_INTERESTING_HEADER_PLUGINS = {
    "x-powered-by",
    "x-generator",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
    "server",
    "via",
    "set-cookie",
}

# WhatWeb plugins that carry meta info but are not tech categories
_META_PLUGINS = {
    "ip", "title", "country", "email", "http-status",
    "uncommonheaders", "redirect-location", "meta-refresh",
    "script", "script-tags", "comments", "html5",
    "cookies", "password-field", "html",
}


def _normalize_key(name: str) -> str:
    return name.lower().replace(" ", "-").replace("_", "-")


def _classify_plugin(
    name: str,
    version: str,
    raw_data: Dict,
) -> Tuple[str, Dict]:
    """
    Classify a WhatWeb plugin name into a category.
    Returns (category, {name, version}) or (None, ...) if meta/unclassified.
    category: "server" | "language" | "frontend" | "cms" | "waf" | "cdn" |
              "header" | "meta" | None
    """
    key = _normalize_key(name)
    entry = {"name": name, "version": version}

    # Meta plugins — carry IP/title/country, handled separately
    if key in _META_PLUGINS:
        return "meta", entry

    for pattern, canonical in _SERVER_PLUGINS.items():
        if pattern in key:
            if canonical is None:
                # "HTTPServer" — extract server string from version
                srv_str = version or name
                parts = srv_str.split("/", 1)
                canonical = parts[0].strip()
                entry["name"] = canonical
                entry["version"] = parts[1].strip() if len(parts) > 1 else ""
            else:
                entry["name"] = canonical
            return "server", entry

    for pattern, canonical in _LANG_PLUGINS.items():
        if pattern in key:
            entry["name"] = canonical
            return "language", entry

    for pattern, canonical in _CMS_PLUGINS.items():
        if pattern in key:
            entry["name"] = canonical
            return "cms", entry

    for pattern, canonical in _WAF_PLUGINS.items():
        if pattern in key:
            entry["name"] = canonical
            return "waf", entry

    for pattern, canonical in _CDN_PLUGINS.items():
        if pattern in key:
            entry["name"] = canonical
            return "cdn", entry

    for pattern, canonical in _FRONTEND_PLUGINS.items():
        if pattern in key:
            entry["name"] = canonical
            return "frontend", entry

    return "other", entry


def _extract_version(plugin_data: Dict) -> str:
    """Pull the best version string from a WhatWeb plugin dict."""
    if not isinstance(plugin_data, dict):
        return ""
    # "version" field is canonical; "string" is a raw match
    for key in ("version", "string"):
        val = plugin_data.get(key)
        if isinstance(val, list) and val:
            return str(val[0]).strip()
        if isinstance(val, str) and val:
            return val.strip()
    return ""


def _build_result_from_entry(entry: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
    """Convert a single WhatWeb JSON entry into a Briar result dict."""
    url = entry.get("target", target)
    plugins = entry.get("plugins", {})
    if not plugins:
        return None

    technologies: List[str] = list(plugins.keys())
    tech_with_versions: Dict[str, str] = {}

    # Categorized sections for the App Info Card
    categorized: Dict[str, Any] = {
        "server":               [],
        "languages":            [],
        "frontend_libs":        [],
        "cms":                  [],
        "waf":                  [],
        "cdn":                  [],
        "interesting_headers":  {},
        "ip":                   None,
        "title":                None,
        "http_status":          entry.get("http_status"),
        "country":              None,
    }

    seen_names: Dict[str, set] = {
        "server": set(), "languages": set(), "frontend_libs": set(),
        "cms": set(), "waf": set(), "cdn": set(),
    }

    for tech_name, tech_data in plugins.items():
        version = _extract_version(tech_data) if isinstance(tech_data, dict) else ""
        tech_with_versions[tech_name] = version
        key = _normalize_key(tech_name)

        # ── Special meta fields ────────────────────────────────────────────
        if key == "ip":
            val = _extract_version(tech_data) if isinstance(tech_data, dict) else ""
            if val:
                categorized["ip"] = val
            continue

        if key == "title":
            val = _extract_version(tech_data) if isinstance(tech_data, dict) else ""
            if val:
                categorized["title"] = val
            continue

        if key == "country":
            val = _extract_version(tech_data) if isinstance(tech_data, dict) else ""
            if val:
                categorized["country"] = val
            continue

        # ── Interesting response headers ───────────────────────────────────
        if key in _INTERESTING_HEADER_PLUGINS:
            hval = _extract_version(tech_data) if isinstance(tech_data, dict) else version
            if hval:
                categorized["interesting_headers"][tech_name.lower()] = hval
            continue

        # ── Technology classification ──────────────────────────────────────
        category, entry_dict = _classify_plugin(tech_name, version, tech_data or {})

        if category == "server":
            uname = entry_dict["name"]
            if uname not in seen_names["server"]:
                seen_names["server"].add(uname)
                categorized["server"].append(entry_dict)
        elif category == "language":
            uname = entry_dict["name"]
            if uname not in seen_names["languages"]:
                seen_names["languages"].add(uname)
                categorized["languages"].append(entry_dict)
        elif category == "cms":
            uname = entry_dict["name"]
            if uname not in seen_names["cms"]:
                seen_names["cms"].add(uname)
                categorized["cms"].append(entry_dict)
        elif category == "waf":
            uname = entry_dict["name"]
            if uname not in seen_names["waf"]:
                seen_names["waf"].add(uname)
                categorized["waf"].append(entry_dict)
        elif category == "cdn":
            uname = entry_dict["name"]
            if uname not in seen_names["cdn"]:
                seen_names["cdn"].add(uname)
                categorized["cdn"].append(entry_dict)
        elif category == "frontend":
            uname = entry_dict["name"]
            if uname not in seen_names["frontend_libs"]:
                seen_names["frontend_libs"].add(uname)
                categorized["frontend_libs"].append(entry_dict)
        # "other" and "meta" categories are ignored here — they show in tech_with_versions

    description_parts = [f"{n} {v}".strip() for n, v in tech_with_versions.items() if v]
    if not description_parts:
        description_parts = technologies[:15]

    return {
        "url": url,
        "type": "technology",
        "description": "Detected: " + ", ".join(description_parts[:20]),
        "severity": SeverityLevel.info,
        "raw_output": {
            "technologies":      technologies,
            "tech_with_versions": tech_with_versions,
            "categorized":       categorized,
            "http_status":       entry.get("http_status"),
        },
    }


class WhatWebWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="whatweb", queue_name="scan.recon.whatweb")
        self.timeout = int(os.getenv("WHATWEB_TIMEOUT", "120"))
        self.aggression = int(os.getenv("WHATWEB_AGGRESSION", "3"))

    async def execute_tool(
        self,
        target: str,
        auth_context: Dict[str, Any],
        task_payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        work_dir = "/tmp/whatweb"
        os.makedirs(work_dir, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            dir=work_dir, suffix=".json", delete=False
        ) as tf:
            out_file = tf.name

        try:
            # Choose redirect policy: plain-HTTP targets use NEW-SITE (follow
            # any redirect), HTTPS targets use HTTPS_ONLY (avoid downgrade).
            # Using HTTPS_ONLY on a plain-HTTP target prevents WhatWeb from
            # following HTTP→HTTP redirects, causing 0 plugins detected.
            follow_redirect = (
                "HTTPS_ONLY" if target.startswith("https://") else "NEW-SITE"
            )

            cmd = [
                "whatweb",
                "--no-errors",
                f"--aggression={self.aggression}",
                f"--log-json={out_file}",
                f"--follow-redirect={follow_redirect}",
                # Generic browser UA — some CDNs/WAFs block non-browser strings.
                "--user-agent=Mozilla/5.0 (compatible; Briar-Scanner/1.0)",
                # NOTE: do NOT add --quiet — it suppresses --log-json output in
                # some WhatWeb versions and causes 0 results.
                # NOTE: --color=never and --max-redirect=N do NOT exist in
                # WhatWeb 0.5.5 (Debian apt) and cause exit code 1.
            ]

            # Auth headers → Cookie flag
            cookies = auth_context.get("cookies", [])
            if cookies:
                cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
                cmd.extend(["--header", f"Cookie: {cookie_str}"])

            for key, value in auth_context.get("headers", {}).items():
                cmd.extend(["--header", f"{key}: {value}"])

            cmd.append(target)

            logger.info(f"[whatweb] Detecting tech stack: {target}")
            logger.debug(f"[whatweb] Command: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning(f"[whatweb] Timed out after {self.timeout}s")
                return []

            if process.returncode not in (0, None):
                stderr_text = stderr_data.decode("utf-8", errors="ignore").strip()
                logger.warning(
                    f"[whatweb] Exited with code {process.returncode}. stderr: {stderr_text[:300]}"
                )

            # If log-json file is empty, fall back to parsing stdout
            result = _parse_whatweb_output(out_file, target)
            if not result:
                stdout_text = stdout_data.decode("utf-8", errors="ignore").strip()
                if stdout_text:
                    logger.debug(f"[whatweb] stdout (fallback parse): {stdout_text[:200]}")
                    result = _parse_whatweb_stdout(stdout_text, target)
            return result

        except Exception as exc:
            logger.error(f"[whatweb] Execution failed: {exc}", exc_info=True)
            return []
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)


def _parse_whatweb_output(out_file: str, target: str) -> List[Dict[str, Any]]:
    try:
        with open(out_file, "r", errors="ignore") as f:
            content = f.read().strip()
        if not content:
            return []

        # WhatWeb --log-json writes one JSON object per line OR a JSON array
        entries: List[Dict[str, Any]] = []
        try:
            data = json.loads(content)
            entries = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            for line in content.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    except FileNotFoundError:
        return []

    results = [r for entry in entries if (r := _build_result_from_entry(entry, target)) is not None]
    logger.info(f"[whatweb] Detected {len(results)} tech entries for {target}")
    return results


def _parse_whatweb_stdout(stdout: str, target: str) -> List[Dict[str, Any]]:
    """
    Fallback: parse WhatWeb's human-readable stdout format.
    Example line:
      http://example.com [200 OK] Apache[2.4.41], Bootstrap[3.4.1], ...
    """
    results: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("http"):
            continue
        # Split off the URL
        parts = line.split(" ", 1)
        if len(parts) < 2:
            continue
        url = parts[0]
        rest = parts[1]

        # Extract technology names and versions
        # Matches: Apache[2.4.41] or Bootstrap or HTTPServer[Ubuntu][Apache/2.4.41]
        tech_with_versions: Dict[str, str] = {}
        technologies = []
        for match in re.finditer(r'([\w][\w\-\.]+)(?:\[([^\]]*)\])?', rest):
            name = match.group(1)
            ver = match.group(2) or ""
            if name in ("OK", "Redirect") or name.isdigit():
                continue
            technologies.append(name)
            tech_with_versions[name] = ver

        if not technologies:
            continue

        # Build minimal categorized structure from stdout parse
        categorized: Dict[str, Any] = {
            "server": [], "languages": [], "frontend_libs": [],
            "cms": [], "waf": [], "cdn": [],
            "interesting_headers": {}, "ip": None, "title": None,
            "http_status": None, "country": None,
        }
        seen: Dict[str, set] = {k: set() for k in categorized if isinstance(categorized[k], list)}
        for name, ver in tech_with_versions.items():
            category, entry_dict = _classify_plugin(name, ver, {})
            if category == "server" and entry_dict["name"] not in seen["server"]:
                seen["server"].add(entry_dict["name"])
                categorized["server"].append(entry_dict)
            elif category == "language" and entry_dict["name"] not in seen["languages"]:
                seen["languages"].add(entry_dict["name"])
                categorized["languages"].append(entry_dict)
            elif category == "cms" and entry_dict["name"] not in seen["cms"]:
                seen["cms"].add(entry_dict["name"])
                categorized["cms"].append(entry_dict)
            elif category == "waf" and entry_dict["name"] not in seen["waf"]:
                seen["waf"].add(entry_dict["name"])
                categorized["waf"].append(entry_dict)
            elif category == "cdn" and entry_dict["name"] not in seen["cdn"]:
                seen["cdn"].add(entry_dict["name"])
                categorized["cdn"].append(entry_dict)
            elif category == "frontend" and entry_dict["name"] not in seen["frontend_libs"]:
                seen["frontend_libs"].add(entry_dict["name"])
                categorized["frontend_libs"].append(entry_dict)

        results.append({
            "url": url,
            "type": "technology",
            "description": "Detected: " + ", ".join(technologies[:20]),
            "severity": SeverityLevel.info,
            "raw_output": {
                "technologies": technologies,
                "tech_with_versions": tech_with_versions,
                "categorized": categorized,
                "http_status": None,
            },
        })
    return results


async def main():
    worker = WhatWebWorker()
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
