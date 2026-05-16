"""
Briar Tool Definitions Registry
================================
Three groups of tools:
  GROUP 1 — RECON: Endpoint discovery + technology fingerprinting
  GROUP 2 — DAST:  Dynamic analysis and vulnerability exploitation
  GROUP 3 — SMART: Intelligent orchestration based on findings

Each tool has:
  - id: unique key matching the worker queue name
  - name: display name
  - group: 'recon' | 'dast' | 'smart'
  - description: what it does
  - emoji: icon character for UI
  - color: tailwind color class for card accent
  - available: whether a worker exists (False = planned/coming soon)
  - params: list of configurable parameters
"""

from typing import List, Dict, Any

TOOL_GROUPS = {
    "recon": {
        "label": "Reconnaissance & Discovery",
        "description": "Discover endpoints, map application structure, fingerprint technologies",
        "color": "blue",
    },
    "dast": {
        "label": "Dynamic Analysis (DAST)",
        "description": "Exploit vulnerabilities using discovered endpoints and application context",
        "color": "orange",
    },
    "smart": {
        "label": "Smart Orchestration",
        "description": "AI-driven analysis that chains tools based on findings",
        "color": "purple",
    },
}

def _param(key, label, description, type_, default, **kwargs):
    return {"key": key, "label": label, "description": description,
            "type": type_, "default": default, "value": default, **kwargs}

TOOL_DEFINITIONS: List[Dict[str, Any]] = [

    # ═══════════════════════════════════════════════════════════════
    # GROUP 1: RECON
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "whatweb",
        "name": "WhatWeb",
        "group": "recon",
        "emoji": "🔍",
        "color": "blue",
        "available": True,
        "description": "Fingerprints web technologies: CMS, frameworks, server software, libraries, analytics. Identifies versions and maps to known CVEs.",
        "params": [
            _param("aggression", "Aggression Level", "1=stealthy (1 request), 3=standard, 4=aggressive (many requests). Higher finds more but is noisier.", "select", "3", options=["1","2","3","4"]),
            _param("timeout", "Request Timeout (s)", "Max seconds to wait for each HTTP response.", "number", "120", min=10, max=600),
            _param("max_redirects", "Max Redirects", "Maximum number of HTTP redirects to follow.", "number", "10", min=0, max=30),
            _param("user_agent", "User-Agent", "Custom User-Agent header. Leave empty for default.", "string", ""),
        ],
    },

    {
        "id": "katana",
        "name": "Katana",
        "group": "recon",
        "emoji": "🕸️",
        "color": "blue",
        "available": True,
        "description": "Fast JavaScript-aware web crawler by ProjectDiscovery. Crawls links, forms, APIs. Extracts endpoints from HTML, JS bundles, robots.txt, sitemap.xml. Supports headless mode for SPA applications.",
        "params": [
            _param("depth", "Crawl Depth", "Maximum depth to crawl from the starting URL. Higher values discover more endpoints but take longer.", "number", "3", min=1, max=10),
            _param("concurrency", "Concurrency", "Number of concurrent browser tabs / HTTP requests.", "number", "10", min=1, max=50),
            _param("rate_limit", "Rate Limit (req/s)", "Maximum requests per second to avoid overwhelming the target.", "number", "100", min=1, max=1000),
            _param("timeout", "Request Timeout (s)", "Timeout per HTTP request in seconds.", "number", "15", min=5, max=60),
            _param("js_crawl", "JavaScript Crawling", "Parse and execute JavaScript to discover dynamically loaded endpoints. Essential for React/Vue/Angular apps.", "boolean", True),
            _param("form_extract", "Form Extraction", "Extract and map HTML form fields including hidden inputs. Captures POST endpoint schemas.", "boolean", True),
            _param("known_files", "Known Files", "Check common paths: robots.txt, sitemap.xml, /.well-known/*, /api/swagger.json, /openapi.json, etc.", "boolean", True),
            _param("headless", "Headless Mode", "Use a full Chromium browser for JavaScript-heavy SPAs. Slower but finds more endpoints in complex apps.", "boolean", True),
            _param("passive_gau", "Passive Discovery (gau)", "Supplement active crawling with historical URLs from Wayback Machine, CommonCrawl, and AlienVault OTX.", "boolean", True),
        ],
    },

    {
        "id": "httpx",
        "name": "HTTPX",
        "group": "recon",
        "emoji": "🌐",
        "color": "blue",
        "available": True,
        "description": "HTTP probe by ProjectDiscovery. Validates discovered endpoints, detects HTTP status codes, titles, content types, server headers, technologies, and TLS info. Filters live endpoints for DAST tools.",
        "params": [
            _param("threads", "Threads", "Concurrent HTTP requests. High values speed up probing but may trigger rate limits.", "number", "50", min=1, max=200),
            _param("rate_limit", "Rate Limit (req/s)", "Maximum requests per second.", "number", "200", min=1, max=2000),
            _param("timeout", "Timeout (s)", "HTTP request timeout in seconds.", "number", "10", min=3, max=60),
            _param("follow_redirects", "Follow Redirects", "Follow HTTP 301/302 redirects to final destination.", "boolean", True),
            _param("max_redirects", "Max Redirects", "Maximum redirect chain length before stopping.", "number", "10", min=1, max=20),
            _param("tech_detect", "Technology Detection", "Run technology fingerprinting on each probed endpoint.", "boolean", True),
            _param("screenshot", "Screenshots", "Capture screenshots of web pages (requires headless browser). Useful for visual inspection.", "boolean", False),
        ],
    },

    {
        "id": "ffuf",
        "name": "FFUF",
        "group": "recon",
        "emoji": "🔨",
        "color": "blue",
        "available": True,
        "description": "Fast web fuzzer for directory and file discovery. Brute-forces paths using wordlists. Identifies hidden endpoints, admin panels, API routes, backup files, and configuration files.",
        "params": [
            _param("wordlist", "Wordlist Path", "Path to the wordlist file inside the container. SecLists wordlists are pre-installed.", "select", "/usr/share/seclists/Discovery/Web-Content/common.txt", options=[
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
                "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
                "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                "/usr/share/seclists/Discovery/Web-Content/big.txt",
            ]),
            _param("extensions", "File Extensions", "Comma-separated list of extensions to append to each wordlist entry.", "string", "php,asp,aspx,jsp,html,js,json,xml,txt,bak,old,zip"),
            _param("threads", "Threads", "Number of concurrent fuzzing threads.", "number", "40", min=1, max=200),
            _param("rate", "Rate Limit (req/s)", "Maximum requests per second.", "number", "1000", min=1, max=5000),
            _param("timeout", "Timeout (s)", "HTTP request timeout.", "number", "10", min=3, max=60),
            _param("filter_status", "Filter Status Codes", "Comma-separated HTTP status codes to hide from results (negative filter).", "string", "404,400,500"),
            _param("match_status", "Match Status Codes", "Only show these HTTP status codes. Leave empty to show all non-filtered.", "string", ""),
            _param("follow_redirects", "Follow Redirects", "Follow HTTP redirects to final URL.", "boolean", False),
        ],
    },

    {
        "id": "gobuster",
        "name": "Gobuster",
        "group": "recon",
        "emoji": "💥",
        "color": "blue",
        "available": True,
        "description": "Directory/file, DNS subdomain, and virtual host brute-forcer. Complements FFUF with DNS and VHost enumeration modes — discovers subdomains and virtual hosts on the same IP address.",
        "params": [
            _param("mode", "Mode", "dir=directory brute-force, dns=subdomain discovery, vhost=virtual host discovery.", "select", "dir", options=["dir","dns","vhost"]),
            _param("wordlist", "Wordlist Path", "Path to the wordlist file.", "select", "/usr/share/seclists/Discovery/Web-Content/common.txt", options=[
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/seclists/Discovery/DNS/namelist.txt",
            ]),
            _param("threads", "Threads", "Number of concurrent threads.", "number", "20", min=1, max=100),
            _param("timeout", "Timeout (s)", "HTTP/DNS request timeout.", "number", "10", min=3, max=30),
            _param("extensions", "Extensions (dir mode)", "File extensions for directory mode.", "string", "php,html,js,txt"),
        ],
    },

    {
        "id": "arjun",
        "name": "Arjun",
        "group": "recon",
        "emoji": "🎯",
        "color": "blue",
        "available": True,
        "description": "HTTP parameter discovery tool. Finds hidden GET and POST parameters on each endpoint. Undocumented parameters are often the source of injection vulnerabilities, IDORs, and logic bugs.",
        "params": [
            _param("method", "HTTP Method", "Test GET, POST, or both.", "select", "GET,POST", options=["GET","POST","GET,POST"]),
            _param("rate", "Rate Limit (req/s)", "Requests per second.", "number", "9999", min=1, max=10000),
            _param("timeout", "Timeout (s)", "Request timeout.", "number", "15", min=5, max=60),
            _param("wordlist", "Parameter Wordlist", "Path to parameter names wordlist.", "select", "default", options=["default", "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"]),
            _param("stable", "Stable Mode", "Use stable (slower but more accurate) parameter detection algorithm.", "boolean", False),
        ],
    },

    {
        "id": "linkfinder",
        "name": "LinkFinder",
        "group": "recon",
        "emoji": "🔗",
        "color": "blue",
        "available": False,
        "description": "Extracts endpoints from JavaScript files. Parses JS bundles (React/Vue/Angular) to find API routes, internal paths, and hardcoded URLs that are invisible to standard crawlers.",
        "params": [
            _param("regex", "Custom Regex", "Custom regex pattern for endpoint extraction. Leave empty for defaults.", "string", ""),
            _param("output_format", "Output Format", "Output format for discovered endpoints.", "select", "cli", options=["cli","json"]),
        ],
    },

    {
        "id": "retire",
        "name": "Retire.js",
        "group": "recon",
        "emoji": "📦",
        "color": "blue",
        "available": False,
        "description": "Detects vulnerable JavaScript libraries on the frontend (jQuery, Bootstrap, Angular, etc.). Cross-references with a database of known CVEs for each library version.",
        "params": [
            _param("severity", "Min Severity", "Minimum severity of vulnerabilities to report.", "select", "low", options=["low","medium","high","critical"]),
        ],
    },

    # ═══════════════════════════════════════════════════════════════
    # GROUP 2: DAST
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "nuclei",
        "name": "Nuclei",
        "group": "dast",
        "emoji": "⚡",
        "color": "orange",
        "available": True,
        "description": "Template-based vulnerability scanner by ProjectDiscovery. Runs thousands of community-written templates covering CVEs, misconfigurations, exposed panels, default credentials, XSS, SQLi, SSRF, and more. Uses tech fingerprinting from WhatWeb to select relevant templates.",
        "params": [
            _param("severity", "Min Severity", "Minimum severity level to include in results. Lower = more noise, higher = fewer but critical findings.", "select", "low", options=["info","low","medium","high","critical"]),
            _param("rate_limit", "Rate Limit (req/s)", "Maximum requests per second across all templates.", "number", "100", min=1, max=500),
            _param("concurrency", "Concurrency", "Number of templates running in parallel.", "number", "25", min=1, max=100),
            _param("timeout", "Request Timeout (s)", "Per-request timeout.", "number", "5", min=3, max=30),
            _param("follow_redirects", "Follow Redirects", "Follow HTTP redirects during template execution.", "boolean", True),
            _param("max_redirects", "Max Redirects", "Max redirect chain length.", "number", "10", min=1, max=20),
            _param("templates_cve", "CVE Templates", "Include CVE-specific templates mapped to discovered technologies.", "boolean", True),
            _param("templates_exposed", "Exposed Panels", "Check for exposed admin panels, monitoring tools, debug endpoints (Grafana, Kibana, phpMyAdmin, etc.).", "boolean", True),
            _param("templates_misconfig", "Misconfigurations", "Check for misconfigured servers: open redirects, CORS issues, path traversal, etc.", "boolean", True),
            _param("templates_default_creds", "Default Credentials", "Test default username/password combinations on login forms.", "boolean", True),
            _param("templates_xss", "XSS Templates", "Cross-site scripting detection templates.", "boolean", True),
            _param("templates_sqli", "SQLi Templates", "SQL injection detection templates (non-exploiting).", "boolean", True),
            _param("templates_ssrf", "SSRF Templates", "Server-Side Request Forgery detection.", "boolean", True),
            _param("custom_templates_dir", "Custom Templates Dir", "Path to directory with custom .yaml templates. Leave empty to use built-in only.", "string", ""),
        ],
    },

    {
        "id": "zap",
        "name": "OWASP ZAP",
        "group": "dast",
        "emoji": "🛡️",
        "color": "orange",
        "available": True,
        "description": "OWASP Zed Attack Proxy — industry-standard DAST scanner. Performs active scanning for OWASP Top 10 vulnerabilities. Imports all discovered endpoints and probes them with a full suite of attack payloads.",
        "params": [
            _param("max_duration", "Max Scan Duration (min)", "Maximum active scan duration in minutes. Increase for thorough testing.", "number", "30", min=5, max=180),
            _param("attack_strength", "Attack Strength", "INSANE sends the most requests and finds the most vulnerabilities but is very noisy.", "select", "MEDIUM", options=["LOW","MEDIUM","HIGH","INSANE"]),
            _param("alert_threshold", "Alert Threshold", "Minimum confidence level to include an alert in results.", "select", "MEDIUM", options=["LOW","MEDIUM","HIGH"]),
            _param("ajax_spider", "AJAX Spider", "Use the AJAX spider to crawl JavaScript-heavy applications before active scanning.", "boolean", False),
            _param("scan_policy", "Active Scan Policy", "Scan policy preset. Default covers OWASP Top 10.", "select", "Default Policy", options=["Default Policy","API-Minimal","Aggressive"]),
        ],
    },

    {
        "id": "nikto",
        "name": "Nikto",
        "group": "dast",
        "emoji": "🔎",
        "color": "orange",
        "available": True,
        "description": "Web server vulnerability scanner. Checks for dangerous files (/.git, /.env, phpMyAdmin, backup files), outdated server software, HTTP security header issues, and thousands of known server misconfigurations.",
        "params": [
            _param("timeout", "Timeout (s)", "Request timeout per check.", "number", "30", min=5, max=120),
            _param("tuning", "Scan Tuning", "Comma-separated tuning codes: 1=files, 2=misconfig, 3=info, 4=injection, 5=retrieval, 6=dos, 7=remote, 8=cms, 9=sql, 0=file_upload, a=auth.", "string", "1,2,3,4,5,7,8,9"),
            _param("max_time", "Max Time (s)", "Maximum total scan duration in seconds.", "number", "600", min=60, max=3600),
            _param("no_ssl_check", "Skip SSL Verification", "Don't verify SSL certificates on HTTPS targets.", "boolean", True),
        ],
    },

    {
        "id": "dalfox",
        "name": "Dalfox",
        "group": "dast",
        "emoji": "🐺",
        "color": "orange",
        "available": True,
        "description": "Specialized XSS scanner. Finds reflected, DOM-based, and stored XSS vulnerabilities. Includes WAF bypass techniques, Blind XSS with callback URL support, and generates working PoC payloads.",
        "params": [
            _param("blind_url", "Blind XSS Callback URL", "URL for blind XSS detection. Leave empty to skip blind XSS testing.", "string", ""),
            _param("timeout", "Timeout (s)", "Request timeout.", "number", "10", min=3, max=30),
            _param("worker", "Workers", "Concurrent workers for scanning.", "number", "10", min=1, max=50),
            _param("waf_bypass", "WAF Bypass Mode", "Try WAF bypass payloads when a WAF is detected.", "boolean", True),
            _param("mining_dict", "Dictionary Mining", "Use a dictionary to discover additional parameters for XSS testing.", "boolean", True),
        ],
    },

    {
        "id": "sqlmap",
        "name": "SQLMap",
        "group": "dast",
        "emoji": "💉",
        "color": "orange",
        "available": True,
        "description": "Automated SQL injection detection and exploitation. Tests all discovered parameters with SQLi payloads. Runs only on endpoints with SQL injection indicators found by Nuclei/ZAP. Supports error-based, time-based, boolean-based, and UNION-based techniques.",
        "params": [
            _param("level", "Test Level", "1=minimal tests, 5=exhaustive. Higher finds more but takes much longer.", "select", "1", options=["1","2","3","4","5"]),
            _param("risk", "Risk Level", "1=safe payloads only, 3=includes heavy time-based and OR-based payloads (may modify data).", "select", "1", options=["1","2","3"]),
            _param("technique", "Injection Techniques", "B=boolean, E=error, U=UNION, S=stacked, T=time, Q=inline query.", "string", "BEUSTQ"),
            _param("threads", "Threads", "Max concurrent requests.", "number", "4", min=1, max=10),
            _param("timeout", "Timeout (s)", "Seconds to wait for each response.", "number", "30", min=5, max=120),
            _param("per_url_timeout", "Per-URL Timeout (s)", "Max total time spent testing one URL.", "number", "600", min=60, max=3600),
            _param("dump_tables", "Dump Tables (DANGEROUS)", "Attempt to dump database table contents when SQLi is confirmed. Use only with explicit permission.", "boolean", False),
            _param("dbms", "Force DBMS", "Force detection of specific DBMS type (faster). Leave empty to auto-detect.", "select", "", options=["","MySQL","PostgreSQL","MsSQL","Oracle","SQLite"]),
        ],
    },

    {
        "id": "commix",
        "name": "Commix",
        "group": "dast",
        "emoji": "💣",
        "color": "orange",
        "available": False,
        "description": "Command injection exploiter. Tests for OS command injection vulnerabilities in web parameters. Supports time-based, results-based, and file-based detection techniques. Runs on endpoints identified as potentially injectable.",
        "params": [
            _param("level", "Test Level", "Number of payloads to test per parameter.", "select", "1", options=["1","2","3"]),
            _param("timeout", "Timeout (s)", "Request timeout.", "number", "30", min=5, max=120),
            _param("skip_waf", "Skip WAF Checks", "Skip WAF/IPS detection heuristics.", "boolean", False),
        ],
    },

    # ═══════════════════════════════════════════════════════════════
    # GROUP 3: SMART ORCHESTRATION
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "smart_pipeline",
        "name": "Smart Pipeline",
        "group": "smart",
        "emoji": "🧠",
        "color": "purple",
        "available": True,
        "description": "Intelligent pipeline manager. Analyzes recon findings to decide which DAST tools to run and with what parameters. Automatically focuses tools on the most promising attack surfaces.",
        "params": [
            _param("auto_sqlmap", "Auto-trigger SQLMap", "Automatically run SQLMap on endpoints where Nuclei/ZAP detect SQL injection indicators.", "boolean", True),
            _param("auto_dalfox", "Auto-trigger Dalfox", "Run Dalfox on endpoints with reflection points discovered during DAST.", "boolean", True),
            _param("auto_commix", "Auto-trigger Commix", "Run Commix on endpoints with command injection indicators.", "boolean", False),
            _param("tech_template_mapping", "Technology-based Template Selection", "Use WhatWeb fingerprinting to automatically select Nuclei template categories (e.g., WordPress → CMS templates, PHP → injection templates).", "boolean", True),
            _param("exploit_confirmed_only", "Exploit Only Confirmed Vulns", "Only run exploitation tools (sqlmap, commix) on endpoints with confirmed high/critical severity findings.", "boolean", True),
        ],
    },

    {
        "id": "cve_lookup",
        "name": "CVE Lookup",
        "group": "smart",
        "emoji": "📋",
        "color": "purple",
        "available": False,
        "description": "Maps detected technologies (from WhatWeb/HTTPX) to known CVEs using the NVD database API. Generates a technology risk card for the target application with CVE IDs, CVSS scores, and links to exploit-db.",
        "params": [
            _param("nvd_api_key", "NVD API Key", "Optional API key for higher NVD rate limits. Get one at nvd.nist.gov.", "string", ""),
            _param("min_cvss", "Min CVSS Score", "Minimum CVSS score to include (0-10).", "number", "6.0", min=0, max=10),
            _param("search_exploitdb", "Search Exploit-DB", "Search Exploit-DB via searchsploit for matching exploits.", "boolean", True),
        ],
    },

    {
        "id": "metasploit",
        "name": "Metasploit",
        "group": "smart",
        "emoji": "🎭",
        "color": "purple",
        "available": False,
        "description": "Searches Metasploit Framework module database for exploits matching detected CVEs and technologies. Does NOT run exploits automatically — provides a list of relevant modules for manual use.",
        "params": [
            _param("auto_search", "Auto-search on CVE detection", "Automatically search for Metasploit modules when CVEs are identified.", "boolean", True),
            _param("min_reliability", "Min Reliability", "Minimum module reliability rank.", "select", "Normal", options=["Low","Normal","Good","Great","Excellent"]),
        ],
    },
]

# Build lookup dict
TOOLS_BY_ID: Dict[str, Dict] = {t["id"]: t for t in TOOL_DEFINITIONS}
