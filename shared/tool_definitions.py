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
        "id": "jsscanner",
        "name": "JS Scanner",
        "group": "recon",
        "emoji": "🔗",
        "color": "blue",
        "available": True,
        "description": "Scans JavaScript bundles for secrets, API keys, internal endpoints, and hardcoded credentials. Also performs supply chain attack detection: downloads package.json backups and checks dependencies against a compromised-package database and typosquat variants.",
        "params": [
            _param("scan_secrets", "Scan for Secrets", "Search JS files for API keys, tokens, and hardcoded credentials using regex patterns.", "boolean", True),
            _param("scan_endpoints", "Extract Endpoints", "Extract API routes and internal paths from JS bundles.", "boolean", True),
            _param("probe_supply_chain", "Supply Chain Audit", "Download package.json backup from /ftp/ and check for known-compromised or typosquatted packages.", "boolean", True),
        ],
    },

    {
        "id": "retirejs",
        "name": "Retire.js",
        "group": "recon",
        "emoji": "📦",
        "color": "blue",
        "available": True,
        "description": "Detects vulnerable JavaScript libraries on the frontend (jQuery, Bootstrap, Angular, lodash, etc.). Cross-references detected versions with a database of known CVEs. Identifies which pages load vulnerable libraries.",
        "params": [
            _param("severity", "Min Severity", "Minimum severity of vulnerabilities to report.", "select", "low", options=["low","medium","high","critical"]),
            _param("timeout", "Timeout (s)", "Request timeout when fetching JS files.", "number", "15", min=5, max=60),
        ],
    },

    {
        "id": "inspector",
        "name": "Smart Inspector",
        "group": "recon",
        "emoji": "🧬",
        "color": "blue",
        "available": True,
        "description": "Smart pre-exploitation triage. Sends lightweight canary payloads to each (endpoint, parameter) pair and emits structured candidates for specialized tools: sqli_candidate → SQLMap, xss_candidate → Dalfox, ssti_candidate → Tplmap, cmdi_candidate → Commix. Also detects rate limit bypass and open redirects.",
        "params": [
            _param("test_sqli", "Test SQLi Candidates", "Probe parameters with SQL error-triggering payloads.", "boolean", True),
            _param("test_xss", "Test XSS Candidates", "Probe parameters with XSS reflection canaries.", "boolean", True),
            _param("test_ssti", "Test SSTI Candidates", "Probe parameters with template injection payloads.", "boolean", True),
            _param("test_rate_limit", "Test Rate Limit Bypass", "Send 20 parallel requests to detect missing rate limiting.", "boolean", True),
            _param("test_open_redirect", "Test Open Redirects", "Probe redirect parameters with 10 bypass variants.", "boolean", True),
            _param("timeout", "Timeout (s)", "Request timeout per probe.", "number", "8", min=3, max=30),
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
        "available": True,
        "description": "Command injection exploiter. Tests for OS command injection vulnerabilities in web parameters. Supports time-based, results-based, and file-based detection techniques. Triggered automatically when a cmdi_candidate finding is routed.",
        "params": [
            _param("level", "Test Level", "Number of payloads to test per parameter.", "select", "1", options=["1","2","3"]),
            _param("timeout", "Timeout (s)", "Request timeout.", "number", "30", min=5, max=120),
            _param("skip_waf", "Skip WAF Checks", "Skip WAF/IPS detection heuristics.", "boolean", False),
        ],
    },

    {
        "id": "cors",
        "name": "CORS Tester",
        "group": "dast",
        "emoji": "🔓",
        "color": "orange",
        "available": True,
        "description": "Tests Cross-Origin Resource Sharing misconfigurations. Probes every endpoint with crafted Origin headers to detect reflected origins, null-origin bypass, prefix/suffix bypass, and wildcard CORS policies that can lead to credential theft.",
        "params": [
            _param("timeout", "Timeout (s)", "Request timeout per endpoint.", "number", "10", min=3, max=30),
            _param("include_null_origin", "Test Null Origin", "Send Origin: null header to detect misconfigured servers that reflect null origin.", "boolean", True),
            _param("include_prefix_bypass", "Test Prefix/Suffix Bypass", "Try origin values like evil.target.com and target.com.evil.com.", "boolean", True),
        ],
    },

    {
        "id": "xxe",
        "name": "XXE Tester",
        "group": "dast",
        "emoji": "📄",
        "color": "orange",
        "available": True,
        "description": "XML External Entity injection tester. Identifies XML/SOAP endpoints, SVG upload points, and JSON APIs that parse XML. Tests for file read, SSRF, and blind XXE via out-of-band callback.",
        "params": [
            _param("timeout", "Timeout (s)", "Request timeout per probe.", "number", "15", min=5, max=60),
            _param("test_file_read", "Test File Read", "Try to read /etc/passwd via XXE payload.", "boolean", True),
            _param("test_ssrf", "Test SSRF via XXE", "Use XXE to trigger SSRF to an internal address.", "boolean", True),
            _param("oob_server", "OOB Callback Server", "URL of out-of-band server for blind XXE detection. Leave empty to skip OOB testing.", "string", ""),
        ],
    },

    {
        "id": "tplmap",
        "name": "Tplmap",
        "group": "dast",
        "emoji": "🧪",
        "color": "orange",
        "available": True,
        "description": "Server-Side Template Injection (SSTI) detection and exploitation. Tests Jinja2, Twig, Smarty, Mako, ERB, and 15+ template engines. Triggered automatically when inspector emits an ssti_candidate finding.",
        "params": [
            _param("level", "Test Level", "1=safe detection, 5=full exploitation attempt.", "select", "3", options=["1","2","3","4","5"]),
            _param("timeout", "Timeout (s)", "Request timeout.", "number", "30", min=5, max=120),
            _param("engine", "Force Engine", "Force a specific template engine (faster). Leave empty to auto-detect.", "select", "", options=["","Jinja2","Twig","Smarty","Mako","Tornado","Erb","Slim"]),
        ],
    },

    {
        "id": "jwt_tool",
        "name": "JWT Tool",
        "group": "dast",
        "emoji": "🔑",
        "color": "orange",
        "available": True,
        "description": "JWT security tester. Probes for algorithm confusion (RS256→HS256), 'none' algorithm bypass, weak secret brute-force, JKU/X5U header injection, and kid header path traversal. Triggered on jwt_found findings.",
        "params": [
            _param("brute_force_secrets", "Brute-force Weak Secrets", "Try a wordlist of common JWT secrets (password, secret, jwt, etc.).", "boolean", True),
            _param("test_alg_none", "Test 'none' Algorithm", "Attempt to bypass verification by setting alg=none.", "boolean", True),
            _param("test_alg_confusion", "Test Algorithm Confusion", "Test RS256→HS256 confusion when public key is discoverable.", "boolean", True),
        ],
    },

    {
        "id": "graphql",
        "name": "GraphQL Tester",
        "group": "dast",
        "emoji": "🕸️",
        "color": "orange",
        "available": True,
        "description": "GraphQL security battery. Runs 8 checks: introspection enabled, field suggestion leakage, batching DoS, depth limit bypass, query complexity, IDOR via node IDs, SQL/NoSQL injection in arguments, and auth bypass via alias overloading.",
        "params": [
            _param("test_introspection", "Test Introspection", "Check if schema introspection is enabled (information disclosure).", "boolean", True),
            _param("test_batching", "Test Query Batching DoS", "Send batched mutation arrays to test for rate-limit bypass.", "boolean", True),
            _param("test_depth", "Test Depth Limit", "Generate deeply nested queries to test recursion limits.", "boolean", True),
            _param("timeout", "Timeout (s)", "Request timeout.", "number", "10", min=3, max=30),
        ],
    },

    {
        "id": "openapi",
        "name": "OpenAPI Tester",
        "group": "dast",
        "emoji": "📖",
        "color": "orange",
        "available": True,
        "description": "Spec-driven API security testing. Parses Swagger/OpenAPI specs (auto-discovered or provided) to generate test cases for every endpoint: auth bypass, BOLA via object ID enumeration, mass-assignment via extra fields, and missing rate limits.",
        "params": [
            _param("spec_url", "Spec URL Override", "Explicit path to swagger.json or openapi.yaml. Leave empty to auto-discover.", "string", ""),
            _param("test_auth_bypass", "Test Auth Bypass", "Try each endpoint without Authorization header.", "boolean", True),
            _param("test_mass_assignment", "Test Mass Assignment", "Send extra fields not in the schema to detect mass assignment.", "boolean", True),
            _param("test_bola", "Test BOLA/IDOR", "Enumerate integer IDs on resource endpoints.", "boolean", True),
        ],
    },

    {
        "id": "playwright",
        "name": "Playwright (Headless)",
        "group": "dast",
        "emoji": "🎭",
        "color": "orange",
        "available": True,
        "description": "Headless Chromium browser for DOM-based and Stored XSS, open redirect chain confirmation, Angular/React SPA route testing, and admin workflow automation. Triggered on credential_exposure findings for automated admin panel verification.",
        "params": [
            _param("headless", "Headless Mode", "Run without a visible browser window.", "boolean", True),
            _param("timeout", "Page Timeout (ms)", "Maximum time to wait for a page to load.", "number", "30000", min=5000, max=120000),
            _param("test_dom_xss", "Test DOM XSS", "Inject XSS canary into hash fragment and URL parameters, check DOM via JS evaluation.", "boolean", True),
            _param("test_stored_xss", "Test Stored XSS", "Submit canary payloads via forms and check if they render on other pages.", "boolean", True),
            _param("test_open_redirect", "Test Redirect Chains", "Follow redirect chains in headless browser to confirm open redirects.", "boolean", True),
        ],
    },

    {
        "id": "bola",
        "name": "BOLA / IDOR Scanner",
        "group": "dast",
        "emoji": "🔐",
        "color": "orange",
        "available": True,
        "description": "Broken Object-Level Authorization (BOLA/IDOR) scanner. Enumerates integer IDs across REST API endpoints using two authentication contexts. Also tests basket manipulation, forged feedback/reviews, and GDPR data theft via sequential user ID enumeration.",
        "params": [
            _param("id_range_max", "ID Enumeration Range", "Maximum object ID to test during enumeration (1..N).", "number", "20", min=5, max=100),
            _param("test_idor_extended", "Extended IDOR Tests", "Run Juice Shop specific IDOR tests: basket, feedback, reviews, GDPR data exfiltration.", "boolean", True),
            _param("timeout", "Timeout (s)", "Request timeout per probe.", "number", "10", min=3, max=30),
            _param("boundary_strategy", "Boundary Strategy", "How to detect BOLA: status_code=401/403 expected, response_diff=compare bodies.", "select", "response_diff", options=["status_code","response_diff"]),
        ],
    },

    {
        "id": "creds",
        "name": "Credential Attacker",
        "group": "dast",
        "emoji": "🗝️",
        "color": "orange",
        "available": True,
        "description": "Multi-vector credential attack worker. Pass 1: known default credentials. Pass 2: common password spray. Pass 3: SQL injection login bypass (tautology payloads + JWT response detection). Pass 4: security question bypass via known answers. Emits credential_exposure findings that auto-trigger admin workflow testing.",
        "params": [
            _param("max_attempts_per_user", "Max Attempts per User", "Maximum password attempts per username to avoid account lockout.", "number", "5", min=1, max=20),
            _param("delay_ms", "Delay Between Attempts (ms)", "Milliseconds to wait between login attempts.", "number", "200", min=0, max=2000),
            _param("test_sqli_login", "Test SQLi Login Bypass", "Try SQL injection tautology payloads in the email/username field.", "boolean", True),
            _param("test_forgot_password", "Test Security Question Bypass", "Attempt password reset using known security question answers.", "boolean", True),
        ],
    },

    {
        "id": "bizlogic",
        "name": "Business Logic Tester",
        "group": "dast",
        "emoji": "⚙️",
        "color": "orange",
        "available": True,
        "description": "Business logic vulnerability tester for OWASP Juice Shop. Tests: negative quantity abuse, zero-price checkout, coupon reuse/manipulation, product review manipulation, admin-only endpoint access, and Christmas Special SQLi to expose deleted products.",
        "params": [
            _param("test_negative_quantity", "Test Negative Quantity", "Add items with negative quantities to manipulate basket total.", "boolean", True),
            _param("test_coupon_abuse", "Test Coupon Manipulation", "Try expired, reused, and forged coupon codes.", "boolean", True),
            _param("test_christmas_special", "Test Christmas Special SQLi", "Use SQLi in product search to discover soft-deleted products.", "boolean", True),
            _param("test_five_star_feedback", "Test Admin Feedback Deletion", "Verify if non-admin users can delete customer feedback.", "boolean", True),
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
