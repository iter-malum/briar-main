"""
JS Library Fingerprinting Engine
=================================
Detects JavaScript libraries and their versions from three sources:
  1. Filename patterns  — jquery-3.6.0.min.js, bootstrap.4.3.1.bundle.min.js
  2. Banner comments    — /*! jQuery v3.6.0 | ... */
  3. Version variables  — jQuery.fn.jquery = "3.6.0", React.version = "18.2.0"

Returns LibraryMatch instances.  The caller decides how to surface them:
  - worker-jsscanner: emits js_library findings (info) → app tech-stack enrichment
  - worker-retirejs:  runs retire.js CLI against downloaded files → CVE findings

No CVE database lives here.  Vulnerability lookup is the responsibility of
worker-retirejs, which delegates to the retire.js tool and its maintained DB.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse


# ── Result type ───────────────────────────────────────────────────────────────

@dataclass
class LibraryMatch:
    library_key: str        # internal key, e.g. "jquery"
    display_name: str       # human-readable, e.g. "jQuery"
    version: str            # "3.6.0" | "unknown" | "detected"
    detection_method: str   # "filename" | "banner" | "version_var"
    js_url: str
    nuclei_tags: List[str]  # base nuclei tags for this technology (no CVE tags)


# ── Library patterns ──────────────────────────────────────────────────────────
#
# Each LibraryPattern defines how to detect one library.
# Strategies run in order; first match for a given library wins.

@dataclass
class _LibraryPattern:
    key: str
    display_name: str
    filename_re: Optional[re.Pattern]
    banner_re: Optional[re.Pattern]
    version_re: Optional[re.Pattern]
    fallback_version: str = "unknown"
    nuclei_tags: List[str] = field(default_factory=list)


def _lib(
    key: str,
    display: str,
    filename: Optional[str],
    banner: Optional[str],
    version: Optional[str],
    fallback: str = "unknown",
    tags: Optional[List[str]] = None,
) -> _LibraryPattern:
    return _LibraryPattern(
        key=key,
        display_name=display,
        filename_re=re.compile(filename, re.IGNORECASE) if filename else None,
        banner_re=re.compile(banner, re.IGNORECASE | re.DOTALL) if banner else None,
        version_re=re.compile(version, re.IGNORECASE) if version else None,
        fallback_version=fallback,
        nuclei_tags=tags or [],
    )


_PATTERNS: List[_LibraryPattern] = [
    # ── jQuery ────────────────────────────────────────────────────────────────
    _lib(
        "jquery", "jQuery",
        filename=r"(?:^|/)jquery[-.](?:v?(\d+\.\d+[\.\d]*)\.)?(?:min\.)?js$",
        banner=r"/\*!?\s*(?:jQuery|jquery)\s+v?(\d+\.\d+[\d.]*)",
        version=r"""jQuery\.fn\.jquery\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["jquery", "javascript"],
    ),

    # ── Bootstrap ─────────────────────────────────────────────────────────────
    _lib(
        "bootstrap", "Bootstrap",
        filename=r"(?:^|/)bootstrap[-.](?:v?(\d+\.\d+[\d.]*)\.)?(?:bundle\.)?(?:min\.)?js$",
        banner=r"/\*!?\s*Bootstrap\s+v?(\d+\.\d+[\d.]*)",
        version=r"""Bootstrap\.VERSION\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["bootstrap", "javascript"],
    ),

    # ── AngularJS (1.x) ───────────────────────────────────────────────────────
    _lib(
        "angularjs", "AngularJS",
        filename=r"(?:^|/)angular(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.min)?\.js$",
        banner=r"/\*!?\s*AngularJS\s+v?(\d+\.\d+[\d.]*)",
        version=r"""angular\.version\s*=\s*\{[^}]*full\s*:\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["angularjs", "javascript"],
    ),

    # ── Angular (2+) ──────────────────────────────────────────────────────────
    _lib(
        "angular", "Angular",
        filename=r"(?:^|/)(?:@angular|angular2)[-./](?:v?(\d+\.\d+[\d.]*))?",
        banner=r"Angular\s+(?:v|version\s*)(\d+\.\d+[\d.]*)",
        version=r"""VERSION\s*=\s*\{\s*full\s*:\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["angular", "javascript"],
    ),

    # ── React ─────────────────────────────────────────────────────────────────
    _lib(
        "react", "React",
        filename=r"(?:^|/)react(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.(?:development|production\.min))?\.js$",
        banner=r"@license\s+React\s+v?(\d+\.\d+[\d.]*)",
        version=r"""exports\.version\s*=\s*["'](\d+\.\d+[\d.]*)["']|React\.version\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["react", "javascript"],
    ),

    # ── Vue ───────────────────────────────────────────────────────────────────
    _lib(
        "vue", "Vue.js",
        filename=r"(?:^|/)vue(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.(?:esm|runtime|common))?(?:\.min)?\.js$",
        banner=r"/\*!?\s*Vue\.js\s+v?(\d+\.\d+[\d.]*)",
        version=r"""Vue\.version\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["vue", "javascript"],
    ),

    # ── Lodash ────────────────────────────────────────────────────────────────
    _lib(
        "lodash", "Lodash",
        filename=r"(?:^|/)lodash(?:[-.](?:v?(\d+\.\d+[\d.]*)\.)?(?:core\.)?(?:min\.)?js)?$",
        banner=r"/\*!?\s*(?:Lo-Dash|Lodash)\s+(?:Modern\s+)?v?(\d+\.\d+[\d.]*)",
        version=r"""_\.VERSION\s*=\s*["'](\d+\.\d+[\d.]*)["']|exports\.VERSION\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["lodash", "javascript"],
    ),

    # ── Underscore ────────────────────────────────────────────────────────────
    _lib(
        "underscore", "Underscore.js",
        filename=r"(?:^|/)underscore(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.min)?\.js$",
        banner=r"/\*!?\s*Underscore\.js\s+(\d+\.\d+[\d.]*)",
        version=r"""_\.VERSION\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["underscore", "javascript"],
    ),

    # ── Moment.js ─────────────────────────────────────────────────────────────
    _lib(
        "moment", "Moment.js",
        filename=r"(?:^|/)moment(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.min)?\.js$",
        banner=r"/\*!?\s*moment\.js\s+v?(\d+\.\d+[\d.]*)",
        version=r"""moment\.version\s*=\s*["'](\d+\.\d+[\d.]*)["']|exports\.version\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["moment", "javascript"],
    ),

    # ── Handlebars ────────────────────────────────────────────────────────────
    _lib(
        "handlebars", "Handlebars.js",
        filename=r"(?:^|/)handlebars(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.min)?\.js$",
        banner=r"/\*!\s*\n\s*handlebars\s+v(\d+\.\d+[\d.]*)",
        version=r"""Handlebars\.VERSION\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["handlebars", "javascript"],
    ),

    # ── Axios ─────────────────────────────────────────────────────────────────
    _lib(
        "axios", "Axios",
        filename=r"(?:^|/)axios(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.min)?\.js$",
        banner=r"/\*!?\s*axios\s+v?(\d+\.\d+[\d.]*)",
        version=r"""axios\.VERSION\s*=\s*["'](\d+\.\d+[\d.]*)["']|exports\.VERSION\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["axios", "javascript"],
    ),

    # ── Socket.io ─────────────────────────────────────────────────────────────
    _lib(
        "socketio", "Socket.IO",
        filename=r"(?:^|/)socket\.io(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.min)?\.js$",
        banner=r"socket\.io\s+v?(\d+\.\d+[\d.]*)",
        version=r"""exports\.version\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["socketio", "websocket", "javascript"],
    ),

    # ── RxJS ──────────────────────────────────────────────────────────────────
    _lib(
        "rxjs", "RxJS",
        filename=r"(?:^|/)rxjs(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.min)?\.js$",
        banner=r"rxjs\s+v?(\d+\.\d+[\d.]*)",
        version=r"""exports\.VERSION\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["rxjs", "javascript"],
    ),

    # ── D3.js ─────────────────────────────────────────────────────────────────
    _lib(
        "d3", "D3.js",
        filename=r"(?:^|/)d3(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.min)?\.js$",
        banner=r"/\*!\s*D3\s+v?(\d+\.\d+[\d.]*)",
        version=r"""exports\.version\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["d3", "javascript"],
    ),

    # ── Backbone ──────────────────────────────────────────────────────────────
    _lib(
        "backbone", "Backbone.js",
        filename=r"(?:^|/)backbone(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.min)?\.js$",
        banner=r"Backbone\.js\s+(\d+\.\d+[\d.]*)",
        version=r"""Backbone\.VERSION\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["backbone", "javascript"],
    ),

    # ── Ember ─────────────────────────────────────────────────────────────────
    _lib(
        "ember", "Ember.js",
        filename=r"(?:^|/)ember(?:[-.]v?(\d+\.\d+[\d.]*))?(?:\.min)?\.js$",
        banner=r"@version\s+(\d+\.\d+[\d.]*)\s+@license\s+MIT",
        version=r"""Ember\.VERSION\s*=\s*["'](\d+\.\d+[\d.]*)["']""",
        tags=["ember", "javascript"],
    ),

    # ── Build tools (no version, presence-only) ────────────────────────────────
    _lib(
        "webpack", "Webpack",
        filename=None,
        banner=r"webpackBootstrap|__webpack_require__|webpack/runtime",
        version=None,
        fallback="detected",
        tags=["webpack", "javascript"],
    ),
    _lib(
        "vite", "Vite",
        filename=None,
        banner=r"/@vite/client|vite/dist/client|__vite_is_modern_browser",
        version=None,
        fallback="detected",
        tags=["vite", "javascript"],
    ),
]


# ── Core detection ────────────────────────────────────────────────────────────

def fingerprint_js(js_url: str, content: str) -> List[LibraryMatch]:
    """
    Analyse a JS file URL + text content.
    Returns one LibraryMatch per detected library (no duplicates).

    Strategy per library (first match wins):
      1. Filename regex  — version extracted from group 1 if captured
      2. Banner comment  — first 3 kB, version from group 1
      3. Version variable — full body, version from group 1 or 2
    """
    basename = urlparse(js_url).path.split("/")[-1]
    header = content[:3000]
    matches: List[LibraryMatch] = []
    detected: set = set()

    for pat in _PATTERNS:
        if pat.key in detected:
            continue

        version: Optional[str] = None
        method: Optional[str] = None

        # 1. Filename
        if pat.filename_re:
            m = pat.filename_re.search(basename)
            if m:
                v = next((g for g in (m.groups() or []) if g), None)
                version = v or pat.fallback_version
                method = "filename"

        # 2. Banner comment
        if method is None and pat.banner_re:
            m = pat.banner_re.search(header)
            if m:
                v = next((g for g in (m.groups() or []) if g), None)
                version = v or pat.fallback_version
                method = "banner"

        # 3. Version variable (full body)
        if method is None and pat.version_re:
            m = pat.version_re.search(content)
            if m:
                v = next((g for g in (m.groups() or []) if g), None)
                version = v or pat.fallback_version
                method = "version_var"

        if method is None:
            continue

        detected.add(pat.key)
        matches.append(LibraryMatch(
            library_key=pat.key,
            display_name=pat.display_name,
            version=version or pat.fallback_version,
            detection_method=method,
            js_url=js_url,
            nuclei_tags=list(pat.nuclei_tags),
        ))

    return matches


def aggregate_tech_stack(matches: List[LibraryMatch]) -> Dict[str, str]:
    """Collapse matches → {library_key: version} for app-level tech-stack context."""
    return {m.library_key: m.version for m in matches}
