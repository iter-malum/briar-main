"""
services/orchestrator/report_generator.py — M13 Reporting
===========================================================
Generates structured JSON and styled HTML scan reports.

JSON report
-----------
  {
    "meta":            {scan_id, target_url, status, created_at, duration_s, tools},
    "summary":         {total, by_severity, by_tool, confirmed_count, avg_confidence},
    "owasp_coverage":  {A01..A10 matrix},
    "findings":        [sorted by severity desc, confidence desc],
  }

HTML report
-----------
  Self-contained single-file HTML (inline CSS, no external deps).
  Sections: header card, severity chart, OWASP matrix, findings table.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from typing import Any, Optional

from shared.owasp import build_coverage_matrix, OWASP_CATEGORIES
from shared.dedup import normalize_vuln_type, TOOL_BASE_SCORES


# ── Severity ordering ──────────────────────────────────────────────────────────

_SEV_ORDER   = ["critical", "high", "medium", "low", "info"]
_SEV_COLOURS = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#27ae60",
    "info":     "#2980b9",
}
_SEV_BG = {
    "critical": "#fdf0ef",
    "high":     "#fef5ec",
    "medium":   "#fefde7",
    "low":      "#edfaf1",
    "info":     "#eaf3fb",
}


def _sev_rank(sev: str) -> int:
    try:
        return _SEV_ORDER.index((sev or "info").lower())
    except ValueError:
        return len(_SEV_ORDER)


def _field(r, attr: str):
    """Get attribute from ORM instance or dict."""
    return getattr(r, attr, None) if not isinstance(r, dict) else r.get(attr)


# ── JSON report ────────────────────────────────────────────────────────────────

def generate_json_report(scan, results: list) -> dict[str, Any]:
    """
    Build a structured JSON-serialisable report dict.

    *scan*    — ScanORM instance (or dict with id/target_url/status/created_at/config).
    *results* — list of ScanResultORM instances (or dicts).
    """
    # Meta
    created_at = _field(scan, "created_at")
    updated_at = _field(scan, "updated_at")
    duration_s: Optional[float] = None
    if created_at and updated_at:
        try:
            ca = created_at.replace(tzinfo=None) if hasattr(created_at, "replace") else created_at
            ua = updated_at.replace(tzinfo=None) if hasattr(updated_at, "replace") else updated_at
            duration_s = round((ua - ca).total_seconds(), 1)
        except Exception:
            pass

    config = _field(scan, "config") or {}
    tools_used = config.get("tools", [])

    meta = {
        "scan_id":    str(_field(scan, "id") or ""),
        "target_url": str(_field(scan, "target_url") or ""),
        "status":     str(_field(scan, "status") or ""),
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at or ""),
        "finished_at": updated_at.isoformat() if hasattr(updated_at, "isoformat") else str(updated_at or ""),
        "duration_s": duration_s,
        "tools":      tools_used,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator":  "Briar DAST Platform",
    }

    # Summary
    by_sev: dict[str, int] = {s: 0 for s in _SEV_ORDER}
    by_tool: dict[str, int] = {}
    confirmed_count = 0
    confidence_sum = 0

    for r in results:
        sev = (_field(r, "severity") or "info").lower()
        if sev in by_sev:
            by_sev[sev] += 1
        tool = _field(r, "tool") or "unknown"
        by_tool[tool] = by_tool.get(tool, 0) + 1
        conf = _field(r, "confidence") or 50
        confidence_sum += conf
        if conf >= 70:
            confirmed_count += 1

    total = len(results)
    avg_conf = round(confidence_sum / total, 1) if total else 0

    summary = {
        "total":           total,
        "by_severity":     by_sev,
        "by_tool":         by_tool,
        "confirmed_count": confirmed_count,
        "avg_confidence":  avg_conf,
    }

    # OWASP coverage matrix (serialisable subset)
    owasp_raw = build_coverage_matrix(results)
    owasp_coverage: dict[str, Any] = {}
    for key, cell in owasp_raw.items():
        owasp_coverage[key] = {
            "id":              cell["category"]["id"],
            "name":            cell["category"]["name"],
            "covered":         cell["covered"],
            "max_severity":    cell["max_severity"],
            "confirmed_count": cell["confirmed_count"],
            "severity_counts": cell["severity_counts"],
            "finding_count":   len(cell["findings"]),
        }

    # Findings list — sorted by (severity rank asc, confidence desc)
    def _sort_key(r):
        return (_sev_rank(_field(r, "severity")), -(_field(r, "confidence") or 50))

    sorted_results = sorted(results, key=_sort_key)

    findings = []
    for r in sorted_results:
        confirmed_by = _field(r, "confirmed_by")
        findings.append({
            "id":               str(_field(r, "id") or ""),
            "tool":             _field(r, "tool") or "",
            "severity":         (_field(r, "severity") or "info").lower(),
            "url":              _field(r, "url") or "",
            "vulnerability_type": _field(r, "vulnerability_type") or "",
            "description":      _field(r, "description") or "",
            "confidence":       _field(r, "confidence") or 50,
            "confirmed_by":     confirmed_by or [],
            "dedup_key":        _field(r, "dedup_key") or "",
            "vuln_status":      str(_field(r, "vuln_status") or "open"),
            "owasp":            OWASP_CATEGORIES.get(
                                    _get_owasp_key_for_result(r), {}
                                ).get("id", ""),
            "request_method":   _field(r, "request_method") or "",
            "analyst_note":     _field(r, "analyst_note") or "",
        })

    return {
        "meta":           meta,
        "summary":        summary,
        "owasp_coverage": owasp_coverage,
        "findings":       findings,
    }


def _get_owasp_key_for_result(r) -> str:
    from shared.owasp import get_owasp_category
    vtype = _field(r, "vulnerability_type")
    cls = normalize_vuln_type(vtype)
    return get_owasp_category(cls) or ""


# ── HTML report ────────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Briar DAST Report — {{ target_url }}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#f4f6f9;color:#2c3e50;font-size:14px;line-height:1.5}
  a{color:#2980b9;text-decoration:none}a:hover{text-decoration:underline}
  /* Layout */
  .page{max-width:1200px;margin:0 auto;padding:24px 16px}
  /* Header */
  .header{background:linear-gradient(135deg,#1a252f 0%,#2c3e50 100%);
          color:#fff;border-radius:8px;padding:28px 32px;margin-bottom:24px}
  .header h1{font-size:22px;font-weight:700;letter-spacing:.3px}
  .header .sub{opacity:.7;font-size:13px;margin-top:4px}
  .header .meta{display:flex;flex-wrap:wrap;gap:24px;margin-top:20px}
  .header .meta-item label{font-size:11px;opacity:.6;text-transform:uppercase;
                            letter-spacing:.6px;display:block}
  .header .meta-item span{font-size:15px;font-weight:600}
  .badge{display:inline-block;padding:2px 10px;border-radius:12px;
         font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px}
  .badge-completed{background:#27ae60;color:#fff}
  .badge-running{background:#e67e22;color:#fff}
  .badge-failed{background:#c0392b;color:#fff}
  .badge-pending{background:#7f8c8d;color:#fff}
  /* Cards */
  .cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));
         gap:16px;margin-bottom:24px}
  .card{background:#fff;border-radius:8px;padding:18px 16px;
        box-shadow:0 1px 4px rgba(0,0,0,.06)}
  .card .count{font-size:32px;font-weight:700;line-height:1.1}
  .card .label{font-size:12px;color:#7f8c8d;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}
  .card-critical .count{color:#c0392b}
  .card-high    .count{color:#e67e22}
  .card-medium  .count{color:#d4ac0d}
  .card-low     .count{color:#27ae60}
  .card-info    .count{color:#2980b9}
  /* Section */
  .section{background:#fff;border-radius:8px;padding:20px 24px;
           margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,.06)}
  .section h2{font-size:15px;font-weight:700;margin-bottom:16px;
              padding-bottom:10px;border-bottom:1px solid #ecf0f1}
  /* OWASP matrix */
  .owasp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
  .owasp-cell{border-radius:6px;padding:12px 14px;border:1px solid #ecf0f1}
  .owasp-cell.covered{border-color:#e74c3c;background:#fdf6f6}
  .owasp-cell .oid{font-size:11px;font-weight:700;color:#7f8c8d;margin-bottom:2px}
  .owasp-cell .oname{font-size:13px;font-weight:600}
  .owasp-cell .ostats{font-size:11px;color:#7f8c8d;margin-top:6px}
  .owasp-cell.covered .ostats{color:#c0392b}
  /* Severity bar */
  .sev-bar{display:inline-block;height:8px;border-radius:4px;min-width:4px}
  /* Findings table */
  .findings-table{width:100%;border-collapse:collapse}
  .findings-table th{text-align:left;font-size:11px;text-transform:uppercase;
                     letter-spacing:.5px;color:#7f8c8d;padding:8px 12px;
                     border-bottom:2px solid #ecf0f1;white-space:nowrap}
  .findings-table td{padding:10px 12px;border-bottom:1px solid #f5f6fa;
                     vertical-align:top;max-width:320px;word-break:break-word}
  .findings-table tr:hover td{background:#fafbfc}
  .sev-tag{display:inline-block;padding:2px 8px;border-radius:10px;
           font-size:11px;font-weight:700;text-transform:uppercase}
  .conf-pill{display:inline-block;padding:1px 7px;border-radius:8px;
             font-size:11px;background:#eaf3fb;color:#2980b9;font-weight:600}
  .conf-high{background:#edfaf1;color:#27ae60}
  .conf-critical{background:#fdf0ef;color:#c0392b}
  .tool-tag{display:inline-block;padding:1px 6px;border-radius:4px;
            font-size:11px;background:#f4f6f9;color:#555;font-weight:500}
  .url-cell{font-family:'SF Mono',Consolas,monospace;font-size:12px;
            color:#2c3e50;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .confirmed-tag{font-size:10px;color:#27ae60;font-weight:600}
  .superseded{opacity:.55}
  /* Footer */
  .footer{text-align:center;color:#aaa;font-size:12px;padding:16px 0}
</style>
</head>
<body>
<div class="page">

<!-- Header -->
<div class="header">
  <h1>🔍 Briar DAST Security Report</h1>
  <div class="sub">Generated {{ generated_at }}</div>
  <div class="meta">
    <div class="meta-item">
      <label>Target</label>
      <span>{{ target_url }}</span>
    </div>
    <div class="meta-item">
      <label>Scan ID</label>
      <span style="font-size:12px;font-family:monospace">{{ scan_id }}</span>
    </div>
    <div class="meta-item">
      <label>Status</label>
      <span class="badge badge-{{ status }}">{{ status }}</span>
    </div>
    <div class="meta-item">
      <label>Duration</label>
      <span>{{ duration }}</span>
    </div>
    <div class="meta-item">
      <label>Tools</label>
      <span>{{ tools_count }}</span>
    </div>
    <div class="meta-item">
      <label>Started</label>
      <span>{{ created_at }}</span>
    </div>
  </div>
</div>

<!-- Severity summary cards -->
<div class="cards">
  <div class="card card-critical">
    <div class="count">{{ sev_counts.critical }}</div>
    <div class="label">Critical</div>
  </div>
  <div class="card card-high">
    <div class="count">{{ sev_counts.high }}</div>
    <div class="label">High</div>
  </div>
  <div class="card card-medium">
    <div class="count">{{ sev_counts.medium }}</div>
    <div class="label">Medium</div>
  </div>
  <div class="card card-low">
    <div class="count">{{ sev_counts.low }}</div>
    <div class="label">Low</div>
  </div>
  <div class="card card-info">
    <div class="count">{{ sev_counts.info }}</div>
    <div class="label">Info</div>
  </div>
  <div class="card">
    <div class="count" style="color:#8e44ad">{{ confirmed_count }}</div>
    <div class="label">Confirmed ≥70%</div>
  </div>
  <div class="card">
    <div class="count" style="color:#16a085">{{ avg_confidence }}%</div>
    <div class="label">Avg Confidence</div>
  </div>
</div>

<!-- OWASP Coverage Matrix -->
<div class="section">
  <h2>OWASP Top 10 — 2021 Coverage</h2>
  <div class="owasp-grid">
    {% for key, cell in owasp_cells %}
    <div class="owasp-cell{% if cell.covered %} covered{% endif %}">
      <div class="oid">{{ cell.category.id }}</div>
      <div class="oname">{{ cell.category.name }}</div>
      {% if cell.covered %}
      <div class="ostats">
        {{ cell.findings|length }} finding{{ 's' if cell.findings|length != 1 else '' }}
        {% if cell.max_severity %}
        &nbsp;·&nbsp;max: <strong>{{ cell.max_severity }}</strong>
        {% endif %}
        {% if cell.confirmed_count %}
        &nbsp;·&nbsp;{{ cell.confirmed_count }} confirmed
        {% endif %}
      </div>
      {% else %}
      <div class="ostats">Not detected</div>
      {% endif %}
    </div>
    {% endfor %}
  </div>
</div>

<!-- Tool breakdown -->
<div class="section">
  <h2>Findings by Tool</h2>
  <table class="findings-table">
    <thead>
      <tr>
        <th>Tool</th>
        <th>Findings</th>
        <th>Base Confidence</th>
        <th>Severity Breakdown</th>
      </tr>
    </thead>
    <tbody>
      {% for item in tool_rows %}
      <tr>
        <td><span class="tool-tag">{{ item.tool }}</span></td>
        <td><strong>{{ item.total }}</strong></td>
        <td>
          <span class="conf-pill {% if item.base_conf >= 80 %}conf-high{% elif item.base_conf >= 90 %}conf-critical{% endif %}">
            {{ item.base_conf }}
          </span>
        </td>
        <td>
          {% for sev in ['critical','high','medium','low','info'] %}
          {% if item.by_sev[sev] %}
          <span class="sev-bar" style="width:{{ [item.by_sev[sev]*12,80]|min }}px;background:{{ sev_colours[sev] }};margin-right:2px" title="{{ sev }}: {{ item.by_sev[sev] }}"></span>
          {% endif %}
          {% endfor %}
          &nbsp;
          {% for sev in ['critical','high','medium','low','info'] %}
          {% if item.by_sev[sev] %}
          <span style="color:{{ sev_colours[sev] }};font-weight:600;font-size:12px">{{ item.by_sev[sev] }}{{ sev[0].upper() }}</span>&nbsp;
          {% endif %}
          {% endfor %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<!-- Findings table -->
<div class="section">
  <h2>All Findings ({{ total_findings }})</h2>
  {% if findings %}
  <div style="overflow-x:auto">
  <table class="findings-table">
    <thead>
      <tr>
        <th>#</th>
        <th>Severity</th>
        <th>Vulnerability</th>
        <th>URL</th>
        <th>Tool</th>
        <th>Confidence</th>
        <th>OWASP</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      {% for f in findings %}
      <tr class="{% if f.vuln_status == 'false_positive' %}superseded{% endif %}">
        <td style="color:#aaa;font-size:12px">{{ loop.index }}</td>
        <td>
          <span class="sev-tag" style="background:{{ sev_bg[f.severity] }};color:{{ sev_colours[f.severity] }}">
            {{ f.severity }}
          </span>
        </td>
        <td>
          <div style="font-weight:600;font-size:13px">{{ f.vulnerability_type or '—' }}</div>
          {% if f.description %}
          <div style="color:#7f8c8d;font-size:12px;margin-top:2px">{{ f.description[:120] }}{% if f.description|length > 120 %}…{% endif %}</div>
          {% endif %}
          {% if f.confirmed_by and f.confirmed_by|length > 1 %}
          <div class="confirmed-tag">✓ Confirmed by {{ f.confirmed_by|join(', ') }}</div>
          {% endif %}
        </td>
        <td class="url-cell" title="{{ f.url }}">{{ f.url or '—' }}</td>
        <td><span class="tool-tag">{{ f.tool }}</span></td>
        <td>
          <span class="conf-pill {% if f.confidence >= 80 %}conf-high{% endif %}">
            {{ f.confidence }}%
          </span>
        </td>
        <td style="font-size:12px;color:#7f8c8d;white-space:nowrap">{{ f.owasp or '—' }}</td>
        <td style="font-size:12px">
          {% if f.vuln_status == 'false_positive' %}
          <span style="color:#aaa">FP (auto)</span>
          {% elif f.vuln_status == 'fixed' %}
          <span style="color:#27ae60">Fixed</span>
          {% elif f.vuln_status == 'accepted' %}
          <span style="color:#e67e22">Accepted</span>
          {% else %}
          <span style="color:#c0392b">Open</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  </div>
  {% else %}
  <p style="color:#aaa;padding:16px 0">No findings recorded for this scan.</p>
  {% endif %}
</div>

<div class="footer">
  Generated by <strong>Briar DAST Platform</strong> · {{ generated_at }}
</div>
</div>
</body>
</html>
"""


def generate_html_report(scan, results: list) -> str:
    """
    Render a self-contained HTML report.  Requires Jinja2 (already a
    transitive dependency via FastAPI).
    """
    from jinja2 import Environment

    json_data = generate_json_report(scan, results)
    meta = json_data["meta"]
    summary = json_data["summary"]
    owasp_raw = build_coverage_matrix(results)
    owasp_cells = sorted(owasp_raw.items())   # A01..A10

    # Duration string
    dur = meta.get("duration_s")
    if dur is not None:
        m, s = divmod(int(dur), 60)
        duration_str = f"{m}m {s}s" if m else f"{s}s"
    else:
        duration_str = "—"

    # Format dates
    def _fmt_dt(iso_str: str) -> str:
        try:
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            return iso_str

    # Tool rows
    tool_rows = []
    tool_sev: dict[str, dict] = {}
    for r in results:
        tool = _field(r, "tool") or "unknown"
        sev  = (_field(r, "severity") or "info").lower()
        if tool not in tool_sev:
            tool_sev[tool] = {s: 0 for s in _SEV_ORDER}
        if sev in tool_sev[tool]:
            tool_sev[tool][sev] += 1

    for tool, by_sev in sorted(tool_sev.items(), key=lambda x: -sum(x[1].values())):
        tool_rows.append({
            "tool":      tool,
            "total":     sum(by_sev.values()),
            "by_sev":    by_sev,
            "base_conf": TOOL_BASE_SCORES.get(tool, 45),
        })

    # Findings — already sorted in JSON report
    findings = json_data["findings"]

    env = Environment(autoescape=True)
    tmpl = env.from_string(_HTML_TEMPLATE)

    return tmpl.render(
        target_url    = meta["target_url"],
        scan_id       = meta["scan_id"],
        status        = meta["status"],
        duration      = duration_str,
        tools_count   = len(meta["tools"]),
        created_at    = _fmt_dt(meta["created_at"]),
        generated_at  = _fmt_dt(meta["generated_at"]),
        sev_counts    = summary["by_severity"],
        confirmed_count = summary["confirmed_count"],
        avg_confidence  = summary["avg_confidence"],
        owasp_cells   = owasp_cells,
        tool_rows     = tool_rows,
        findings      = findings,
        total_findings = len(findings),
        sev_colours   = _SEV_COLOURS,
        sev_bg        = _SEV_BG,
    )
