import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeft, Download, FileBarChart, Shield, ShieldAlert,
  ShieldCheck, ShieldOff, AlertTriangle, CheckCircle2,
} from 'lucide-react'
import { fetchScanReport, downloadHtmlReport, downloadJsonReport } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import type { Severity, OWASPCellSummary } from '../types'

// ── Helpers ────────────────────────────────────────────────────────────────────

const SEV_COLOURS: Record<Severity, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-emerald-400',
  info:     'text-blue-400',
}

const SEV_BG: Record<Severity, string> = {
  critical: 'bg-red-500/10 border-red-500/30',
  high:     'bg-orange-500/10 border-orange-500/30',
  medium:   'bg-yellow-500/10 border-yellow-500/30',
  low:      'bg-emerald-500/10 border-emerald-500/30',
  info:     'bg-blue-500/10 border-blue-500/30',
}

function ConfidenceBar({ value }: { value: number }) {
  let colour = 'bg-slate-600'
  if (value >= 90) colour = 'bg-red-500'
  else if (value >= 80) colour = 'bg-emerald-500'
  else if (value >= 70) colour = 'bg-blue-500'
  else if (value >= 55) colour = 'bg-yellow-500'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-briar-border rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${colour}`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-xs font-mono text-slate-400 w-8 text-right">{value}%</span>
    </div>
  )
}

// ── OWASP cell ────────────────────────────────────────────────────────────────

function OWASPCell({ k, cell }: { k: string; cell: OWASPCellSummary }) {
  const maxSev = cell.max_severity as Severity | null

  return (
    <div className={`rounded-lg border p-3 transition-colors ${
      cell.covered
        ? `${SEV_BG[maxSev ?? 'info']} border-opacity-60`
        : 'bg-briar-surface border-briar-border opacity-50'
    }`}>
      <div className="flex items-start justify-between mb-1">
        <span className="text-xs font-bold text-slate-500">{k}:2021</span>
        {cell.covered
          ? <ShieldAlert size={13} className={SEV_COLOURS[maxSev ?? 'info']} />
          : <ShieldCheck size={13} className="text-slate-600" />
        }
      </div>
      <p className="text-xs font-semibold text-slate-200 leading-tight">{cell.name}</p>
      {cell.covered ? (
        <div className="mt-2 space-y-0.5">
          <p className={`text-xs font-bold ${SEV_COLOURS[maxSev ?? 'info']}`}>
            {cell.finding_count} finding{cell.finding_count !== 1 ? 's' : ''}
          </p>
          {cell.confirmed_count > 0 && (
            <p className="text-xs text-purple-400">✓ {cell.confirmed_count} confirmed</p>
          )}
          <div className="flex gap-1 flex-wrap mt-1">
            {(['critical','high','medium','low'] as Severity[]).map((s) =>
              (cell.severity_counts[s] ?? 0) > 0 ? (
                <span key={s} className={`text-xs px-1 rounded ${SEV_COLOURS[s]}`}>
                  {cell.severity_counts[s]}{s[0].toUpperCase()}
                </span>
              ) : null
            )}
          </div>
        </div>
      ) : (
        <p className="text-xs text-slate-600 mt-2">Not detected</p>
      )}
    </div>
  )
}

// ── Summary bar ───────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

function SeverityBar({ by_severity, total }: { by_severity: Record<string, number>; total: number }) {
  if (!total) return null
  return (
    <div className="flex h-4 rounded overflow-hidden">
      {SEVERITY_ORDER.map((s) => {
        const n = by_severity[s] ?? 0
        if (!n) return null
        const pct = (n / total) * 100
        const colMap: Record<Severity, string> = {
          critical: 'bg-red-500',
          high: 'bg-orange-400',
          medium: 'bg-yellow-400',
          low: 'bg-emerald-500',
          info: 'bg-blue-500',
        }
        return (
          <div
            key={s}
            className={`${colMap[s]} h-full`}
            style={{ width: `${pct}%` }}
            title={`${s}: ${n}`}
          />
        )
      })}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Report() {
  const { id } = useParams<{ id: string }>()
  const [htmlLoading, setHtmlLoading] = useState(false)
  const [jsonLoading, setJsonLoading] = useState(false)

  const { data: report, isLoading, isError } = useQuery({
    queryKey: ['report', id],
    queryFn: () => fetchScanReport(id!),
    enabled: !!id,
  })

  const handleHtml = async () => {
    setHtmlLoading(true)
    try { await downloadHtmlReport(id!) }
    catch (e: any) { alert(e.message) }
    finally { setHtmlLoading(false) }
  }

  const handleJson = async () => {
    setJsonLoading(true)
    try { await downloadJsonReport(id!) }
    catch (e: any) { alert(e.message) }
    finally { setJsonLoading(false) }
  }

  if (isLoading) return (
    <div className="flex items-center justify-center h-full text-slate-500">
      Generating report…
    </div>
  )

  if (isError || !report) return (
    <div className="p-8 text-center text-red-400">
      Failed to load report. Make sure the scan has completed.
    </div>
  )

  const { meta, summary, owasp_coverage, findings } = report
  const coveredCount = Object.values(owasp_coverage).filter((c) => c.covered).length

  const duration = meta.duration_s != null
    ? (() => { const m = Math.floor(meta.duration_s! / 60); const s = meta.duration_s! % 60; return m ? `${m}m ${s}s` : `${s}s` })()
    : '—'

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <Link to={`/scan/${id}/vulns`} className="btn-ghost py-1 px-2 flex items-center gap-1">
            <ArrowLeft size={14} /> Vulns
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
              <FileBarChart size={22} className="text-briar-accent" />
              Security Report
            </h1>
            <p className="text-slate-400 text-sm mt-0.5 font-mono">{meta.target_url}</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleJson}
            disabled={jsonLoading}
            className="btn-ghost flex items-center gap-1"
          >
            <Download size={14} /> {jsonLoading ? '…' : 'JSON'}
          </button>
          <button
            onClick={handleHtml}
            disabled={htmlLoading}
            className="btn-primary flex items-center gap-1"
          >
            <Download size={14} /> {htmlLoading ? 'Generating…' : 'HTML Report'}
          </button>
        </div>
      </div>

      {/* Meta card */}
      <div className="card">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Status</p>
            <StatusBadge value={meta.status as any} />
          </div>
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Duration</p>
            <p className="text-slate-200 font-semibold">{duration}</p>
          </div>
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Tools</p>
            <p className="text-slate-200 font-semibold">{meta.tools.length} tools</p>
            <p className="text-xs text-slate-600 mt-0.5">{meta.tools.join(', ')}</p>
          </div>
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Generated</p>
            <p className="text-slate-200 font-semibold">
              {new Date(meta.generated_at).toLocaleString()}
            </p>
          </div>
        </div>
      </div>

      {/* Severity summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        {SEVERITY_ORDER.map((s) => (
          <div key={s} className={`card text-center border ${SEV_BG[s]}`}>
            <div className={`text-2xl font-bold ${SEV_COLOURS[s]}`}>
              {summary.by_severity[s] ?? 0}
            </div>
            <p className="text-xs text-slate-400 capitalize mt-1">{s}</p>
          </div>
        ))}
        <div className="card text-center border border-purple-500/20 bg-purple-500/5">
          <div className="text-2xl font-bold text-purple-400">{summary.confirmed_count}</div>
          <p className="text-xs text-slate-400 mt-1">Confirmed</p>
        </div>
        <div className="card text-center">
          <div className="text-2xl font-bold text-slate-200">{summary.avg_confidence}%</div>
          <p className="text-xs text-slate-400 mt-1">Avg Confidence</p>
        </div>
      </div>

      {/* Severity bar chart */}
      {summary.total > 0 && (
        <div className="card">
          <div className="flex justify-between items-center mb-2">
            <p className="text-sm font-semibold text-slate-200">{summary.total} total findings</p>
            <div className="flex gap-3">
              {SEVERITY_ORDER.filter(s => (summary.by_severity[s] ?? 0) > 0).map(s => (
                <span key={s} className={`text-xs ${SEV_COLOURS[s]}`}>
                  {summary.by_severity[s]} {s}
                </span>
              ))}
            </div>
          </div>
          <SeverityBar by_severity={summary.by_severity} total={summary.total} />
        </div>
      )}

      {/* OWASP matrix */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-slate-100 flex items-center gap-2">
            <Shield size={16} className="text-briar-accent" />
            OWASP Top 10 — 2021 Coverage
          </h2>
          <div className="flex items-center gap-2 text-xs">
            <span className={`flex items-center gap-1 ${coveredCount > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
              {coveredCount > 0
                ? <><AlertTriangle size={12} /> {coveredCount} categor{coveredCount === 1 ? 'y' : 'ies'} affected</>
                : <><CheckCircle2 size={12} /> Clean — no OWASP categories detected</>
              }
            </span>
            <span className="text-slate-600">· {10 - coveredCount} not detected</span>
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {Object.entries(owasp_coverage)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, cell]) => (
              <OWASPCell key={k} k={k} cell={cell} />
            ))
          }
        </div>
      </div>

      {/* Tool breakdown */}
      <div className="card">
        <h2 className="font-semibold text-slate-100 mb-4">Findings by Tool</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {Object.entries(summary.by_tool)
            .sort(([, a], [, b]) => b - a)
            .map(([tool, count]) => (
              <div key={tool} className="flex items-center gap-3 bg-briar-bg rounded-lg px-3 py-2">
                <span className="font-mono text-xs text-briar-accent bg-briar-accent/10 px-2 py-0.5 rounded w-28 text-center shrink-0">
                  {tool}
                </span>
                <div className="flex-1">
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-400">{count} finding{count !== 1 ? 's' : ''}</span>
                  </div>
                  <div className="h-1.5 bg-briar-border rounded-full overflow-hidden">
                    <div
                      className="h-full bg-briar-accent rounded-full"
                      style={{ width: `${Math.min(100, (count / summary.total) * 100 * 3)}%` }}
                    />
                  </div>
                </div>
              </div>
            ))
          }
        </div>
      </div>

      {/* Top findings table */}
      {findings.length > 0 && (
        <div className="card p-0 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-briar-border">
            <h2 className="font-semibold text-slate-100">
              Top Findings
              <span className="ml-2 text-sm text-slate-500 font-normal">
                (showing {Math.min(findings.length, 50)} of {findings.length})
              </span>
            </h2>
            <Link
              to={`/scan/${id}/vulns`}
              className="text-xs text-briar-accent hover:underline flex items-center gap-1"
            >
              <ShieldAlert size={12} /> View all in Vulns
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-briar-border">
                <tr>
                  <th className="table-header">Severity</th>
                  <th className="table-header">Vulnerability</th>
                  <th className="table-header">Tool</th>
                  <th className="table-header">URL</th>
                  <th className="table-header text-center">Confidence</th>
                  <th className="table-header">OWASP</th>
                  <th className="table-header">Status</th>
                </tr>
              </thead>
              <tbody>
                {findings.slice(0, 50).map((f) => (
                  <tr
                    key={f.id}
                    className={`border-b border-briar-border hover:bg-white/[0.02] ${
                      f.vuln_status === 'false_positive' ? 'opacity-40' : ''
                    }`}
                  >
                    <td className="table-cell">
                      <StatusBadge value={f.severity} variant="severity" />
                    </td>
                    <td className="table-cell max-w-xs">
                      <p className="text-sm font-medium text-slate-200">{f.vulnerability_type || '—'}</p>
                      {f.description && (
                        <p className="text-xs text-slate-500 line-clamp-1 mt-0.5">{f.description}</p>
                      )}
                      {f.confirmed_by.length > 1 && (
                        <span className="text-xs text-purple-400">
                          ✓ {f.confirmed_by.join(' · ')}
                        </span>
                      )}
                    </td>
                    <td className="table-cell">
                      <span className="text-xs font-mono text-slate-400 bg-briar-bg px-1.5 py-0.5 rounded">
                        {f.tool}
                      </span>
                    </td>
                    <td className="table-cell max-w-xs">
                      {f.url
                        ? <a href={f.url} target="_blank" rel="noreferrer"
                            className="text-xs text-briar-accent hover:underline truncate block max-w-[220px]">
                            {f.url}
                          </a>
                        : '—'
                      }
                    </td>
                    <td className="table-cell w-32">
                      <ConfidenceBar value={f.confidence} />
                    </td>
                    <td className="table-cell">
                      {f.owasp
                        ? <span className="text-xs font-mono text-slate-400">{f.owasp}</span>
                        : '—'
                      }
                    </td>
                    <td className="table-cell text-xs">
                      {f.vuln_status === 'false_positive' && <span className="text-slate-500">FP (auto)</span>}
                      {f.vuln_status === 'fixed'          && <span className="text-emerald-400">Fixed</span>}
                      {f.vuln_status === 'accepted'       && <span className="text-yellow-400">Accepted</span>}
                      {f.vuln_status === 'open'           && <span className="text-red-400">Open</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {findings.length === 0 && (
        <div className="card text-center py-12">
          <ShieldCheck size={40} className="mx-auto text-emerald-400 mb-3" />
          <p className="text-slate-200 font-semibold">No findings recorded</p>
          <p className="text-slate-500 text-sm mt-1">This scan produced no security findings.</p>
        </div>
      )}
    </div>
  )
}
