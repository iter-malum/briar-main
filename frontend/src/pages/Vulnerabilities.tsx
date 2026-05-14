import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Download, Filter } from 'lucide-react'
import { fetchVulnerabilities } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import type { Severity, Vulnerability } from '../types'

const SEVERITIES: Array<Severity | ''> = ['', 'critical', 'high', 'medium', 'low', 'info']
const TOOLS = ['', 'nuclei', 'zap', 'ffuf']

function exportCsv(rows: Vulnerability[]) {
  const header = 'id,scan_id,tool,severity,url,type,description,created_at'
  const lines = rows.map((r) =>
    [r.id, r.scan_id, r.tool, r.severity, r.url ?? '', r.vulnerability_type ?? '', (r.description ?? '').replace(/,/g, ';'), r.created_at].join(','),
  )
  const blob = new Blob([[header, ...lines].join('\n')], { type: 'text/csv' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = 'vulnerabilities.csv'
  a.click()
}

function exportJson(rows: Vulnerability[]) {
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = 'vulnerabilities.json'
  a.click()
}

export default function Vulnerabilities() {
  const { id } = useParams<{ id: string }>()
  const [severity, setSeverity] = useState<string>('')
  const [tool, setTool] = useState<string>('')

  const { data: vulns, isLoading, isError } = useQuery({
    queryKey: ['vulns', id, severity, tool],
    queryFn: () =>
      fetchVulnerabilities({
        scan_id: id,
        severity: severity || undefined,
        tool: tool || undefined,
        limit: 500,
      }),
    refetchInterval: 10000,
  })

  const counts = vulns
    ? SEVERITIES.filter(Boolean).map((s) => ({
        sev: s as Severity,
        count: vulns.filter((v) => v.severity === s).length,
      }))
    : []

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          {id && (
            <Link to={`/scan/${id}/graph`} className="btn-ghost py-1 px-2 flex items-center gap-1">
              <ArrowLeft size={14} /> Graph
            </Link>
          )}
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Vulnerabilities</h1>
            {id && <p className="text-slate-400 text-sm mt-0.5">Scan {id.slice(0, 8)}…</p>}
          </div>
        </div>
        {vulns && vulns.length > 0 && (
          <div className="flex gap-2">
            <button onClick={() => exportCsv(vulns)} className="btn-ghost flex items-center gap-1">
              <Download size={14} /> CSV
            </button>
            <button onClick={() => exportJson(vulns)} className="btn-ghost flex items-center gap-1">
              <Download size={14} /> JSON
            </button>
          </div>
        )}
      </div>

      {/* Severity summary */}
      {counts.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {counts.map(({ sev, count }) => (
            <button
              key={sev}
              onClick={() => setSeverity(severity === sev ? '' : sev)}
              className={`card text-center hover:border-briar-accent/50 transition-colors ${severity === sev ? 'border-briar-accent' : ''}`}
            >
              <div className="text-2xl font-bold text-slate-100">{count}</div>
              <StatusBadge value={sev} variant="severity" />
            </button>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <Filter size={14} className="text-slate-400" />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="bg-briar-surface border border-briar-border rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:border-briar-accent"
        >
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s || 'All severities'}</option>
          ))}
        </select>
        <select
          value={tool}
          onChange={(e) => setTool(e.target.value)}
          className="bg-briar-surface border border-briar-border rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:border-briar-accent"
        >
          {TOOLS.map((t) => (
            <option key={t} value={t}>{t || 'All tools'}</option>
          ))}
        </select>
        {(severity || tool) && (
          <button onClick={() => { setSeverity(''); setTool('') }} className="text-xs text-slate-500 hover:text-slate-300">
            Clear filters
          </button>
        )}
        <span className="ml-auto text-xs text-slate-500">{vulns?.length ?? 0} results</span>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        {isLoading && <div className="p-8 text-center text-slate-500">Loading…</div>}
        {isError && <div className="p-8 text-center text-red-400">Failed to load vulnerabilities.</div>}
        {vulns?.length === 0 && (
          <div className="p-8 text-center text-slate-500">No vulnerabilities found with current filters.</div>
        )}
        {vulns && vulns.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-briar-border">
                <tr>
                  <th className="table-header">Severity</th>
                  <th className="table-header">Type</th>
                  <th className="table-header">URL</th>
                  <th className="table-header">Tool</th>
                  <th className="table-header">Description</th>
                  <th className="table-header">Found</th>
                </tr>
              </thead>
              <tbody>
                {vulns.map((v) => (
                  <tr key={v.id} className="border-b border-briar-border hover:bg-white/[0.02] transition-colors">
                    <td className="table-cell">
                      <StatusBadge value={v.severity} variant="severity" />
                    </td>
                    <td className="table-cell font-medium">{v.vulnerability_type ?? '—'}</td>
                    <td className="table-cell max-w-xs">
                      {v.url ? (
                        <a
                          href={v.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-briar-accent hover:underline text-xs truncate block"
                          title={v.url}
                        >
                          {v.url}
                        </a>
                      ) : '—'}
                    </td>
                    <td className="table-cell">
                      <span className="text-xs font-mono text-slate-400">{v.tool}</span>
                    </td>
                    <td className="table-cell max-w-sm">
                      <p className="text-xs text-slate-400 line-clamp-2">{v.description ?? '—'}</p>
                    </td>
                    <td className="table-cell text-xs text-slate-500 whitespace-nowrap">
                      {new Date(v.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
