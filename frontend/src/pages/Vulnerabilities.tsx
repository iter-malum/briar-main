import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Download, Filter, ChevronDown, ChevronRight,
  Layers, List, CheckCircle, XCircle, ShieldOff, Clock, History,
  MessageSquare, X, GitCompare, Plus, Minus, Equal,
} from 'lucide-react'
import { fetchVulnerabilities, fetchVulnHistory, updateVulnStatus, fetchScanDiff, fetchScans } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import type { Severity, Vulnerability, VulnStatus } from '../types'

// ── Constants ──────────────────────────────────────────────────────────────────

const SEVERITIES: Array<Severity | ''> = ['', 'critical', 'high', 'medium', 'low', 'info']
const TOOLS = ['', 'nuclei', 'zap', 'nikto', 'dalfox', 'sqlmap', 'ffuf']

const VULN_STATUS_OPTIONS: Array<{ value: VulnStatus | ''; label: string }> = [
  { value: '',               label: 'All statuses' },
  { value: 'open',           label: 'Open' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'accepted',       label: 'Accepted Risk' },
  { value: 'fixed',          label: 'Fixed' },
]

// ── Status badge & actions ────────────────────────────────────────────────────

const STATUS_META: Record<VulnStatus, { label: string; cls: string; Icon: any }> = {
  open:           { label: 'Open',       cls: 'text-red-400 bg-red-400/10 border-red-500/30',         Icon: Clock },
  false_positive: { label: 'False +',   cls: 'text-slate-400 bg-slate-400/10 border-slate-500/30',   Icon: XCircle },
  accepted:       { label: 'Accepted',  cls: 'text-yellow-400 bg-yellow-400/10 border-yellow-500/30', Icon: ShieldOff },
  fixed:          { label: 'Fixed',     cls: 'text-emerald-400 bg-emerald-400/10 border-emerald-500/30', Icon: CheckCircle },
}

function VulnStatusBadge({ status }: { status: VulnStatus | undefined }) {
  const s = status ?? 'open'
  const { label, cls, Icon } = STATUS_META[s]
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${cls}`}>
      <Icon size={10} />
      {label}
    </span>
  )
}

// ── Inline status actions ─────────────────────────────────────────────────────

function StatusActions({ vulnId, current, onUpdated }: {
  vulnId: string
  current: VulnStatus | undefined
  onUpdated: () => void
}) {
  const qc = useQueryClient()
  const mut = useMutation({
    mutationFn: (status: VulnStatus) => updateVulnStatus(vulnId, { vuln_status: status }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['vulns'] }); onUpdated() },
  })

  const actions: Array<{ status: VulnStatus; label: string; Icon: any }> = [
    { status: 'open',           label: 'Open',       Icon: Clock },
    { status: 'false_positive', label: 'False +',   Icon: XCircle },
    { status: 'accepted',       label: 'Accept',    Icon: ShieldOff },
    { status: 'fixed',          label: 'Fixed',     Icon: CheckCircle },
  ]

  return (
    <div className="flex gap-1 flex-wrap">
      {actions.map(({ status, label, Icon }) => {
        const active = (current ?? 'open') === status
        const { cls } = STATUS_META[status]
        return (
          <button
            key={status}
            onClick={(e) => { e.stopPropagation(); mut.mutate(status) }}
            disabled={active || mut.isPending}
            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs transition-colors
              ${active
                ? `${cls} cursor-default opacity-90`
                : 'text-slate-500 border-slate-700 hover:border-slate-500 hover:text-slate-300'
              }`}
          >
            <Icon size={10} />
            {label}
          </button>
        )
      })}
    </div>
  )
}

// ── Note editor (inline) ──────────────────────────────────────────────────────

function NoteEditor({ vulnId, note, onDone }: {
  vulnId: string
  note: string | null | undefined
  onDone: () => void
}) {
  const [text, setText] = useState(note ?? '')
  const qc = useQueryClient()
  const mut = useMutation({
    mutationFn: () => updateVulnStatus(vulnId, { analyst_note: text }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['vulns'] }); onDone() },
  })
  return (
    <div className="mt-2 flex gap-2 items-start" onClick={(e) => e.stopPropagation()}>
      <textarea
        className="flex-1 bg-briar-bg border border-briar-border rounded px-2 py-1 text-xs text-slate-200
                   focus:outline-none focus:border-briar-accent resize-none"
        rows={2}
        placeholder="Add analyst note…"
        value={text}
        onChange={(e) => setText(e.target.value)}
        autoFocus
      />
      <div className="flex flex-col gap-1">
        <button
          onClick={() => mut.mutate()}
          disabled={mut.isPending}
          className="px-2 py-1 rounded bg-briar-accent text-white text-xs hover:opacity-80"
        >
          Save
        </button>
        <button onClick={onDone} className="px-2 py-1 rounded border border-briar-border text-xs text-slate-400 hover:text-slate-200">
          Cancel
        </button>
      </div>
    </div>
  )
}

// ── History drawer ────────────────────────────────────────────────────────────

function HistoryDrawer({ vulnId, onClose }: { vulnId: string; onClose: () => void }) {
  const { data, isLoading } = useQuery({
    queryKey: ['vuln-history', vulnId],
    queryFn: () => fetchVulnHistory(vulnId),
  })

  return (
    <div
      className="fixed inset-0 bg-black/50 z-50 flex items-end justify-center"
      onClick={onClose}
    >
      <div
        className="card w-full max-w-lg mb-4 max-h-[60vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex justify-between items-center mb-3">
          <h3 className="font-semibold flex items-center gap-2"><History size={14} /> Status History</h3>
          <button onClick={onClose}><X size={16} className="text-slate-400 hover:text-slate-200" /></button>
        </div>
        {isLoading && <p className="text-sm text-slate-500">Loading…</p>}
        {data?.length === 0 && <p className="text-sm text-slate-500">No status changes yet.</p>}
        <div className="space-y-2">
          {data?.map((h) => (
            <div key={h.id} className="flex gap-3 items-start text-xs">
              <span className="text-slate-600 whitespace-nowrap mt-0.5">
                {new Date(h.changed_at).toLocaleString()}
              </span>
              <div className="flex-1">
                <span className="text-slate-400">
                  {h.old_status
                    ? <><span className="line-through text-slate-600">{h.old_status}</span> → </>
                    : null}
                  <VulnStatusBadge status={h.new_status as VulnStatus} />
                </span>
                {h.note && <p className="text-slate-500 mt-0.5 italic">"{h.note}"</p>}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── GroupedRow ────────────────────────────────────────────────────────────────

function GroupedRow({ v }: { v: Vulnerability }) {
  const [open, setOpen] = useState(false)
  const [editNote, setEditNote] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const urls: string[] = v.affected_urls ?? []
  const count: number = v.count ?? 1
  const status = v.vuln_status ?? 'open'

  return (
    <>
      <tr
        className="border-b border-briar-border hover:bg-white/[0.02] transition-colors cursor-pointer"
        onClick={() => setOpen((x) => !x)}
      >
        <td className="table-cell">
          <StatusBadge value={v.severity} variant="severity" />
        </td>
        <td className="table-cell font-medium text-sm">{v.vulnerability_type ?? '—'}</td>
        <td className="table-cell">
          <span className="text-xs font-mono text-slate-400">{v.tool}</span>
        </td>
        <td className="table-cell text-center">
          <span className="text-sm font-bold text-slate-200">{count}</span>
          <span className="text-xs text-slate-500 ml-1">URL{count !== 1 ? 's' : ''}</span>
        </td>
        <td className="table-cell max-w-xs">
          <p className="text-xs text-slate-400 line-clamp-1">{v.description ?? '—'}</p>
        </td>
        <td className="table-cell">
          <VulnStatusBadge status={status} />
        </td>
        <td className="table-cell text-slate-500 w-6">
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </td>
      </tr>

      {open && (
        <tr className="border-b border-briar-border bg-briar-bg/40">
          <td colSpan={7} className="px-4 py-3 space-y-3">
            {/* Affected URLs */}
            {urls.length > 0 && (
              <div className="space-y-1 max-h-36 overflow-y-auto">
                {urls.map((url) => (
                  <a key={url} href={url} target="_blank" rel="noreferrer"
                    className="block text-xs text-briar-accent hover:underline truncate"
                    onClick={(e) => e.stopPropagation()}
                  >{url}</a>
                ))}
              </div>
            )}

            {/* Status actions */}
            <div className="flex flex-wrap items-center gap-3">
              <StatusActions vulnId={v.id} current={status} onUpdated={() => setOpen(true)} />

              <button
                onClick={(e) => { e.stopPropagation(); setEditNote((x) => !x) }}
                className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300"
              >
                <MessageSquare size={12} />
                {v.analyst_note ? 'Edit note' : 'Add note'}
              </button>

              <button
                onClick={(e) => { e.stopPropagation(); setShowHistory(true) }}
                className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300"
              >
                <History size={12} /> History
              </button>
            </div>

            {/* Current note */}
            {v.analyst_note && !editNote && (
              <p className="text-xs text-slate-400 italic border-l-2 border-slate-600 pl-2">
                "{v.analyst_note}"
              </p>
            )}

            {/* Note editor */}
            {editNote && (
              <NoteEditor vulnId={v.id} note={v.analyst_note} onDone={() => setEditNote(false)} />
            )}
          </td>
        </tr>
      )}

      {showHistory && <HistoryDrawer vulnId={v.id} onClose={() => setShowHistory(false)} />}
    </>
  )
}

// ── Diff view ─────────────────────────────────────────────────────────────────

const DIFF_META = {
  new:       { label: 'New',       Icon: Plus,  cls: 'text-red-400 bg-red-400/10 border-red-500/20' },
  fixed:     { label: 'Fixed',     Icon: Minus, cls: 'text-emerald-400 bg-emerald-400/10 border-emerald-500/20' },
  persisted: { label: 'Persisted', Icon: Equal, cls: 'text-slate-400 bg-slate-400/10 border-slate-500/20' },
} as const

type DiffCategory = keyof typeof DIFF_META

function DiffRow({ v, category }: { v: Vulnerability; category: DiffCategory }) {
  const { cls, Icon } = DIFF_META[category]
  return (
    <tr className="border-b border-briar-border hover:bg-white/[0.02]">
      <td className="table-cell">
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs ${cls}`}>
          <Icon size={10} /> {DIFF_META[category].label}
        </span>
      </td>
      <td className="table-cell"><StatusBadge value={v.severity} variant="severity" /></td>
      <td className="table-cell font-medium text-sm">{v.vulnerability_type ?? '—'}</td>
      <td className="table-cell"><span className="text-xs font-mono text-slate-400">{v.tool}</span></td>
      <td className="table-cell max-w-xs">
        {v.url
          ? <a href={v.url} target="_blank" rel="noreferrer" className="text-briar-accent hover:underline text-xs truncate block">{v.url}</a>
          : '—'}
      </td>
      <td className="table-cell max-w-sm">
        <p className="text-xs text-slate-400 line-clamp-1">{v.description ?? '—'}</p>
      </td>
    </tr>
  )
}

function DiffView({ scanId, compareToId, onClose }: {
  scanId: string
  compareToId: string
  onClose: () => void
}) {
  const [activeTab, setActiveTab] = useState<DiffCategory>('new')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-diff', scanId, compareToId],
    queryFn: () => fetchScanDiff(scanId, compareToId),
  })

  return (
    <div className="space-y-4">
      {/* Diff header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <GitCompare size={16} className="text-briar-accent" />
          <span className="text-sm font-medium text-slate-200">Scan comparison</span>
          <span className="text-xs text-slate-500">
            #{scanId.slice(0, 8)} vs #{compareToId.slice(0, 8)}
          </span>
        </div>
        <button onClick={onClose} className="btn-ghost py-1 px-2 text-xs flex items-center gap-1">
          <X size={12} /> Close diff
        </button>
      </div>

      {isLoading && <div className="p-8 text-center text-slate-500">Comparing scans…</div>}
      {isError  && <div className="p-6 text-center text-red-400">Failed to load diff.</div>}

      {data && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-3 gap-3">
            {(['new', 'fixed', 'persisted'] as DiffCategory[]).map((cat) => {
              const { label, Icon, cls } = DIFF_META[cat]
              const count = data.summary[cat]
              return (
                <button
                  key={cat}
                  onClick={() => setActiveTab(cat)}
                  className={`card text-center hover:border-briar-accent/50 transition-colors ${
                    activeTab === cat ? 'border-briar-accent' : ''
                  }`}
                >
                  <div className={`text-3xl font-bold mb-1 ${cls.split(' ')[0]}`}>{count}</div>
                  <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs ${cls}`}>
                    <Icon size={10} /> {label}
                  </span>
                </button>
              )
            })}
          </div>

          {/* Tab content */}
          <div className="card p-0 overflow-hidden">
            {data[activeTab].length === 0 ? (
              <div className="p-8 text-center text-slate-500">
                No {DIFF_META[activeTab].label.toLowerCase()} findings.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="border-b border-briar-border">
                    <tr>
                      <th className="table-header">Change</th>
                      <th className="table-header">Severity</th>
                      <th className="table-header">Type</th>
                      <th className="table-header">Tool</th>
                      <th className="table-header">URL</th>
                      <th className="table-header">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data[activeTab].map((v) => (
                      <DiffRow key={v.id} v={v} category={activeTab} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

function DiffSelector({ currentScanId, onSelect }: {
  currentScanId: string
  onSelect: (id: string) => void
}) {
  const { data: scans } = useQuery({ queryKey: ['scans'], queryFn: fetchScans })

  // Only show completed scans, excluding current
  const candidates = (scans ?? [])
    .filter((s) => s.id !== currentScanId && s.status === 'completed')
    .slice(0, 20)

  if (candidates.length === 0) return (
    <span className="text-xs text-slate-500">No other completed scans to compare with.</span>
  )

  return (
    <select
      defaultValue=""
      onChange={(e) => { if (e.target.value) onSelect(e.target.value) }}
      className="bg-briar-surface border border-briar-border rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:border-briar-accent"
    >
      <option value="">Compare with…</option>
      {candidates.map((s) => (
        <option key={s.id} value={s.id}>
          #{s.id.slice(0, 8)} — {s.target_url} ({new Date(s.created_at).toLocaleDateString()})
        </option>
      ))}
    </select>
  )
}

// ── Export helpers ────────────────────────────────────────────────────────────

function exportCsv(rows: Vulnerability[]) {
  const header = 'tool,severity,type,status,count,description'
  const lines = rows.map((r) =>
    [r.tool, r.severity, r.vulnerability_type ?? '', r.vuln_status ?? 'open',
     r.count ?? 1, (r.description ?? '').replace(/,/g, ';')].join(','),
  )
  const blob = new Blob([[header, ...lines].join('\n')], { type: 'text/csv' })
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
  a.download = 'vulnerabilities.csv'; a.click()
}

function exportJson(rows: Vulnerability[]) {
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' })
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
  a.download = 'vulnerabilities.json'; a.click()
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Vulnerabilities() {
  const { id } = useParams<{ id: string }>()
  const [severity, setSeverity] = useState<string>('')
  const [tool, setTool] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('open')
  const [grouped, setGrouped] = useState(true)
  const [diffTarget, setDiffTarget] = useState<string | null>(null)

  const { data: vulns, isLoading, isError } = useQuery({
    queryKey: ['vulns', id, severity, tool, statusFilter, grouped],
    queryFn: () =>
      fetchVulnerabilities({
        scan_id: id,
        severity: severity || undefined,
        tool: tool || undefined,
        deduplicate: grouped,
      }),
    refetchInterval: 10000,
    select: (data) => {
      // Client-side status filter (deduplicate mode uses worst-status heuristic,
      // so we apply the filter after fetching to keep counts accurate)
      if (!statusFilter) return data
      return data.filter((v) => (v.vuln_status ?? 'open') === statusFilter)
    },
  })

  const counts = vulns
    ? SEVERITIES.filter(Boolean).map((s) => ({
        sev: s as Severity,
        count: vulns.filter((v) => v.severity === s).length,
      }))
    : []

  const totalAffected = grouped
    ? vulns?.reduce((acc, v) => acc + (v.count ?? 1), 0) ?? 0
    : vulns?.length ?? 0

  const hasFilters = !!(severity || tool || statusFilter)

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
        <div className="flex gap-2 items-center">
          <div className="flex items-center gap-1 bg-briar-bg border border-briar-border rounded-lg p-0.5">
            <button
              onClick={() => setGrouped(true)}
              className={`flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors ${
                grouped ? 'bg-briar-accent text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers size={12} /> Grouped
            </button>
            <button
              onClick={() => setGrouped(false)}
              className={`flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors ${
                !grouped ? 'bg-briar-accent text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <List size={12} /> All
            </button>
          </div>
          {/* Compare button — only available for a specific scan */}
          {id && !diffTarget && (
            <DiffSelector currentScanId={id} onSelect={setDiffTarget} />
          )}
          {id && diffTarget && (
            <button
              onClick={() => setDiffTarget(null)}
              className="btn-ghost flex items-center gap-1 text-briar-accent"
            >
              <GitCompare size={14} /> Diff active
            </button>
          )}
          {vulns && vulns.length > 0 && (
            <>
              <button onClick={() => exportCsv(vulns)} className="btn-ghost flex items-center gap-1">
                <Download size={14} /> CSV
              </button>
              <button onClick={() => exportJson(vulns)} className="btn-ghost flex items-center gap-1">
                <Download size={14} /> JSON
              </button>
            </>
          )}
        </div>
      </div>

      {/* Diff view — shown when a baseline scan is selected */}
      {id && diffTarget && (
        <DiffView
          scanId={id}
          compareToId={diffTarget}
          onClose={() => setDiffTarget(null)}
        />
      )}

      {/* Normal view — hidden while diff is active */}
      {!diffTarget && <>

      {/* Severity summary */}
      {counts.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {counts.map(({ sev, count }) => (
            <button
              key={sev}
              onClick={() => setSeverity(severity === sev ? '' : sev)}
              className={`card text-center hover:border-briar-accent/50 transition-colors ${
                severity === sev ? 'border-briar-accent' : ''
              }`}
            >
              <div className="text-2xl font-bold text-slate-100">{count}</div>
              <StatusBadge value={sev} variant="severity" />
            </button>
          ))}
        </div>
      )}

      {/* Status tabs */}
      <div className="flex gap-1 border-b border-briar-border pb-0">
        {VULN_STATUS_OPTIONS.map(({ value, label }) => (
          <button
            key={value}
            onClick={() => setStatusFilter(value)}
            className={`px-3 py-2 text-xs font-medium transition-colors border-b-2 -mb-px ${
              statusFilter === value
                ? 'border-briar-accent text-slate-100'
                : 'border-transparent text-slate-500 hover:text-slate-300'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

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
        {hasFilters && (
          <button
            onClick={() => { setSeverity(''); setTool(''); setStatusFilter('open') }}
            className="text-xs text-slate-500 hover:text-slate-300"
          >
            Clear filters
          </button>
        )}
        <span className="ml-auto text-xs text-slate-500">
          {vulns?.length ?? 0} {grouped ? 'unique types' : 'findings'}
          {grouped && totalAffected > 0 && (
            <span className="text-slate-600 ml-1">({totalAffected} total occurrences)</span>
          )}
        </span>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        {isLoading && <div className="p-8 text-center text-slate-500">Loading…</div>}
        {isError && <div className="p-8 text-center text-red-400">Failed to load vulnerabilities.</div>}
        {vulns?.length === 0 && (
          <div className="p-8 text-center text-slate-500">
            No vulnerabilities found
            {statusFilter === 'open' ? ' — all findings have been triaged!' : ' with current filters.'}
          </div>
        )}
        {vulns && vulns.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-briar-border">
                <tr>
                  <th className="table-header">Severity</th>
                  <th className="table-header">Type</th>
                  <th className="table-header">Tool</th>
                  <th className="table-header text-center">{grouped ? 'Affected' : 'URL'}</th>
                  <th className="table-header">Description</th>
                  <th className="table-header">Status</th>
                  <th className="table-header w-6"></th>
                </tr>
              </thead>
              <tbody>
                {grouped
                  ? vulns.map((v) => <GroupedRow key={`${v.vulnerability_type}-${v.tool}`} v={v} />)
                  : vulns.map((v) => (
                      <tr key={v.id} className="border-b border-briar-border hover:bg-white/[0.02]">
                        <td className="table-cell"><StatusBadge value={v.severity} variant="severity" /></td>
                        <td className="table-cell font-medium text-sm">{v.vulnerability_type ?? '—'}</td>
                        <td className="table-cell"><span className="text-xs font-mono text-slate-400">{v.tool}</span></td>
                        <td className="table-cell max-w-xs">
                          {v.url ? (
                            <a href={v.url} target="_blank" rel="noreferrer"
                              className="text-briar-accent hover:underline text-xs truncate block">{v.url}</a>
                          ) : '—'}
                        </td>
                        <td className="table-cell max-w-sm">
                          <p className="text-xs text-slate-400 line-clamp-2">{v.description ?? '—'}</p>
                        </td>
                        <td className="table-cell">
                          <VulnStatusBadge status={v.vuln_status} />
                        </td>
                        <td className="table-cell"></td>
                      </tr>
                    ))
                }
              </tbody>
            </table>
          </div>
        )}
      </div>

      </> /* end !diffTarget */}
    </div>
  )
}
