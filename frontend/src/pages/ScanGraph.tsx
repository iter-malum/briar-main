import { useEffect, useState, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Wifi, WifiOff, StopCircle, Play, List, ExternalLink, Cpu, Network,
} from 'lucide-react'
import {
  fetchScan, fetchScanEndpoints, getWsUrl, cancelScan, runTool,
  type EndpointItem,
} from '../api/client'
import { useWebSocket } from '../hooks/useWebSocket'
import { StatusBadge } from '../components/StatusBadge'
import AppInfoCard from '../components/AppInfoCard'
import EndpointTree from '../components/EndpointTree'
import type { GraphNode, GraphLink, WsEvent } from '../types'

// ── Pipeline phase definitions ────────────────────────────────────────────────
const PHASES = [
  { id: 'recon',   label: 'RECON',   tools: ['whatweb', 'katana'] },
  { id: 'probe',   label: 'PROBE',   tools: ['httpx', 'ffuf', 'gobuster', 'arjun'] },
  { id: 'dast',    label: 'DAST',    tools: ['nuclei', 'zap', 'nikto', 'dalfox'] },
  { id: 'exploit', label: 'EXPLOIT', tools: ['sqlmap'] },
]

const ALL_TOOLS = [
  'katana', 'httpx', 'nuclei', 'ffuf', 'zap', 'whatweb',
  'gobuster', 'arjun', 'nikto', 'dalfox', 'sqlmap',
]

// ── Pipeline sidebar ──────────────────────────────────────────────────────────
function PipelinePanel({ scan }: { scan: any }) {
  if (!scan) return null
  const stepMap: Record<string, string> = {}
  for (const s of scan.steps ?? []) stepMap[s.tool] = s.status

  return (
    <div className="w-52 shrink-0 border-r border-briar-border bg-briar-surface overflow-y-auto p-3 space-y-4">
      {PHASES.map(phase => {
        const phaseTools = phase.tools.filter(t => scan.tools?.includes(t))
        if (phaseTools.length === 0) return null
        const statuses = phaseTools.map(t => stepMap[t] ?? 'pending')
        const phaseStatus =
          statuses.includes('running')            ? 'running'
          : statuses.every(s => s === 'completed') ? 'completed'
          : statuses.some(s => s === 'failed')     ? 'failed'
          : 'pending'

        const dotCls =
          phaseStatus === 'running'    ? 'bg-amber-400 animate-pulse'
          : phaseStatus === 'completed'? 'bg-emerald-500'
          : phaseStatus === 'failed'   ? 'bg-red-500'
          : 'bg-slate-700'

        return (
          <div key={phase.id}>
            <div className="flex items-center gap-1.5 mb-1.5">
              <span className={`w-2 h-2 rounded-full shrink-0 ${dotCls}`} />
              <span className="text-xs font-semibold text-slate-400 tracking-wider">{phase.label}</span>
            </div>
            <div className="space-y-1 pl-3.5">
              {phaseTools.map(tool => (
                <div key={tool} className="flex items-center justify-between">
                  <span className="text-xs text-slate-500 font-mono">{tool}</span>
                  <StatusBadge value={stepMap[tool] ?? 'pending'} />
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Run Tool modal ────────────────────────────────────────────────────────────
function RunToolModal({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const qc = useQueryClient()
  const [tool, setTool] = useState('')
  const [error, setError] = useState('')

  const mut = useMutation({
    mutationFn: () => runTool(scanId, tool),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scan', scanId] }); onClose() },
    onError: (e: Error) => setError(e.message),
  })

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="card w-full max-w-md mx-4 space-y-4">
        <h2 className="text-lg font-semibold">Run Tool</h2>
        <p className="text-sm text-slate-400">
          Select a tool to run against this scan's collected endpoints.
          Runs immediately, bypassing phase dependencies.
        </p>
        <div className="flex flex-wrap gap-2">
          {ALL_TOOLS.map(t => (
            <button key={t} onClick={() => setTool(t)}
              className={`px-3 py-1 rounded-lg text-sm border transition-colors ${
                tool === t
                  ? 'bg-briar-accent border-briar-accent text-black font-semibold'
                  : 'border-briar-border text-slate-400 hover:border-briar-border-light'
              }`}>
              {t}
            </button>
          ))}
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="btn-ghost">Cancel</button>
          <button onClick={() => mut.mutate()} disabled={!tool || mut.isPending}
            className="btn-primary flex items-center gap-2">
            <Play size={13} />
            {mut.isPending ? 'Launching…' : `Run ${tool || '…'}`}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Endpoint table (list fallback) ────────────────────────────────────────────
function statusColor(code: number) {
  if (!code)      return 'text-slate-500'
  if (code < 300) return 'text-emerald-400'
  if (code < 400) return 'text-amber-400'
  return 'text-red-400'
}

function MethodBadge({ method }: { method: string }) {
  const colors: Record<string, string> = {
    GET:    'text-emerald-400 bg-emerald-400/10',
    POST:   'text-sky-400 bg-sky-400/10',
    PUT:    'text-amber-400 bg-amber-400/10',
    DELETE: 'text-red-400 bg-red-400/10',
    PATCH:  'text-purple-400 bg-purple-400/10',
  }
  const cls = colors[method?.toUpperCase()] ?? 'text-slate-400 bg-slate-400/10'
  return (
    <span className={`px-1.5 py-0.5 rounded text-xs font-mono font-bold ${cls}`}>
      {method || 'GET'}
    </span>
  )
}

function EndpointTable({ endpoints, isLoading }: { endpoints: EndpointItem[]; isLoading: boolean }) {
  const [search, setSearch] = useState('')
  const filtered = endpoints.filter(ep =>
    ep.url.toLowerCase().includes(search.toLowerCase()) ||
    ep.title?.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-2 border-b border-briar-border bg-briar-surface shrink-0">
        <input type="text" placeholder="Filter URLs…" value={search}
          onChange={e => setSearch(e.target.value)} className="input max-w-xs py-1.5 text-xs" />
        <span className="text-xs text-slate-500 ml-auto font-mono">
          {filtered.length} / {endpoints.length}
        </span>
      </div>
      <div className="flex-1 overflow-auto">
        {isLoading && <div className="p-8 text-center text-slate-500 text-sm">Loading…</div>}
        {!isLoading && filtered.length === 0 && (
          <div className="p-8 text-center text-slate-500 text-sm">No endpoints found.</div>
        )}
        {filtered.length > 0 && (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-briar-surface border-b border-briar-border">
              <tr>
                <th className="table-header">Method</th>
                <th className="table-header">Status</th>
                <th className="table-header">URL</th>
                <th className="table-header">Title</th>
                <th className="table-header">Tool</th>
                <th className="table-header">Params</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((ep: EndpointItem) => (
                <tr key={ep.url + ep.method}
                  className="border-b border-briar-border/50 hover:bg-briar-surface-2 transition-colors">
                  <td className="table-cell w-16"><MethodBadge method={ep.method} /></td>
                  <td className={`table-cell w-14 font-mono font-bold ${statusColor(ep.status_code)}`}>
                    {ep.status_code || '—'}
                  </td>
                  <td className="table-cell max-w-xs">
                    <a href={ep.url} target="_blank" rel="noreferrer"
                      className="flex items-center gap-1 text-briar-accent hover:underline font-mono truncate"
                      title={ep.url}>
                      <span className="truncate">{ep.url}</span>
                      <ExternalLink size={10} className="shrink-0" />
                    </a>
                  </td>
                  <td className="table-cell text-slate-400 truncate max-w-[160px]" title={ep.title}>
                    {ep.title || '—'}
                  </td>
                  <td className="table-cell">
                    <span className="px-1.5 py-0.5 rounded text-xs bg-briar-surface-2 text-slate-400 font-mono">
                      {ep.tool}
                    </span>
                  </td>
                  <td className="table-cell">
                    {ep.has_params && (
                      <span className="px-1.5 py-0.5 rounded text-xs bg-purple-500/15 text-purple-300"
                        title={ep.param_names.join(', ')}>
                        ✓ {ep.param_names.slice(0, 3).join(', ')}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────
export default function ScanGraph() {
  const { id } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'tree' | 'table' | 'app'>('tree')
  const [showRunTool, setShowRunTool] = useState(false)

  const { data: scan, refetch: refetchScan } = useQuery({
    queryKey: ['scan', id],
    queryFn:  () => fetchScan(id!),
    enabled:  !!id,
    refetchInterval: 4000,
  })

  const { data: epData, isLoading: epLoading, refetch: refetchEp } = useQuery({
    queryKey: ['endpoints', id, false],
    queryFn:  () => fetchScanEndpoints(id!, { include_static: false }),
    enabled:  !!id,
    refetchInterval: scan?.status === 'running' ? 8000 : false,
  })

  const cancelMut = useMutation({
    mutationFn: () => cancelScan(id!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan', id] })
      qc.invalidateQueries({ queryKey: ['scans'] })
      refetchScan()
    },
  })

  const { lastEvent, connected } = useWebSocket(id ? getWsUrl(id) : null)

  useEffect(() => {
    if (!lastEvent) return
    const ev = lastEvent as WsEvent
    if (ev.event === 'step_update' || ev.event === 'scan_complete') {
      refetchScan()
      refetchEp()
    }
  }, [lastEvent, refetchScan, refetchEp])

  const tabs = [
    { id: 'tree',  label: 'Endpoints', Icon: Network },
    { id: 'table', label: 'Table',     Icon: List    },
    { id: 'app',   label: 'App Info',  Icon: Cpu     },
  ] as const

  return (
    <div className="h-screen flex flex-col bg-briar-bg">
      {/* ── Toolbar ── */}
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-briar-border bg-briar-surface shrink-0">
        <Link to="/dashboard" className="btn-ghost py-1 px-2 flex items-center gap-1 text-xs">
          <ArrowLeft size={13} /> Back
        </Link>
        <div className="h-4 w-px bg-briar-border" />
        {scan && (
          <>
            <span className="text-slate-300 text-sm font-medium truncate max-w-xs font-mono">
              {scan.target_url}
            </span>
            <StatusBadge value={scan.status} />
          </>
        )}

        {/* Tabs */}
        <div className="flex items-center gap-0.5 ml-4 border border-briar-border rounded-lg p-0.5">
          {tabs.map(({ id: tid, label, Icon }) => (
            <button key={tid} onClick={() => setActiveTab(tid)}
              className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-colors ${
                activeTab === tid
                  ? 'bg-briar-accent text-black font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}>
              <Icon size={12} /> {label}
            </button>
          ))}
        </div>

        {/* Right controls */}
        <div className="ml-auto flex items-center gap-3 text-xs text-slate-400">
          {epData && (
            <span className="font-mono text-slate-500">{epData.total} endpoints</span>
          )}
          {connected
            ? <span className="text-emerald-400 flex items-center gap-1"><Wifi size={11} /> live</span>
            : <span className="text-slate-600 flex items-center gap-1"><WifiOff size={11} /> offline</span>
          }
          <button onClick={() => setShowRunTool(true)}
            className="flex items-center gap-1 px-2 py-1 rounded text-emerald-400
                       border border-emerald-500/30 hover:bg-emerald-500/10 transition-colors">
            <Play size={11} /> Run Tool
          </button>
          {(scan?.status === 'running' || scan?.status === 'pending') && (
            <button
              onClick={() => { if (confirm('Cancel this scan?')) cancelMut.mutate() }}
              disabled={cancelMut.isPending}
              className="flex items-center gap-1 px-2 py-1 rounded text-red-400
                         border border-red-500/30 hover:bg-red-500/10 transition-colors">
              <StopCircle size={11} />
              {cancelMut.isPending ? 'Stopping…' : 'Stop'}
            </button>
          )}
        </div>
      </div>

      {/* ── Body ── */}
      <div className="flex flex-1 overflow-hidden">
        <PipelinePanel scan={scan} />

        {/* Radial endpoint tree */}
        {activeTab === 'tree' && (
          <div className="flex-1 overflow-hidden">
            <EndpointTree endpoints={epData?.endpoints ?? []} isLoading={epLoading} />
          </div>
        )}

        {/* Table view */}
        {activeTab === 'table' && (
          <div className="flex-1 overflow-hidden">
            <EndpointTable endpoints={epData?.endpoints ?? []} isLoading={epLoading} />
          </div>
        )}

        {/* App Info */}
        {activeTab === 'app' && (
          <div className="flex-1 overflow-hidden flex">
            <AppInfoCard scanId={id!} />
          </div>
        )}
      </div>

      {showRunTool && id && (
        <RunToolModal scanId={id} onClose={() => setShowRunTool(false)} />
      )}
    </div>
  )
}
