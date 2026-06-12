import { useRef, useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import ForceGraph2D, { type ForceGraphMethods } from 'react-force-graph-2d'
import {
  ArrowLeft, RefreshCw, Wifi, WifiOff, ZoomIn, ZoomOut,
  Maximize2, StopCircle, Play, List, GitGraph, ExternalLink,
  Cpu, Network,
} from 'lucide-react'
import {
  fetchScan, fetchScanGraph, fetchScanEndpoints, getWsUrl, cancelScan, runTool,
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

// ── Carbon Pro severity/node colours ─────────────────────────────────────────
const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#38bdf8',
  info:     '#f59e0b',    // amber — brand accent
  root:     '#f8fafc',   // near-white trunk
  endpoint: '#f59e0b',   // amber for clean endpoints
}

function nodeColor(node: GraphNode): string {
  if (node.type === 'root') return SEV_COLORS.root
  const sev = (node as any).max_severity as string | undefined
  return SEV_COLORS[sev ?? 'endpoint'] ?? SEV_COLORS.endpoint
}

function nodeRadius(node: GraphNode): number {
  if (node.type === 'root') return 9
  const vc = (node as any).vuln_count as number ?? 0
  return 4 + Math.min(Math.log1p(vc) * 2, 7)
}

// ── Pipeline sidebar ──────────────────────────────────────────────────────────
function PipelinePanel({ scan }: { scan: any }) {
  if (!scan) return null
  const stepMap: Record<string, string> = {}
  for (const s of scan.steps ?? []) stepMap[s.tool] = s.status

  return (
    <div className="w-52 shrink-0 border-r border-briar-border bg-briar-surface overflow-y-auto p-3 space-y-4">
      {PHASES.map((phase) => {
        const phaseTools = phase.tools.filter((t) => scan.tools?.includes(t))
        if (phaseTools.length === 0) return null
        const statuses = phaseTools.map((t) => stepMap[t] ?? 'pending')
        const phaseStatus =
          statuses.includes('running')           ? 'running'
          : statuses.every(s => s === 'completed') ? 'completed'
          : statuses.some(s => s === 'failed')     ? 'failed'
          : 'pending'

        const dotCls =
          phaseStatus === 'running'   ? 'bg-amber-400 animate-pulse'
          : phaseStatus === 'completed' ? 'bg-emerald-500'
          : phaseStatus === 'failed'    ? 'bg-red-500'
          : 'bg-slate-700'

        return (
          <div key={phase.id}>
            <div className="flex items-center gap-1.5 mb-1.5">
              <span className={`w-2 h-2 rounded-full shrink-0 ${dotCls}`} />
              <span className="text-xs font-semibold text-slate-400 tracking-wider">
                {phase.label}
              </span>
            </div>
            <div className="space-y-1 pl-3.5">
              {phaseTools.map((tool) => (
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

// ── Node detail ───────────────────────────────────────────────────────────────
function NodeDetail({ node }: { node: GraphNode | null }) {
  if (!node) return null
  const n = node as any
  return (
    <div className="absolute top-4 right-4 w-72 card space-y-2 z-10 text-sm">
      <div className="font-semibold text-slate-100 break-all text-xs font-mono">{node.url}</div>
      {n.status_code > 0 && (
        <div className="text-xs text-slate-400">
          Status:{' '}
          <span className={n.status_code < 400 ? 'text-emerald-400' : 'text-red-400'}>
            HTTP {n.status_code}
          </span>
        </div>
      )}
      {n.title && <div className="text-xs text-slate-400">Title: {n.title}</div>}
      {n.vuln_count > 0 && (
        <div className="text-xs">
          <span className="text-slate-400">Vulnerabilities: </span>
          <span className="text-red-400 font-bold">{n.vuln_count}</span>{' '}
          <StatusBadge value={n.max_severity ?? 'info'} variant="severity" />
        </div>
      )}
      {n.vuln_types?.length > 0 && (
        <div className="text-xs text-slate-500 space-y-0.5">
          {n.vuln_types.map((t: string) => (
            <div key={t} className="truncate">• {t}</div>
          ))}
        </div>
      )}
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
          {ALL_TOOLS.map((t) => (
            <button
              key={t}
              onClick={() => setTool(t)}
              className={`px-3 py-1 rounded-lg text-sm border transition-colors ${
                tool === t
                  ? 'bg-briar-accent border-briar-accent text-black font-semibold'
                  : 'border-briar-border text-slate-400 hover:border-briar-border-light'
              }`}
            >
              {t}
            </button>
          ))}
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="btn-ghost">Cancel</button>
          <button
            onClick={() => mut.mutate()}
            disabled={!tool || mut.isPending}
            className="btn-primary flex items-center gap-2"
          >
            <Play size={13} />
            {mut.isPending ? 'Launching…' : `Run ${tool || '…'}`}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Endpoint list (table fallback) ────────────────────────────────────────────
function statusColor(code: number) {
  if (code === 0)  return 'text-slate-500'
  if (code < 300)  return 'text-emerald-400'
  if (code < 400)  return 'text-amber-400'
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

function EndpointTable({
  scanId,
  isRunning,
}: {
  scanId: string
  isRunning: boolean
}) {
  const [includeStatic, setIncludeStatic] = useState(false)
  const [search, setSearch] = useState('')

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['endpoints', scanId, includeStatic],
    queryFn:  () => fetchScanEndpoints(scanId, { include_static: includeStatic }),
    enabled:  !!scanId,
    refetchInterval: isRunning ? 8000 : false,
  })

  const filtered = (data?.endpoints ?? []).filter(ep =>
    ep.url.toLowerCase().includes(search.toLowerCase()) ||
    ep.title?.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-2 border-b border-briar-border bg-briar-surface shrink-0">
        <input
          type="text"
          placeholder="Filter URLs…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="input max-w-xs py-1.5 text-xs"
        />
        <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={includeStatic}
            onChange={e => setIncludeStatic(e.target.checked)}
            className="accent-briar-accent"
          />
          Include static
        </label>
        <span className="text-xs text-slate-500 ml-auto font-mono">
          {filtered.length} / {data?.total ?? 0}
        </span>
        <button onClick={() => refetch()} className="btn-ghost py-1 px-2 flex items-center gap-1 text-xs">
          <RefreshCw size={12} /> Reload
        </button>
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
                <tr
                  key={ep.url + ep.method}
                  className="border-b border-briar-border/50 hover:bg-briar-surface-2 transition-colors"
                >
                  <td className="table-cell w-16">
                    <MethodBadge method={ep.method} />
                  </td>
                  <td className={`table-cell w-14 font-mono font-bold ${statusColor(ep.status_code)}`}>
                    {ep.status_code || '—'}
                  </td>
                  <td className="table-cell max-w-xs">
                    <a
                      href={ep.url} target="_blank" rel="noreferrer"
                      className="flex items-center gap-1 text-briar-accent hover:underline font-mono truncate"
                      title={ep.url}
                    >
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
                      <span
                        className="px-1.5 py-0.5 rounded text-xs bg-purple-500/15 text-purple-300"
                        title={ep.param_names.join(', ')}
                      >
                        ✓ {ep.param_names.length > 0 ? ep.param_names.slice(0, 3).join(', ') : 'params'}
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graphRef = useRef<any>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const engineStoppedRef = useRef(false)
  const [dims, setDims] = useState({ w: 800, h: 600 })
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [activeTab, setActiveTab] = useState<'graph' | 'tree' | 'table' | 'app'>('graph')
  const [showRunTool, setShowRunTool] = useState(false)
  // Endpoint view mode inside 'tree' tab (kept for future)
  const [endpointMode, setEndpointMode] = useState<'tree' | 'table'>('tree')

  const { data: scan, refetch: refetchScan } = useQuery({
    queryKey: ['scan', id],
    queryFn:  () => fetchScan(id!),
    enabled:  !!id,
    refetchInterval: 4000,
  })

  const { data: graphData, refetch: refetchGraph } = useQuery({
    queryKey: ['graph', id],
    queryFn:  () => fetchScanGraph(id!),
    enabled:  !!id && activeTab === 'graph',
    refetchInterval: scan?.status === 'running' ? 8000 : false,
  })

  // Endpoints for tree/table tab
  const { data: epData, isLoading: epLoading } = useQuery({
    queryKey: ['endpoints', id, false],
    queryFn:  () => fetchScanEndpoints(id!, { include_static: false }),
    enabled:  !!id && (activeTab === 'tree' || activeTab === 'table'),
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
      refetchGraph()
      refetchScan()
    }
  }, [lastEvent, refetchGraph, refetchScan])

  useEffect(() => { engineStoppedRef.current = false }, [graphData])

  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver(entries => {
      const e = entries[0]
      setDims({ w: e.contentRect.width, h: e.contentRect.height })
    })
    ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  const paintNode = useCallback(
    (node: GraphNode, ctx: CanvasRenderingContext2D) => {
      const r = nodeRadius(node)
      const x = node.x ?? 0
      const y = node.y ?? 0
      ctx.beginPath()
      ctx.arc(x, y, r, 0, 2 * Math.PI)
      ctx.fillStyle = nodeColor(node)
      ctx.fill()
      if (selectedNode?.id === node.id) {
        ctx.strokeStyle = '#f59e0b'
        ctx.lineWidth = 2
        ctx.stroke()
      }
      const sev = (node as any).max_severity as string | undefined
      const showLabel =
        node.type === 'root' ||
        selectedNode?.id === node.id ||
        sev === 'critical' || sev === 'high'
      if (showLabel) {
        const fontSize = node.type === 'root' ? 9 : 7
        ctx.font = `${fontSize}px sans-serif`
        ctx.fillStyle = node.type === 'root' ? 'rgba(255,255,255,0.95)' : 'rgba(255,255,255,0.75)'
        ctx.textAlign = 'center'
        ctx.fillText((node.label ?? '').slice(0, 28), x, y + r + fontSize + 2)
      }
    },
    [selectedNode],
  )

  const handleEngineStop = useCallback(() => {
    if (!engineStoppedRef.current) {
      engineStoppedRef.current = true
      graphData?.nodes.forEach((node: any) => {
        if (node.x !== undefined) { node.fx = node.x; node.fy = node.y }
      })
      graphRef.current?.zoomToFit(400, 80)
    }
  }, [graphData])

  const endpointCount = graphData?.nodes.filter(n => (n as any).type !== 'root').length ?? 0
  const vulnNodes     = graphData?.nodes.filter(n => (n as any).vuln_count > 0) ?? []

  const tabs = [
    { id: 'graph', label: 'Graph',     Icon: GitGraph  },
    { id: 'tree',  label: 'Endpoints', Icon: Network   },
    { id: 'table', label: 'Table',     Icon: List      },
    { id: 'app',   label: 'App Info',  Icon: Cpu       },
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
            <button
              key={tid}
              onClick={() => setActiveTab(tid)}
              className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs transition-colors ${
                activeTab === tid
                  ? 'bg-briar-accent text-black font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon size={12} /> {label}
            </button>
          ))}
        </div>

        {/* Right stats / controls */}
        <div className="ml-auto flex items-center gap-3 text-xs text-slate-400">
          {activeTab === 'graph' && (
            <>
              <span className="font-mono">{endpointCount} nodes</span>
              <span className="text-slate-700">|</span>
              <span className="text-red-400 font-mono">{vulnNodes.length} vulns</span>
              <span className="text-slate-700">|</span>
            </>
          )}
          {connected
            ? <span className="text-emerald-400 flex items-center gap-1"><Wifi size={11} /> live</span>
            : <span className="text-slate-600 flex items-center gap-1"><WifiOff size={11} /> offline</span>
          }
          {activeTab === 'graph' && (
            <>
              <button onClick={() => refetchGraph()} className="btn-ghost py-1 px-2 flex items-center gap-1 text-xs">
                <RefreshCw size={11} /> Reload
              </button>
              <button onClick={() => graphRef.current?.zoom(1.3, 300)} className="btn-ghost p-1"><ZoomIn size={13} /></button>
              <button onClick={() => graphRef.current?.zoom(0.77, 300)} className="btn-ghost p-1"><ZoomOut size={13} /></button>
              <button onClick={() => graphRef.current?.zoomToFit(400)} className="btn-ghost p-1"><Maximize2 size={13} /></button>
            </>
          )}
          <button
            onClick={() => setShowRunTool(true)}
            className="flex items-center gap-1 px-2 py-1 rounded text-emerald-400
                       border border-emerald-500/30 hover:bg-emerald-500/10 text-xs transition-colors"
          >
            <Play size={11} /> Run Tool
          </button>
          {(scan?.status === 'running' || scan?.status === 'pending') && (
            <button
              onClick={() => { if (confirm('Cancel this scan?')) cancelMut.mutate() }}
              disabled={cancelMut.isPending}
              className="flex items-center gap-1 px-2 py-1 rounded text-red-400
                         border border-red-500/30 hover:bg-red-500/10 text-xs transition-colors"
            >
              <StopCircle size={11} />
              {cancelMut.isPending ? 'Stopping…' : 'Stop'}
            </button>
          )}
        </div>
      </div>

      {/* ── Body ── */}
      <div className="flex flex-1 overflow-hidden">
        <PipelinePanel scan={scan} />

        {/* Force-graph tab */}
        {activeTab === 'graph' && (
          <div ref={containerRef} className="relative flex-1 overflow-hidden" style={{ background: '#111010' }}>
            {graphData && graphData.nodes.length > 0 && (
              <ForceGraph2D
                ref={graphRef}
                width={dims.w}
                height={dims.h}
                graphData={graphData as { nodes: GraphNode[]; links: GraphLink[] }}
                nodeLabel={n => (n as any).url ?? n.label}
                nodeCanvasObject={paintNode}
                nodeCanvasObjectMode={() => 'replace'}
                linkColor={() => 'rgba(100,116,139,0.2)'}
                linkWidth={1}
                onNodeClick={node =>
                  setSelectedNode(prev => prev?.id === node.id ? null : node as GraphNode)
                }
                backgroundColor="#111010"
                warmupTicks={150}
                cooldownTicks={0}
                d3AlphaDecay={0.04}
                d3VelocityDecay={0.35}
                onEngineStop={handleEngineStop}
              />
            )}
            {graphData && graphData.nodes.length === 0 && (
              <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 gap-2 text-sm">
                <span>No httpx-confirmed endpoints yet.</span>
                <span className="text-xs">Endpoints appear after HTTPX probe phase completes.</span>
              </div>
            )}
            {!graphData && (
              <div className="absolute inset-0 flex items-center justify-center text-slate-500 text-sm">
                Loading graph…
              </div>
            )}
            <NodeDetail node={selectedNode} />
            {/* Legend */}
            <div className="absolute bottom-4 left-4 card-sm text-xs space-y-1.5">
              {[
                { color: '#f8fafc', label: 'Root' },
                { color: '#f59e0b', label: 'Endpoint (clean)' },
                { color: '#38bdf8', label: 'Low' },
                { color: '#eab308', label: 'Medium' },
                { color: '#f97316', label: 'High' },
                { color: '#ef4444', label: 'Critical' },
              ].map(({ color, label }) => (
                <div key={label} className="flex items-center gap-2 text-slate-400">
                  <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: color }} />
                  {label}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tree tab */}
        {activeTab === 'tree' && (
          <div className="flex-1 overflow-hidden">
            <EndpointTree
              endpoints={epData?.endpoints ?? []}
              isLoading={epLoading}
            />
          </div>
        )}

        {/* Table tab */}
        {activeTab === 'table' && (
          <div className="flex-1 overflow-hidden">
            <EndpointTable scanId={id!} isRunning={scan?.status === 'running'} />
          </div>
        )}

        {/* App Info tab */}
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
