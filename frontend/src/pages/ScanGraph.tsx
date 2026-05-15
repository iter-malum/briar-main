import { useRef, useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import ForceGraph2D, { type ForceGraphMethods } from 'react-force-graph-2d'
import {
  ArrowLeft, RefreshCw, Wifi, WifiOff, ZoomIn, ZoomOut,
  Maximize2, StopCircle, ChevronRight,
} from 'lucide-react'
import { fetchScan, fetchScanGraph, getWsUrl, cancelScan } from '../api/client'
import { useWebSocket } from '../hooks/useWebSocket'
import { StatusBadge } from '../components/StatusBadge'
import type { GraphNode, GraphLink, WsEvent } from '../types'

// ── Pipeline phase definitions (mirrors backend) ──────────────────────────────
const PHASES = [
  { id: 'recon',   label: 'RECON',   tools: ['whatweb', 'katana'] },
  { id: 'probe',   label: 'PROBE',   tools: ['httpx', 'ffuf'] },
  { id: 'dast',    label: 'DAST',    tools: ['nuclei', 'zap'] },
  { id: 'exploit', label: 'EXPLOIT', tools: ['sqlmap'] },
]

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
  info:     '#6366f1',
  root:     '#ffffff',
  endpoint: '#6366f1',
}

function nodeColor(node: GraphNode): string {
  if (node.type === 'root') return SEV_COLORS.root
  const sev = (node as any).max_severity as string | undefined
  return SEV_COLORS[sev ?? 'endpoint'] ?? SEV_COLORS.endpoint
}

function nodeRadius(node: GraphNode): number {
  if (node.type === 'root') return 14
  const vc = (node as any).vuln_count as number ?? 0
  return Math.max(5, 5 + vc * 1.2)
}

// ── Tool status panel ─────────────────────────────────────────────────────────
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
        const phaseStatus = statuses.includes('running')
          ? 'running'
          : statuses.every((s) => s === 'completed')
          ? 'completed'
          : statuses.some((s) => s === 'failed')
          ? 'failed'
          : 'pending'

        return (
          <div key={phase.id}>
            <div className="flex items-center gap-1.5 mb-1.5">
              {phaseStatus === 'running' && (
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shrink-0" />
              )}
              {phaseStatus === 'completed' && (
                <span className="w-2 h-2 rounded-full bg-emerald-600 shrink-0" />
              )}
              {phaseStatus === 'failed' && (
                <span className="w-2 h-2 rounded-full bg-red-500 shrink-0" />
              )}
              {phaseStatus === 'pending' && (
                <span className="w-2 h-2 rounded-full bg-slate-600 shrink-0" />
              )}
              <span className="text-xs font-semibold text-slate-300 tracking-wider">
                {phase.label}
              </span>
            </div>
            <div className="space-y-1 pl-3.5">
              {phaseTools.map((tool) => {
                const st = stepMap[tool] ?? 'pending'
                return (
                  <div key={tool} className="flex items-center justify-between">
                    <span className="text-xs text-slate-400 font-mono">{tool}</span>
                    <StatusBadge value={st} />
                  </div>
                )
              })}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Node detail sidebar ───────────────────────────────────────────────────────
function NodeDetail({ node }: { node: GraphNode | null }) {
  if (!node) return null
  const n = node as any
  return (
    <div className="absolute top-4 right-4 w-72 card space-y-2 z-10 text-sm">
      <div className="font-semibold text-slate-100 break-all text-xs">{node.url}</div>
      {n.status_code > 0 && (
        <div className="text-xs text-slate-400">
          Status: <span className={n.status_code < 400 ? 'text-emerald-400' : 'text-red-400'}>
            HTTP {n.status_code}
          </span>
        </div>
      )}
      {n.title && <div className="text-xs text-slate-400">Title: {n.title}</div>}
      {n.vuln_count > 0 && (
        <div className="text-xs">
          <span className="text-slate-400">Vulnerabilities: </span>
          <span className="text-red-400 font-bold">{n.vuln_count}</span>
          {' '}
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

// ── Main component ────────────────────────────────────────────────────────────
export default function ScanGraph() {
  const { id } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const graphRef = useRef<ForceGraphMethods<GraphNode, GraphLink>>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [dims, setDims] = useState({ w: 800, h: 600 })
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)

  const { data: scan, refetch: refetchScan } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => fetchScan(id!),
    enabled: !!id,
    refetchInterval: 4000,
  })

  const { data: graphData, refetch: refetchGraph } = useQuery({
    queryKey: ['graph', id],
    queryFn: () => fetchScanGraph(id!),
    enabled: !!id,
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

  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver((entries) => {
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
        ctx.strokeStyle = '#fff'
        ctx.lineWidth = 2
        ctx.stroke()
      }

      // Label
      const fontSize = Math.max(4, Math.min(r * 0.8, 9))
      ctx.font = `${fontSize}px sans-serif`
      ctx.fillStyle = 'rgba(255,255,255,0.8)'
      ctx.textAlign = 'center'
      const label = (node.label ?? '').slice(0, 22)
      ctx.fillText(label, x, y + r + fontSize + 1)
    },
    [selectedNode],
  )

  const endpointCount = graphData?.nodes.filter((n) => (n as any).type !== 'root').length ?? 0
  const vulnNodes = graphData?.nodes.filter((n) => (n as any).vuln_count > 0) ?? []

  return (
    <div className="h-screen flex flex-col">
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-briar-border bg-briar-surface shrink-0">
        <Link to="/dashboard" className="btn-ghost py-1 px-2 flex items-center gap-1">
          <ArrowLeft size={14} /> Back
        </Link>
        <div className="h-4 w-px bg-briar-border" />
        {scan && (
          <>
            <span className="text-slate-300 text-sm font-medium truncate max-w-xs">
              {scan.target_url}
            </span>
            <StatusBadge value={scan.status} />
          </>
        )}

        <div className="ml-auto flex items-center gap-3 text-xs text-slate-400">
          <span>{endpointCount} endpoints</span>
          <span className="text-slate-600">|</span>
          <span className="text-red-400">{vulnNodes.length} with vulns</span>
          <span className="text-slate-600">|</span>
          {connected
            ? <span className="text-emerald-400 flex items-center gap-1"><Wifi size={12} /> live</span>
            : <span className="text-slate-500 flex items-center gap-1"><WifiOff size={12} /> offline</span>
          }
          <button onClick={() => refetchGraph()} className="btn-ghost py-1 px-2 flex items-center gap-1">
            <RefreshCw size={12} /> Reload
          </button>
          <button onClick={() => graphRef.current?.zoom(1.3, 300)} className="btn-ghost p-1"><ZoomIn size={14} /></button>
          <button onClick={() => graphRef.current?.zoom(0.77, 300)} className="btn-ghost p-1"><ZoomOut size={14} /></button>
          <button onClick={() => graphRef.current?.zoomToFit(400)} className="btn-ghost p-1"><Maximize2 size={14} /></button>
          {scan?.status === 'running' && (
            <button
              onClick={() => {
                if (confirm('Cancel this scan?')) cancelMut.mutate()
              }}
              disabled={cancelMut.isPending}
              className="flex items-center gap-1 px-2 py-1 rounded text-red-400 border border-red-500/30 hover:bg-red-500/10 text-xs transition-colors"
            >
              <StopCircle size={12} />
              {cancelMut.isPending ? 'Stopping…' : 'Stop Scan'}
            </button>
          )}
        </div>
      </div>

      {/* Body: pipeline panel + graph */}
      <div className="flex flex-1 overflow-hidden">
        <PipelinePanel scan={scan} />

        <div ref={containerRef} className="relative flex-1 bg-briar-bg overflow-hidden">
          {graphData && graphData.nodes.length > 0 && (
            <ForceGraph2D
              ref={graphRef}
              width={dims.w}
              height={dims.h}
              graphData={graphData as { nodes: GraphNode[]; links: GraphLink[] }}
              nodeLabel={(n) => (n as any).url ?? n.label}
              nodeCanvasObject={paintNode}
              nodeCanvasObjectMode={() => 'replace'}
              linkColor={() => 'rgba(100,116,139,0.25)'}
              linkWidth={1}
              onNodeClick={(node) =>
                setSelectedNode((prev) => (prev?.id === node.id ? null : node as GraphNode))
              }
              backgroundColor="#0f1117"
              dagMode="radial"
              dagLevelDistance={80}
              cooldownTicks={120}
              onEngineStop={() => graphRef.current?.zoomToFit(500, 60)}
            />
          )}

          {graphData && graphData.nodes.length === 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 gap-2">
              <span>No httpx-confirmed endpoints yet.</span>
              <span className="text-xs">
                Endpoints appear here after HTTPX probe phase completes.
              </span>
            </div>
          )}

          {!graphData && (
            <div className="absolute inset-0 flex items-center justify-center text-slate-500">
              Loading graph…
            </div>
          )}

          <NodeDetail node={selectedNode} />

          {/* Legend */}
          <div className="absolute bottom-4 left-4 card p-3 text-xs space-y-1.5">
            {[
              { color: '#ffffff', label: 'Root (target URL)' },
              { color: '#6366f1', label: 'Endpoint (clean)' },
              { color: '#3b82f6', label: 'Endpoint (low vuln)' },
              { color: '#eab308', label: 'Endpoint (medium)' },
              { color: '#f97316', label: 'Endpoint (high)' },
              { color: '#ef4444', label: 'Endpoint (critical)' },
            ].map(({ color, label }) => (
              <div key={label} className="flex items-center gap-2 text-slate-400">
                <div className="w-3 h-3 rounded-full shrink-0" style={{ background: color }} />
                {label}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
