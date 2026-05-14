import { useRef, useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import ForceGraph2D, { type ForceGraphMethods } from 'react-force-graph-2d'
import { ArrowLeft, RefreshCw, Wifi, WifiOff, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react'
import { fetchScan, fetchScanGraph, getWsUrl } from '../api/client'
import { useWebSocket } from '../hooks/useWebSocket'
import { StatusBadge } from '../components/StatusBadge'
import type { GraphNode, GraphLink, WsEvent } from '../types'

const NODE_COLORS: Record<string, string> = {
  endpoint_ok:       '#6366f1',
  endpoint_critical: '#ef4444',
  endpoint_high:     '#f97316',
  vulnerability_critical: '#ef4444',
  vulnerability_high:     '#f97316',
  vulnerability_medium:   '#eab308',
  vulnerability_low:      '#3b82f6',
  vulnerability_info:     '#64748b',
}

function nodeColor(node: GraphNode): string {
  if (node.type === 'endpoint') {
    if (node.has_critical) return NODE_COLORS.endpoint_critical
    if (node.has_high) return NODE_COLORS.endpoint_high
    return NODE_COLORS.endpoint_ok
  }
  return NODE_COLORS[`vulnerability_${node.severity}`] ?? NODE_COLORS.vulnerability_info
}

function nodeRadius(node: GraphNode): number {
  if (node.type === 'endpoint') return Math.max(6, 6 + (node.vuln_count ?? 0) * 1.5)
  return 5
}

interface SidebarProps {
  node: GraphNode | null
}

function NodeSidebar({ node }: SidebarProps) {
  if (!node) return null
  return (
    <div className="absolute top-4 right-4 w-72 card space-y-3 z-10 text-sm">
      <div className="flex items-center justify-between">
        <span className="font-semibold text-slate-100 truncate">{node.label}</span>
        <StatusBadge value={node.type === 'endpoint' ? 'completed' : (node.severity ?? 'info')} variant={node.type === 'endpoint' ? 'status' : 'severity'} />
      </div>
      {node.url && (
        <a href={node.url} target="_blank" rel="noreferrer" className="text-briar-accent text-xs break-all hover:underline">
          {node.url}
        </a>
      )}
      <div className="space-y-1 text-slate-400 text-xs">
        {node.method && <div><span className="text-slate-500">Method: </span>{node.method}</div>}
        {node.discovered_by && <div><span className="text-slate-500">Discovered by: </span>{node.discovered_by}</div>}
        {node.tool && <div><span className="text-slate-500">Tool: </span>{node.tool}</div>}
        {node.vuln_count !== undefined && node.vuln_count > 0 && (
          <div><span className="text-slate-500">Vulnerabilities: </span>{node.vuln_count}</div>
        )}
        {node.description && (
          <div className="mt-2 p-2 bg-briar-bg rounded text-slate-300">{node.description}</div>
        )}
      </div>
    </div>
  )
}

export default function ScanGraph() {
  const { id } = useParams<{ id: string }>()
  const graphRef = useRef<ForceGraphMethods<GraphNode, GraphLink>>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [dims, setDims] = useState({ w: 800, h: 600 })
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [wsStats, setWsStats] = useState({ endpoints: 0, vulns: 0 })

  const { data: scan } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => fetchScan(id!),
    enabled: !!id,
    refetchInterval: 5000,
  })

  const { data: graphData, refetch: refetchGraph } = useQuery({
    queryKey: ['graph', id],
    queryFn: () => fetchScanGraph(id!),
    enabled: !!id,
    refetchInterval: scan?.status === 'running' ? 8000 : false,
  })

  const { lastEvent, connected } = useWebSocket(id ? getWsUrl(id) : null)

  useEffect(() => {
    if (!lastEvent) return
    const ev = lastEvent as WsEvent
    if (ev.event === 'stats_update') {
      setWsStats({ endpoints: ev.endpoint_count ?? 0, vulns: ev.vuln_count ?? 0 })
    }
    if (ev.event === 'step_update' || ev.event === 'scan_complete') {
      refetchGraph()
    }
  }, [lastEvent, refetchGraph])

  // Resize observer
  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver((entries) => {
      const e = entries[0]
      setDims({ w: e.contentRect.width, h: e.contentRect.height })
    })
    ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  const handleNodeClick = useCallback((node: GraphNode) => {
    setSelectedNode((prev) => (prev?.id === node.id ? null : node))
    graphRef.current?.centerAt(node.x, node.y, 600)
    graphRef.current?.zoom(2, 600)
  }, [])

  const paintNode = useCallback((node: GraphNode, ctx: CanvasRenderingContext2D) => {
    const r = nodeRadius(node)
    ctx.beginPath()
    ctx.arc(node.x ?? 0, node.y ?? 0, r, 0, 2 * Math.PI)
    ctx.fillStyle = nodeColor(node)
    ctx.fill()
    if (selectedNode?.id === node.id) {
      ctx.strokeStyle = '#fff'
      ctx.lineWidth = 2
      ctx.stroke()
    }
    // Label
    if (r > 5) {
      ctx.font = `${Math.max(3, r * 0.7)}px sans-serif`
      ctx.fillStyle = 'rgba(255,255,255,0.75)'
      ctx.textAlign = 'center'
      ctx.fillText(node.label.slice(0, 20), node.x ?? 0, (node.y ?? 0) + r + 4)
    }
  }, [selectedNode])

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
            <span className="text-slate-300 text-sm font-medium truncate max-w-xs">{scan.target_url}</span>
            <StatusBadge value={scan.status} />
          </>
        )}

        <div className="ml-auto flex items-center gap-3 text-xs text-slate-400">
          <span>{graphData?.nodes.length ?? 0} nodes</span>
          <span className="text-slate-600">|</span>
          <span>{wsStats.endpoints} endpoints</span>
          <span className="text-slate-600">|</span>
          <span className="text-red-400">{wsStats.vulns} vulns</span>
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
        </div>
      </div>

      {/* Graph canvas */}
      <div ref={containerRef} className="relative flex-1 bg-briar-bg overflow-hidden">
        {graphData && (
          <ForceGraph2D
            ref={graphRef}
            width={dims.w}
            height={dims.h}
            graphData={graphData as { nodes: GraphNode[]; links: GraphLink[] }}
            nodeLabel="label"
            nodeCanvasObject={paintNode}
            nodeCanvasObjectMode={() => 'replace'}
            linkColor={() => 'rgba(100,116,139,0.3)'}
            linkWidth={1}
            onNodeClick={handleNodeClick}
            backgroundColor="#0f1117"
            cooldownTicks={80}
            onEngineStop={() => graphRef.current?.zoomToFit(400, 40)}
          />
        )}
        {!graphData && (
          <div className="absolute inset-0 flex items-center justify-center text-slate-500">
            Loading graph data…
          </div>
        )}
        {graphData?.nodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 gap-2">
            <span>No endpoints discovered yet.</span>
            <span className="text-xs">The graph will update automatically once workers report results.</span>
          </div>
        )}
        <NodeSidebar node={selectedNode} />

        {/* Legend */}
        <div className="absolute bottom-4 left-4 card p-3 text-xs space-y-1.5">
          {[
            { color: '#6366f1', label: 'Endpoint' },
            { color: '#f97316', label: 'Endpoint (high vuln)' },
            { color: '#ef4444', label: 'Endpoint (critical)' },
            { color: '#eab308', label: 'Vuln: medium' },
            { color: '#f97316', label: 'Vuln: high' },
            { color: '#ef4444', label: 'Vuln: critical' },
          ].map(({ color, label }) => (
            <div key={label} className="flex items-center gap-2 text-slate-400">
              <div className="w-3 h-3 rounded-full shrink-0" style={{ background: color }} />
              {label}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
