/**
 * EndpointTree — Radial tree visualisation
 * =========================================
 * Root (domain) sits at the centre.
 * Path-segment branches radiate outward.
 * Endpoint leaves appear as small method-coloured dots at the tips.
 *
 * Layout engine: d3-hierarchy tree in polar coordinates.
 * Rendering:     pure SVG — no canvas, no WebGL.
 * Interactions:  pan (drag), zoom (wheel/buttons), collapse (click branch),
 *                detail panel (click leaf).
 */

import {
  useMemo, useState, useRef, useEffect, useCallback,
} from 'react'
import { hierarchy, tree as d3tree } from 'd3-hierarchy'
import type { HierarchyPointNode } from 'd3-hierarchy'
import { Search, X, ExternalLink, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react'
import type { EndpointItem } from '../api/client'

// ── Constants ─────────────────────────────────────────────────────────────────

const LEVEL_R   = 120   // radial distance between depth levels (px)
const ROOT_R    = 22    // root node circle radius
const SEG_R     = 10    // segment (branch) node radius
const LEAF_R    = 5     // leaf (endpoint) dot radius
const MIN_ZOOM  = 0.15
const MAX_ZOOM  = 4

// ── Colours ───────────────────────────────────────────────────────────────────

const METHOD_CLR: Record<string, { fill: string; stroke: string }> = {
  GET:     { fill: '#10b981', stroke: 'rgba(16,185,129,.4)' },
  POST:    { fill: '#38bdf8', stroke: 'rgba(56,189,248,.4)' },
  PUT:     { fill: '#eab308', stroke: 'rgba(234,179,8,.4)' },
  PATCH:   { fill: '#f59e0b', stroke: 'rgba(245,158,11,.4)' },
  DELETE:  { fill: '#ef4444', stroke: 'rgba(239,68,68,.4)' },
  OPTIONS: { fill: '#a78bfa', stroke: 'rgba(167,139,250,.4)' },
  HEAD:    { fill: '#94a3b8', stroke: 'rgba(148,163,184,.4)' },
}
const METHOD_DEFAULT = { fill: '#94a3b8', stroke: 'rgba(148,163,184,.4)' }

function methodClr(m: string) {
  return METHOD_CLR[m?.toUpperCase()] ?? METHOD_DEFAULT
}

function trunc(s: string, n: number) {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

// ── Tree data model ───────────────────────────────────────────────────────────

interface TreeNode {
  id:            string
  label:         string
  type:          'root' | 'segment' | 'endpoint'
  endpoint?:     EndpointItem
  fullPath:      string
  children:      TreeNode[]
  endpointCount: number
}

function buildTree(endpoints: EndpointItem[], domain: string): TreeNode {
  const root: TreeNode = {
    id: '__root__', label: domain, type: 'root',
    fullPath: '/', children: [], endpointCount: 0,
  }

  for (const ep of endpoints) {
    let pathname = '/'
    try { pathname = new URL(ep.url).pathname } catch { /**/ }

    const segs = pathname.replace(/\/$/, '').split('/').filter(Boolean)
    let cur = root
    let pathSoFar = ''

    for (const seg of segs) {
      pathSoFar += '/' + seg
      let child = cur.children.find(c => c.type === 'segment' && c.label === seg)
      if (!child) {
        child = {
          id: `seg:${pathSoFar}`, label: seg, type: 'segment',
          fullPath: pathSoFar, children: [], endpointCount: 0,
        }
        cur.children.push(child)
      }
      cur = child
    }

    const leafId = `ep:${ep.method}:${ep.url}`
    if (!cur.children.find(c => c.id === leafId)) {
      cur.children.push({
        id: leafId, label: `${ep.method} ${pathname || '/'}`,
        type: 'endpoint', endpoint: ep,
        fullPath: pathname || '/', children: [], endpointCount: 1,
      })
    }
  }

  const countUp = (n: TreeNode): number => {
    if (n.type === 'endpoint') { n.endpointCount = 1; return 1 }
    const t = n.children.reduce((s, c) => s + countUp(c), 0)
    n.endpointCount = t; return t
  }
  countUp(root)
  return root
}

function applyCollapse(node: TreeNode, collapsed: Set<string>): TreeNode {
  if (node.type === 'endpoint') return node
  if (collapsed.has(node.id)) return { ...node, children: [] }
  return { ...node, children: node.children.map(c => applyCollapse(c, collapsed)) }
}

// ── Polar ↔ Cartesian ─────────────────────────────────────────────────────────

/** d3 tree angles start from top and increase clockwise */
function polar(angle: number, r: number) {
  const a = angle - Math.PI / 2
  return { x: r * Math.cos(a), y: r * Math.sin(a) }
}

/** Cubic-bezier branch curve between two nodes in polar layout */
function radialPath(
  sa: number, sr: number,   // source angle, radius
  ta: number, tr: number,   // target angle, radius
): string {
  const s  = polar(sa, sr)
  const t  = polar(ta, tr)
  // Control points at the midpoint radius, each aimed along its own radial
  const mr = (sr + tr) / 2
  const c1 = polar(sa, mr)
  const c2 = polar(ta, mr)
  return `M ${s.x},${s.y} C ${c1.x},${c1.y} ${c2.x},${c2.y} ${t.x},${t.y}`
}

// ── Detail panel ──────────────────────────────────────────────────────────────

function DetailPanel({ endpoint, onClose }: { endpoint: EndpointItem; onClose: () => void }) {
  const mc = methodClr(endpoint.method)
  return (
    <div className="w-72 shrink-0 border-l border-briar-border bg-briar-surface flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-briar-border shrink-0">
        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wide">Endpoint</span>
        <button onClick={onClose} className="text-slate-500 hover:text-slate-300">
          <X size={14} />
        </button>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        <div>
          <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">URL</p>
          <a href={endpoint.url} target="_blank" rel="noreferrer"
            className="flex items-start gap-1 text-briar-accent hover:underline break-all font-mono leading-snug">
            {endpoint.url}
            <ExternalLink size={10} className="shrink-0 mt-0.5" />
          </a>
        </div>
        <div className="flex gap-3">
          <div>
            <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">Method</p>
            <span className="px-2 py-0.5 rounded text-xs font-mono font-bold"
              style={{ color: mc.fill, background: mc.stroke }}>
              {endpoint.method || 'GET'}
            </span>
          </div>
          {endpoint.status_code > 0 && (
            <div>
              <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">Status</p>
              <span className="font-mono font-bold"
                style={{ color: endpoint.status_code < 300 ? '#10b981' : endpoint.status_code < 400 ? '#eab308' : '#ef4444' }}>
                {endpoint.status_code}
              </span>
            </div>
          )}
        </div>
        {endpoint.title && (
          <div>
            <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">Page title</p>
            <p className="text-slate-300">{endpoint.title}</p>
          </div>
        )}
        <div>
          <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">Discovered by</p>
          <span className="px-2 py-0.5 rounded bg-briar-surface-2 text-slate-300 font-mono">{endpoint.tool}</span>
        </div>
        {endpoint.content_type && (
          <div>
            <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">Content-Type</p>
            <p className="text-slate-400 font-mono">{endpoint.content_type}</p>
          </div>
        )}
        {endpoint.has_params && endpoint.param_names?.length > 0 && (
          <div>
            <p className="text-slate-500 mb-1.5 uppercase tracking-wide text-[10px]">
              Parameters ({endpoint.param_names.length})
            </p>
            <div className="flex flex-wrap gap-1">
              {endpoint.param_names.map(p => (
                <span key={p}
                  className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-purple-500/15 text-purple-300 border border-purple-500/25">
                  {p}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── SVG Node components ───────────────────────────────────────────────────────

function RootCircle({ count, label }: { count: number; label: string }) {
  return (
    <g>
      {/* outer glow ring */}
      <circle r={ROOT_R + 6} fill="none" stroke="rgba(245,158,11,0.12)" strokeWidth={8} />
      <circle r={ROOT_R + 2} fill="none" stroke="rgba(245,158,11,0.25)" strokeWidth={2} />
      {/* body */}
      <circle r={ROOT_R} fill="#f59e0b" />
      <text y={-7} textAnchor="middle" fill="#1a0e00"
        fontSize={10} fontWeight={700} fontFamily="JetBrains Mono, monospace">
        {trunc(label, 18)}
      </text>
      <text y={6} textAnchor="middle" fill="rgba(0,0,0,0.55)" fontSize={8}>
        {count} endpoints
      </text>
    </g>
  )
}

function SegmentCircle({
  label, count, isCollapsed, isHovered, angle,
}: {
  label: string; count: number
  isCollapsed: boolean; isHovered: boolean; angle: number
}) {
  // Determine which side label goes on
  const cosA = Math.cos(angle - Math.PI / 2)
  const textDir = cosA >= 0 ? 1 : -1
  const labelOffset = (SEG_R + 6) * textDir
  const anchor = cosA >= 0 ? 'start' : 'end'

  return (
    <g>
      <circle r={SEG_R}
        fill={isHovered ? '#242121' : '#1c1a1a'}
        stroke={isHovered ? 'rgba(245,158,11,0.6)' : '#3a3636'}
        strokeWidth={1.5}
      />
      {/* collapse indicator */}
      {count > 0 && (
        <text x={isCollapsed ? -1 : 0} y={3.5} textAnchor="middle"
          fill="rgba(245,158,11,0.8)" fontSize={7} fontWeight={700}>
          {isCollapsed ? '▶' : '●'}
        </text>
      )}
      {/* path label */}
      <text x={labelOffset} y={3}
        textAnchor={anchor}
        fill="#e2e8f0" fontSize={9}
        fontFamily="JetBrains Mono, monospace">
        /{trunc(label, 14)}
      </text>
      {/* count badge on collapsed nodes */}
      {isCollapsed && count > 0 && (
        <text x={labelOffset + (textDir * (label.length * 5.5 + 6))}
          y={3} textAnchor={anchor}
          fill="#f59e0b" fontSize={8}>
          ({count})
        </text>
      )}
    </g>
  )
}

function LeafDot({
  endpoint, isSelected, isHovered, isDimmed,
}: {
  endpoint: EndpointItem; isSelected: boolean; isHovered: boolean; isDimmed: boolean
}) {
  const mc = methodClr(endpoint.method)
  const r  = isSelected ? LEAF_R + 2 : isHovered ? LEAF_R + 1 : LEAF_R

  return (
    <g style={{ opacity: isDimmed ? 0.2 : 1 }}>
      {isSelected && (
        <circle r={r + 4} fill="none" stroke="#f59e0b" strokeWidth={1.5} opacity={0.6} />
      )}
      <circle r={r} fill={mc.fill} stroke={mc.stroke} strokeWidth={1} />
    </g>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

interface Props { endpoints: EndpointItem[]; isLoading: boolean }

export default function EndpointTree({ endpoints, isLoading }: Props) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const [selected,  setSelected]  = useState<EndpointItem | null>(null)
  const [hovered,   setHovered]   = useState<string | null>(null)
  const [search,    setSearch]    = useState('')

  // Pan / zoom state
  const [tx, setTx] = useState(0)
  const [ty, setTy] = useState(0)
  const [k,  setK]  = useState(0.9)
  const dragRef = useRef<{ startX: number; startY: number; tx: number; ty: number } | null>(null)
  const svgRef  = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  // ── Filter ──────────────────────────────────────────────────────────────────
  const q = search.trim().toLowerCase()
  const filteredIds = useMemo(() => {
    if (!q) return null
    const ids = new Set<string>()
    for (const ep of endpoints) {
      if (ep.url.toLowerCase().includes(q) || ep.method?.toLowerCase().includes(q))
        ids.add(`ep:${ep.method}:${ep.url}`)
    }
    return ids
  }, [endpoints, q])

  // ── Build tree ──────────────────────────────────────────────────────────────
  const rawTree = useMemo(() => {
    let domain = 'target'
    if (endpoints.length > 0) try { domain = new URL(endpoints[0].url).hostname } catch { /**/ }
    return buildTree(endpoints, domain)
  }, [endpoints])

  const visibleTree = useMemo(() => applyCollapse(rawTree, collapsed), [rawTree, collapsed])

  // ── Radial layout ───────────────────────────────────────────────────────────
  const { nodes, links, maxRadius } = useMemo(() => {
    const root  = hierarchy<TreeNode>(visibleTree, n => n.children)
    const depth = Math.max(root.height, 1)
    const mr    = depth * LEVEL_R

    d3tree<TreeNode>()
      .size([2 * Math.PI, mr])
      .separation((a, b) => (a.parent === b.parent ? 1 : 2) / Math.max(a.depth, 1))(root)

    return {
      nodes:     root.descendants() as HierarchyPointNode<TreeNode>[],
      links:     root.links(),
      maxRadius: mr,
    }
  }, [visibleTree])

  // ── Centre the view on mount / tree change ──────────────────────────────────
  useEffect(() => {
    if (!containerRef.current) return
    const { width, height } = containerRef.current.getBoundingClientRect()
    setTx(width  / 2)
    setTy(height / 2)
    // auto-fit: choose scale so the whole tree fits with 40px padding
    const fitScale = Math.min(
      (width  - 80) / (maxRadius * 2),
      (height - 80) / (maxRadius * 2),
      1,           // never zoom IN beyond 100% on load
    )
    setK(Math.max(fitScale, MIN_ZOOM))
  }, [maxRadius])

  // ── Zoom helpers ─────────────────────────────────────────────────────────────
  const zoomBy = useCallback((factor: number) => {
    setK(prev => Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, prev * factor)))
  }, [])

  const resetView = useCallback(() => {
    if (!containerRef.current) return
    const { width, height } = containerRef.current.getBoundingClientRect()
    setTx(width / 2); setTy(height / 2)
    const fitScale = Math.min((width - 80) / (maxRadius * 2), (height - 80) / (maxRadius * 2), 1)
    setK(Math.max(fitScale, MIN_ZOOM))
  }, [maxRadius])

  // Wheel zoom toward cursor
  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    const factor = e.deltaY < 0 ? 1.12 : 0.89
    const rect = svgRef.current?.getBoundingClientRect()
    if (!rect) return
    const cx = e.clientX - rect.left
    const cy = e.clientY - rect.top
    setK(prev => {
      const nk = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, prev * factor))
      // zoom toward cursor
      setTx(t => cx - (cx - t) * (nk / prev))
      setTy(t => cy - (cy - t) * (nk / prev))
      return nk
    })
  }, [])

  // Drag pan
  const onMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return
    dragRef.current = { startX: e.clientX, startY: e.clientY, tx, ty }
  }, [tx, ty])

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragRef.current) return
    setTx(dragRef.current.tx + e.clientX - dragRef.current.startX)
    setTy(dragRef.current.ty + e.clientY - dragRef.current.startY)
  }, [])

  const onMouseUp = useCallback(() => { dragRef.current = null }, [])

  const toggleCollapse = useCallback((id: string) => {
    setCollapsed(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }, [])

  // ── Empty states ─────────────────────────────────────────────────────────────
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500 text-sm">
        Loading endpoints…
      </div>
    )
  }
  if (endpoints.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500 gap-2 text-sm">
        <span>No endpoints discovered yet.</span>
        <span className="text-xs">Endpoints appear after katana + httpx phases complete.</span>
      </div>
    )
  }

  // ── Render ───────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-full overflow-hidden bg-briar-bg">

      {/* ── Canvas ── */}
      <div ref={containerRef} className="flex-1 flex flex-col overflow-hidden relative">

        {/* Search + controls bar */}
        <div className="shrink-0 px-4 py-2 border-b border-briar-border bg-briar-bg flex items-center gap-3">
          <Search size={13} className="text-slate-500 shrink-0" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Filter by URL or method…"
            className="flex-1 bg-transparent text-xs text-slate-200 outline-none placeholder-slate-600" />
          {search && (
            <button onClick={() => setSearch('')} className="text-slate-500 hover:text-slate-300">
              <X size={12} />
            </button>
          )}
          <span className="text-xs text-slate-600 font-mono shrink-0">{endpoints.length} ep</span>
          {/* zoom controls */}
          <div className="flex items-center gap-1 ml-2">
            <button onClick={() => zoomBy(1.25)} className="btn-ghost p-1" title="Zoom in"><ZoomIn size={13} /></button>
            <button onClick={() => zoomBy(0.8)}  className="btn-ghost p-1" title="Zoom out"><ZoomOut size={13} /></button>
            <button onClick={resetView}           className="btn-ghost p-1" title="Fit"><Maximize2 size={13} /></button>
          </div>
        </div>

        {/* SVG */}
        <div className="flex-1 overflow-hidden">
          <svg
            ref={svgRef}
            width="100%" height="100%"
            style={{ cursor: dragRef.current ? 'grabbing' : 'grab', display: 'block' }}
            onWheel={onWheel}
            onMouseDown={onMouseDown}
            onMouseMove={onMouseMove}
            onMouseUp={onMouseUp}
            onMouseLeave={onMouseUp}
          >
            {/* subtle radial grid rings for depth reference */}
            <g transform={`translate(${tx},${ty}) scale(${k})`} style={{ userSelect: 'none' }}>
              {Array.from({ length: Math.ceil(maxRadius / LEVEL_R) }, (_, i) => (
                <circle key={i} r={(i + 1) * LEVEL_R}
                  fill="none" stroke="rgba(46,43,43,0.6)" strokeWidth={1} strokeDasharray="3,5" />
              ))}

              {/* ── Branch curves ── */}
              {links.map((lnk, i) => {
                const src = lnk.source as HierarchyPointNode<TreeNode>
                const tgt = lnk.target as HierarchyPointNode<TreeNode>
                const isLeafLink = tgt.data.type === 'endpoint'
                const weight = isLeafLink
                  ? 1
                  : Math.max(1, Math.log2((src.data.endpointCount ?? 1) + 1) * 1.2)
                const opacity = isLeafLink ? 0.22 : Math.min(0.5, 0.25 + (src.data.endpointCount ?? 1) / 60)
                return (
                  <path key={i}
                    d={radialPath(src.x, src.y, tgt.x, tgt.y)}
                    fill="none"
                    stroke={`rgba(245,158,11,${opacity})`}
                    strokeWidth={weight}
                    strokeLinecap="round"
                  />
                )
              })}

              {/* ── Nodes ── */}
              {nodes.map(n => {
                const { id, type, label, endpoint, endpointCount } = n.data
                const pos = polar(n.x, n.y)
                const isDimmed = !!filteredIds && type === 'endpoint' && !filteredIds.has(id)
                const isSelected = type === 'endpoint' && !!endpoint &&
                  selected?.url === endpoint.url && selected?.method === endpoint.method

                if (type === 'root') {
                  return (
                    <g key={id} transform={`translate(0,0)`}>
                      <RootCircle label={label} count={endpointCount} />
                    </g>
                  )
                }

                if (type === 'segment') {
                  return (
                    <g key={id}
                      transform={`translate(${pos.x},${pos.y})`}
                      style={{ cursor: 'pointer' }}
                      onClick={e => { e.stopPropagation(); toggleCollapse(id) }}
                      onMouseEnter={() => setHovered(id)}
                      onMouseLeave={() => setHovered(null)}
                    >
                      <SegmentCircle
                        label={label}
                        count={endpointCount}
                        isCollapsed={collapsed.has(id)}
                        isHovered={hovered === id}
                        angle={n.x}
                      />
                    </g>
                  )
                }

                if (type === 'endpoint' && endpoint) {
                  return (
                    <g key={id}
                      transform={`translate(${pos.x},${pos.y})`}
                      style={{ cursor: 'pointer' }}
                      onClick={e => { e.stopPropagation(); setSelected(isSelected ? null : endpoint) }}
                      onMouseEnter={() => setHovered(id)}
                      onMouseLeave={() => setHovered(null)}
                    >
                      <LeafDot
                        endpoint={endpoint}
                        isSelected={isSelected}
                        isHovered={hovered === id}
                        isDimmed={isDimmed}
                      />
                    </g>
                  )
                }
                return null
              })}
            </g>
          </svg>
        </div>

        {/* Legend */}
        <div className="shrink-0 flex items-center gap-4 px-4 py-2 border-t border-briar-border text-xs text-slate-500">
          <span>Drag to pan · Scroll to zoom</span>
          <span>Click branch to collapse</span>
          <span>Click dot to inspect</span>
          <div className="ml-auto flex items-center gap-3">
            {Object.entries(METHOD_CLR).slice(0, 5).map(([m, c]) => (
              <span key={m} className="flex items-center gap-1">
                <svg width="8" height="8"><circle cx="4" cy="4" r="4" fill={c.fill} /></svg>
                <span style={{ color: c.fill }} className="font-mono text-[10px] font-bold">{m}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ── Detail panel ── */}
      {selected && (
        <DetailPanel endpoint={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}
