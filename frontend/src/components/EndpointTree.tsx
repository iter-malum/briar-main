/**
 * EndpointTree
 * ============
 * Visualises discovered endpoints as a living tree that grows upward:
 *   - Root  (trunk)  = target domain            — bottom of the canvas
 *   - Nodes (branch) = URL path segments         — middle layers
 *   - Leaves         = concrete endpoint+method  — top of the canvas
 *
 * Built with d3-hierarchy for layout + pure SVG rendering.
 * Supports: expand/collapse branches, click-to-detail, search filter.
 */

import {
  useMemo, useState, useRef, useEffect, useCallback,
} from 'react'
import { hierarchy, tree as d3tree } from 'd3-hierarchy'
import type { HierarchyPointNode, HierarchyPointLink } from 'd3-hierarchy'
import { Search, X, ExternalLink, ChevronRight, ChevronDown } from 'lucide-react'
import type { EndpointItem } from '../api/client'

// ── Layout constants ──────────────────────────────────────────────────────────

const LEAF_W     = 180   // leaf (endpoint) pill width
const SEG_W      = 110   // segment branch node width
const ROOT_W     = 160   // root node width
const NODE_H     = 24    // node height (all types)
const LEVEL_H    = 70    // vertical distance between levels
const NODE_SEP   = 195   // horizontal space allocated per node by d3.tree
const PAD_X      = 40    // horizontal padding around the tree
const PAD_BOTTOM = 44    // space below root
const PAD_TOP    = 30    // space above top leaves

// ── Colours ───────────────────────────────────────────────────────────────────

const METHOD_CLR: Record<string, { fill: string; text: string }> = {
  GET:     { fill: 'rgba(16,185,129,.15)',  text: '#10b981' },
  POST:    { fill: 'rgba(56,189,248,.15)',  text: '#38bdf8' },
  PUT:     { fill: 'rgba(234,179,8,.15)',   text: '#eab308' },
  PATCH:   { fill: 'rgba(245,158,11,.15)',  text: '#f59e0b' },
  DELETE:  { fill: 'rgba(239,68,68,.15)',   text: '#ef4444' },
  OPTIONS: { fill: 'rgba(167,139,250,.15)', text: '#a78bfa' },
  HEAD:    { fill: 'rgba(148,163,184,.15)', text: '#94a3b8' },
}

function methodClr(m: string) {
  return METHOD_CLR[m?.toUpperCase()] ?? { fill: 'rgba(148,163,184,.15)', text: '#94a3b8' }
}

function statusClr(code: number): string {
  if (!code)       return '#475569'
  if (code < 300)  return '#10b981'
  if (code < 400)  return '#eab308'
  return '#ef4444'
}

function trunc(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s
}

// ── Tree data model ───────────────────────────────────────────────────────────

interface TreeNode {
  id:            string
  label:         string
  type:          'root' | 'segment' | 'endpoint'
  endpoint?:     EndpointItem
  fullPath:      string
  children:      TreeNode[]
  endpointCount: number   // total live endpoints in this subtree
}

// Build hierarchical tree from flat endpoint list.
function buildTree(endpoints: EndpointItem[], domain: string): TreeNode {
  const root: TreeNode = {
    id: '__root__', label: domain, type: 'root',
    fullPath: '/', children: [], endpointCount: 0,
  }

  for (const ep of endpoints) {
    let pathname = '/'
    try { pathname = new URL(ep.url).pathname } catch { /* keep / */ }

    const segments = pathname.replace(/\/$/, '').split('/').filter(Boolean)
    let cur = root
    let pathSoFar = ''

    for (const seg of segments) {
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

    // leaf — one per (url, method) pair
    const leafId = `ep:${ep.method}:${ep.url}`
    if (!cur.children.find(c => c.id === leafId)) {
      cur.children.push({
        id: leafId,
        label: `${ep.method} ${pathname || '/'}`,
        type: 'endpoint',
        endpoint: ep,
        fullPath: pathname || '/',
        children: [],
        endpointCount: 1,
      })
    }
  }

  // Propagate endpoint counts upward
  const count = (n: TreeNode): number => {
    if (n.type === 'endpoint') { n.endpointCount = 1; return 1 }
    const total = n.children.reduce((s, c) => s + count(c), 0)
    n.endpointCount = total
    return total
  }
  count(root)

  return root
}

// Prune collapsed branches before passing to d3-hierarchy
function applyCollapse(node: TreeNode, collapsed: Set<string>): TreeNode {
  if (node.type === 'endpoint') return node
  if (collapsed.has(node.id)) return { ...node, children: [] }
  return { ...node, children: node.children.map(c => applyCollapse(c, collapsed)) }
}

// ── SVG sub-components ────────────────────────────────────────────────────────

// Organic branch curve from child (top) to parent (bottom)
function BranchCurve({
  src, dst, weight,
}: {
  src: { x: number; y: number }   // child position (flipped = top)
  dst: { x: number; y: number }   // parent position (flipped = bottom)
  weight: number                  // stroke width proportional to descendants
}) {
  const midY = (src.y + dst.y) / 2
  const d = `M ${src.x} ${src.y} C ${src.x} ${midY}, ${dst.x} ${midY}, ${dst.x} ${dst.y}`
  const opacity = weight > 1.5 ? 0.45 : 0.28
  return (
    <path
      d={d}
      fill="none"
      stroke={`rgba(245,158,11,${opacity})`}
      strokeWidth={weight}
      strokeLinecap="round"
    />
  )
}

// Root node (trunk)
function RootNode({
  cx, cy, label, count,
}: {
  cx: number; cy: number; label: string; count: number
}) {
  const w = ROOT_W, h = NODE_H + 6
  return (
    <g transform={`translate(${cx}, ${cy})`}>
      {/* glow halo */}
      <rect
        x={-w / 2 - 3} y={-h / 2 - 3}
        width={w + 6} height={h + 6}
        rx={11} fill="rgba(245,158,11,0.08)"
      />
      {/* main rect */}
      <rect
        x={-w / 2} y={-h / 2}
        width={w} height={h}
        rx={8}
        fill="#f59e0b"
        stroke="rgba(245,158,11,0.6)"
        strokeWidth={1}
      />
      <text
        x={0} y={-2}
        textAnchor="middle"
        fill="#1a0e00"
        fontSize={11}
        fontWeight={700}
        fontFamily="JetBrains Mono, monospace"
      >
        {trunc(label, 20)}
      </text>
      <text
        x={0} y={10}
        textAnchor="middle"
        fill="rgba(0,0,0,0.5)"
        fontSize={8}
      >
        {count} ep
      </text>
    </g>
  )
}

// Segment (branch) node
function SegmentNode({
  cx, cy, label, count, isCollapsed, isHovered,
  onClick,
}: {
  cx: number; cy: number
  label: string; count: number
  isCollapsed: boolean
  isHovered: boolean
  onClick: () => void
}) {
  const w = SEG_W, h = NODE_H
  const hasChildren = count > 0

  return (
    <g
      transform={`translate(${cx}, ${cy})`}
      onClick={onClick}
      style={{ cursor: hasChildren ? 'pointer' : 'default' }}
    >
      {/* hit area */}
      <rect x={-w / 2 - 3} y={-h / 2 - 3} width={w + 6} height={h + 6} rx={8} fill="transparent" />
      {/* body */}
      <rect
        x={-w / 2} y={-h / 2}
        width={w} height={h}
        rx={5}
        fill={isHovered ? '#242121' : '#1c1a1a'}
        stroke={isHovered ? 'rgba(245,158,11,0.5)' : '#2e2b2b'}
        strokeWidth={1}
      />
      {/* left accent bar */}
      <rect
        x={-w / 2} y={-h / 2}
        width={3} height={h}
        rx={1}
        fill="rgba(245,158,11,0.35)"
      />

      {/* collapse chevron */}
      {hasChildren && (
        <text x={-w / 2 + 8} y={3} fill="rgba(245,158,11,0.7)" fontSize={8} fontWeight={700}>
          {isCollapsed ? '▶' : '▼'}
        </text>
      )}

      {/* segment label */}
      <text
        x={hasChildren ? -w / 2 + 20 : -w / 2 + 8}
        y={3}
        fill="#e2e8f0"
        fontSize={10}
        fontFamily="JetBrains Mono, monospace"
      >
        {trunc('/' + label, hasChildren ? 10 : 13)}
      </text>

      {/* endpoint count badge */}
      {count > 0 && (
        <>
          <rect
            x={w / 2 - 24} y={-7}
            width={20} height={14}
            rx={7}
            fill="rgba(245,158,11,0.12)"
            stroke="rgba(245,158,11,0.25)"
            strokeWidth={1}
          />
          <text
            x={w / 2 - 14} y={3}
            textAnchor="middle"
            fill="#f59e0b"
            fontSize={8}
            fontWeight={600}
          >
            {count > 99 ? '99+' : count}
          </text>
        </>
      )}
    </g>
  )
}

// Endpoint leaf node
function LeafNode({
  cx, cy, endpoint, isSelected, isHovered, isDimmed,
  onClick,
}: {
  cx: number; cy: number
  endpoint: EndpointItem
  isSelected: boolean
  isHovered: boolean
  isDimmed: boolean
  onClick: () => void
}) {
  const w = LEAF_W, h = NODE_H
  const mc = methodClr(endpoint.method)
  const sc = statusClr(endpoint.status_code)
  const method = (endpoint.method || 'GET').toUpperCase().slice(0, 6)
  const methodW = Math.max(method.length * 6 + 8, 30)

  let pathname = '/'
  try { pathname = new URL(endpoint.url).pathname } catch {}
  const pathLabel = trunc(pathname, 18)

  return (
    <g
      transform={`translate(${cx}, ${cy})`}
      onClick={onClick}
      style={{ cursor: 'pointer', opacity: isDimmed ? 0.3 : 1 }}
    >
      {/* hit area */}
      <rect x={-w / 2 - 2} y={-h / 2 - 2} width={w + 4} height={h + 4} rx={13} fill="transparent" />

      {/* body */}
      <rect
        x={-w / 2} y={-h / 2}
        width={w} height={h}
        rx={11}
        fill={isSelected ? 'rgba(245,158,11,0.12)' : isHovered ? '#242121' : '#1c1a1a'}
        stroke={isSelected ? '#f59e0b' : isHovered ? 'rgba(245,158,11,0.35)' : '#2e2b2b'}
        strokeWidth={isSelected ? 1.5 : 1}
      />

      {/* method badge */}
      <rect
        x={-w / 2 + 4} y={-h / 2 + 3}
        width={methodW} height={h - 6}
        rx={7}
        fill={mc.fill}
      />
      <text
        x={-w / 2 + 4 + methodW / 2}
        y={3}
        textAnchor="middle"
        fill={mc.text}
        fontSize={8}
        fontWeight={700}
        fontFamily="JetBrains Mono, monospace"
      >
        {method}
      </text>

      {/* path */}
      <text
        x={-w / 2 + methodW + 10}
        y={3}
        fill="#cbd5e1"
        fontSize={9}
        fontFamily="JetBrains Mono, monospace"
      >
        {pathLabel}
      </text>

      {/* status dot + code */}
      {endpoint.status_code > 0 && (
        <>
          <circle cx={w / 2 - 20} cy={0} r={2.5} fill={sc} />
          <text
            x={w / 2 - 15}
            y={3}
            textAnchor="start"
            fill={sc}
            fontSize={8}
            fontFamily="JetBrains Mono, monospace"
          >
            {endpoint.status_code}
          </text>
        </>
      )}
    </g>
  )
}

// ── Detail panel ──────────────────────────────────────────────────────────────

function DetailPanel({
  endpoint,
  onClose,
}: {
  endpoint: EndpointItem
  onClose: () => void
}) {
  const mc = methodClr(endpoint.method)
  const sc = statusClr(endpoint.status_code)

  return (
    <div className="w-72 shrink-0 border-l border-briar-border bg-briar-surface flex flex-col overflow-hidden">
      {/* header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-briar-border shrink-0">
        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wide">
          Endpoint
        </span>
        <button onClick={onClose} className="text-slate-500 hover:text-slate-300 p-0.5 rounded">
          <X size={14} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {/* URL */}
        <div>
          <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">URL</p>
          <a
            href={endpoint.url}
            target="_blank"
            rel="noreferrer"
            className="flex items-start gap-1 text-briar-accent hover:underline break-all font-mono leading-snug"
          >
            {endpoint.url}
            <ExternalLink size={10} className="shrink-0 mt-0.5" />
          </a>
        </div>

        {/* method + status */}
        <div className="flex gap-3">
          <div>
            <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">Method</p>
            <span
              className="px-2 py-0.5 rounded text-xs font-mono font-bold"
              style={{ color: mc.text, background: mc.fill }}
            >
              {endpoint.method || 'GET'}
            </span>
          </div>
          {endpoint.status_code > 0 && (
            <div>
              <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">Status</p>
              <span className="font-mono font-bold" style={{ color: sc }}>
                {endpoint.status_code}
              </span>
            </div>
          )}
        </div>

        {/* title */}
        {endpoint.title && (
          <div>
            <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">Page title</p>
            <p className="text-slate-300">{endpoint.title}</p>
          </div>
        )}

        {/* tool */}
        <div>
          <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">Discovered by</p>
          <span className="px-2 py-0.5 rounded bg-briar-surface-2 text-slate-300 font-mono">
            {endpoint.tool}
          </span>
        </div>

        {/* content type */}
        {endpoint.content_type && (
          <div>
            <p className="text-slate-500 mb-1 uppercase tracking-wide text-[10px]">Content-Type</p>
            <p className="text-slate-400 font-mono">{endpoint.content_type}</p>
          </div>
        )}

        {/* params */}
        {endpoint.has_params && endpoint.param_names?.length > 0 && (
          <div>
            <p className="text-slate-500 mb-1.5 uppercase tracking-wide text-[10px]">
              Parameters ({endpoint.param_names.length})
            </p>
            <div className="flex flex-wrap gap-1">
              {endpoint.param_names.map(p => (
                <span
                  key={p}
                  className="px-2 py-0.5 rounded-full text-[10px] font-mono
                             bg-purple-500/15 text-purple-300 border border-purple-500/25"
                >
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

// ── Main component ────────────────────────────────────────────────────────────

interface Props {
  endpoints:  EndpointItem[]
  isLoading:  boolean
}

export default function EndpointTree({ endpoints, isLoading }: Props) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const [selected,  setSelected]  = useState<EndpointItem | null>(null)
  const [hovered,   setHovered]   = useState<string | null>(null)
  const [search,    setSearch]    = useState('')

  const containerRef = useRef<HTMLDivElement>(null)

  // ── Filter endpoints by search ────────────────────────────────────────────
  const filtered = useMemo(() => {
    if (!search.trim()) return endpoints
    const q = search.toLowerCase()
    return endpoints.filter(
      ep => ep.url.toLowerCase().includes(q) || ep.method?.toLowerCase().includes(q),
    )
  }, [endpoints, search])

  const hasSearch = search.trim().length > 0
  const filteredIds = useMemo(() => new Set(filtered.map(e => e.url + ':' + e.method)), [filtered])

  // ── Build tree ────────────────────────────────────────────────────────────
  const rawTree = useMemo(() => {
    // derive domain from first endpoint
    let domain = 'target'
    if (endpoints.length > 0) {
      try { domain = new URL(endpoints[0].url).hostname } catch {}
    }
    // Build tree from ALL endpoints (search dims nodes, not removes them)
    return buildTree(endpoints, domain)
  }, [endpoints])

  const visibleTree = useMemo(
    () => applyCollapse(rawTree, collapsed),
    [rawTree, collapsed],
  )

  // ── d3-hierarchy layout ───────────────────────────────────────────────────
  const layout = useMemo(() => {
    const root = hierarchy<TreeNode>(visibleTree, n => n.children)
    // treeLayout() mutates root and returns HierarchyPointNode with x/y filled in
    const treeLayout = d3tree<TreeNode>().nodeSize([NODE_SEP, LEVEL_H])
    const pointRoot = treeLayout(root)   // HierarchyPointNode<TreeNode>

    // bounding box
    let minX = Infinity, maxX = -Infinity, maxY = 0
    pointRoot.each(n => {
      if (n.x < minX) minX = n.x
      if (n.x > maxX) maxX = n.x
      if (n.y > maxY) maxY = n.y
    })

    const treeWidth = maxX - minX
    const svgW = treeWidth + PAD_X * 2 + NODE_SEP
    const svgH = maxY + PAD_BOTTOM + PAD_TOP + NODE_H

    // xCenter: offset so the tree is horizontally centred in the SVG
    const xCenter = (maxX + minX) / 2

    return {
      nodes:   pointRoot.descendants(),
      links:   pointRoot.links(),
      svgW:    Math.max(svgW, 600),
      svgH:    Math.max(svgH, 300),
      maxY,
      xCenter,
    }
  }, [visibleTree])

  const toggleCollapse = useCallback((nodeId: string) => {
    setCollapsed(prev => {
      const next = new Set(prev)
      if (next.has(nodeId)) next.delete(nodeId)
      else next.add(nodeId)
      return next
    })
  }, [])

  // SVG group origin: root lives at (svgW/2, svgH - PAD_BOTTOM)
  // Each node is rendered at (node.x - xCenter,  -node.y) relative to origin
  // → root (y=0):    absolute y = svgH - PAD_BOTTOM  ✓ (bottom)
  // → leaf (y=maxY): absolute y = svgH - PAD_BOTTOM - maxY ✓ (top)

  const originX = layout.svgW / 2
  const originY = layout.svgH - PAD_BOTTOM

  const nx = (n: HierarchyPointNode<TreeNode>) => n.x - layout.xCenter
  const ny = (n: HierarchyPointNode<TreeNode>) => -(n.y)

  // ── Render ─────────────────────────────────────────────────────────────────

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

  return (
    <div className="flex h-full overflow-hidden bg-briar-bg">

      {/* ── Tree canvas ── */}
      <div ref={containerRef} className="flex-1 flex flex-col overflow-hidden">

        {/* Search bar */}
        <div className="shrink-0 px-4 py-2 border-b border-briar-border bg-briar-bg flex items-center gap-3">
          <Search size={13} className="text-slate-500 shrink-0" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter by URL or method…"
            className="flex-1 bg-transparent text-xs text-slate-200 outline-none placeholder-slate-600"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="text-slate-500 hover:text-slate-300 transition-colors"
            >
              <X size={12} />
            </button>
          )}
          <span className="text-xs text-slate-600 shrink-0 font-mono">
            {hasSearch ? `${filtered.length} / ` : ''}{endpoints.length}
          </span>
        </div>

        {/* SVG scroll area */}
        <div className="flex-1 overflow-auto">
          <svg
            width={layout.svgW}
            height={layout.svgH}
            style={{ display: 'block', minWidth: '100%' }}
          >
            {/* subtle radial ambient behind the root trunk */}
            <defs>
              <radialGradient id="trunk-glow" cx="50%" cy="100%" r="40%">
                <stop offset="0%"   stopColor="rgba(245,158,11,0.08)" />
                <stop offset="100%" stopColor="rgba(245,158,11,0)" />
              </radialGradient>
            </defs>
            <rect
              x={originX - 200} y={originY - 100}
              width={400} height={200}
              fill="url(#trunk-glow)"
            />

            <g transform={`translate(${originX}, ${originY})`}>

              {/* ── Branch curves ── */}
              {layout.links.map((link, i) => {
                const src = link.target
                const dst = link.source
                // stroke weight by descendant count — trunk is thicker
                const weight = Math.max(
                  1,
                  Math.log2((dst.data.endpointCount ?? 1) + 1) * 1.4,
                )
                return (
                  <BranchCurve
                    key={i}
                    src={{ x: nx(src), y: ny(src) }}
                    dst={{ x: nx(dst), y: ny(dst) }}
                    weight={weight}
                  />
                )
              })}

              {/* ── Nodes ── */}
              {layout.nodes.map(n => {
                const x = nx(n)
                const y = ny(n)
                const { id, type, endpoint, label, endpointCount } = n.data
                const isCollapsed = collapsed.has(id)

                if (type === 'root') {
                  return (
                    <RootNode
                      key={id}
                      cx={x} cy={y}
                      label={label}
                      count={endpointCount}
                    />
                  )
                }

                if (type === 'segment') {
                  return (
                    <SegmentNode
                      key={id}
                      cx={x} cy={y}
                      label={label}
                      count={endpointCount}
                      isCollapsed={isCollapsed}
                      isHovered={hovered === id}
                      onClick={() => toggleCollapse(id)}
                    />
                  )
                }

                if (type === 'endpoint' && endpoint) {
                  const epKey = endpoint.url + ':' + endpoint.method
                  const isDimmed = hasSearch && !filteredIds.has(epKey)
                  const isSelected = selected?.url === endpoint.url && selected?.method === endpoint.method
                  return (
                    <LeafNode
                      key={id}
                      cx={x} cy={y}
                      endpoint={endpoint}
                      isSelected={isSelected}
                      isHovered={hovered === id}
                      isDimmed={isDimmed}
                      onClick={() => setSelected(isSelected ? null : endpoint)}
                    />
                  )
                }

                return null
              })}

            </g>
          </svg>
        </div>

        {/* Legend */}
        <div className="shrink-0 flex items-center gap-4 px-4 py-2 border-t border-briar-border text-xs text-slate-500">
          <span className="font-mono text-amber-500/70">⬡ trunk</span>
          <span>Click segment to collapse/expand</span>
          <span>Click endpoint for details</span>
          <div className="ml-auto flex items-center gap-3">
            {Object.entries(METHOD_CLR).slice(0, 5).map(([m, c]) => (
              <span key={m} style={{ color: c.text }} className="font-mono font-bold text-[10px]">
                {m}
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
