/**
 * AppInfoCard
 * ============
 * Displays technology fingerprint data collected by WhatWeb and
 * app-type detection (M8) for a given scan.
 *
 * Layout:
 *   ┌─ Header ──────────────────────────────────────────────────────┐
 *   │  Target URL  •  HTTP status  •  IP  •  App-type badge         │
 *   ├─ Server & Runtime ────────────────────────────────────────────┤
 *   │  nginx 1.18  │  PHP 8.1  │  Node.js 18.0                     │
 *   ├─ Frontend Libraries ──────────────────────────────────────────┤
 *   │  React 18.2  │  jQuery 3.7  │  Bootstrap 5.3  …              │
 *   ├─ CMS / Framework ─────────────────────────────────────────────┤
 *   │  WordPress 6.4                                                │
 *   ├─ Security ────────────────────────────────────────────────────┤
 *   │  ✓ Cloudflare WAF  │  ✓ HSTS  │  ✗ X-Frame-Options          │
 *   ├─ Response Headers ────────────────────────────────────────────┤
 *   │  table of interesting headers                                 │
 *   └─ All Detected Technologies ───────────────────────────────────┘
 */

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Server, Code2, Globe, Shield, Layers, ChevronDown, ChevronUp,
  AlertTriangle, CheckCircle2, XCircle, Monitor, Package, Cpu,
  RefreshCw,
} from 'lucide-react'
import { fetchAppInfo } from '../api/client'
import type { AppInfo, TechEntry } from '../types'

// ── App-type badge ────────────────────────────────────────────────────────────

const APP_TYPE_COLORS: Record<string, string> = {
  spa:         'bg-violet-500/20 text-violet-300 border-violet-500/30',
  api:         'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  cms:         'bg-amber-500/20 text-amber-300 border-amber-500/30',
  traditional: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  unknown:     'bg-slate-500/20 text-slate-400 border-slate-500/30',
}

const APP_TYPE_LABELS: Record<string, string> = {
  spa:         'SPA',
  api:         'API',
  cms:         'CMS',
  traditional: 'Traditional',
  unknown:     'Unknown',
}

function AppTypeBadge({ type, framework }: { type: string; framework?: string | null }) {
  const cls = APP_TYPE_COLORS[type] ?? APP_TYPE_COLORS.unknown
  const label = APP_TYPE_LABELS[type] ?? type
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${cls}`}>
      {label}
      {framework && <span className="opacity-70">· {framework}</span>}
    </span>
  )
}

// ── Status code badge ─────────────────────────────────────────────────────────

function HttpStatusBadge({ code }: { code: number | null }) {
  if (!code) return null
  const cls = code < 300
    ? 'text-emerald-400'
    : code < 400
    ? 'text-yellow-400'
    : 'text-red-400'
  return <span className={`font-mono text-xs font-semibold ${cls}`}>HTTP {code}</span>
}

// ── Tech pill ─────────────────────────────────────────────────────────────────

function TechPill({ entry }: { entry: TechEntry }) {
  return (
    <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-briar-bg border border-briar-border text-xs">
      <span className="text-slate-200 font-medium">{entry.name}</span>
      {entry.version && (
        <span className="text-slate-500 font-mono">{entry.version}</span>
      )}
    </div>
  )
}

// ── Section block ─────────────────────────────────────────────────────────────

function Section({
  icon,
  title,
  children,
  empty,
}: {
  icon: React.ReactNode
  title: string
  children: React.ReactNode
  empty?: boolean
}) {
  if (empty) return null
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
        {icon}
        {title}
      </div>
      {children}
    </div>
  )
}

// ── Security section ──────────────────────────────────────────────────────────

const SECURITY_HEADERS = [
  { key: 'strict-transport-security',  label: 'HSTS' },
  { key: 'content-security-policy',    label: 'CSP' },
  { key: 'x-frame-options',            label: 'X-Frame-Options' },
  { key: 'x-content-type-options',     label: 'X-Content-Type-Options' },
  { key: 'referrer-policy',            label: 'Referrer-Policy' },
  { key: 'permissions-policy',         label: 'Permissions-Policy' },
  { key: 'x-xss-protection',           label: 'X-XSS-Protection' },
]

function SecuritySection({ info }: { info: AppInfo }) {
  const headers = info.interesting_headers
  const hasWaf = info.waf.length > 0
  const hasHttps = (info.http_status ?? 0) > 0
    && (info.target_url?.startsWith('https://') ?? false)

  const checks = [
    ...SECURITY_HEADERS.map(({ key, label }) => ({
      label,
      present: key in headers,
      value: headers[key] ?? null,
    })),
    { label: 'HTTPS', present: hasHttps, value: null },
    ...info.waf.map((w) => ({ label: `WAF: ${w.name}`, present: true, value: null })),
  ]

  const good = checks.filter((c) => c.present)
  const bad  = checks.filter((c) => !c.present && !c.label.startsWith('WAF'))

  if (good.length === 0 && bad.length === 0) return null

  return (
    <Section icon={<Shield size={12} />} title="Security Posture">
      <div className="grid grid-cols-2 gap-1">
        {good.map((c) => (
          <div key={c.label} className="flex items-center gap-1.5 text-xs text-emerald-400">
            <CheckCircle2 size={11} className="shrink-0" />
            <span className="truncate">{c.label}</span>
          </div>
        ))}
        {bad.map((c) => (
          <div key={c.label} className="flex items-center gap-1.5 text-xs text-slate-500">
            <XCircle size={11} className="shrink-0" />
            <span className="truncate">{c.label}</span>
          </div>
        ))}
      </div>
    </Section>
  )
}

// ── All technologies collapsible ──────────────────────────────────────────────

function AllTechSection({ all }: { all: Record<string, string> }) {
  const [open, setOpen] = useState(false)
  const entries = Object.entries(all)
  if (entries.length === 0) return null

  return (
    <div>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors w-full"
      >
        {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        All detected plugins ({entries.length})
      </button>
      {open && (
        <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs">
          {entries.map(([name, ver]) => (
            <div key={name} className="flex items-center gap-1 truncate">
              <span className="text-slate-400 truncate">{name}</span>
              {ver && <span className="text-slate-600 font-mono shrink-0">{ver}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AppInfoCard({ scanId }: { scanId: string }) {
  const { data, isLoading, error, refetch, isRefetching } = useQuery({
    queryKey: ['app-info', scanId],
    queryFn: () => fetchAppInfo(scanId),
    staleTime: 30_000,
    refetchInterval: 60_000,   // re-fetch every minute while page is open
  })

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
        Loading application profile…
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-3 text-slate-500 text-sm">
        <AlertTriangle size={20} className="text-amber-500" />
        <span>Could not load app info.</span>
        <button onClick={() => refetch()} className="btn-ghost text-xs py-1 px-3 flex items-center gap-1">
          <RefreshCw size={12} /> Retry
        </button>
      </div>
    )
  }

  const info = data

  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-5 text-sm">

      {/* ── Header ── */}
      <div className="card space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <Globe size={14} className="text-briar-accent shrink-0" />
              <span className="text-slate-100 font-medium break-all text-sm">{info.target_url}</span>
              <button
                onClick={() => refetch()}
                className={`text-slate-500 hover:text-slate-300 transition-colors ${isRefetching ? 'animate-spin' : ''}`}
              >
                <RefreshCw size={12} />
              </button>
            </div>
            <div className="flex flex-wrap items-center gap-2 pl-5 text-xs text-slate-400">
              <HttpStatusBadge code={info.http_status} />
              {info.ip && <span className="font-mono">{info.ip}</span>}
              {info.country && <span>{info.country}</span>}
              {info.title && (
                <span className="truncate max-w-xs italic text-slate-500">"{info.title}"</span>
              )}
            </div>
          </div>
          <div className="shrink-0">
            <AppTypeBadge type={info.app_type} framework={info.framework} />
          </div>
        </div>

        {!info.whatweb_ran && (
          <div className="flex items-center gap-2 text-xs text-amber-400/80 bg-amber-400/10 rounded-lg px-3 py-2">
            <AlertTriangle size={12} className="shrink-0" />
            WhatWeb has not run yet for this scan — add it to the tool selection to populate this card.
          </div>
        )}
      </div>

      {/* ── Server & Runtime ── */}
      <Section
        icon={<Server size={12} />}
        title="Server & Runtime"
        empty={info.server.length === 0 && info.languages.length === 0}
      >
        <div className="flex flex-wrap gap-2">
          {info.server.map((e) => <TechPill key={e.name} entry={e} />)}
          {info.languages.map((e) => <TechPill key={e.name} entry={e} />)}
        </div>
      </Section>

      {/* ── Frontend Libraries ── */}
      <Section
        icon={<Monitor size={12} />}
        title="Frontend Libraries"
        empty={info.frontend_libs.length === 0}
      >
        <div className="flex flex-wrap gap-2">
          {info.frontend_libs.map((e) => <TechPill key={e.name} entry={e} />)}
        </div>
      </Section>

      {/* ── CMS / Platform ── */}
      <Section
        icon={<Layers size={12} />}
        title="CMS / Platform"
        empty={info.cms.length === 0}
      >
        <div className="flex flex-wrap gap-2">
          {info.cms.map((e) => <TechPill key={e.name} entry={e} />)}
        </div>
      </Section>

      {/* ── CDN ── */}
      <Section
        icon={<Globe size={12} />}
        title="CDN"
        empty={info.cdn.length === 0}
      >
        <div className="flex flex-wrap gap-2">
          {info.cdn.map((e) => <TechPill key={e.name} entry={e} />)}
        </div>
      </Section>

      {/* ── Security posture ── */}
      <SecuritySection info={info} />

      {/* ── Interesting Response Headers ── */}
      <Section
        icon={<Code2 size={12} />}
        title="Response Headers"
        empty={Object.keys(info.interesting_headers).length === 0}
      >
        <div className="rounded-lg border border-briar-border overflow-hidden">
          <table className="w-full text-xs">
            <tbody>
              {Object.entries(info.interesting_headers).map(([key, val]) => (
                <tr key={key} className="border-b border-briar-border last:border-0">
                  <td className="px-3 py-1.5 text-slate-400 font-mono w-1/3 shrink-0 whitespace-nowrap">
                    {key}
                  </td>
                  <td className="px-3 py-1.5 text-slate-300 break-all">
                    {val}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      {/* ── All technologies (collapsible) ── */}
      <AllTechSection all={info.all_technologies} />

    </div>
  )
}
