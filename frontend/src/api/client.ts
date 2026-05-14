import type { GraphData, Scan, Vulnerability } from '../types'

const UI_API = import.meta.env.VITE_UI_API_URL || ''
const GATEWAY = import.meta.env.VITE_GATEWAY_URL || ''

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status} ${res.statusText}: ${text}`)
  }
  return res.json() as Promise<T>
}

// ── Scans ─────────────────────────────────────────────────────────────────────

export const fetchScans = (): Promise<Scan[]> =>
  get(`${UI_API}/api/v1/scans`)

export const fetchScan = (id: string): Promise<Scan> =>
  get(`${UI_API}/api/v1/scans/${id}`)

export const fetchScanGraph = (id: string): Promise<GraphData> =>
  get(`${UI_API}/api/v1/scans/${id}/graph`)

export const triggerSync = (id: string): Promise<void> =>
  fetch(`${UI_API}/api/v1/scans/${id}/sync`, { method: 'POST' }).then(() => undefined)

// ── Vulnerabilities ───────────────────────────────────────────────────────────

export interface VulnParams {
  scan_id?: string
  severity?: string
  tool?: string
  limit?: number
}

export const fetchVulnerabilities = (params: VulnParams = {}): Promise<Vulnerability[]> => {
  const qs = new URLSearchParams()
  if (params.scan_id) qs.set('scan_id', params.scan_id)
  if (params.severity) qs.set('severity', params.severity)
  if (params.tool) qs.set('tool', params.tool)
  if (params.limit) qs.set('limit', String(params.limit))
  return get(`${UI_API}/api/v1/vulnerabilities?${qs}`)
}

// ── Create scan (via gateway) ─────────────────────────────────────────────────

export interface CreateScanPayload {
  target_url: string
  tools: string[]
  auth_session_id?: string | null
}

export async function createScan(
  payload: CreateScanPayload,
  token: string,
): Promise<{ scan_id: string; status: string }> {
  const res = await fetch(`${GATEWAY}/api/v1/scans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  })
  if (!res.ok) throw new Error(`Create scan failed: ${res.statusText}`)
  return res.json()
}

// ── WebSocket URL ─────────────────────────────────────────────────────────────

export function getWsUrl(scanId: string): string {
  const base = UI_API.replace(/^http/, 'ws') || `ws://${window.location.hostname}:8003`
  return `${base}/ws/scans/${scanId}`
}
