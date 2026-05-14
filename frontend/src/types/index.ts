export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed'
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface ScanStep {
  tool: string
  status: ScanStatus
  started_at?: string | null
  finished_at?: string | null
}

export interface Scan {
  id: string
  target_url: string
  status: ScanStatus
  created_at: string
  updated_at: string
  tools: string[]
  steps: ScanStep[]
}

export interface Vulnerability {
  id: string
  scan_id: string
  tool: string
  severity: Severity
  url: string | null
  vulnerability_type: string | null
  description: string | null
  created_at: string
}

export interface GraphNode {
  id: string
  label: string
  url?: string
  type: 'endpoint' | 'vulnerability'
  method?: string
  discovered_by?: string
  severity?: Severity
  tool?: string
  vuln_count?: number
  has_critical?: boolean
  has_high?: boolean
  description?: string
  // react-force-graph internal positioning
  x?: number
  y?: number
  vx?: number
  vy?: number
  fx?: number
  fy?: number
}

export interface GraphLink {
  source: string | GraphNode
  target: string | GraphNode
}

export interface GraphData {
  nodes: GraphNode[]
  links: GraphLink[]
}

export interface WsEvent {
  event: 'initial_state' | 'step_update' | 'stats_update' | 'scan_complete'
  scan?: Scan
  tool?: string
  status?: ScanStatus
  progress?: number
  scan_status?: ScanStatus
  endpoint_count?: number
  vuln_count?: number
}
