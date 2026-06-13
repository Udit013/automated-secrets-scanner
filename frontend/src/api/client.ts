import axios from 'axios'

// In dev: proxy via Vite (/api → localhost:8000).
// In production: VITE_API_URL must be set to the Render backend URL.
const BASE = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL}/api/v1`
  : '/api/v1'

export const API_BASE_URL = import.meta.env.VITE_API_URL || ''

export const api = axios.create({
  baseURL: BASE,
  headers: { 'Content-Type': 'application/json' },
})

// Separate instance for root-level endpoints like /health
const ROOT = import.meta.env.VITE_API_URL || ''
export const rootApi = axios.create({ baseURL: ROOT })


// ─── Types ────────────────────────────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed'
export type SourceType = 'github' | 'paste'

export interface Finding {
  id: string
  scan_id: string
  file_path: string
  line_number: number
  secret_type: string
  matched_string: string
  entropy: number
  severity: Severity
  confidence: string
  context: string
  commit_hash: string | null
  remediation: string
  is_in_history: boolean
}

export interface Scan {
  id: string
  source_type: SourceType
  source_ref: string
  scan_git_history: boolean
  max_commits: number
  min_entropy: number
  status: ScanStatus
  total_findings: number
  files_scanned: number
  progress: number
  error_message: string | null
  created_at: string
  completed_at: string | null
  findings: Finding[]
}

export type ScanListItem = Omit<Scan, 'findings'>

export interface Schedule {
  id: string
  name: string
  source_type: SourceType
  source_ref: string
  cron_expression: string
  scan_git_history: boolean
  enabled: boolean
  last_run_at: string | null
  next_run_at: string | null
  last_scan_id: string | null
  created_at: string
}

export interface Stats {
  total_scans: number
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  by_type: Record<string, number>
  recent_scans: ScanListItem[]
  findings_over_time: { date: string; count: number }[]
}

// ─── API Functions ─────────────────────────────────────────────────────────────

export const startScan = (body: {
  source_type: SourceType
  source_ref: string
  scan_git_history?: boolean
  max_commits?: number
  min_entropy?: number
}) => api.post<ScanListItem>('/scans', body).then((r) => r.data)

export const listScans = (limit = 50, offset = 0) =>
  api.get<ScanListItem[]>('/scans', { params: { limit, offset } }).then((r) => r.data)

export const getScan = (id: string) =>
  api.get<Scan>(`/scans/${id}`).then((r) => r.data)

export const getFindings = (
  scanId: string,
  params?: { severity?: string; secret_type?: string; limit?: number; offset?: number },
) =>
  api.get<Finding[]>(`/scans/${scanId}/findings`, { params }).then((r) => r.data)

export const deleteScan = (id: string) => api.delete(`/scans/${id}`)

export const getStats = () => api.get<Stats>('/stats').then((r) => r.data)

export const createSchedule = (body: {
  name: string
  source_type: SourceType
  source_ref: string
  cron_expression: string
  scan_git_history?: boolean
}) => api.post<Schedule>('/schedules', body).then((r) => r.data)

export const listSchedules = () =>
  api.get<Schedule[]>('/schedules').then((r) => r.data)

export const toggleSchedule = (id: string) =>
  api.patch<Schedule>(`/schedules/${id}/toggle`).then((r) => r.data)

export const deleteSchedule = (id: string) => api.delete(`/schedules/${id}`)

export const exportUrl = (scanId: string, format: 'json' | 'csv') =>
  `/api/v1/export/${scanId}/${format}`
