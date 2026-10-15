import axios, { isAxiosError } from 'axios'
import { getToken, markLocked } from './auth'

// In dev: proxy via Vite (/api → localhost:8000).
// In production: VITE_API_URL must be set to the backend URL.
export const API_BASE_URL = import.meta.env.VITE_API_URL || ''

export const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
})

// Root-level endpoints like /health (public, never needs the token).
export const rootApi = axios.create({ baseURL: API_BASE_URL })

api.interceptors.request.use((config) => {
  const token = getToken()
  if (token) config.headers.set('Authorization', `Bearer ${token}`)
  return config
})

api.interceptors.response.use(
  (r) => r,
  (error) => {
    if (isAxiosError(error) && error.response?.status === 401) markLocked()
    return Promise.reject(error)
  },
)

/**
 * A human sentence for any API failure: FastAPI's `detail`, the rate-limit
 * wait, or the network state — never axios's "Request failed with status code".
 */
export function apiErrorMessage(error: unknown, fallback = 'Something went wrong'): string {
  if (isAxiosError(error)) {
    const status = error.response?.status
    const detail = error.response?.data?.detail
    if (status === 429 && typeof detail !== 'string') {
      const wait = Number(error.response?.headers?.['retry-after'])
      return wait > 0 ? `Too many requests. Try again in ${formatWait(wait)}.` : 'Too many requests.'
    }
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail) && detail[0]?.msg) {
      return String(detail[0].msg).replace(/^Value error, /, '')
    }
    if (!error.response) return 'Cannot reach the CipherWatch API. It may be waking up — try again in a few seconds.'
    if (status && status >= 500) return 'The server hit an error. Try again, or check the server logs.'
  }
  return (error as Error)?.message || fallback
}

function formatWait(seconds: number): string {
  if (seconds < 90) return `${Math.ceil(seconds)}s`
  return `${Math.ceil(seconds / 60)} min`
}

// ─── Types ────────────────────────────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed'
export type SourceType = 'github' | 'paste'
export type CredentialStatus = 'open' | 'rotated' | 'false_positive' | 'accepted_risk'
export type Exposure = 'working_tree' | 'history_only'

export interface Health {
  status: string
  version: string
  auth_required: boolean
  demo: boolean
}

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
  risk_score: number
  risk_factors: string[] | null
  occurrences: number
  introduced_at: string | null
  last_seen_at: string | null
  exposure_days: number | null
  commits_affected: number | null
  authors_count: number | null
}

export interface DiffFinding {
  secret_type: string
  severity: Severity
  file_path: string
  line_number: number
  risk_score: number
}

export interface ScanDiff {
  has_baseline: boolean
  baseline_scan_id: string | null
  baseline_created_at: string | null
  current_total: number
  baseline_total: number
  new_count: number
  resolved_count: number
  unchanged_count: number
  net_change: number
  new_findings: DiffFinding[]
  resolved_findings: DiffFinding[]
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

export interface ExposureTotals {
  projects: number
  open: number
  open_history_only: number
  open_by_severity: Partial<Record<Severity, number>>
  review_overdue: number
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
  exposure: ExposureTotals | null
}

export interface CredentialLocation {
  file_path: string
  line_number: number
  in_history: boolean
  commit_hash: string | null
}

export interface Credential {
  fingerprint: string
  secret_type: string
  secret_types: string[]
  severity: Severity
  risk_score: number
  risk_factors: string[]
  masked_value: string
  status: CredentialStatus
  stored_status: CredentialStatus
  review_overdue: boolean
  review_by: string | null
  note: string
  triaged_at: string | null
  exposure: Exposure
  first_seen: string | null
  exposure_days: number | null
  commits_affected: number | null
  authors_count: number | null
  location_count: number
  locations: CredentialLocation[]
  remediation: string
  rotation_url: string
}

export interface CredentialSummary {
  total: number
  open: number
  open_by_severity: Partial<Record<Severity, number>>
  open_history_only: number
  rotated: number
  accepted_risk: number
  false_positive: number
  review_overdue: number
}

export interface Project {
  slug: string
  source_ref: string
  last_scan_id: string | null
  last_scanned_at: string | null
  files_scanned: number
  history_scanned: boolean
  latest_status: ScanStatus | null
  latest_scan_id: string | null
  summary: CredentialSummary
  schedule: { id: string; cron_expression: string; enabled: boolean; next_run_at: string | null } | null
}

export interface TrendPoint {
  scan_id: string
  completed_at: string | null
  credentials: number
  open: number
  critical_open: number
  new: number
  removed: number
}

export interface ProjectDetail extends Project {
  trend: TrendPoint[]
}

export interface TriageBody {
  status: CredentialStatus
  note?: string
  review_by?: string | null
}

// ─── API Functions ─────────────────────────────────────────────────────────────

export const getHealth = () => rootApi.get<Health>('/health', { timeout: 60_000 }).then((r) => r.data)

/** Check a candidate token without storing it. */
export const verifyToken = (token: string) =>
  axios
    .get(`${API_BASE_URL}/api/v1/stats`, { headers: { Authorization: `Bearer ${token}` } })
    .then(() => true)

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

export const getScanDiff = (id: string) =>
  api.get<ScanDiff>(`/scans/${id}/diff`).then((r) => r.data)

export const listProjects = () => api.get<Project[]>('/projects').then((r) => r.data)

export const getProject = (slug: string) =>
  api.get<ProjectDetail>(`/projects/${slug}`).then((r) => r.data)

export const listCredentials = (
  slug: string,
  params?: { status?: CredentialStatus; severity?: Severity; exposure?: Exposure },
) =>
  api
    .get<{ scan_id: string | null; credentials: Credential[] }>(`/projects/${slug}/credentials`, { params })
    .then((r) => r.data)

export const triageCredential = (slug: string, fingerprint: string, body: TriageBody) =>
  api.put<Credential>(`/projects/${slug}/credentials/${fingerprint}`, body).then((r) => r.data)

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

export type ExportFormat = 'json' | 'csv' | 'sarif' | 'patch'

/**
 * Download an export through the authenticated client (a plain <a href>
 * cannot carry the access token), naming the file from Content-Disposition.
 */
export async function downloadExport(scanId: string, format: ExportFormat) {
  const resp = await api.get<Blob>(`/export/${scanId}/${format}`, { responseType: 'blob' })
  const disposition = String(resp.headers['content-disposition'] ?? '')
  const name = /filename="?([^";]+)"?/.exec(disposition)?.[1] ?? `scan_${scanId.slice(0, 8)}.${format}`
  const url = URL.createObjectURL(resp.data)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** "https://github.com/acme/api" → "acme/api"; anything else passes through. */
export function shortRef(ref: string, max = 48): string {
  const cleaned = ref.replace(/^https?:\/\/(www\.)?github\.com\//, '').replace(/\.git$/, '')
  return cleaned.length > max ? cleaned.slice(0, max) + '…' : cleaned
}

/** Project slug for a GitHub scan, or null for pastes. */
export function projectSlug(ref: string): string | null {
  const m = /github\.com[/:]([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(ref)
  return m ? `${m[1]}/${m[2]}` : null
}

/**
 * The API stores and returns naive UTC timestamps ("2026-01-01T12:00:00").
 * `new Date()` would read those as local time, so mark them UTC first.
 */
export function parseUtc(ts: string): Date {
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(ts) ? ts : `${ts}Z`)
}
