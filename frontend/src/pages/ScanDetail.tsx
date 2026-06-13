import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getScan, getFindings, exportUrl } from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'
import { StatusBadge } from '../components/StatusBadge'
import { format } from 'date-fns'
import { useState } from 'react'
import {
  Download, ChevronDown, ChevronRight, ArrowLeft, GitCommit,
  File, Clock, Database,
} from 'lucide-react'
import type { Finding, Severity } from '../api/client'
import { clsx } from 'clsx'

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const { data: scan } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => getScan(id!),
    refetchInterval: (q) =>
      q.state.data?.status === 'running' ? 3000 : false,
    enabled: !!id,
  })

  const { data: findings } = useQuery({
    queryKey: ['findings', id, severityFilter],
    queryFn: () =>
      getFindings(id!, {
        severity: severityFilter || undefined,
        limit: 500,
      }),
    enabled: !!id && scan?.status === 'completed',
  })

  if (!scan) return <div className="text-gray-500 animate-pulse text-sm">Loading…</div>

  const toggle = (fid: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(fid) ? next.delete(fid) : next.add(fid)
      return next
    })
  }

  const grouped = groupByFile(findings ?? [])

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link to="/history" className="text-gray-500 hover:text-gray-300 transition-colors">
          <ArrowLeft size={16} />
        </Link>
        <h1 className="text-xl font-bold text-white flex-1">Scan Details</h1>
        <div className="flex gap-2">
          <a
            href={exportUrl(id!, 'json')}
            download
            className="btn-secondary text-xs flex items-center gap-1"
          >
            <Download size={13} /> JSON
          </a>
          <a
            href={exportUrl(id!, 'csv')}
            download
            className="btn-secondary text-xs flex items-center gap-1"
          >
            <Download size={13} /> CSV
          </a>
        </div>
      </div>

      {/* Meta card */}
      <div className="card grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
        <MetaItem icon={<Database size={13} />} label="Source" value={scan.source_ref} truncate />
        <MetaItem icon={<StatusBadge status={scan.status} />} label="Status" value="" />
        <MetaItem icon={<File size={13} />} label="Files Scanned" value={String(scan.files_scanned)} />
        <MetaItem
          icon={<Clock size={13} />}
          label="Completed"
          value={scan.completed_at ? format(new Date(scan.completed_at), 'MMM d, HH:mm') : '—'}
        />
      </div>

      {/* Severity summary */}
      {scan.status === 'completed' && (
        <div className="flex flex-wrap gap-3">
          {SEVERITIES.map((sev) => {
            const count = (findings ?? []).filter((f) => f.severity === sev).length
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? '' : sev)}
                className={clsx(
                  'flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm transition-colors',
                  severityFilter === sev
                    ? 'border-brand-500 bg-brand-500/10'
                    : 'border-gray-700 bg-gray-900 hover:border-gray-500',
                )}
              >
                <SeverityBadge severity={sev} />
                <span className="text-gray-300 font-mono">{count}</span>
              </button>
            )
          })}
          {severityFilter && (
            <button
              onClick={() => setSeverityFilter('')}
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors px-2"
            >
              Clear filter
            </button>
          )}
        </div>
      )}

      {/* Findings */}
      {scan.status === 'running' && (
        <div className="card text-center py-10">
          <div className="text-gray-400 animate-pulse">Scan in progress… {scan.progress}%</div>
          <div className="mt-3 w-full bg-gray-800 rounded-full h-2">
            <div
              className="bg-brand-500 h-2 rounded-full transition-all"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
        </div>
      )}

      {scan.status === 'failed' && (
        <div className="card border-red-800 bg-red-900/10 text-red-400">
          Scan failed: {scan.error_message}
        </div>
      )}

      {scan.status === 'completed' && (findings ?? []).length === 0 && (
        <div className="card text-center py-10 text-green-400">
          ✓ No secrets detected
        </div>
      )}

      {/* Grouped by file */}
      {Object.entries(grouped).map(([filePath, fileFindings]) => (
        <div key={filePath} className="card p-0 overflow-hidden">
          <div className="px-4 py-3 bg-gray-800/50 flex items-center gap-2 border-b border-gray-800">
            <File size={13} className="text-gray-500" />
            <span className="text-sm font-mono text-gray-300 flex-1">{filePath}</span>
            <span className="text-xs text-gray-500">{fileFindings.length} finding(s)</span>
          </div>
          <div className="divide-y divide-gray-800">
            {fileFindings.map((f) => (
              <FindingRow
                key={f.id}
                finding={f}
                isOpen={expanded.has(f.id)}
                onToggle={() => toggle(f.id)}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function FindingRow({
  finding: f,
  isOpen,
  onToggle,
}: {
  finding: Finding
  isOpen: boolean
  onToggle: () => void
}) {
  return (
    <div>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-800/30 transition-colors"
      >
        {isOpen ? (
          <ChevronDown size={13} className="text-gray-500 flex-shrink-0" />
        ) : (
          <ChevronRight size={13} className="text-gray-500 flex-shrink-0" />
        )}
        <SeverityBadge severity={f.severity} />
        <span className="text-sm text-gray-300 font-medium flex-1">{f.secret_type}</span>
        <span className="text-xs font-mono text-gray-500">:{f.line_number}</span>
        <span className="text-xs font-mono text-gray-600 ml-2 max-w-[200px] truncate">
          {f.matched_string}
        </span>
        {f.is_in_history && (
          <span className="ml-2 flex items-center gap-1 text-xs text-purple-400" title="Found in git history">
            <GitCommit size={11} /> history
          </span>
        )}
      </button>

      {isOpen && (
        <div className="px-6 pb-4 space-y-3 bg-gray-900/40">
          <InfoRow label="Matched" value={<code className="text-red-300 text-xs bg-gray-800 px-2 py-0.5 rounded">{f.matched_string}</code>} />
          <InfoRow label="Entropy" value={<span className="text-xs font-mono text-yellow-400">{f.entropy}</span>} />
          <InfoRow label="Confidence" value={<span className="text-xs text-gray-300">{f.confidence}</span>} />
          {f.commit_hash && (
            <InfoRow label="Commit" value={<code className="text-purple-300 text-xs">{f.commit_hash}</code>} />
          )}
          <InfoRow
            label="Context"
            value={
              <pre className="text-xs text-gray-400 bg-gray-800 rounded px-3 py-2 overflow-x-auto whitespace-pre-wrap break-all">
                {f.context}
              </pre>
            }
          />
          {f.remediation && (
            <div>
              <div className="text-xs text-gray-500 font-medium mb-1">Remediation</div>
              <pre className="text-xs text-green-400 bg-gray-800 rounded px-3 py-2 whitespace-pre-wrap">
                {f.remediation}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-4 items-start">
      <span className="text-xs text-gray-500 w-20 flex-shrink-0 pt-0.5">{label}</span>
      <div className="flex-1 min-w-0">{value}</div>
    </div>
  )
}

function MetaItem({
  icon,
  label,
  value,
  truncate,
}: {
  icon: React.ReactNode
  label: string
  value: string
  truncate?: boolean
}) {
  return (
    <div>
      <div className="text-xs text-gray-500 flex items-center gap-1 mb-1">
        {icon} {label}
      </div>
      <div className={clsx('text-sm text-gray-300', truncate && 'truncate')} title={value}>
        {value || '—'}
      </div>
    </div>
  )
}

function groupByFile(findings: Finding[]): Record<string, Finding[]> {
  const groups: Record<string, Finding[]> = {}
  for (const f of findings) {
    ;(groups[f.file_path] ??= []).push(f)
  }
  return groups
}
