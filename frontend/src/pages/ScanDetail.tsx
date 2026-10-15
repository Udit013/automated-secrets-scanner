import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { format } from 'date-fns'
import { getScan, getFindings, getScanDiff, downloadExport, parseUtc, projectSlug, shortRef } from '../api/client'
import type { ExportFormat } from '../api/client'
import { ErrorState, InlineError, LoadingRows } from '../components/ui'
import { SeverityBadge } from '../components/SeverityBadge'
import { SEV_COLOR, SEV_ORDER } from '../lib/severity'
import { StatusBadge } from '../components/StatusBadge'
import { RiskBadge, RiskMeter } from '../components/RiskBadge'
import { LifecycleTimeline } from '../components/LifecycleTimeline'
import { DiffSummary } from '../components/DiffSummary'
import { clsx } from 'clsx'
import type { Finding, Severity } from '../api/client'

const EXPORTS = [
  { fmt: 'json' as const, label: 'JSON' },
  { fmt: 'csv' as const, label: 'CSV' },
  { fmt: 'sarif' as const, label: 'SARIF' },
  { fmt: 'patch' as const, label: 'Patch' },
]

export function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const { data: scan, error: scanError, refetch } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => getScan(id!),
    refetchInterval: (q) =>
      q.state.data?.status === 'running' || q.state.data?.status === 'queued' ? 2500 : false,
    enabled: !!id,
  })

  const exporter = useMutation({
    mutationFn: (fmt: ExportFormat) => downloadExport(id!, fmt),
  })

  const { data: findings, error: findingsError } = useQuery({
    queryKey: ['findings', id],
    queryFn: () => getFindings(id!, { limit: 500 }),
    enabled: !!id && scan?.status === 'completed',
  })

  const { data: diff } = useQuery({
    queryKey: ['diff', id],
    queryFn: () => getScanDiff(id!),
    enabled: !!id && scan?.status === 'completed',
  })

  if (scanError) {
    return (
      <div>
        <Link to="/history" className="text-2xs text-ivory-mute hover:text-ivory transition-colors">← scans</Link>
        <ErrorState error={scanError} onRetry={() => refetch()} />
      </div>
    )
  }
  if (!scan) return <LoadingRows rows={5} label="Loading report" />
  const slug = scan.source_type === 'github' ? projectSlug(scan.source_ref) : null

  const toggle = (fid: string) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(fid)) next.delete(fid)
      else next.add(fid)
      return next
    })

  const all = findings ?? []
  const visible = severityFilter ? all.filter((f) => f.severity === severityFilter) : all
  const grouped = groupByFile(visible)
  const counts = Object.fromEntries(
    SEV_ORDER.map((s) => [s, all.filter((f) => f.severity === s).length]),
  ) as Record<Severity, number>

  return (
    <div>
      {/* Report header */}
      <div className="pb-5">
        <Link to="/history" className="text-2xs text-ivory-mute hover:text-ivory transition-colors">
          ← scans
        </Link>
        <div className="flex flex-wrap items-end justify-between gap-4 mt-2">
          <div className="min-w-0">
            <p className="kicker mb-1">Scan report</p>
            <h1 className="page-title font-mono text-[18px] truncate max-w-xl" title={scan.source_ref}>
              {scan.source_type === 'paste' ? 'pasted snippet' : shortRef(scan.source_ref, 60)}
            </h1>
            {slug && (
              <Link to={`/projects/${slug}`} className="inline-block mt-1.5 text-2xs text-ivory-dim hover:text-ivory underline underline-offset-4">
                Open the credential ledger to triage →
              </Link>
            )}
          </div>
          {scan.status === 'completed' && (
            <div className="flex flex-col items-end gap-1.5">
              <div className="flex items-center gap-1">
                <span className="kicker mr-2">export</span>
                {EXPORTS.map(({ fmt, label }) => (
                  <button
                    key={fmt}
                    onClick={() => exporter.mutate(fmt)}
                    disabled={exporter.isPending}
                    className="btn-outline h-7 px-2.5 text-2xs"
                  >
                    {exporter.isPending && exporter.variables === fmt ? '…' : label}
                  </button>
                ))}
              </div>
              <InlineError error={exporter.error} />
            </div>
          )}
        </div>

        {/* Meta line */}
        <dl className="flex flex-wrap gap-x-8 gap-y-1 mt-4">
          <Meta term="status"><StatusBadge status={scan.status} /></Meta>
          <Meta term="files">
            <span className="font-mono text-2xs text-ivory-dim tabular-nums">{scan.files_scanned}</span>
          </Meta>
          <Meta term="completed">
            <span className="font-mono text-2xs text-ivory-dim">
              {scan.completed_at ? format(parseUtc(scan.completed_at), 'MMM d, yyyy · HH:mm') : '—'}
            </span>
          </Meta>
          <Meta term="id">
            <span className="font-mono text-2xs text-ivory-mute">{scan.id.slice(0, 8)}</span>
          </Meta>
        </dl>
      </div>

      {(scan.status === 'running' || scan.status === 'queued') && (
        <div className="rule pt-8 pb-10 text-center" role="status" aria-live="polite">
          <p className="font-mono text-2xs text-ivory-dim mb-3">
            {scan.status === 'queued' ? 'queued…' : `scanning… ${scan.progress}%`}
          </p>
          <div className="mx-auto max-w-sm h-[3px] rounded-full bg-line overflow-hidden">
            <div
              className="h-full bg-ivory transition-[width] duration-300"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
        </div>
      )}

      {scan.status === 'failed' && (
        <div className="rule pt-6">
          <p className="text-2xs font-mono text-sev-critical" role="alert">scan failed — {scan.error_message || 'unknown error'}</p>
        </div>
      )}

      {scan.status === 'completed' && (
        <>
          {diff && (
            <div className="rule pt-5 pb-6">
              <DiffSummary diff={diff} />
            </div>
          )}

          {/* Severity filter strip */}
          <div className="rule pt-4 pb-4 flex flex-wrap items-center gap-2">
            {SEV_ORDER.map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? '' : sev)}
                disabled={counts[sev] === 0}
                aria-pressed={severityFilter === sev}
                className={clsx(
                  'inline-flex items-center gap-2 h-7 px-2.5 rounded-sm text-2xs transition-colors',
                  'disabled:opacity-30 disabled:pointer-events-none',
                  severityFilter === sev
                    ? 'bg-ink-overlay ring-1 ring-line-strong'
                    : 'hover:bg-ink-raised',
                )}
              >
                <SeverityBadge severity={sev} />
                <span className="font-mono text-ivory-dim tabular-nums">{counts[sev]}</span>
              </button>
            ))}
            {severityFilter && (
              <button
                onClick={() => setSeverityFilter('')}
                className="text-2xs text-ivory-mute hover:text-ivory ml-1 underline underline-offset-4"
              >
                clear
              </button>
            )}
            <span className="ml-auto text-2xs font-mono text-ivory-mute">
              {visible.length} of {all.length} shown
            </span>
          </div>

          {findingsError ? (
            <ErrorState error={findingsError} />
          ) : !findings ? (
            <LoadingRows rows={3} label="Loading findings" />
          ) : null}

          {findings && all.length === 0 && (
            <div className="pt-12 pb-10 text-center">
              <p className="font-mono text-2xs text-ok mb-1">[ clean ]</p>
              <p className="text-2xs text-ivory-mute">no secrets detected in this source</p>
            </div>
          )}

          {/* Findings grouped by file */}
          <div className="space-y-5">
            {Object.entries(grouped).map(([filePath, fileFindings]) => (
              <section key={filePath}>
                <div className="flex items-center gap-3 py-2">
                  <h2 className="font-mono text-2xs text-ivory truncate">{filePath}</h2>
                  <span className="flex-1 rule" />
                  <span className="text-2xs font-mono text-ivory-mute shrink-0">
                    {fileFindings.length}
                  </span>
                </div>
                <div className="panel overflow-hidden">
                  {fileFindings.map((f, i) => (
                    <FindingRow
                      key={f.id}
                      finding={f}
                      first={i === 0}
                      isOpen={expanded.has(f.id)}
                      onToggle={() => toggle(f.id)}
                    />
                  ))}
                </div>
              </section>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function FindingRow({
  finding: f,
  first,
  isOpen,
  onToggle,
}: {
  finding: Finding
  first: boolean
  isOpen: boolean
  onToggle: () => void
}) {
  const spine = SEV_COLOR[f.severity as Severity] ?? '#888681'
  return (
    <div
      className={clsx(!first && 'border-t border-line/60')}
      style={{ boxShadow: `inset 3px 0 0 ${spine}` }}
    >
      <button
        onClick={onToggle}
        aria-expanded={isOpen}
        className="w-full grid grid-cols-[7rem_1fr_auto_auto] items-center gap-3 pl-4 pr-4 py-2.5 text-left
                   hover:bg-ink-overlay transition-colors"
      >
        <SeverityBadge severity={f.severity} />
        <span className="min-w-0 flex items-baseline gap-3">
          <span className="text-[13px] text-ivory truncate">{f.secret_type}</span>
          <code className="hidden md:inline text-2xs text-ivory-mute truncate">{f.matched_string}</code>
        </span>
        <span className="font-mono text-2xs text-ivory-mute tabular-nums">
          L{f.line_number}
          {f.is_in_history && <span className="ml-2 text-sev-medium" title="Present in git history">◆ history</span>}
        </span>
        <RiskBadge score={f.risk_score} />
      </button>

      {/* Progressive disclosure with a measured grid transition */}
      <div
        className="grid transition-[grid-template-rows] duration-200"
        style={{ gridTemplateRows: isOpen ? '1fr' : '0fr' }}
      >
        {/* invisible when collapsed: out of the tab order and the accessibility tree */}
        <div className={clsx('overflow-hidden', !isOpen && 'invisible')}>
          <div className="px-4 pb-4 pt-1 space-y-4">
            <RiskMeter score={f.risk_score} />

            {f.risk_factors && f.risk_factors.length > 0 && (
              <div>
                <div className="kicker mb-1.5">Contributing factors</div>
                <ul className="space-y-0.5">
                  {f.risk_factors.map((factor) => (
                    <li key={factor} className="text-2xs text-ivory-dim flex gap-2">
                      <span className="text-ivory-mute font-mono">·</span>
                      {factor}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <LifecycleTimeline finding={f} />

            <dl className="space-y-2">
              <Detail term="matched">
                <code className="text-2xs text-ivory bg-ink-inset rounded-sm px-1.5 py-0.5">
                  {f.matched_string}
                </code>
              </Detail>
              <Detail term="entropy">
                <span className="font-mono text-2xs text-ivory-dim">{f.entropy} bits</span>
              </Detail>
              <Detail term="confidence">
                <span className="text-2xs text-ivory-dim lowercase">{f.confidence}</span>
              </Detail>
              {f.commit_hash && (
                <Detail term="commit">
                  <code className="font-mono text-2xs text-ivory-dim">{f.commit_hash.slice(0, 12)}</code>
                </Detail>
              )}
              <Detail term="context">
                <pre className="well text-2xs text-ivory-dim px-3 py-2 overflow-x-auto whitespace-pre-wrap break-all">
                  {f.context}
                </pre>
              </Detail>
            </dl>

            {f.remediation && (
              <div>
                <div className="kicker mb-1.5">Remediation</div>
                <ol className="space-y-1">
                  {f.remediation.split('\n').filter(Boolean).map((step, i) => (
                    <li key={i} className="text-2xs text-ivory-dim flex gap-2">
                      <span className="font-mono text-ok shrink-0">{String(i + 1).padStart(2, '0')}</span>
                      {step.replace(/^\d+\.\s*/, '')}
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function Meta({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2">
      <dt className="kicker">{term}</dt>
      <dd>{children}</dd>
    </div>
  )
}

function Detail({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[6rem_1fr] gap-3 items-start">
      <dt className="kicker pt-0.5">{term}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  )
}

function groupByFile(findings: Finding[]): Record<string, Finding[]> {
  const groups: Record<string, Finding[]> = {}
  for (const f of findings) {
    groups[f.file_path] ??= []
    groups[f.file_path].push(f)
  }
  for (const list of Object.values(groups)) {
    list.sort((a, b) => b.risk_score - a.risk_score)
  }
  return groups
}
