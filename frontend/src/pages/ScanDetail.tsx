import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { format } from 'date-fns'
import { getScan, getFindings, getScanDiff, exportUrl } from '../api/client'
import { SeverityBadge, SEV_COLOR, SEV_ORDER } from '../components/SeverityBadge'
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

  const { data: scan } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => getScan(id!),
    refetchInterval: (q) => (q.state.data?.status === 'running' ? 3000 : false),
    enabled: !!id,
  })

  const { data: findings } = useQuery({
    queryKey: ['findings', id],
    queryFn: () => getFindings(id!, { limit: 500 }),
    enabled: !!id && scan?.status === 'completed',
  })

  const { data: diff } = useQuery({
    queryKey: ['diff', id],
    queryFn: () => getScanDiff(id!),
    enabled: !!id && scan?.status === 'completed',
  })

  if (!scan) {
    return <p className="text-2xs font-mono text-ivory-mute animate-pulse py-12">loading report…</p>
  }

  const toggle = (fid: string) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(fid) ? next.delete(fid) : next.add(fid)
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
              {scan.source_ref.replace('https://github.com/', '')}
            </h1>
          </div>
          <div className="flex items-center gap-1">
            <span className="kicker mr-2">export</span>
            {EXPORTS.map(({ fmt, label }) => (
              <a key={fmt} href={exportUrl(id!, fmt)} download className="btn-outline h-7 px-2.5 text-2xs">
                {label}
              </a>
            ))}
          </div>
        </div>

        {/* Meta line */}
        <dl className="flex flex-wrap gap-x-8 gap-y-1 mt-4">
          <Meta term="status"><StatusBadge status={scan.status} /></Meta>
          <Meta term="files">
            <span className="font-mono text-2xs text-ivory-dim tabular-nums">{scan.files_scanned}</span>
          </Meta>
          <Meta term="completed">
            <span className="font-mono text-2xs text-ivory-dim">
              {scan.completed_at ? format(new Date(scan.completed_at), 'MMM d, yyyy · HH:mm') : '—'}
            </span>
          </Meta>
          <Meta term="id">
            <span className="font-mono text-2xs text-ivory-mute">{scan.id.slice(0, 8)}</span>
          </Meta>
        </dl>
      </div>

      {scan.status === 'running' && (
        <div className="rule pt-8 pb-10 text-center">
          <p className="font-mono text-2xs text-ivory-dim mb-3">scanning… {scan.progress}%</p>
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
          <p className="text-2xs font-mono text-sev-critical">scan failed — {scan.error_message}</p>
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

          {all.length === 0 && (
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
  const spine = SEV_COLOR[f.severity as Severity] ?? '#66645F'
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
        <div className="overflow-hidden">
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
    ;(groups[f.file_path] ??= []).push(f)
  }
  for (const list of Object.values(groups)) {
    list.sort((a, b) => b.risk_score - a.risk_score)
  }
  return groups
}
