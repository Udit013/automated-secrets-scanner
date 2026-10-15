import { useMemo, useState } from 'react'
import { isAxiosError } from 'axios'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { format, formatDistanceToNowStrict } from 'date-fns'
import { clsx } from 'clsx'
import { getProject, listCredentials, parseUtc, startScan } from '../api/client'
import type { Credential, CredentialStatus, Exposure, Severity } from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'
import { SEV_COLOR, SEV_ORDER } from '../lib/severity'
import { RiskBadge } from '../components/RiskBadge'
import { StatusBadge } from '../components/StatusBadge'
import { TrendChart } from '../components/charts'
import { CredentialStatusBadge, ExposureFacts, ExposureTag, TriageForm } from '../components/credentials'
import { STATUS_LABEL } from '../lib/status'
import { EmptyState, ErrorState, InlineError, LoadingRows, PageHeader, Stat } from '../components/ui'

type StatusFilter = 'needs_action' | CredentialStatus | 'all'

const STATUS_TABS: { id: StatusFilter; label: string }[] = [
  { id: 'needs_action', label: 'Needs action' },
  { id: 'accepted_risk', label: 'Accepted' },
  { id: 'rotated', label: 'Rotated' },
  { id: 'false_positive', label: 'False positive' },
  { id: 'all', label: 'All' },
]

function matchesStatus(c: Credential, f: StatusFilter) {
  if (f === 'all') return true
  if (f === 'needs_action') return c.status === 'open'
  // An overdue waiver needs action, so it leaves the "accepted" tab.
  return c.status === f
}

export function ProjectDetail() {
  const { owner, repo } = useParams<{ owner: string; repo: string }>()
  const slug = `${owner}/${repo}`
  const navigate = useNavigate()
  const qc = useQueryClient()

  const [statusFilter, setStatusFilter] = useState<StatusFilter>('needs_action')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [exposure, setExposure] = useState<Exposure | ''>('')
  const [openFp, setOpenFp] = useState<string | null>(null)
  // Survives the row leaving the current tab after a decision.
  const [lastSaved, setLastSaved] = useState<Credential | null>(null)

  const project = useQuery({
    queryKey: ['project', slug],
    queryFn: () => getProject(slug),
    refetchInterval: (q) =>
      q.state.data?.latest_status === 'running' || q.state.data?.latest_status === 'queued' ? 4000 : false,
  })
  const creds = useQuery({
    queryKey: ['credentials', slug],
    queryFn: () => listCredentials(slug),
    enabled: project.isSuccess,
  })

  const rescan = useMutation({
    mutationFn: () =>
      startScan({
        source_type: 'github',
        source_ref: project.data!.source_ref,
        scan_git_history: project.data!.history_scanned,
      }),
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: ['project', slug] })
      qc.invalidateQueries({ queryKey: ['scans'] })
      navigate(`/history/${scan.id}`)
    },
  })

  const all = useMemo(() => creds.data?.credentials ?? [], [creds.data])
  const tabCounts = useMemo(
    () => Object.fromEntries(STATUS_TABS.map((t) => [t.id, all.filter((c) => matchesStatus(c, t.id)).length])),
    [all],
  ) as Record<StatusFilter, number>
  const visible = all.filter(
    (c) =>
      matchesStatus(c, statusFilter) &&
      (!severity || c.severity === severity) &&
      (!exposure || c.exposure === exposure),
  )

  if (project.isLoading) return <LoadingRows rows={5} label="Loading project" />
  if (project.error) {
    const notFound = isAxiosError(project.error) && project.error.response?.status === 404
    return (
      <div>
        <BackLink />
        {notFound ? (
          <EmptyState title={`${slug} has not been scanned`} action={{ to: '/scan', label: 'Scan a repository' }}>
            Projects appear here after their first GitHub scan.
          </EmptyState>
        ) : (
          <ErrorState error={project.error} onRetry={() => project.refetch()} />
        )}
      </div>
    )
  }
  const p = project.data!
  const s = p.summary
  const inFlight = p.latest_status === 'running' || p.latest_status === 'queued'
  const trend = p.trend.map((t) => ({ date: (t.completed_at ?? '').slice(0, 10), count: t.open }))
  const last = p.trend[p.trend.length - 1]

  return (
    <div>
      <BackLink />
      <PageHeader
        kicker="Credential ledger"
        title={<span className="font-mono text-[19px]">{p.slug}</span>}
        aside={
          <div className="flex flex-wrap items-center gap-2">
            <a href={p.source_ref} target="_blank" rel="noreferrer noopener" className="btn-ghost h-8 text-2xs">
              GitHub ↗
            </a>
            {p.last_scan_id && (
              <Link to={`/history/${p.last_scan_id}`} className="btn-outline h-8 text-2xs">
                Latest report
              </Link>
            )}
            <button
              onClick={() => rescan.mutate()}
              disabled={rescan.isPending || inFlight}
              className="btn-primary h-8 text-2xs"
              title={p.history_scanned ? 'Rescan, including git history' : 'Rescan the current code'}
            >
              {rescan.isPending ? 'Starting…' : inFlight ? 'Scan in progress' : 'Rescan'}
            </button>
          </div>
        }
      >
        {p.last_scanned_at ? (
          <>
            Last scanned {formatDistanceToNowStrict(parseUtc(p.last_scanned_at), { addSuffix: true })} ·{' '}
            {p.files_scanned.toLocaleString()} files · {p.history_scanned ? 'with git history' : 'current code only'}
            {p.schedule && (
              <>
                {' '}· {p.schedule.enabled ? 'scheduled' : 'schedule paused'}{' '}
                <span className="font-mono">{p.schedule.cron_expression}</span> UTC
              </>
            )}
          </>
        ) : (
          'No completed scan yet.'
        )}
      </PageHeader>

      {rescan.error && (
        <div className="pb-4">
          <InlineError error={rescan.error} />
        </div>
      )}

      {inFlight && p.latest_scan_id && (
        <div className="panel px-4 py-3 mb-5 flex items-center justify-between gap-3" role="status">
          <StatusBadge status={p.latest_status!} />
          <Link to={`/history/${p.latest_scan_id}`} className="text-2xs text-ivory-dim hover:text-ivory">
            follow progress →
          </Link>
        </div>
      )}

      {!p.last_scan_id ? (
        <EmptyState title="no completed scan">
          The ledger fills in once a scan of this repository completes.
        </EmptyState>
      ) : (
        <>
          <div className="rule grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 lg:divide-x divide-line">
            <Stat label="open" value={s.open} color={s.open > 0 ? '#ECEAE6' : '#57AB5A'} />
            <Stat
              label="critical open"
              value={s.open_by_severity.CRITICAL ?? 0}
              color={(s.open_by_severity.CRITICAL ?? 0) > 0 ? SEV_COLOR.CRITICAL : undefined}
            />
            <Stat
              label="history only"
              value={s.open_history_only}
              color={s.open_history_only > 0 ? SEV_COLOR.MEDIUM : undefined}
              hint="Open credentials deleted from the code but still readable in git history"
            />
            <Stat label="accepted" value={s.accepted_risk} hint="Accepted risks with a future review date" />
            <Stat label="rotated" value={s.rotated} color={s.rotated > 0 ? '#57AB5A' : undefined} />
            <Stat label="false positive" value={s.false_positive} />
          </div>

          {s.review_overdue > 0 && (
            <p className="rule py-3 text-2xs font-mono text-sev-critical" role="status">
              {s.review_overdue} accepted risk{s.review_overdue === 1 ? ' has' : 's have'} passed the review date and
              reopened.
            </p>
          )}

          {p.trend.length > 1 && (
            <section className="rule pt-5 pb-7">
              <div className="flex flex-wrap items-baseline justify-between gap-2 mb-4">
                <h2 className="kicker">Open credentials per scan</h2>
                {last && (
                  <span className="text-2xs font-mono text-ivory-mute">
                    latest scan:{' '}
                    <span className={last.new > 0 ? 'text-sev-critical' : undefined}>+{last.new} new</span> ·{' '}
                    <span className={last.removed > 0 ? 'text-ok' : undefined}>−{last.removed} gone from code</span>
                  </span>
                )}
              </div>
              <TrendChart points={trend} />
            </section>
          )}

          {/* Filters */}
          <div className="rule pt-4 pb-3 flex flex-wrap items-center gap-x-4 gap-y-3">
            <div className="inline-flex flex-wrap rounded-sm bg-ink-inset p-0.5 border border-line" role="group" aria-label="Filter by status">
              {STATUS_TABS.map((t) => (
                <button
                  key={t.id}
                  aria-pressed={statusFilter === t.id}
                  onClick={() => setStatusFilter(t.id)}
                  className={clsx(
                    'h-7 px-2.5 rounded-[1px] text-2xs font-medium transition-colors',
                    statusFilter === t.id ? 'bg-ink-overlay text-ivory' : 'text-ivory-mute hover:text-ivory-dim',
                  )}
                >
                  {t.label}
                  <span className="ml-1.5 font-mono text-ivory-mute">{tabCounts[t.id]}</span>
                </button>
              ))}
            </div>
            <label className="inline-flex items-center gap-2">
              <span className="kicker">severity</span>
              <select
                className="field h-7 w-28 text-2xs py-0"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity | '')}
              >
                <option value="">any</option>
                {SEV_ORDER.map((sv) => (
                  <option key={sv} value={sv}>{sv.toLowerCase()}</option>
                ))}
              </select>
            </label>
            <label className="inline-flex items-center gap-2">
              <span className="kicker">where</span>
              <select
                className="field h-7 w-36 text-2xs py-0"
                value={exposure}
                onChange={(e) => setExposure(e.target.value as Exposure | '')}
              >
                <option value="">anywhere</option>
                <option value="working_tree">in current code</option>
                <option value="history_only">history only</option>
              </select>
            </label>
            <span className="ml-auto text-2xs font-mono text-ivory-mute">
              {visible.length} of {all.length}
            </span>
          </div>

          <div role="status" aria-live="polite">
            {lastSaved && (
              <p className="mb-3 text-2xs font-mono text-ivory-dim flex flex-wrap items-center gap-x-3">
                <span className="text-ok">✓</span>
                <span>
                  {lastSaved.secret_type} ({lastSaved.masked_value}) marked {STATUS_LABEL[lastSaved.status]}
                </span>
                {!matchesStatus(lastSaved, statusFilter) && (
                  <button
                    className="underline underline-offset-4 hover:text-ivory"
                    onClick={() => {
                      setStatusFilter(lastSaved.status === 'open' ? 'needs_action' : lastSaved.status)
                      setOpenFp(lastSaved.fingerprint)
                    }}
                  >
                    show it
                  </button>
                )}
                <button className="text-ivory-mute hover:text-ivory" onClick={() => setLastSaved(null)} aria-label="Dismiss">
                  ×
                </button>
              </p>
            )}
          </div>

          {creds.isLoading ? (
            <LoadingRows rows={4} label="Loading credentials" />
          ) : creds.error ? (
            <ErrorState error={creds.error} onRetry={() => creds.refetch()} />
          ) : all.length === 0 ? (
            <EmptyState title="clean" tone="ok">
              The latest scan found no credentials in this repository.
            </EmptyState>
          ) : visible.length === 0 ? (
            <EmptyState title={statusFilter === 'needs_action' && !severity && !exposure ? 'nothing needs action' : 'nothing matches these filters'} tone={statusFilter === 'needs_action' ? 'ok' : 'neutral'}>
              {statusFilter === 'needs_action' && !severity && !exposure
                ? 'Every credential in the latest scan has a decision recorded.'
                : 'Try another status tab or clear the filters.'}
            </EmptyState>
          ) : (
            <ul className="panel overflow-hidden">
              {visible.map((c, i) => (
                <CredentialRow
                  key={c.fingerprint}
                  slug={slug}
                  credential={c}
                  first={i === 0}
                  isOpen={openFp === c.fingerprint}
                  onToggle={() => setOpenFp(openFp === c.fingerprint ? null : c.fingerprint)}
                  onSaved={setLastSaved}
                />
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  )
}

function BackLink() {
  return (
    <Link to="/projects" className="inline-block text-2xs text-ivory-mute hover:text-ivory transition-colors mb-2">
      ← projects
    </Link>
  )
}

function CredentialRow({
  slug,
  credential: c,
  first,
  isOpen,
  onToggle,
  onSaved,
}: {
  slug: string
  credential: Credential
  first: boolean
  isOpen: boolean
  onToggle: () => void
  onSaved: (c: Credential) => void
}) {
  const panelId = `cred-${c.fingerprint}`
  const handled = c.status !== 'open'
  return (
    <li
      className={clsx(!first && 'border-t border-line/60')}
      style={{ boxShadow: `inset 3px 0 0 ${handled ? '#26262C' : SEV_COLOR[c.severity]}` }}
    >
      <button
        onClick={onToggle}
        aria-expanded={isOpen}
        aria-controls={panelId}
        className="w-full grid grid-cols-[6.5rem_1fr_auto] md:grid-cols-[6.5rem_1fr_7rem_7.5rem_2.5rem] items-center gap-3 px-4 py-3 text-left hover:bg-ink-overlay transition-colors"
      >
        <span className={clsx(handled && 'opacity-50')}>
          <SeverityBadge severity={c.severity} />
        </span>
        <span className="min-w-0">
          <span className={clsx('block text-[13px] truncate', handled ? 'text-ivory-dim' : 'text-ivory')}>
            {c.secret_type}
            {c.location_count > 1 && (
              <span className="ml-2 text-2xs font-mono text-ivory-mute">× {c.location_count} locations</span>
            )}
          </span>
          <span className="block font-mono text-2xs text-ivory-mute truncate">
            {c.masked_value} · {c.locations[0]?.file_path}
          </span>
        </span>
        <span className="hidden md:block"><ExposureTag exposure={c.exposure} /></span>
        <span className="justify-self-end md:justify-self-start"><CredentialStatusBadge credential={c} /></span>
        <span className="hidden md:block text-right"><RiskBadge score={c.risk_score} /></span>
      </button>

      {isOpen && (
        <div id={panelId} className="px-4 pb-5 pt-1 grid lg:grid-cols-[1fr_22rem] gap-x-8 gap-y-6">
          <div className="space-y-5 min-w-0">
            <div className="md:hidden flex gap-4">
              <ExposureTag exposure={c.exposure} />
              <RiskBadge score={c.risk_score} />
            </div>
            <ExposureFacts credential={c} />

            {c.exposure === 'history_only' && c.status === 'open' && (
              <p className="text-2xs text-sev-medium">
                Deleting the file did not remove this credential: it is still in the repository's history, readable by
                anyone with a clone. Rotate it at the provider; rewriting history is optional cleanup, not the fix.
              </p>
            )}

            <div>
              <div className="kicker mb-1.5">Locations</div>
              <ul className="space-y-1">
                {c.locations.slice(0, 12).map((l, i) => (
                  <li key={i} className="font-mono text-2xs text-ivory-dim flex flex-wrap gap-x-3">
                    <span className="break-all">
                      {l.file_path}:{l.line_number}
                    </span>
                    {l.in_history && (
                      <span className="text-ivory-mute">history{l.commit_hash ? ` @ ${l.commit_hash.slice(0, 8)}` : ''}</span>
                    )}
                  </li>
                ))}
                {c.locations.length > 12 && (
                  <li className="text-2xs text-ivory-mute">+ {c.locations.length - 12} more</li>
                )}
              </ul>
            </div>

            {c.risk_factors.length > 0 && (
              <div>
                <div className="kicker mb-1.5">Why this risk score</div>
                <ul className="space-y-0.5">
                  {c.risk_factors.map((f) => (
                    <li key={f} className="text-2xs text-ivory-dim flex gap-2">
                      <span className="text-ivory-mute font-mono">·</span>
                      {f}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {c.remediation && (
              <div>
                <div className="kicker mb-1.5">Remediation</div>
                <ol className="space-y-1">
                  {c.remediation.split('\n').filter(Boolean).map((step, i) => (
                    <li key={i} className="text-2xs text-ivory-dim flex gap-2">
                      <span className="font-mono text-ok shrink-0">{String(i + 1).padStart(2, '0')}</span>
                      {step.replace(/^\d+\.\s*/, '')}
                    </li>
                  ))}
                </ol>
              </div>
            )}

            {c.rotation_url && (
              <a href={c.rotation_url} target="_blank" rel="noreferrer noopener" className="btn-outline h-7 text-2xs">
                Rotate at the provider ↗
              </a>
            )}

            {c.review_by && c.status === 'accepted_risk' && (
              <p className="text-2xs font-mono text-ivory-mute">
                review by {format(parseUtc(c.review_by), 'MMM d, yyyy')}
              </p>
            )}
          </div>

          <div className="lg:border-l lg:border-line lg:pl-8">
            <TriageForm slug={slug} credential={c} onSaved={onSaved} />
          </div>
        </div>
      )}
    </li>
  )
}
