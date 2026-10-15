import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { formatDistanceToNowStrict } from 'date-fns'
import { listProjects, parseUtc } from '../api/client'
import type { Project, Severity } from '../api/client'
import { SEV_COLOR, SEV_ORDER } from '../lib/severity'
import { StatusBadge } from '../components/StatusBadge'
import { EmptyState, ErrorState, LoadingRows, PageHeader } from '../components/ui'

/**
 * Every GitHub repository ever scanned, ordered by what needs a human
 * first: open critical credentials, then open high, then any open.
 */
export function Projects() {
  const { data: projects, isLoading, error, refetch } = useQuery({
    queryKey: ['projects'],
    queryFn: listProjects,
    refetchInterval: 30_000,
  })
  const navigate = useNavigate()

  return (
    <div>
      <PageHeader
        kicker="Inventory"
        title="Projects"
        aside={
          <Link to="/scan" className="btn-outline h-8">
            Scan a repository
          </Link>
        }
      >
        One row per repository. Counts are credentials, not lines: the same key copied into five
        files is one thing to rotate.
      </PageHeader>

      {isLoading ? (
        <LoadingRows rows={4} label="Loading projects" />
      ) : error ? (
        <ErrorState error={error} onRetry={() => refetch()} />
      ) : !projects || projects.length === 0 ? (
        <EmptyState title="no repositories yet" action={{ to: '/scan', label: 'Scan a repository' }}>
          Scan a public GitHub repository to start its credential ledger. Pasted snippets are
          one-off checks and don't create projects.
        </EmptyState>
      ) : (
        <div className="rule overflow-x-auto">
          <table className="ledger-table min-w-[720px]">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Open credentials</th>
                <th className="!text-right">History only</th>
                <th className="!text-right">Handled</th>
                <th>Last scan</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((p) => (
                <tr
                  key={p.slug}
                  className="group cursor-pointer"
                  onClick={() => navigate(`/projects/${p.slug}`)}
                >
                  <td>
                    <Link
                      to={`/projects/${p.slug}`}
                      className="font-mono text-2xs text-ivory-dim group-hover:text-ivory transition-colors"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {p.slug}
                    </Link>
                    {p.summary.review_overdue > 0 && (
                      <span className="ml-2 text-2xs font-mono text-sev-critical">
                        {p.summary.review_overdue} review overdue
                      </span>
                    )}
                  </td>
                  <td>
                    <OpenBreakdown project={p} />
                  </td>
                  <td className="text-right font-mono text-2xs tabular-nums">
                    <span className={p.summary.open_history_only > 0 ? 'text-sev-medium' : 'text-ivory-mute'}>
                      {p.summary.open_history_only}
                    </span>
                  </td>
                  <td className="text-right font-mono text-2xs tabular-nums text-ivory-mute">
                    {p.summary.rotated + p.summary.false_positive + p.summary.accepted_risk}
                    <span className="text-ivory-faint"> / {p.summary.total}</span>
                  </td>
                  <td className="whitespace-nowrap">
                    <span className="inline-flex items-center gap-3">
                      {p.latest_status && p.latest_status !== 'completed' ? (
                        <StatusBadge status={p.latest_status} />
                      ) : (
                        <span className="font-mono text-2xs text-ivory-mute">
                          {p.last_scanned_at
                            ? formatDistanceToNowStrict(parseUtc(p.last_scanned_at), { addSuffix: true })
                            : 'never completed'}
                        </span>
                      )}
                      {p.schedule?.enabled && (
                        <span className="text-2xs font-mono text-ivory-mute" title={`Scheduled: ${p.schedule.cron_expression} (UTC)`}>
                          ↻ scheduled
                        </span>
                      )}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function OpenBreakdown({ project: p }: { project: Project }) {
  const { open, open_by_severity } = p.summary
  if (open === 0) {
    return <span className="font-mono text-2xs text-ok">{p.summary.total === 0 ? 'clean' : 'all handled'}</span>
  }
  const present = SEV_ORDER.filter((s) => (open_by_severity[s] ?? 0) > 0)
  return (
    <span className="inline-flex items-center gap-3">
      <span className="font-mono text-2xs text-ivory tabular-nums w-6">{open}</span>
      <span className="flex h-1.5 w-24 gap-[2px] overflow-hidden rounded-full" aria-hidden>
        {present.map((s) => (
          <span
            key={s}
            style={{ width: `${((open_by_severity[s] ?? 0) / open) * 100}%`, backgroundColor: SEV_COLOR[s] }}
          />
        ))}
      </span>
      <span className="text-2xs font-mono text-ivory-mute">
        {present.map((s: Severity) => `${open_by_severity[s]} ${s.toLowerCase()}`).join(' · ')}
      </span>
    </span>
  )
}
