import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { format } from 'date-fns'
import { getStats, listProjects, parseUtc, shortRef } from '../api/client'
import type { Severity } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import { SEV_COLOR, SEV_ORDER } from '../lib/severity'
import { SeveritySpectrum, TrendChart, RankedTypes } from '../components/charts'
import { EmptyState, ErrorState, LoadingRows, PageHeader, Stat } from '../components/ui'

export function Dashboard() {
  const stats = useQuery({ queryKey: ['stats'], queryFn: getStats, refetchInterval: 15_000 })
  const projects = useQuery({ queryKey: ['projects'], queryFn: listProjects, refetchInterval: 30_000 })

  if (stats.isLoading) return <LoadingRows rows={6} label="Loading overview" />
  if (stats.error) return <ErrorState error={stats.error} onRetry={() => stats.refetch()} />
  const st = stats.data!
  const ex = st.exposure ?? { projects: 0, open: 0, open_history_only: 0, open_by_severity: {}, review_overdue: 0 }

  if (st.total_scans === 0) {
    return (
      <div>
        <PageHeader kicker="Posture" title="Overview" />
        <EmptyState title="no scans yet" action={{ to: '/scan', label: 'Run the first scan' }}>
          Scan a public GitHub repository to build its credential ledger, or paste a snippet for a one-off check.
        </EmptyState>
      </div>
    )
  }

  const openBySev = Object.fromEntries(SEV_ORDER.map((s) => [s, ex.open_by_severity[s] ?? 0])) as Record<
    Severity,
    number
  >
  const attention = (projects.data ?? []).filter((p) => p.summary.open > 0 || p.summary.review_overdue > 0).slice(0, 5)
  const typeData = Object.entries(st.by_type)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name, value }))

  return (
    <div>
      <PageHeader kicker="Posture" title="Overview">
        Open means detected and not yet rotated, dismissed, or accepted. Each credential counts once, however many
        files or commits it appears in.
      </PageHeader>

      <div className="rule grid grid-cols-2 lg:grid-cols-5 lg:divide-x divide-line">
        <Stat label="open credentials" value={ex.open} color={ex.open === 0 ? '#57AB5A' : undefined} />
        <Stat
          label="critical open"
          value={openBySev.CRITICAL}
          color={openBySev.CRITICAL > 0 ? SEV_COLOR.CRITICAL : undefined}
        />
        <Stat
          label="history only"
          value={ex.open_history_only}
          color={ex.open_history_only > 0 ? SEV_COLOR.MEDIUM : undefined}
          hint="Deleted from the code, still readable in git history"
        />
        <Stat
          label="reviews overdue"
          value={ex.review_overdue}
          color={ex.review_overdue > 0 ? SEV_COLOR.CRITICAL : undefined}
        />
        <Stat label="projects" value={ex.projects} />
      </div>

      <section className="rule pt-5 pb-7">
        <h2 className="kicker mb-3">Open credentials by severity</h2>
        {ex.open === 0 ? (
          <p className="text-2xs font-mono text-ok">nothing open: every detected credential has a decision</p>
        ) : (
          <SeveritySpectrum counts={openBySev} />
        )}
      </section>

      <section className="rule pt-5 pb-7">
        <div className="flex items-baseline justify-between mb-3">
          <h2 className="kicker">Needs attention</h2>
          <Link to="/projects" className="text-2xs text-ivory-mute hover:text-ivory transition-colors">
            all projects →
          </Link>
        </div>
        {projects.isLoading ? (
          <LoadingRows rows={2} />
        ) : projects.error ? (
          <ErrorState error={projects.error} onRetry={() => projects.refetch()} />
        ) : attention.length === 0 ? (
          <p className="text-2xs font-mono text-ivory-mute">
            {(projects.data ?? []).length === 0 ? 'no repositories scanned yet' : 'every project is handled'}
          </p>
        ) : (
          <ul className="divide-y divide-line/60">
            {attention.map((p) => (
              <li key={p.slug}>
                <Link
                  to={`/projects/${p.slug}`}
                  className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2.5 hover:bg-ink-raised -mx-2 px-2 rounded-sm transition-colors"
                >
                  <span className="font-mono text-2xs text-ivory flex-1 min-w-[10rem] truncate">{p.slug}</span>
                  {SEV_ORDER.filter((s) => (p.summary.open_by_severity[s] ?? 0) > 0).map((s) => (
                    <span key={s} className="text-2xs font-mono" style={{ color: SEV_COLOR[s] }}>
                      {p.summary.open_by_severity[s]} {s.toLowerCase()}
                    </span>
                  ))}
                  {p.summary.open_history_only > 0 && (
                    <span className="text-2xs font-mono text-ivory-mute">{p.summary.open_history_only} history-only</span>
                  )}
                  {p.summary.review_overdue > 0 && (
                    <span className="text-2xs font-mono text-sev-critical">{p.summary.review_overdue} overdue</span>
                  )}
                  <span className="text-2xs text-ivory-mute">→</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="rule grid grid-cols-1 lg:grid-cols-5 gap-x-10">
        <section className="lg:col-span-3 pt-5 pb-7">
          <h2 className="kicker mb-4">Detections per day (raw lines)</h2>
          <TrendChart points={st.findings_over_time} />
        </section>
        <section className="pt-5 pb-7 lg:col-span-2 lg:border-l lg:border-line lg:pl-10">
          <h2 className="kicker mb-4">Most detected types</h2>
          <RankedTypes data={typeData} />
        </section>
      </div>

      <section className="rule pt-5">
        <div className="flex items-baseline justify-between mb-3">
          <h2 className="kicker">Recent activity</h2>
          <Link to="/history" className="text-2xs text-ivory-mute hover:text-ivory transition-colors">
            all scans →
          </Link>
        </div>
        <div className="overflow-x-auto">
          <table className="ledger-table min-w-[520px]">
            <thead>
              <tr>
                <th>Source</th>
                <th>Status</th>
                <th className="!text-right">Findings</th>
                <th className="!text-right">When</th>
              </tr>
            </thead>
            <tbody>
              {st.recent_scans.slice(0, 6).map((s) => (
                <tr key={s.id}>
                  <td className="max-w-[320px]">
                    <Link
                      to={`/history/${s.id}`}
                      className="block truncate font-mono text-2xs text-ivory-dim hover:text-ivory transition-colors"
                      title={s.source_ref}
                    >
                      {s.source_type === 'paste' ? 'pasted snippet' : shortRef(s.source_ref)}
                    </Link>
                  </td>
                  <td>
                    <StatusBadge status={s.status} />
                  </td>
                  <td className="text-right">
                    <span className={`font-mono text-2xs tabular-nums ${s.total_findings > 0 ? 'text-ivory' : 'text-ivory-mute'}`}>
                      {s.total_findings}
                    </span>
                  </td>
                  <td className="text-right font-mono text-2xs text-ivory-mute whitespace-nowrap">
                    {format(parseUtc(s.created_at), 'MMM d · HH:mm')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
