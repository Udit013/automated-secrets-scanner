import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { format } from 'date-fns'
import { getStats, getScanDiff } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import { DiffSummary } from '../components/DiffSummary'
import { SeveritySpectrum, TrendChart, RankedTypes } from '../components/charts'
import type { Severity } from '../api/client'

export function Dashboard() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
    refetchInterval: 15_000,
  })

  const latestCompletedId = stats?.recent_scans.find((s) => s.status === 'completed')?.id
  const { data: diff } = useQuery({
    queryKey: ['dashboard-diff', latestCompletedId],
    queryFn: () => getScanDiff(latestCompletedId!),
    enabled: !!latestCompletedId,
  })

  if (isLoading || !stats) {
    return (
      <p className="text-2xs font-mono text-ivory-mute animate-pulse py-12">
        loading overview…
      </p>
    )
  }

  const sevCounts: Record<Severity, number> = {
    CRITICAL: stats.critical_count,
    HIGH: stats.high_count,
    MEDIUM: stats.medium_count,
    LOW: stats.low_count,
  }

  const typeData = Object.entries(stats.by_type)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name, value }))

  return (
    <div>
      {/* Page header */}
      <div className="pb-5">
        <p className="kicker mb-1">Posture</p>
        <h1 className="page-title">Overview</h1>
      </div>

      {/* Stat strip — one measured line, hairline-separated */}
      <div className="rule grid grid-cols-2 lg:grid-cols-4 lg:divide-x divide-line">
        <Stat label="scans" value={stats.total_scans} />
        <Stat label="findings" value={stats.total_findings} />
        <Stat
          label="critical"
          value={stats.critical_count}
          color={stats.critical_count > 0 ? '#F2545B' : undefined}
        />
        <Stat
          label="high"
          value={stats.high_count}
          color={stats.high_count > 0 ? '#EE7A3B' : undefined}
        />
      </div>

      {/* Severity spectrum */}
      <section className="rule pt-5 pb-7">
        <h2 className="kicker mb-3">Severity distribution</h2>
        <SeveritySpectrum counts={sevCounts} />
      </section>

      {/* Trend + ranking */}
      <div className="rule grid grid-cols-1 lg:grid-cols-5 gap-x-10">
        <section className="lg:col-span-3 pt-5 pb-7">
          <h2 className="kicker mb-4">Findings over time</h2>
          <TrendChart points={stats.findings_over_time} />
        </section>
        <section className="pt-5 pb-7 lg:col-span-2 lg:border-l lg:border-line lg:pl-10">
          <h2 className="kicker mb-4">Most detected</h2>
          <RankedTypes data={typeData} />
        </section>
      </div>

      {/* Latest movement */}
      {diff?.has_baseline && (
        <section className="rule pt-5 pb-7">
          <DiffSummary diff={diff} />
        </section>
      )}

      {/* Activity ledger */}
      <section className="rule pt-5">
        <div className="flex items-baseline justify-between mb-3">
          <h2 className="kicker">Recent activity</h2>
          <Link to="/history" className="text-2xs text-ivory-mute hover:text-ivory transition-colors">
            all scans →
          </Link>
        </div>
        {stats.recent_scans.length === 0 ? (
          <EmptyLedger />
        ) : (
          <table className="ledger-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Status</th>
                <th className="!text-right">Findings</th>
                <th className="!text-right">When</th>
              </tr>
            </thead>
            <tbody>
              {stats.recent_scans.slice(0, 6).map((s) => (
                <tr key={s.id}>
                  <td className="max-w-[320px]">
                    <Link
                      to={`/history/${s.id}`}
                      className="block truncate font-mono text-2xs text-ivory-dim hover:text-ivory transition-colors"
                      title={s.source_ref}
                    >
                      {shortRef(s.source_ref)}
                    </Link>
                  </td>
                  <td><StatusBadge status={s.status} /></td>
                  <td className="text-right">
                    <span
                      className="font-mono text-2xs tabular-nums"
                      style={{ color: s.total_findings > 0 ? '#ECEAE6' : '#66645F' }}
                    >
                      {s.total_findings}
                    </span>
                  </td>
                  <td className="text-right font-mono text-2xs text-ivory-mute whitespace-nowrap">
                    {format(new Date(s.created_at), 'MMM d · HH:mm')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}

function Stat({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div className="py-5 lg:px-6 first:lg:pl-0">
      <div className="numeral" style={color ? { color } : undefined}>
        {value.toLocaleString()}
      </div>
      <div className="kicker mt-1.5">{label}</div>
    </div>
  )
}

function EmptyLedger() {
  return (
    <div className="py-10 text-center">
      <p className="font-mono text-2xs text-ivory-mute mb-2">[ no scans recorded ]</p>
      <Link to="/scan" className="text-2xs text-ivory-dim hover:text-ivory underline underline-offset-4">
        run the first scan
      </Link>
    </div>
  )
}

function shortRef(ref: string): string {
  const cleaned = ref.replace('https://github.com/', '')
  return cleaned.length > 48 ? cleaned.slice(0, 48) + '…' : cleaned
}
