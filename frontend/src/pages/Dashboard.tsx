import { useQuery } from '@tanstack/react-query'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, CartesianGrid, Legend,
} from 'recharts'
import { getStats, getScanDiff } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import { DiffSummary } from '../components/DiffSummary'
import { format } from 'date-fns'
import { ShieldAlert, AlertTriangle, Info, Scan } from 'lucide-react'
import type { Severity } from '../api/client'

const SEV_COLORS: Record<Severity, string> = {
  CRITICAL: '#F85149',
  HIGH: '#FF7B72',
  MEDIUM: '#D29922',
  LOW: '#3FB950',
}

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
      <div className="flex items-center justify-center h-48 text-gray-500 animate-pulse">
        Loading dashboard…
      </div>
    )
  }

  const severityData = [
    { name: 'CRITICAL', value: stats.critical_count, color: SEV_COLORS.CRITICAL },
    { name: 'HIGH', value: stats.high_count, color: SEV_COLORS.HIGH },
    { name: 'MEDIUM', value: stats.medium_count, color: SEV_COLORS.MEDIUM },
    { name: 'LOW', value: stats.low_count, color: SEV_COLORS.LOW },
  ]

  const typeData = Object.entries(stats.by_type)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, value]) => ({ name, value }))

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-white">Dashboard</h1>

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard icon={<Scan size={18} />} label="Total Scans" value={stats.total_scans} color="text-brand-500" />
        <KpiCard icon={<ShieldAlert size={18} />} label="Critical" value={stats.critical_count} color="text-[#F85149]" />
        <KpiCard icon={<AlertTriangle size={18} />} label="High" value={stats.high_count} color="text-[#FF7B72]" />
        <KpiCard icon={<Info size={18} />} label="Total Findings" value={stats.total_findings} color="text-gray-300" />
      </div>

      {/* Differential summary for the latest scan */}
      {diff?.has_baseline && <DiffSummary diff={diff} compact />}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity pie chart */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-400 mb-4">Severity Breakdown</h2>
          {stats.total_findings === 0 ? (
            <p className="text-gray-600 text-sm text-center py-8">No findings yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={severityData.filter((d) => d.value > 0)}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                  labelLine={false}
                >
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151' }}
                  labelStyle={{ color: '#9ca3af' }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Findings over time */}
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-400 mb-4">Findings Over Time</h2>
          {stats.findings_over_time.length === 0 ? (
            <p className="text-gray-600 text-sm text-center py-8">No data yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={stats.findings_over_time}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis
                  dataKey="date"
                  tick={{ fill: '#6b7280', fontSize: 11 }}
                  tickFormatter={(v) => v.slice(5)}
                />
                <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151' }}
                />
                <Line type="monotone" dataKey="count" stroke="#0ea5e9" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Secret type distribution */}
      {typeData.length > 0 && (
        <div className="card">
          <h2 className="text-sm font-semibold text-gray-400 mb-4">Top Secret Types</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={typeData} layout="vertical">
              <XAxis type="number" allowDecimals={false} tick={{ fill: '#6b7280', fontSize: 11 }} />
              <YAxis type="category" dataKey="name" width={180} tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151' }}
              />
              <Bar dataKey="value" fill="#0ea5e9" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent scans */}
      <div className="card">
        <h2 className="text-sm font-semibold text-gray-400 mb-3">Recent Scans</h2>
        {stats.recent_scans.length === 0 ? (
          <p className="text-gray-600 text-sm">No scans yet. <a href="/scan" className="text-brand-400 hover:underline">Start one →</a></p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-2 pr-4 font-medium">Source</th>
                <th className="pb-2 pr-4 font-medium">Status</th>
                <th className="pb-2 pr-4 font-medium">Findings</th>
                <th className="pb-2 font-medium">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {stats.recent_scans.map((s) => (
                <tr key={s.id} className="hover:bg-gray-800/30">
                  <td className="py-2 pr-4 text-gray-300 truncate max-w-[200px]">
                    <a href={`/history/${s.id}`} className="hover:text-brand-400 transition-colors">
                      {s.source_ref.length > 40 ? s.source_ref.slice(0, 40) + '…' : s.source_ref}
                    </a>
                  </td>
                  <td className="py-2 pr-4"><StatusBadge status={s.status} /></td>
                  <td className="py-2 pr-4 text-gray-300">{s.total_findings}</td>
                  <td className="py-2 text-gray-500 text-xs">
                    {format(new Date(s.created_at), 'MMM d, HH:mm')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function KpiCard({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode
  label: string
  value: number
  color: string
}) {
  return (
    <div className="card flex items-center gap-4">
      <div className={`${color} opacity-80`}>{icon}</div>
      <div>
        <div className="text-2xl font-bold text-white">{value.toLocaleString()}</div>
        <div className="text-xs text-gray-500">{label}</div>
      </div>
    </div>
  )
}
