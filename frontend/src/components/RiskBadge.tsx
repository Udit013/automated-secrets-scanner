import { clsx } from 'clsx'

export function riskColor(score: number): string {
  if (score >= 80) return '#F85149' // critical
  if (score >= 55) return '#FF7B72' // high
  if (score >= 30) return '#D29922' // medium
  return '#3FB950' // low
}

export function riskBand(score: number): string {
  if (score >= 80) return 'Critical'
  if (score >= 55) return 'High'
  if (score >= 30) return 'Medium'
  return 'Low'
}

/** Compact inline chip, e.g. in finding rows. */
export function RiskBadge({ score }: { score: number }) {
  const color = riskColor(score)
  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-mono font-semibold border"
      style={{ color, borderColor: `${color}55`, backgroundColor: `${color}15` }}
      title={`Exposure risk: ${riskBand(score)}`}
    >
      {score}
    </span>
  )
}

/** Large radial-style meter for the finding detail view. */
export function RiskMeter({ score }: { score: number }) {
  const color = riskColor(score)
  const pct = Math.max(0, Math.min(100, score))
  return (
    <div className="flex items-center gap-4">
      <div
        className="relative h-20 w-20 rounded-full flex items-center justify-center"
        style={{ background: `conic-gradient(${color} ${pct * 3.6}deg, #21262D 0deg)` }}
      >
        <div className="h-[60px] w-[60px] rounded-full bg-gray-900 flex flex-col items-center justify-center">
          <span className="text-lg font-bold font-mono" style={{ color }}>
            {score}
          </span>
          <span className="text-[9px] text-gray-500 -mt-0.5">/100</span>
        </div>
      </div>
      <div>
        <div className="text-xs text-gray-500 mb-0.5">Exposure Risk</div>
        <div
          className={clsx('text-sm font-semibold')}
          style={{ color }}
        >
          {riskBand(score)}
        </div>
      </div>
    </div>
  )
}
