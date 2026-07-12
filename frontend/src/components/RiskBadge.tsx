export function riskColor(score: number): string {
  if (score >= 80) return '#F2545B'
  if (score >= 55) return '#EE7A3B'
  if (score >= 30) return '#D9A514'
  return '#7E9CC9'
}

export function riskBand(score: number): string {
  if (score >= 80) return 'critical'
  if (score >= 55) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

/** Zero-padded mono score — instrument readout, not a chip. */
export function RiskBadge({ score }: { score: number }) {
  return (
    <span
      className="font-mono text-2xs font-medium tabular-nums"
      style={{ color: riskColor(score) }}
      title={`Exposure risk ${score}/100 (${riskBand(score)})`}
    >
      {String(score).padStart(3, '0')}
    </span>
  )
}

/**
 * Ten-segment exposure meter. Segments fill in the band color; the readout
 * carries the exact value. Reads like hardware, not a donut chart.
 */
export function RiskMeter({ score }: { score: number }) {
  const color = riskColor(score)
  const filled = Math.round(Math.max(0, Math.min(100, score)) / 10)
  return (
    <div className="flex items-center gap-4">
      <div>
        <div className="kicker mb-1.5">Exposure risk</div>
        <div className="flex items-baseline gap-2">
          <span className="font-mono text-[22px] font-medium leading-none tabular-nums" style={{ color }}>
            {score}
          </span>
          <span className="text-2xs font-mono text-ivory-mute">/100</span>
          <span className="text-2xs font-medium uppercase tracking-kicker" style={{ color }}>
            {riskBand(score)}
          </span>
        </div>
      </div>
      <div className="flex gap-[3px]" role="img" aria-label={`Risk ${score} of 100`}>
        {Array.from({ length: 10 }, (_, i) => (
          <span
            key={i}
            className="h-4 w-1.5 rounded-[1px] transition-colors"
            style={{ backgroundColor: i < filled ? color : '#26262C' }}
          />
        ))}
      </div>
    </div>
  )
}
