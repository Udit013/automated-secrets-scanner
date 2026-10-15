import { useEffect, useMemo, useRef, useState } from 'react'
import { SEV_COLOR, SEV_ORDER } from '../lib/severity'
import type { Severity } from '../api/client'

/* Hand-built chart primitives. One series each, ink-and-ivory marks,
 * severity hues appear only in the spectrum bar where they mean severity. */

/** Stacked severity spectrum: one bar, 2px gaps, direct labels below. */
export function SeveritySpectrum({
  counts,
}: {
  counts: Record<Severity, number>
}) {
  const total = SEV_ORDER.reduce((n, s) => n + counts[s], 0)
  if (total === 0) {
    return <p className="text-2xs font-mono text-ivory-mute">no findings recorded</p>
  }
  return (
    <div>
      <div className="flex h-5 gap-[2px] rounded-sm overflow-hidden">
        {SEV_ORDER.filter((s) => counts[s] > 0).map((s) => (
          <div
            key={s}
            className="transition-[width] duration-500"
            style={{
              width: `${(counts[s] / total) * 100}%`,
              backgroundColor: SEV_COLOR[s],
            }}
            title={`${s}: ${counts[s]}`}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-5 gap-y-1 mt-2.5">
        {SEV_ORDER.map((s) => (
          <span key={s} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-[1px]" style={{ backgroundColor: SEV_COLOR[s] }} />
            <span className="text-2xs uppercase tracking-kicker text-ivory-dim">{s.toLowerCase()}</span>
            <span className="text-2xs font-mono text-ivory">{counts[s]}</span>
          </span>
        ))}
      </div>
    </div>
  )
}

/**
 * Findings-over-time as a stepped line in ivory with a soft area fill,
 * baseline only, crosshair + tooltip on hover. 260×72 viewBox scales to
 * its container.
 */
export function TrendChart({ points }: { points: { date: string; count: number }[] }) {
  const [hover, setHover] = useState<number | null>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const boxRef = useRef<HTMLDivElement>(null)

  // Draw in the container's real pixel width, so the line spans the column
  // at any size without stretching the markers.
  const [W, setW] = useState(560)
  const empty = points.length === 0
  useEffect(() => {
    const el = boxRef.current
    if (!el || empty) return
    const ro = new ResizeObserver(([entry]) => setW(Math.max(120, Math.round(entry.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [empty])
  const H = 120
  const PAD_Y = 10

  const { path, area, xs, ys, max } = useMemo(() => {
    const max = Math.max(1, ...points.map((p) => p.count))
    const stepX = points.length > 1 ? W / (points.length - 1) : W
    const xs = points.map((_, i) => i * stepX)
    const ys = points.map((p) => H - PAD_Y - (p.count / max) * (H - PAD_Y * 2))
    // Stepped path: horizontal run then vertical rise, like a monitoring tool.
    let d = `M ${xs[0]} ${ys[0]}`
    for (let i = 1; i < points.length; i++) {
      const midX = (xs[i - 1] + xs[i]) / 2
      d += ` L ${midX} ${ys[i - 1]} L ${midX} ${ys[i]} L ${xs[i]} ${ys[i]}`
    }
    const area = `${d} L ${xs[xs.length - 1]} ${H} L ${xs[0]} ${H} Z`
    return { path: d, area, xs, ys, max }
  }, [points, W])

  if (points.length === 0) {
    return <p className="text-2xs font-mono text-ivory-mute">no scan activity yet</p>
  }

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = svgRef.current!.getBoundingClientRect()
    const x = ((e.clientX - rect.left) / rect.width) * W
    let best = 0
    for (let i = 1; i < xs.length; i++) if (Math.abs(xs[i] - x) < Math.abs(xs[best] - x)) best = i
    setHover(best)
  }

  const h = hover
  return (
    <div className="relative" ref={boxRef}>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        className="w-full h-[120px] block"
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
        role="img"
        aria-label={`Findings per day, peaking at ${max}`}
      >
        {/* baseline only — no grid cage */}
        <line x1="0" y1={H - 0.5} x2={W} y2={H - 0.5} stroke="#26262C" />
        <path d={area} fill="#ECEAE6" opacity="0.06" />
        <path d={path} fill="none" stroke="#ECEAE6" strokeWidth="1.5" />
        {/* last point always marked with its value */}
        <circle cx={xs[xs.length - 1]} cy={ys[ys.length - 1]} r="3" fill="#ECEAE6" />
        {h != null && (
          <g>
            <line x1={xs[h]} y1="0" x2={xs[h]} y2={H} stroke="#3B3B44" strokeDasharray="3 3" />
            <circle cx={xs[h]} cy={ys[h]} r="3.5" fill="#101014" stroke="#ECEAE6" strokeWidth="1.5" />
          </g>
        )}
      </svg>
      {h != null && (
        <div
          className="pointer-events-none absolute -top-1 -translate-x-1/2 -translate-y-full
                     bg-ink-overlay border border-line-strong rounded-sm px-2 py-1 whitespace-nowrap"
          style={{ left: `${(xs[h] / W) * 100}%` }}
        >
          <span className="text-2xs font-mono text-ivory">{points[h].count}</span>
          <span className="text-2xs font-mono text-ivory-mute"> · {points[h].date.slice(5)}</span>
        </div>
      )}
      <div className="flex justify-between mt-1.5">
        <span className="text-2xs font-mono text-ivory-mute">{points[0].date.slice(5)}</span>
        <span className="text-2xs font-mono text-ivory-mute">{points[points.length - 1].date.slice(5)}</span>
      </div>
    </div>
  )
}

/** Ranked magnitude list: rank, name, measured ivory bar, mono count. */
export function RankedTypes({ data }: { data: { name: string; value: number }[] }) {
  if (data.length === 0) {
    return <p className="text-2xs font-mono text-ivory-mute">no findings recorded</p>
  }
  const max = Math.max(...data.map((d) => d.value))
  return (
    <ol className="space-y-2">
      {data.map((d, i) => (
        <li key={d.name} className="grid grid-cols-[1.5rem_11rem_1fr_2rem] items-center gap-2">
          <span className="text-2xs font-mono text-ivory-mute">{String(i + 1).padStart(2, '0')}</span>
          <span className="text-2xs text-ivory-dim truncate" title={d.name}>{d.name}</span>
          <span className="h-[3px] rounded-full bg-line">
            <span
              className="block h-full rounded-full bg-ivory transition-[width] duration-500"
              style={{ width: `${(d.value / max) * 100}%` }}
            />
          </span>
          <span className="text-2xs font-mono text-ivory text-right tabular-nums">{d.value}</span>
        </li>
      ))}
    </ol>
  )
}
