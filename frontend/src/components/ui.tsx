import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { clsx } from 'clsx'
import { apiErrorMessage } from '../api/client'

/* Shared page furniture: headers and the three non-happy states every data
 * view needs — loading, empty, and error. */

export function PageHeader({
  kicker,
  title,
  children,
  aside,
}: {
  kicker: string
  title: ReactNode
  children?: ReactNode
  aside?: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 pb-5">
      <div className="min-w-0">
        <p className="kicker mb-1">{kicker}</p>
        <h1 className="page-title">{title}</h1>
        {children && <div className="text-2xs text-ivory-mute mt-2 max-w-2xl">{children}</div>}
      </div>
      {aside}
    </div>
  )
}

/** Skeleton rows: the page keeps its shape while data arrives. */
export function LoadingRows({ rows = 4, label = 'Loading' }: { rows?: number; label?: string }) {
  return (
    <div className="rule pt-4 space-y-2.5" role="status" aria-live="polite">
      <span className="sr-only">{label}…</span>
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className="h-9 rounded-sm bg-ink-raised animate-pulse"
          style={{ opacity: 1 - i * (0.6 / rows) }}
          aria-hidden
        />
      ))}
    </div>
  )
}

export function EmptyState({
  title,
  children,
  action,
  tone = 'neutral',
}: {
  title: string
  children?: ReactNode
  action?: { to: string; label: string }
  tone?: 'neutral' | 'ok'
}) {
  return (
    <div className="rule pt-14 pb-12 text-center">
      <p className={clsx('font-mono text-2xs mb-2', tone === 'ok' ? 'text-ok' : 'text-ivory-mute')}>
        [ {title} ]
      </p>
      {children && <p className="text-2xs text-ivory-mute max-w-md mx-auto">{children}</p>}
      {action && (
        <Link to={action.to} className="btn-outline h-7 text-2xs mt-4">
          {action.label}
        </Link>
      )}
    </div>
  )
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div className="rule pt-8 pb-8" role="alert">
      <p className="text-2xs font-mono text-sev-critical">✕ {apiErrorMessage(error)}</p>
      {onRetry && (
        <button onClick={onRetry} className="btn-outline h-7 text-2xs mt-3">
          Try again
        </button>
      )}
    </div>
  )
}

export function InlineError({ error }: { error: unknown }) {
  if (!error) return null
  return (
    <p className="text-2xs font-mono text-sev-critical" role="alert">
      ✕ {apiErrorMessage(error)}
    </p>
  )
}

/** A big measured number with a tracked label beneath. */
export function Stat({
  label,
  value,
  color,
  hint,
}: {
  label: string
  value: number | string
  color?: string
  hint?: string
}) {
  return (
    <div className="py-5 lg:px-6 first:lg:pl-0" title={hint}>
      <div className="numeral" style={color ? { color } : undefined}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      <div className="kicker mt-1.5">{label}</div>
    </div>
  )
}
