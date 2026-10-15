import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { format, formatDistanceToNowStrict } from 'date-fns'
import { clsx } from 'clsx'
import { parseUtc, triageCredential } from '../api/client'
import type { Credential, CredentialStatus, Exposure } from '../api/client'
import { InlineError } from './ui'
import { STATUS_LABEL } from '../lib/status'

const STATUS_META: Record<CredentialStatus, { label: string; dot: string; text: string; help: string }> = {
  open: {
    label: STATUS_LABEL.open,
    dot: 'bg-sev-critical',
    text: 'text-ivory',
    help: 'Not yet handled. Treat the credential as compromised.',
  },
  rotated: {
    label: STATUS_LABEL.rotated,
    dot: 'bg-ok',
    text: 'text-ok',
    help: 'Revoked at the provider and replaced. Copies left in code are inert.',
  },
  false_positive: {
    label: STATUS_LABEL.false_positive,
    dot: 'bg-ivory-mute',
    text: 'text-ivory-mute',
    help: 'Not a real credential: a fixture, an example, or a mis-match.',
  },
  accepted_risk: {
    label: STATUS_LABEL.accepted_risk,
    dot: 'bg-sev-medium',
    text: 'text-sev-medium',
    help: 'Known and tolerated until a review date, then it reopens on its own.',
  },
}

export function CredentialStatusBadge({ credential: c }: { credential: Credential }) {
  // An expired waiver reads "open" with the reason beside it.
  if (c.review_overdue) {
    return (
      <span className="inline-flex items-center gap-1.5 text-2xs font-mono whitespace-nowrap">
        <span className="h-1.5 w-1.5 rounded-full bg-sev-critical" aria-hidden />
        <span className="text-sev-critical">review overdue</span>
      </span>
    )
  }
  const meta = STATUS_META[c.status]
  return (
    <span className="inline-flex items-center gap-1.5 text-2xs font-mono whitespace-nowrap" title={meta.help}>
      <span className={clsx('h-1.5 w-1.5 rounded-full', meta.dot)} aria-hidden />
      <span className={meta.text}>{meta.label}</span>
    </span>
  )
}

export function ExposureTag({ exposure }: { exposure: Exposure }) {
  return exposure === 'history_only' ? (
    <span
      className="text-2xs font-mono text-sev-medium whitespace-nowrap"
      title="Deleted from the current code but still in git history: anyone with a clone can read it."
    >
      ◆ history only
    </span>
  ) : (
    <span className="text-2xs font-mono text-ivory-mute whitespace-nowrap" title="Present in the current code">
      ● in code
    </span>
  )
}

const DAY = 86_400_000

function isoDate(d: Date) {
  return d.toISOString().slice(0, 10)
}

/**
 * The decision form for one credential. Accepting a risk requires a review
 * date within a year, enforced by the API, so a waiver can't silently
 * become permanent.
 */
export function TriageForm({
  slug,
  credential: c,
  onSaved,
}: {
  slug: string
  credential: Credential
  onSaved?: (saved: Credential) => void
}) {
  const qc = useQueryClient()
  const [status, setStatus] = useState<CredentialStatus>(c.review_overdue ? 'accepted_risk' : c.stored_status)
  const [note, setNote] = useState(c.note)
  const [reviewBy, setReviewBy] = useState(
    c.review_by && !c.review_overdue ? c.review_by.slice(0, 10) : isoDate(new Date(Date.now() + 30 * DAY)),
  )
  const [saved, setSaved] = useState(false)

  const mutation = useMutation({
    mutationFn: () =>
      triageCredential(slug, c.fingerprint, {
        status,
        note: note.trim(),
        // End of the chosen day, UTC, so "review by the 14th" includes the 14th.
        review_by: status === 'accepted_risk' ? `${reviewBy}T23:59:59Z` : null,
      }),
    onSuccess: (updated) => {
      setSaved(true)
      onSaved?.(updated)
      setTimeout(() => setSaved(false), 2500)
      qc.invalidateQueries({ queryKey: ['credentials', slug] })
      qc.invalidateQueries({ queryKey: ['project', slug] })
      qc.invalidateQueries({ queryKey: ['projects'] })
      qc.invalidateQueries({ queryKey: ['stats'] })
    },
  })

  const unchanged =
    status === c.stored_status &&
    note.trim() === c.note &&
    !c.review_overdue &&
    (status !== 'accepted_risk' || reviewBy === c.review_by?.slice(0, 10))

  const name = `triage-${c.fingerprint}`
  const tomorrow = isoDate(new Date(Date.now() + DAY))
  const yearOut = isoDate(new Date(Date.now() + 365 * DAY))

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        mutation.mutate()
      }}
      className="space-y-4"
    >
      <fieldset>
        <legend className="kicker mb-2">Decision</legend>
        <div className="grid sm:grid-cols-2 gap-1.5">
          {(Object.keys(STATUS_META) as CredentialStatus[]).map((s) => (
            <label
              key={s}
              className={clsx(
                'flex items-start gap-2.5 rounded-sm px-3 py-2 cursor-pointer border transition-colors',
                status === s ? 'border-line-strong bg-ink-overlay' : 'border-line hover:bg-ink-overlay/60',
              )}
            >
              <input
                type="radio"
                name={name}
                value={s}
                checked={status === s}
                onChange={() => setStatus(s)}
                className="mt-1 accent-[#ECEAE6]"
              />
              <span>
                <span className="block text-[13px] text-ivory">{STATUS_META[s].label}</span>
                <span className="block text-2xs text-ivory-mute">{STATUS_META[s].help}</span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      {status === 'accepted_risk' && (
        <div>
          <label htmlFor={`${name}-review`} className="field-label">Review by</label>
          <input
            id={`${name}-review`}
            type="date"
            className="field w-44 font-mono text-2xs [color-scheme:dark]"
            min={tomorrow}
            max={yearOut}
            value={reviewBy}
            onChange={(e) => setReviewBy(e.target.value)}
            required
          />
          <p className="text-2xs text-ivory-mute mt-1">At most a year out. After this date the credential reopens.</p>
        </div>
      )}

      <div>
        <label htmlFor={`${name}-note`} className="field-label">Note</label>
        <textarea
          id={`${name}-note`}
          className="field text-2xs h-16 resize-y"
          maxLength={2000}
          placeholder={status === 'rotated' ? 'e.g. revoked in IAM, new key in the vault' : 'Why this decision?'}
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
        <p className="text-2xs text-ivory-mute mt-1">Visible to everyone with access to this workspace. Never paste the secret itself.</p>
      </div>

      <InlineError error={mutation.error} />

      <div className="flex items-center gap-3">
        <button type="submit" className="btn-primary h-7 text-2xs" disabled={mutation.isPending || unchanged}>
          {mutation.isPending ? 'Saving…' : 'Save decision'}
        </button>
        {saved && (
          <span className="text-2xs font-mono text-ok" role="status">
            ✓ saved
          </span>
        )}
        {c.triaged_at && !saved && (
          <span className="text-2xs font-mono text-ivory-mute">
            last decided {formatDistanceToNowStrict(parseUtc(c.triaged_at), { addSuffix: true })}
          </span>
        )}
      </div>
    </form>
  )
}

/** Exposure facts in one line: how long, how many commits, how many authors. */
export function ExposureFacts({ credential: c }: { credential: Credential }) {
  const facts: string[] = []
  if (c.first_seen) facts.push(`first seen ${format(parseUtc(c.first_seen), 'MMM d, yyyy')}`)
  if (c.exposure_days != null) facts.push(`${c.exposure_days} day${c.exposure_days === 1 ? '' : 's'} exposed`)
  if (c.commits_affected) facts.push(`${c.commits_affected} commit${c.commits_affected === 1 ? '' : 's'}`)
  if (c.authors_count) facts.push(`${c.authors_count} author${c.authors_count === 1 ? '' : 's'}`)
  if (facts.length === 0) return null
  return <p className="text-2xs font-mono text-ivory-mute">{facts.join(' · ')}</p>
}
