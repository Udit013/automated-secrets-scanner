import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { format } from 'date-fns'
import { clsx } from 'clsx'
import {
  listSchedules, createSchedule, toggleSchedule, deleteSchedule,
} from '../api/client'

const CRON_PRESETS = [
  { label: 'daily 09:00', value: '0 9 * * *' },
  { label: 'mondays 08:00', value: '0 8 * * 1' },
  { label: 'hourly', value: '0 * * * *' },
  { label: 'every 6h', value: '0 */6 * * *' },
]

export function Schedules() {
  const [showForm, setShowForm] = useState(false)
  const [name, setName] = useState('')
  const [sourceRef, setSourceRef] = useState('')
  const [cron, setCron] = useState('0 9 * * *')
  const [scanHistory, setScanHistory] = useState(false)
  const [confirmingId, setConfirmingId] = useState<string | null>(null)

  const qc = useQueryClient()

  const { data: schedules, isLoading } = useQuery({
    queryKey: ['schedules'],
    queryFn: listSchedules,
    refetchInterval: 30_000,
  })

  const createMut = useMutation({
    mutationFn: createSchedule,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['schedules'] })
      setShowForm(false)
      setName('')
      setSourceRef('')
    },
  })

  const toggleMut = useMutation({
    mutationFn: toggleSchedule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['schedules'] }),
  })

  const deleteMut = useMutation({
    mutationFn: deleteSchedule,
    onSuccess: () => {
      setConfirmingId(null)
      qc.invalidateQueries({ queryKey: ['schedules'] })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    createMut.mutate({
      name,
      source_type: 'github',
      source_ref: sourceRef,
      cron_expression: cron,
      scan_git_history: scanHistory,
    })
  }

  return (
    <div>
      <div className="flex items-end justify-between pb-5">
        <div>
          <p className="kicker mb-1">Automation</p>
          <h1 className="page-title">Schedules</h1>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className={showForm ? 'btn-ghost h-8' : 'btn-primary h-8'}
          aria-expanded={showForm}
        >
          {showForm ? 'Close' : 'New schedule'}
        </button>
      </div>

      {/* Create form — inline panel with a measured grid transition */}
      <div
        className="grid transition-[grid-template-rows] duration-200"
        style={{ gridTemplateRows: showForm ? '1fr' : '0fr' }}
      >
        <div className="overflow-hidden">
          <form onSubmit={handleSubmit} className="panel px-5 py-5 mb-6 space-y-5">
            <div className="grid sm:grid-cols-2 gap-5">
              <div>
                <label htmlFor="sched-name" className="field-label">Name</label>
                <input
                  id="sched-name"
                  className="field"
                  placeholder="Nightly main-repo sweep"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </div>
              <div>
                <label htmlFor="sched-repo" className="field-label">Repository URL</label>
                <input
                  id="sched-repo"
                  className="field font-mono text-2xs"
                  placeholder="https://github.com/owner/repo"
                  value={sourceRef}
                  onChange={(e) => setSourceRef(e.target.value)}
                  required
                />
              </div>
            </div>

            <div>
              <label htmlFor="sched-cron" className="field-label">Cadence</label>
              <div className="flex flex-wrap items-center gap-2 mb-2">
                {CRON_PRESETS.map((p) => (
                  <button
                    key={p.value}
                    type="button"
                    onClick={() => setCron(p.value)}
                    aria-pressed={cron === p.value}
                    className={clsx(
                      'h-6 px-2 rounded-sm text-2xs font-mono transition-colors',
                      cron === p.value
                        ? 'bg-ink-overlay text-ivory ring-1 ring-line-strong'
                        : 'text-ivory-mute hover:text-ivory-dim hover:bg-ink-overlay',
                    )}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
              <input
                id="sched-cron"
                className="field w-56 font-mono text-2xs"
                value={cron}
                onChange={(e) => setCron(e.target.value)}
                placeholder="min hour day month weekday"
                required
              />
              <p className="text-2xs text-ivory-mute mt-1.5 font-mono">
                {cron} · five-field cron
              </p>
            </div>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={scanHistory}
                onChange={(e) => setScanHistory(e.target.checked)}
                className="h-3.5 w-3.5 accent-[#ECEAE6]"
              />
              <span className="text-[13px] text-ivory">Include git history each run</span>
            </label>

            {createMut.isError && (
              <p className="text-2xs font-mono text-sev-critical" role="alert">
                ✕ {(createMut.error as Error)?.message}
              </p>
            )}

            <div className="flex gap-2">
              <button type="submit" className="btn-primary" disabled={createMut.isPending}>
                {createMut.isPending ? 'Creating…' : 'Create schedule'}
              </button>
              <button type="button" className="btn-ghost" onClick={() => setShowForm(false)}>
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>

      {isLoading ? (
        <p className="text-2xs font-mono text-ivory-mute animate-pulse rule pt-6">loading…</p>
      ) : (schedules ?? []).length === 0 ? (
        <div className="rule pt-14 pb-10 text-center">
          <p className="font-mono text-2xs text-ivory-mute mb-2">[ no recurring scans ]</p>
          <p className="text-2xs text-ivory-mute">
            Schedules run unattended and alert on critical findings.
          </p>
        </div>
      ) : (
        <div className="rule">
          <table className="ledger-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Repository</th>
                <th>Cadence</th>
                <th className="!text-right">Next run</th>
                <th className="!text-right">Last run</th>
                <th>State</th>
                <th className="w-32" />
              </tr>
            </thead>
            <tbody>
              {schedules!.map((s) => (
                <tr key={s.id} className="group">
                  <td className="text-[13px] text-ivory">{s.name}</td>
                  <td className="max-w-[200px]">
                    <span className="block truncate font-mono text-2xs text-ivory-dim" title={s.source_ref}>
                      {s.source_ref.replace('https://github.com/', '')}
                    </span>
                  </td>
                  <td className="font-mono text-2xs text-ivory-dim">{s.cron_expression}</td>
                  <td className="text-right font-mono text-2xs text-ivory-mute whitespace-nowrap">
                    {s.next_run_at ? format(new Date(s.next_run_at), 'MMM d · HH:mm') : '—'}
                  </td>
                  <td className="text-right font-mono text-2xs text-ivory-mute whitespace-nowrap">
                    {s.last_run_at ? format(new Date(s.last_run_at), 'MMM d · HH:mm') : 'never'}
                  </td>
                  <td>
                    <span className="inline-flex items-center gap-1.5 text-2xs font-mono">
                      <span
                        className={clsx(
                          'h-1.5 w-1.5 rounded-full',
                          s.enabled ? 'bg-ok' : 'bg-ivory-mute',
                        )}
                        aria-hidden
                      />
                      <span className={s.enabled ? 'text-ivory-dim' : 'text-ivory-mute'}>
                        {s.enabled ? 'armed' : 'paused'}
                      </span>
                    </span>
                  </td>
                  <td className="text-right">
                    <span className="inline-flex items-center gap-3">
                      {s.last_scan_id && (
                        <Link
                          to={`/history/${s.last_scan_id}`}
                          className="text-2xs text-ivory-mute hover:text-ivory transition-colors"
                        >
                          report
                        </Link>
                      )}
                      <button
                        onClick={() => toggleMut.mutate(s.id)}
                        className="text-2xs text-ivory-mute hover:text-ivory transition-colors"
                      >
                        {s.enabled ? 'pause' : 'resume'}
                      </button>
                      {confirmingId === s.id ? (
                        <span className="inline-flex items-center gap-2">
                          <button
                            onClick={() => deleteMut.mutate(s.id)}
                            className="text-2xs font-medium text-sev-critical hover:underline underline-offset-2"
                          >
                            delete
                          </button>
                          <button
                            onClick={() => setConfirmingId(null)}
                            className="text-2xs text-ivory-mute hover:text-ivory"
                          >
                            keep
                          </button>
                        </span>
                      ) : (
                        <button
                          onClick={() => setConfirmingId(s.id)}
                          className="text-2xs text-ivory-mute opacity-0 group-hover:opacity-100 focus-visible:opacity-100 hover:text-sev-critical transition-all"
                          aria-label={`Delete schedule ${s.name}`}
                        >
                          remove
                        </button>
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
