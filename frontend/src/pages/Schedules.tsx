import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listSchedules, createSchedule, toggleSchedule, deleteSchedule,
} from '../api/client'
import { format } from 'date-fns'
import { PauseCircle, PlayCircle, Trash2, Plus, ExternalLink } from 'lucide-react'
import { Link } from 'react-router-dom'

const CRON_PRESETS = [
  { label: 'Every day at 9 AM', value: '0 9 * * *' },
  { label: 'Every Monday at 8 AM', value: '0 8 * * 1' },
  { label: 'Every hour', value: '0 * * * *' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
]

export function Schedules() {
  const [showForm, setShowForm] = useState(false)
  const [name, setName] = useState('')
  const [sourceRef, setSourceRef] = useState('')
  const [cron, setCron] = useState('0 9 * * *')
  const [scanHistory, setScanHistory] = useState(false)

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
    onSuccess: () => qc.invalidateQueries({ queryKey: ['schedules'] }),
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
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Scan Schedules</h1>
        <button onClick={() => setShowForm((v) => !v)} className="btn-primary text-sm flex items-center gap-1">
          <Plus size={14} /> New Schedule
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleSubmit} className="card space-y-4">
          <h2 className="font-semibold text-white">Create Schedule</h2>

          <div>
            <label className="label">Schedule name</label>
            <input className="input" placeholder="Nightly main repo scan" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>

          <div>
            <label className="label">GitHub Repository URL</label>
            <input className="input" placeholder="https://github.com/owner/repo" value={sourceRef} onChange={(e) => setSourceRef(e.target.value)} required />
          </div>

          <div>
            <label className="label">Cron expression</label>
            <div className="flex gap-2 flex-wrap mb-2">
              {CRON_PRESETS.map((p) => (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => setCron(p.value)}
                  className={`text-xs px-2 py-1 rounded border transition-colors ${
                    cron === p.value
                      ? 'border-brand-500 text-brand-400 bg-brand-500/10'
                      : 'border-gray-700 text-gray-500 hover:border-gray-500'
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
            <input
              className="input font-mono"
              value={cron}
              onChange={(e) => setCron(e.target.value)}
              placeholder="minute hour day month weekday"
              required
            />
            <p className="text-xs text-gray-600 mt-1">5-field cron: minute hour day month weekday</p>
          </div>

          <label className="flex items-center gap-3 cursor-pointer">
            <input type="checkbox" checked={scanHistory} onChange={(e) => setScanHistory(e.target.checked)} className="accent-brand-500" />
            <span className="text-sm text-gray-300">Include git history (last 100 commits)</span>
          </label>

          {createMut.isError && (
            <p className="text-red-400 text-sm">{(createMut.error as Error)?.message}</p>
          )}

          <div className="flex gap-3">
            <button type="submit" className="btn-primary text-sm" disabled={createMut.isPending}>
              {createMut.isPending ? 'Creating…' : 'Create Schedule'}
            </button>
            <button type="button" className="btn-secondary text-sm" onClick={() => setShowForm(false)}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {isLoading ? (
        <p className="text-gray-500 text-sm animate-pulse">Loading…</p>
      ) : (schedules ?? []).length === 0 ? (
        <div className="card text-center py-12 text-gray-500">
          No schedules yet. Create one above to run recurring scans.
        </div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800/60">
              <tr className="text-left text-gray-500">
                <th className="px-4 py-3 font-medium">Name</th>
                <th className="px-4 py-3 font-medium">Repository</th>
                <th className="px-4 py-3 font-medium">Cron</th>
                <th className="px-4 py-3 font-medium">Next Run</th>
                <th className="px-4 py-3 font-medium">Last Run</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {schedules!.map((s) => (
                <tr key={s.id} className="hover:bg-gray-800/20 transition-colors">
                  <td className="px-4 py-3 text-gray-300 font-medium">{s.name}</td>
                  <td className="px-4 py-3 text-gray-500 truncate max-w-[180px]" title={s.source_ref}>
                    {s.source_ref.replace('https://github.com/', '')}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-400">{s.cron_expression}</td>
                  <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                    {s.next_run_at ? format(new Date(s.next_run_at), 'MMM d, HH:mm') : '—'}
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                    {s.last_run_at ? format(new Date(s.last_run_at), 'MMM d, HH:mm') : 'Never'}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded ${s.enabled ? 'bg-green-900 text-green-300' : 'bg-gray-800 text-gray-500'}`}>
                      {s.enabled ? 'active' : 'paused'}
                    </span>
                  </td>
                  <td className="px-4 py-3 flex items-center gap-2 justify-end">
                    {s.last_scan_id && (
                      <Link to={`/history/${s.last_scan_id}`} className="text-gray-500 hover:text-brand-400 transition-colors" title="Last scan">
                        <ExternalLink size={13} />
                      </Link>
                    )}
                    <button
                      onClick={() => toggleMut.mutate(s.id)}
                      className="text-gray-500 hover:text-yellow-400 transition-colors"
                      title={s.enabled ? 'Pause' : 'Resume'}
                    >
                      {s.enabled ? <PauseCircle size={14} /> : <PlayCircle size={14} />}
                    </button>
                    <button
                      onClick={() => {
                        if (confirm('Delete this schedule?')) deleteMut.mutate(s.id)
                      }}
                      className="text-gray-600 hover:text-red-400 transition-colors"
                    >
                      <Trash2 size={14} />
                    </button>
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
