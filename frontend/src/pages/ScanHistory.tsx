import { useEffect, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { format } from 'date-fns'
import { listScans, deleteScan } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'

export function ScanHistory() {
  const [search, setSearch] = useState('')
  const [confirmingId, setConfirmingId] = useState<string | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  const qc = useQueryClient()

  // `/` focuses search from anywhere on the page — muscle memory from
  // GitHub and Linear.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '/' && document.activeElement?.tagName !== 'INPUT') {
        e.preventDefault()
        searchRef.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => listScans(50),
    refetchInterval: 5_000,
  })

  const deleteMut = useMutation({
    mutationFn: deleteScan,
    onSuccess: () => {
      setConfirmingId(null)
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const filtered = (scans ?? []).filter((s) =>
    s.source_ref.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div>
      <div className="flex items-end justify-between pb-5 gap-4">
        <div>
          <p className="kicker mb-1">Record</p>
          <h1 className="page-title">Scans</h1>
        </div>
        <div className="relative w-64">
          <input
            ref={searchRef}
            className="field h-8 pr-8"
            placeholder="Filter sources"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Filter scans by source"
          />
          <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 text-2xs font-mono text-ivory-mute border border-line rounded-sm px-1">
            /
          </kbd>
        </div>
      </div>

      {isLoading ? (
        <p className="text-2xs font-mono text-ivory-mute animate-pulse rule pt-6">loading…</p>
      ) : filtered.length === 0 ? (
        <div className="rule pt-14 pb-10 text-center">
          <p className="font-mono text-2xs text-ivory-mute mb-2">
            {search ? `[ nothing matches “${search}” ]` : '[ no scans recorded ]'}
          </p>
          {!search && (
            <Link to="/scan" className="text-2xs text-ivory-dim hover:text-ivory underline underline-offset-4">
              run the first scan
            </Link>
          )}
        </div>
      ) : (
        <div className="rule">
          <table className="ledger-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Type</th>
                <th>Status</th>
                <th className="!text-right">Findings</th>
                <th className="!text-right">Files</th>
                <th className="!text-right">When</th>
                <th className="w-24" />
              </tr>
            </thead>
            <tbody>
              {filtered.map((s) => (
                <tr
                  key={s.id}
                  className="group cursor-pointer"
                  onClick={() => navigate(`/history/${s.id}`)}
                >
                  <td className="max-w-[300px]">
                    <span className="block truncate font-mono text-2xs text-ivory-dim group-hover:text-ivory transition-colors" title={s.source_ref}>
                      {s.source_ref.replace('https://github.com/', '')}
                    </span>
                  </td>
                  <td>
                    <span className="kicker">{s.source_type}</span>
                  </td>
                  <td><StatusBadge status={s.status} /></td>
                  <td className="text-right">
                    <span
                      className="font-mono text-2xs tabular-nums"
                      style={{ color: s.total_findings > 0 ? '#ECEAE6' : '#888681' }}
                    >
                      {s.total_findings}
                    </span>
                  </td>
                  <td className="text-right font-mono text-2xs text-ivory-mute tabular-nums">
                    {s.files_scanned}
                  </td>
                  <td className="text-right font-mono text-2xs text-ivory-mute whitespace-nowrap">
                    {format(new Date(s.created_at), 'MMM d · HH:mm')}
                  </td>
                  <td className="text-right" onClick={(e) => e.stopPropagation()}>
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
                        aria-label={`Delete scan of ${s.source_ref}`}
                      >
                        remove
                      </button>
                    )}
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
