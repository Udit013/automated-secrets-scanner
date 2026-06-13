import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { listScans, deleteScan } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import { format } from 'date-fns'
import { Trash2, ExternalLink, Search } from 'lucide-react'
import { useState } from 'react'

export function ScanHistory() {
  const [search, setSearch] = useState('')
  const qc = useQueryClient()

  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => listScans(50),
    refetchInterval: 5_000,
  })

  const deleteMut = useMutation({
    mutationFn: deleteScan,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })

  const filtered = (scans ?? []).filter((s) =>
    s.source_ref.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Scan History</h1>
        <Link to="/scan" className="btn-primary text-sm">+ New Scan</Link>
      </div>

      <div className="relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
        <input
          className="input pl-8"
          placeholder="Filter by source…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {isLoading ? (
        <p className="text-gray-500 text-sm animate-pulse">Loading…</p>
      ) : filtered.length === 0 ? (
        <div className="card text-center py-12 text-gray-500">
          No scans found.{' '}
          <Link to="/scan" className="text-brand-400 hover:underline">
            Start your first scan →
          </Link>
        </div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800/60">
              <tr className="text-left text-gray-500">
                <th className="px-4 py-3 font-medium">Source</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Findings</th>
                <th className="px-4 py-3 font-medium">Files</th>
                <th className="px-4 py-3 font-medium">Date</th>
                <th className="px-4 py-3 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {filtered.map((s) => (
                <tr key={s.id} className="hover:bg-gray-800/20 transition-colors">
                  <td className="px-4 py-3 text-gray-300 max-w-[240px]">
                    <div className="truncate" title={s.source_ref}>
                      {s.source_ref.length > 45 ? s.source_ref.slice(0, 45) + '…' : s.source_ref}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs bg-gray-800 px-2 py-0.5 rounded text-gray-400">
                      {s.source_type}
                    </span>
                  </td>
                  <td className="px-4 py-3"><StatusBadge status={s.status} /></td>
                  <td className="px-4 py-3">
                    <span className={s.total_findings > 0 ? 'text-red-400 font-semibold' : 'text-gray-500'}>
                      {s.total_findings}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-500">{s.files_scanned}</td>
                  <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                    {format(new Date(s.created_at), 'MMM d, HH:mm')}
                  </td>
                  <td className="px-4 py-3 flex items-center gap-2 justify-end">
                    <Link
                      to={`/history/${s.id}`}
                      className="text-gray-500 hover:text-brand-400 transition-colors"
                      title="View details"
                    >
                      <ExternalLink size={14} />
                    </Link>
                    <button
                      onClick={() => {
                        if (confirm('Delete this scan and all its findings?')) {
                          deleteMut.mutate(s.id)
                        }
                      }}
                      className="text-gray-600 hover:text-red-400 transition-colors"
                      title="Delete"
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
