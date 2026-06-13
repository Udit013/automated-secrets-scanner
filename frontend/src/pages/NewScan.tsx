import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { startScan } from '../api/client'
import { useWebSocket } from '../hooks/useWebSocket'
import { Github, Code2, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react'
import { clsx } from 'clsx'

type Tab = 'github' | 'paste'

export function NewScan() {
  const [tab, setTab] = useState<Tab>('github')
  const [githubUrl, setGithubUrl] = useState('')
  const [pasteContent, setPasteContent] = useState('')
  const [scanHistory, setScanHistory] = useState(false)
  const [maxCommits, setMaxCommits] = useState(100)
  const [minEntropy, setMinEntropy] = useState(3.5)
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanMessage, setScanMessage] = useState('')

  const navigate = useNavigate()
  const qc = useQueryClient()
  const { lastMessage } = useWebSocket(activeScanId)

  useEffect(() => {
    if (!lastMessage) return
    if (lastMessage.progress !== undefined) setScanProgress(lastMessage.progress)
    if (lastMessage.message) setScanMessage(lastMessage.message)
    if (lastMessage.event === 'completed') {
      qc.invalidateQueries({ queryKey: ['scans'] })
      qc.invalidateQueries({ queryKey: ['stats'] })
      setTimeout(() => navigate(`/history/${activeScanId}`), 800)
    }
    if (lastMessage.event === 'failed') {
      mutation.reset()
      setActiveScanId(null)
    }
  }, [lastMessage])

  const mutation = useMutation({
    mutationFn: startScan,
    onSuccess: (data) => {
      setActiveScanId(data.id)
      setScanProgress(0)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const source_ref = tab === 'github' ? githubUrl.trim() : pasteContent
    if (!source_ref) return
    mutation.mutate({
      source_type: tab,
      source_ref,
      scan_git_history: tab === 'github' ? scanHistory : false,
      max_commits: maxCommits,
      min_entropy: minEntropy,
    })
  }

  const isRunning = !!activeScanId && !['completed', 'failed'].includes(lastMessage?.event ?? '')

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-xl font-bold text-white">New Scan</h1>

      {/* Source tabs */}
      <div className="flex border-b border-gray-800">
        {[
          { id: 'github' as Tab, label: 'GitHub Repository', icon: Github },
          { id: 'paste' as Tab, label: 'Paste Code', icon: Code2 },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={clsx(
              'flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
              tab === id
                ? 'border-brand-500 text-brand-400'
                : 'border-transparent text-gray-500 hover:text-gray-300',
            )}
          >
            <Icon size={15} /> {label}
          </button>
        ))}
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        {tab === 'github' ? (
          <div>
            <label className="label">GitHub Repository URL</label>
            <input
              className="input"
              placeholder="https://github.com/owner/repo"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              required
            />
            <p className="text-xs text-gray-600 mt-1">
              Public repos work without a token. Add GITHUB_TOKEN in .env for higher rate limits.
            </p>
          </div>
        ) : (
          <div>
            <label className="label">Paste code or configuration</label>
            <textarea
              className="input font-mono text-xs h-48 resize-none"
              placeholder={'# Paste any code, .env file, config, etc.\nAPI_KEY = "sk_live_..."'}
              value={pasteContent}
              onChange={(e) => setPasteContent(e.target.value)}
              required
            />
          </div>
        )}

        {/* Advanced options */}
        <details className="card text-sm">
          <summary className="cursor-pointer text-gray-400 font-medium select-none">
            Advanced options
          </summary>
          <div className="mt-4 space-y-4">
            {tab === 'github' && (
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={scanHistory}
                  onChange={(e) => setScanHistory(e.target.checked)}
                  className="accent-brand-500"
                />
                <span className="text-gray-300">Scan git commit history</span>
              </label>
            )}
            {scanHistory && tab === 'github' && (
              <div>
                <label className="label">Max commits to scan</label>
                <input
                  type="number"
                  className="input w-32"
                  min={1}
                  max={1000}
                  value={maxCommits}
                  onChange={(e) => setMaxCommits(Number(e.target.value))}
                />
              </div>
            )}
            <div>
              <label className="label">Minimum entropy threshold</label>
              <input
                type="number"
                className="input w-32"
                min={0}
                max={8}
                step={0.1}
                value={minEntropy}
                onChange={(e) => setMinEntropy(Number(e.target.value))}
              />
              <p className="text-xs text-gray-600 mt-1">Higher = fewer false positives but may miss weaker secrets (default: 3.5)</p>
            </div>
          </div>
        </details>

        {mutation.isError && (
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 rounded-lg px-4 py-3 border border-red-800">
            <AlertCircle size={15} />
            {(mutation.error as Error)?.message ?? 'Scan failed'}
          </div>
        )}

        {/* Progress */}
        {isRunning && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-400 flex items-center gap-2">
                <Loader2 size={14} className="animate-spin" />
                {scanMessage || 'Scanning…'}
              </span>
              <span className="text-brand-400 font-mono">{scanProgress}%</span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-2">
              <div
                className="bg-brand-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
          </div>
        )}

        {lastMessage?.event === 'completed' && (
          <div className="flex items-center gap-2 text-green-400 text-sm bg-green-900/20 rounded-lg px-4 py-3 border border-green-800">
            <CheckCircle2 size={15} />
            Scan complete — {lastMessage.total_findings} finding(s). Redirecting…
          </div>
        )}

        <button
          type="submit"
          disabled={isRunning || mutation.isPending}
          className="btn-primary w-full flex items-center justify-center gap-2"
        >
          {isRunning || mutation.isPending ? (
            <>
              <Loader2 size={16} className="animate-spin" />
              Scanning…
            </>
          ) : (
            'Start Scan'
          )}
        </button>
      </form>
    </div>
  )
}
