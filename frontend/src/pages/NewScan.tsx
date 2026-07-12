import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { clsx } from 'clsx'
import { startScan, getScan } from '../api/client'
import { useWebSocket } from '../hooks/useWebSocket'

type Tab = 'github' | 'paste'

/** Surface FastAPI validation details instead of axios's generic message. */
function apiErrorMessage(error: unknown): string {
  if (isAxiosError(error)) {
    const detail = error.response?.data?.detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail) && detail[0]?.msg) return detail[0].msg
  }
  return (error as Error)?.message ?? 'Scan failed'
}

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
  const finishedRef = useRef(false)

  const finish = (scanId: string) => {
    if (finishedRef.current) return
    finishedRef.current = true
    qc.invalidateQueries({ queryKey: ['scans'] })
    qc.invalidateQueries({ queryKey: ['stats'] })
    setScanProgress(100)
    setTimeout(() => navigate(`/history/${scanId}`), 600)
  }

  useEffect(() => {
    if (!lastMessage) return
    if (lastMessage.progress !== undefined) setScanProgress(lastMessage.progress)
    if (lastMessage.message) setScanMessage(lastMessage.message)
    if (lastMessage.event === 'completed') finish(activeScanId!)
    if (lastMessage.event === 'failed') {
      mutation.reset()
      setActiveScanId(null)
    }
  }, [lastMessage])

  // Fallback poll: fast scans can complete before the WebSocket connects,
  // so the terminal state is also confirmed over plain HTTP.
  const { data: polledScan } = useQuery({
    queryKey: ['scan-poll', activeScanId],
    queryFn: () => getScan(activeScanId!),
    enabled: !!activeScanId,
    refetchInterval: 1500,
  })
  useEffect(() => {
    if (!polledScan || !activeScanId) return
    if (polledScan.status === 'completed') finish(activeScanId)
    if (polledScan.status === 'failed') {
      mutation.reset()
      setActiveScanId(null)
      setScanMessage(polledScan.error_message ?? 'scan failed')
    }
  }, [polledScan?.status])

  const mutation = useMutation({
    mutationFn: startScan,
    onSuccess: (data) => {
      finishedRef.current = false
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

  const isRunning =
    !!activeScanId &&
    !finishedRef.current &&
    !['completed', 'failed'].includes(lastMessage?.event ?? '')

  return (
    <div className="max-w-xl">
      <div className="pb-5">
        <p className="kicker mb-1">Detection</p>
        <h1 className="page-title">New scan</h1>
        <p className="text-2xs text-ivory-mute mt-2">
          26 patterns · shannon entropy · git-history lifecycle analysis
        </p>
      </div>

      {/* Source selector — segmented, not tabs-with-underline */}
      <div className="rule pt-5">
        <div className="field-label">Source</div>
        <div className="inline-flex rounded-sm bg-ink-inset p-0.5 border border-line" role="tablist">
          {(
            [
              { id: 'github', label: 'GitHub repository' },
              { id: 'paste', label: 'Pasted code' },
            ] as { id: Tab; label: string }[]
          ).map(({ id, label }) => (
            <button
              key={id}
              role="tab"
              aria-selected={tab === id}
              onClick={() => setTab(id)}
              className={clsx(
                'h-7 px-3 rounded-[1px] text-2xs font-medium transition-colors',
                tab === id ? 'bg-ink-overlay text-ivory' : 'text-ivory-mute hover:text-ivory-dim',
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={handleSubmit} className="mt-5 space-y-6">
        {tab === 'github' ? (
          <div>
            <label htmlFor="repo-url" className="field-label">Repository URL</label>
            <input
              id="repo-url"
              className="field font-mono text-2xs"
              placeholder="https://github.com/owner/repo"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              required
            />
            <p className="text-2xs text-ivory-mute mt-1.5">
              Public repositories only. Set GITHUB_TOKEN server-side for higher rate limits.
            </p>
          </div>
        ) : (
          <div>
            <label htmlFor="paste-box" className="field-label">Code, config, or .env content</label>
            <textarea
              id="paste-box"
              className="field font-mono text-2xs h-44 resize-y"
              placeholder={'API_KEY = "sk_live_..."\nDATABASE_URL = "postgres://..."'}
              value={pasteContent}
              onChange={(e) => setPasteContent(e.target.value)}
              required
            />
          </div>
        )}

        {/* Parameters — always visible, an operator sets them deliberately */}
        <fieldset className="rule pt-5">
          <legend className="sr-only">Scan parameters</legend>
          <div className="field-label">Parameters</div>
          <div className="space-y-4">
            {tab === 'github' && (
              <label className="flex items-start gap-3 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={scanHistory}
                  onChange={(e) => setScanHistory(e.target.checked)}
                  className="mt-0.5 h-3.5 w-3.5 accent-[#ECEAE6]"
                />
                <span>
                  <span className="block text-[13px] text-ivory group-hover:text-[#ffffff]">
                    Include git history
                  </span>
                  <span className="block text-2xs text-ivory-mute">
                    Traverses past commits — catches secrets that were added, then deleted
                  </span>
                </span>
              </label>
            )}

            <div className="flex gap-6">
              {scanHistory && tab === 'github' && (
                <NumberField
                  id="max-commits"
                  label="Commit depth"
                  value={maxCommits}
                  min={1}
                  max={1000}
                  step={1}
                  onChange={setMaxCommits}
                />
              )}
              <NumberField
                id="min-entropy"
                label="Entropy floor"
                value={minEntropy}
                min={0}
                max={8}
                step={0.1}
                onChange={setMinEntropy}
                hint="higher → fewer false positives"
              />
            </div>
          </div>
        </fieldset>

        {mutation.isError && (
          <p className="text-2xs font-mono text-sev-critical" role="alert">
            ✕ {apiErrorMessage(mutation.error)}
          </p>
        )}

        {isRunning && (
          <div aria-live="polite">
            <div className="flex items-baseline justify-between mb-1.5">
              <span className="text-2xs font-mono text-ivory-dim">{scanMessage || 'scanning…'}</span>
              <span className="font-mono text-2xs text-ivory tabular-nums">{scanProgress}%</span>
            </div>
            <div className="h-[3px] rounded-full bg-line overflow-hidden">
              <div
                className="h-full bg-ivory transition-[width] duration-300"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
          </div>
        )}

        {lastMessage?.event === 'completed' && (
          <p className="text-2xs font-mono text-ok" role="status">
            ✓ complete — {lastMessage.total_findings} finding(s) · opening report…
          </p>
        )}

        <button type="submit" disabled={isRunning || mutation.isPending} className="btn-primary">
          {isRunning || mutation.isPending ? 'Scanning…' : 'Run scan'}
        </button>
      </form>
    </div>
  )
}

function NumberField({
  id,
  label,
  value,
  min,
  max,
  step,
  onChange,
  hint,
}: {
  id: string
  label: string
  value: number
  min: number
  max: number
  step: number
  onChange: (v: number) => void
  hint?: string
}) {
  return (
    <div>
      <label htmlFor={id} className="field-label">{label}</label>
      <input
        id={id}
        type="number"
        className="field w-28 font-mono text-2xs"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
      {hint && <p className="text-2xs text-ivory-mute mt-1">{hint}</p>}
    </div>
  )
}
