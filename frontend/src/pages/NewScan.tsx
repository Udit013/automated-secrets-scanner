import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { apiErrorMessage, startScan, getScan } from '../api/client'
import { useWebSocket } from '../hooks/useWebSocket'
import { useHealth } from '../hooks/useHealth'

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
  const [failure, setFailure] = useState<string | null>(null)
  const { data: health } = useHealth()

  const navigate = useNavigate()
  const qc = useQueryClient()
  const { lastMessage } = useWebSocket(activeScanId)
  const finishedRef = useRef(false)

  // One place decides what a terminal state means, whichever channel (the
  // WebSocket or the fallback poll) reports it first. Kept in a ref so the
  // effects below always call the current closure.
  const settle = useRef<(status: 'completed' | 'failed', error?: string | null) => void>(() => {})
  settle.current = (status, error) => {
    if (!activeScanId || finishedRef.current) return
    finishedRef.current = true
    if (status === 'completed') {
      qc.invalidateQueries({ queryKey: ['scans'] })
      qc.invalidateQueries({ queryKey: ['stats'] })
      qc.invalidateQueries({ queryKey: ['projects'] })
      setScanProgress(100)
      const id = activeScanId
      setTimeout(() => navigate(`/history/${id}`), 600)
    } else {
      setActiveScanId(null)
      setFailure(error || 'The scan failed.')
    }
  }

  useEffect(() => {
    if (!lastMessage) return
    if (lastMessage.progress !== undefined) setScanProgress(lastMessage.progress)
    if (lastMessage.message) setScanMessage(lastMessage.message)
    if (lastMessage.event === 'completed' || lastMessage.event === 'failed') {
      settle.current(lastMessage.event, lastMessage.error)
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
  const polledStatus = polledScan?.status
  const polledError = polledScan?.error_message
  useEffect(() => {
    if (polledStatus === 'completed' || polledStatus === 'failed') settle.current(polledStatus, polledError)
  }, [polledStatus, polledError])

  const mutation = useMutation({
    mutationFn: startScan,
    onMutate: () => setFailure(null),
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

  const isRunning = !!activeScanId && !finishedRef.current

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
        <div className="inline-flex rounded-sm bg-ink-inset p-0.5 border border-line" role="group" aria-label="Source">
          {(
            [
              { id: 'github', label: 'GitHub repository' },
              { id: 'paste', label: 'Pasted code' },
            ] as { id: Tab; label: string }[]
          ).map(({ id, label }) => (
            <button
              key={id}
              type="button"
              aria-pressed={tab === id}
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
            ✕ {apiErrorMessage(mutation.error, 'Could not start the scan')}
          </p>
        )}
        {failure && (
          <p className="text-2xs font-mono text-sev-critical" role="alert">
            ✕ {failure}
          </p>
        )}

        {health && !health.auth_required && (
          <p className="text-2xs text-ivory-mute border-l-2 border-line-strong pl-3">
            This is a public workspace: anyone with its URL can see scan results. Pasted text is scanned in
            memory and not kept; each finding stores only its line, with the secret masked. Still, don't paste
            live production secrets into a shared demo.
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
