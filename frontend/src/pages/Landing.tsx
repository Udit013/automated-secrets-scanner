import { Link } from 'react-router-dom'
import { useHealth } from '../hooks/useHealth'
import { Mark } from '../components/Mark'

const REPO = 'https://github.com/Udit013/automated-secrets-scanner'
const REPORT = 'https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/'

const STEPS = [
  {
    n: '01',
    title: 'Detect',
    body: '26 detection patterns, most of them provider-specific, plus entropy analysis, across the current code and, optionally, the repository’s git history.',
  },
  {
    n: '02',
    title: 'Deduplicate',
    body: 'Each value gets a keyed fingerprint. The same key in five files and twelve commits is one credential, one decision, one rotation. The fingerprint never contains the secret.',
  },
  {
    n: '03',
    title: 'Decide',
    body: 'Mark a credential rotated, a false positive, or an accepted risk with a review date at most a year out. Decisions follow the credential across future scans; expired waivers reopen themselves.',
  },
  {
    n: '04',
    title: 'Gate',
    body: 'The CLI and GitHub Action compare against a committed baseline of fingerprints, so CI fails on new leaks only, and emit SARIF for GitHub code scanning.',
  },
]

const BOUNDARIES = [
  {
    title: 'Secrets are never stored',
    body: 'Findings keep a masked value, the line with every secret masked, and a fingerprint. Pasted text is scanned in memory and dropped.',
  },
  {
    title: 'Keys are never tested',
    body: 'Checking whether a leaked key works means using someone else’s credential. CipherWatch treats every detection as live until a person says otherwise.',
  },
  {
    title: 'No model in the loop',
    body: 'Detection is deterministic rules and entropy. Every risk score lists the factors behind it, so a reviewer can disagree with a reason.',
  },
  {
    title: 'Runs at zero cost',
    body: 'SQLite or a free Postgres tier, a free web host, and GitHub Actions minutes. No paid API sits anywhere in the path.',
  },
]

const WORKFLOW = `- uses: actions/checkout@v4
  with:
    fetch-depth: 0          # history scanning needs the full log
- uses: Udit013/automated-secrets-scanner@main
  with:
    fail-on: high
    history: "true"`

const CLI = `$ python cli.py baseline .        # accept what is there today
Wrote 45 credential(s) to .cipherwatch-baseline.json

$ python cli.py scan . --history --baseline .cipherwatch-baseline.json
CipherWatch scanned 88 file(s): 46 credential(s), 1 not in baseline.
  [NEW ] CRITICAL AWS Access Key                 history
$ echo $?
1`

export function Landing() {
  const { data: health } = useHealth()

  return (
    <div className="min-h-screen flex flex-col">
      <header className="mx-auto w-full max-w-page px-4 sm:px-6 h-14 flex items-center gap-6">
        <Link to="/" className="flex items-center gap-2.5" aria-label="CipherWatch home">
          <Mark />
          <span className="text-[14px] font-semibold tracking-tight">CipherWatch</span>
        </Link>
        <nav className="hidden sm:flex items-center gap-5 text-[13px] text-ivory-mute" aria-label="Sections">
          <a href="#how" className="hover:text-ivory transition-colors">How it works</a>
          <a href="#ci" className="hover:text-ivory transition-colors">CI</a>
          <a href="#principles" className="hover:text-ivory transition-colors">Principles</a>
        </nav>
        <div className="flex-1" />
        <a href={REPO} target="_blank" rel="noreferrer noopener" className="btn-ghost h-8 text-2xs">
          Source ↗
        </a>
        <Link to="/overview" className="btn-primary h-8">
          Open console
        </Link>
      </header>

      <main className="flex-1">
        {/* Hero */}
        <section className="mx-auto max-w-page px-4 sm:px-6 pt-16 sm:pt-24 pb-16">
          <p className="kicker mb-5">Credential exposure ledger</p>
          <h1 className="text-[34px] sm:text-[52px] font-semibold leading-[1.05] tracking-[-0.025em] max-w-3xl">
            A leaked key stays dangerous until someone rotates it.
          </h1>
          <p className="mt-6 text-[15px] sm:text-[16px] leading-relaxed text-ivory-dim max-w-2xl">
            CipherWatch finds credentials in GitHub repositories and their history, collapses every copy into one
            record, and keeps it on the ledger until it is rotated, dismissed, or accepted with an expiry date.
            Your CI fails on new leaks, not on the ones you already know about.
          </p>
          <div className="mt-9 flex flex-wrap items-center gap-3">
            <Link to="/overview" className="btn-primary h-10 px-5 text-[14px]">
              {health?.demo ? 'Explore the demo workspace' : 'Open the console'}
            </Link>
            <Link to="/scan" className="btn-outline h-10 px-5 text-[14px]">
              Scan a public repository
            </Link>
          </div>
          {health?.demo && (
            <p className="mt-4 text-2xs text-ivory-mute">
              The demo is seeded with sample repositories and fake credentials, including triage decisions, so every
              screen has something to show.
            </p>
          )}
        </section>

        {/* Why */}
        <section className="border-y border-line bg-ink-raised">
          <div className="mx-auto max-w-page px-4 sm:px-6 py-10 grid md:grid-cols-[auto_1fr] gap-x-12 gap-y-4 items-center">
            <p className="font-mono text-[44px] sm:text-[56px] font-medium leading-none text-sev-critical tabular-nums">
              70%
            </p>
            <div className="max-w-2xl">
              <p className="text-[15px] text-ivory leading-relaxed">
                of secrets leaked in 2022 were still valid when GitGuardian checked again for its 2025 report.
              </p>
              <p className="text-2xs text-ivory-mute mt-2">
                Finding a leak is the easy half. The work is tracking it to rotation, and{' '}
                <a href={REPORT} target="_blank" rel="noreferrer noopener" className="underline underline-offset-4 hover:text-ivory">
                  most never get there
                </a>
                .
              </p>
            </div>
          </div>
        </section>

        {/* How it works */}
        <section id="how" className="mx-auto max-w-page px-4 sm:px-6 py-16 scroll-mt-4">
          <p className="kicker mb-2">How it works</p>
          <h2 className="text-[24px] font-semibold tracking-tight mb-10">From a match on a line to a closed record</h2>
          <ol className="grid sm:grid-cols-2 lg:grid-cols-4 gap-px bg-line rounded overflow-hidden">
            {STEPS.map((s) => (
              <li key={s.n} className="bg-ink p-6">
                <span className="font-mono text-2xs text-ivory-mute">{s.n}</span>
                <h3 className="text-[16px] font-semibold mt-3 mb-2">{s.title}</h3>
                <p className="text-[13px] text-ivory-dim leading-relaxed">{s.body}</p>
              </li>
            ))}
          </ol>

          <div className="mt-12 grid lg:grid-cols-2 gap-10 items-start">
            <div>
              <h3 className="text-[16px] font-semibold mb-2">Deleting the file is not the fix</h3>
              <p className="text-[13px] text-ivory-dim leading-relaxed">
                A key removed from the code is still in every clone of the history. CipherWatch labels each credential{' '}
                <span className="font-mono text-ivory">in code</span> or{' '}
                <span className="font-mono text-sev-medium">history only</span>, so a cleaned-up file doesn’t read as a
                solved problem. History-only credentials stay open until they are rotated at the provider; for 19
                providers the ledger links straight to the page where that happens.
              </p>
            </div>
            <div>
              <h3 className="text-[16px] font-semibold mb-2">Alerts that mean something</h3>
              <p className="text-[13px] text-ivory-dim leading-relaxed">
                With email configured, a scan alerts only when a critical credential appears that no earlier scan saw
                and nobody has triaged. A repository that leaked once doesn’t page you every night.
              </p>
            </div>
          </div>
        </section>

        {/* CI */}
        <section id="ci" className="border-t border-line scroll-mt-4">
          <div className="mx-auto max-w-page px-4 sm:px-6 py-16 grid lg:grid-cols-2 gap-10">
            <div className="min-w-0">
              <p className="kicker mb-2">In CI</p>
              <h2 className="text-[24px] font-semibold tracking-tight mb-4">Fail the build on new leaks only</h2>
              <p className="text-[13px] text-ivory-dim leading-relaxed max-w-lg">
                Commit a baseline once. It holds fingerprints, types, and paths, never a secret, so it is safe in the
                repository. From then on the gate fails only when a credential appears that the baseline doesn’t
                know. The CLI runs the same engine as the console; give both the same{' '}
                <span className="font-mono">FINGERPRINT_KEY</span> and their fingerprints line up.
              </p>
              <pre className="well mt-6 p-4 text-2xs text-ivory-dim overflow-x-auto" aria-label="GitHub Actions workflow">
                <code>{WORKFLOW}</code>
              </pre>
            </div>
            <div className="min-w-0">
              <p className="kicker mb-2">On a laptop</p>
              <pre className="well p-4 text-2xs text-ivory-dim overflow-x-auto" aria-label="Example terminal session">
                <code>{CLI}</code>
              </pre>
              <p className="text-2xs text-ivory-mute mt-3">
                Exit 0 when clean, 1 on new findings at or above <span className="font-mono">--fail-on</span>, 2 on
                errors. Output as text, JSON, or SARIF 2.1.0.
              </p>
            </div>
          </div>
        </section>

        {/* Principles */}
        <section id="principles" className="border-t border-line scroll-mt-4">
          <div className="mx-auto max-w-page px-4 sm:px-6 py-16">
            <p className="kicker mb-2">Principles</p>
            <h2 className="text-[24px] font-semibold tracking-tight mb-10">What it deliberately doesn’t do</h2>
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-8">
              {BOUNDARIES.map((b) => (
                <div key={b.title}>
                  <h3 className="text-[14px] font-semibold mb-2">{b.title}</h3>
                  <p className="text-[13px] text-ivory-dim leading-relaxed">{b.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="border-t border-line">
          <div className="mx-auto max-w-page px-4 sm:px-6 py-14 flex flex-wrap items-center justify-between gap-6">
            <p className="text-[18px] font-semibold tracking-tight max-w-lg">
              Find out what your repositories are still exposing.
            </p>
            <Link to="/scan" className="btn-primary h-10 px-5 text-[14px]">
              Run a scan
            </Link>
          </div>
        </section>
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto max-w-page px-4 sm:px-6 py-5 flex flex-wrap justify-between gap-2 text-2xs font-mono text-ivory-mute">
          <span>cipherwatch {health ? `v${health.version}` : ''} · MIT licensed</span>
          <a href={REPO} target="_blank" rel="noreferrer noopener" className="hover:text-ivory">
            github.com/Udit013/automated-secrets-scanner
          </a>
        </div>
      </footer>
    </div>
  )
}
