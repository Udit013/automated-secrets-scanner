# CipherWatch

> **A credential exposure ledger.** CipherWatch finds leaked credentials in GitHub repositories and their git history, collapses every copy of a credential into one record, and keeps it on the ledger until someone rotates it, dismisses it, or accepts the risk with an expiry date. Its CLI and GitHub Action fail CI on *new* leaks only.

**Live demo:** [cipherwatch-web.vercel.app](https://cipherwatch-web.vercel.app) · **API docs:** [secrets-scanner-api.onrender.com/docs](https://secrets-scanner-api.onrender.com/docs)
<sub>Deployed from `main`; the API's [`/health`](https://secrets-scanner-api.onrender.com/health) reports the running version.</sub>

[![CI](https://github.com/Udit013/automated-secrets-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Udit013/automated-secrets-scanner/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61dafb?logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178c6?logo=typescript&logoColor=white)](https://typescriptlang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## Why a ledger, not another scanner

Finding a leaked key is the easy half. GitGuardian's [State of Secrets Sprawl 2025](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/) reports that 70% of the secrets leaked in 2022 were still valid. The gap is follow-through: line-level scanner output can't tell you which *credentials* are exposed, which are already handled, or whether last night's scan found anything new.

Open-source scanners such as Gitleaks and TruffleHog are strong at detection, and Gitleaks supports baselines in CI ([comparison](https://appsecsanta.com/gitleaks-vs-trufflehog), [baseline workflow](https://tessl.io/registry/testland/gitleaks-scanning/files/references/baseline.md)). CipherWatch concentrates on what happens after detection:

| | What it does |
|---|---|
| **One credential, one record** | Each value gets a keyed HMAC fingerprint, so the same AWS key in five files and many commits is one credential with several locations, not one finding per copy. The fingerprint never contains the secret. |
| **Decisions that persist** | Mark a credential `rotated`, `false_positive`, or `accepted_risk`. Decisions are stored per project and fingerprint, so they follow the credential through later scans, file moves, and line shifts. |
| **Waivers that expire** | `accepted_risk` requires a review date at most 366 days out. Once it passes, the credential reads *open · review overdue* again on its own. |
| **History-aware exposure** | Every credential is labelled **in code** or **history only**. Deleting a file doesn't remove a key from existing clones, so history-only credentials stay open until rotated. |
| **Rotation links** | 19 credential types across 12 providers (AWS, GitHub, Google Cloud, Stripe, Slack, Twilio, SendGrid, Azure, npm, PyPI, Discord, Mailgun) link to the provider page where the key is revoked; for npm, its revocation guide. |
| **Alerts that mean something** | With SMTP configured, a scan emails only for CRITICAL credentials that were absent from the previous scan of the project and haven't been triaged. |
| **CI gate on new leaks** | A CLI and a composite GitHub Action with a committed baseline (fingerprints only, safe to commit), `--fail-on` thresholds, and SARIF 2.1.0 for GitHub code scanning. |

### Deliberately out of scope

- **Live key verification.** Testing whether a leaked key works means *using someone else's credential*. Every detection is treated as live until a person decides otherwise.
- **Storing secrets.** Findings keep a masked value, the source line with every detected secret masked, and a fingerprint. Pasted text is scanned in memory and never written to the database.
- **AI in the detection path.** Detection is deterministic patterns plus entropy, and every risk score lists the factors behind it.
- **Paid infrastructure.** Everything runs locally or on free tiers (see [Zero-cost deployment](#zero-cost-deployment)).

---

## Architecture

```
                 ┌──────────────────────────────┐
  CLI / Action ──┤  scanner (pure Python)       │  patterns · entropy · git history · fingerprints
                 └──────────────┬───────────────┘
                                │ same engine
┌───────────────────────────────▼──────────────────────────────────┐
│ FastAPI (async)                                                   │
│  /scans  /projects  /projects/{o}/{r}/credentials  /export        │
│  /schedules  /stats  /health   WebSocket progress                 │
│  optional access token · per-IP rate limit · concurrency cap      │
│  APScheduler (UTC cron) · aiosmtplib alerts                       │
└───────────────────────────────┬──────────────────────────────────┘
                                │ SQLAlchemy 2.0 async
               SQLite (local / demo)  ·  PostgreSQL (e.g. Neon free tier)
               scans · findings · credential_states · scan_schedules · app_settings

React 18 + TypeScript console (Vite 6, React Router 7, TanStack Query, Tailwind CSS 3)
  Landing · Overview · Projects · Credential ledger + triage · Scans · Schedules
```

---

## The console

| Page | What you do there |
|---|---|
| **Overview** | See open credentials (deduplicated and net of triage) by severity, history-only exposure, overdue waivers, and the projects that need attention first. |
| **Projects** | Every scanned repository, sorted by open critical, then open high, then any open. |
| **Credential ledger** | A per-project inventory with *Needs action / Accepted / Rotated / False positive / All* tabs, severity and exposure filters, an open-credentials trend, locations, risk factors, remediation steps, rotation links, and the triage form. |
| **Scans** | Every scan, with a credential-level diff against the previous scan, findings grouped by file, and JSON / CSV / SARIF / remediation-patch exports. |
| **Schedules** | Cron rescans (UTC), with alerting when SMTP is configured. |

Data views have loading, empty, and error states. Controls are keyboard-reachable with visible focus, severity is never conveyed by color alone, and layouts were checked at a 375 px phone width.

---

## Prerequisites

- **Python 3.11+** (CI uses 3.11; also tested locally on 3.14) and the **`git`** binary for history scans
- **Node.js 20+** for the console (React Router 7 and Vite 6 require it)
- Optional: **Docker** for the Compose stack, and **PostgreSQL** (local or a free Neon database)

---

## Quick start

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # defaults work as-is (public mode, SQLite)
python seed_demo.py             # optional: sample projects with fake credentials and triage
uvicorn app.main:app --reload   # http://localhost:8000  (Swagger UI at /docs)

# Console (another terminal)
cd frontend
npm install
npm run dev                     # http://localhost:5173 (proxies /api and /health to :8000)
```

`seed_demo.py` writes nothing if the database already contains any scan or if `ACCESS_TOKEN` is set, so it can't mix sample data into a real workspace.

**Docker Compose** (PostgreSQL 16 + API + nginx-served console on http://localhost:5173):

```bash
docker compose up --build
```

---

## CI: fail on new leaks only

### GitHub Action

```yaml
# .github/workflows/secrets.yml
name: Secrets
on: [push, pull_request]
jobs:
  cipherwatch:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }          # needed for history: "true"
      - uses: Udit013/automated-secrets-scanner@main
        id: scan
        with:
          fail-on: high                   # critical | high | medium | low | none
          history: "true"
          baseline: .cipherwatch-baseline.json   # skipped if the file doesn't exist
      - if: always()
        uses: github/codeql-action/upload-sarif@v4
        with: { sarif_file: "${{ steps.scan.outputs.sarif-file }}" }
```

The action scans once, printing a masked summary to the log, writing the SARIF report, and setting the exit code. It installs GitPython into a private virtualenv using its own Python (`update-environment: false`), so it doesn't change the Python version the rest of your job uses. Linux and macOS runners are supported; Windows runners aren't. Inputs reach the shell only through environment variables, never through `${{ }}` interpolation inside the script. This repository gates itself the same way: see the `self-scan` job in [ci.yml](.github/workflows/ci.yml) and its fixture baseline in [.cipherwatch-baseline.json](.cipherwatch-baseline.json).

### CLI

Needs Python 3.11+, GitPython, and `git` for `--history`. No server or database.

```bash
pip install "GitPython>=3.1.40"

python cli.py baseline .                      # accept what is there today (writes .cipherwatch-baseline.json)
python cli.py scan . --history --fail-on high --baseline .cipherwatch-baseline.json
python cli.py scan . --sarif cipherwatch.sarif   # text summary + SARIF file in one run
python cli.py scan . --format json            # one entry per credential
```

Exit codes: `0` nothing new at or above `--fail-on`, `1` new credentials at or above it, `2` usage or I/O error. Pre-3.0 flags still work (`-d DIR` and `-f FILE` map to `scan PATH`; `-g REPO` maps to `scan REPO --history`).

**Baselines** store `fingerprint`, `secret_type`, and `file_path` per credential, never secret values. Each baseline records a `key_id` derived from the fingerprint key; scanning with a different key exits `2` instead of reporting every known credential as new.

**Matching the console's fingerprints.** The CLI uses a fixed public key unless `FINGERPRINT_KEY` is set. CLI and console fingerprints match only when both use the same `FINGERPRINT_KEY` environment variable; a key the server generated for itself is stored in its database and isn't shared with the CLI.

---

## Detection engine

- **26 patterns**: AWS (access key, secret key), Google (API key, service account), GitHub (PAT, OAuth, App tokens), Stripe (live, test), Slack (bot, app), Twilio, SendGrid, Mailgun, Discord, JWT, private keys (RSA/EC/DSA/OpenSSH/PGP), database connection strings, Azure storage key and SAS token, npm and PyPI tokens, plus generic API key, secret, and password.
- **Entropy gating**: the generic, shape-less patterns must clear a Shannon-entropy floor (default 3.5 bits, configurable per scan).
- **False-positive controls**: placeholder detection (`YOUR_KEY_HERE`, `${VAR}`, `example`, `changeme`, …), severity downgrade for test paths, and comment skipping (except key headers).
- **File selection**: source and config extensions plus extensionless credential files (`id_rsa`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `Dockerfile`, …). Vendored and virtualenv directories, symlinks, and files over 5 MB are skipped, in both the working tree and history.
- **Fingerprints**: HMAC-SHA256 of the value for format-specific patterns. Generic patterns and key-header markers, whose match isn't a stable secret value, are fingerprinted by pattern + file + masked match instead.
- **Risk score**: 0–100 from severity, git-history presence, occurrences, exposure duration, author count, and entropy, with a stated reason for every point.

---

## Security model

| Control | Detail |
|---|---|
| **Two modes** | `ACCESS_TOKEN` unset: public demo mode, protected by abuse limits. Set: every `/api/v1` request needs `Authorization: Bearer <token>`, compared in constant time; failures get `401`. The console asks for the token once per browser session (optionally remembered on the device). The WebSocket sends it as a `Sec-WebSocket-Protocol` entry, so it never appears in URLs or access logs. `/health` is always public. |
| **Abuse limits** | Per-client-IP sliding window on scan creation (default 10 per 10 minutes; `429` with `Retry-After`), a soft cap of 3 queued/running scans, and a cap of 25 schedules. The client IP is read from `X-Forwarded-For` only `TRUSTED_PROXY_HOPS` entries from the right, so a client can't spoof it by prepending addresses. |
| **Untrusted repositories** | Archives stream to disk under a 100 MB cap. Zip-slip, uncompressed-size (500 MB), and member-count (50,000) checks run before extraction. Symlinks aren't followed, files over 5 MB aren't read, scanning runs in worker threads, and the Docker image runs as a non-root user. |
| **No secret retention** | Only masked values and masked lines are stored; pasted text is never stored. Tests assert that no raw secret appears in any API response, export, or CLI baseline. |
| **Data isolation** | Triage state is keyed by (project, fingerprint). A fingerprint that isn't in the project's findings is rejected with `404`; path segments and fingerprints are validated by pattern. |
| **CORS** | Explicit origins, no credentialed requests, explicit methods and headers. |

A private workspace is single-tenant: everyone holding the token sees the same projects, and there are no per-user accounts (see [Limitations](#limitations)).

---

## Zero-cost deployment

| Piece | Free option | Notes |
|---|---|---|
| API | Render free web service via [`render.yaml`](render.yaml) | Sleeps after about 15 minutes idle; the console shows a "waking the server" state on the first request. |
| Database | SQLite on the instance (demo; reset on every redeploy) **or** a free Neon Postgres | To keep triage history, set `DATABASE_URL=postgresql+asyncpg://…`. |
| Console | Vercel free tier | Root directory `frontend`; set `VITE_API_URL=https://<your-api>.onrender.com` at build time. |
| CI | GitHub Actions | The composite action needs only GitPython. |
| Alerts | Any SMTP account (e.g. a Gmail app password) | Optional. |

**Private workspace on Render:** set `ACCESS_TOKEN` (long random), `FINGERPRINT_KEY` (long random, then keep it stable; changing it re-keys every credential), `SEED_DEMO=0`, a Neon `DATABASE_URL`, and `CORS_ORIGINS` for your console's origin. `render.yaml` sets `TRUSTED_PROXY_HOPS=1`, which assumes Render's proxy appends exactly one `X-Forwarded-For` entry. That assumption hasn't been verified against a live deployment; confirm it after deploying (see [PROJECT_DOCUMENTATION.md](PROJECT_DOCUMENTATION.md#troubleshooting)).

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./secrets_scanner.db` | SQLite or `postgresql+asyncpg://…` |
| `ACCESS_TOKEN` | — | Set to make the workspace private |
| `FINGERPRINT_KEY` | generated and stored in the DB | HMAC key for fingerprints; also read by the CLI |
| `SCAN_RATE_LIMIT` / `SCAN_RATE_WINDOW_SECONDS` | `10` / `600` | Scan creations per client IP per window |
| `MAX_CONCURRENT_SCANS` | `3` | Queued + running scans (soft cap) |
| `MAX_SCHEDULES` | `25` | Stored schedules |
| `TRUSTED_PROXY_HOPS` | `0` | Reverse proxies in front of the API |
| `CORS_ORIGINS` | localhost dev origins | Comma-separated console origins |
| `GITHUB_TOKEN` | — | Raises the GitHub API limit from 60 to 5,000 requests/hour |
| `SMTP_HOST` `SMTP_PORT` `SMTP_USER` `SMTP_PASSWORD` `SMTP_FROM` `ALERT_EMAIL` | — | Email alerts (optional) |
| `BACKEND_URL` | `http://localhost:8000` | Links in alert emails |
| `SEED_DEMO` | `1` in `render.yaml` | Run the demo seeder on start (Render start command only) |
| `VITE_API_URL` | — (console build) | API origin for a separately hosted console |

See [backend/.env.example](backend/.env.example) for annotated defaults.

---

## REST API

Interactive docs are served at `/docs`. In private mode every `/api/v1` route requires the bearer token.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scans` | Start a scan (`github` or `paste`); rate- and concurrency-limited |
| `GET` | `/api/v1/scans` · `/scans/{id}` · `/scans/{id}/findings` | Scans and line-level findings |
| `GET` | `/api/v1/scans/{id}/diff` | Credential-level diff against the previous completed scan of the source |
| `DELETE` | `/api/v1/scans/{id}` | Delete a scan |
| `WS` | `/api/v1/scans/ws/{id}` | Live progress (subprotocols `cipherwatch.v1`, `bearer.<token>`) |
| `GET` | `/api/v1/projects` | Projects with credential summaries |
| `GET` | `/api/v1/projects/{owner}/{repo}` | Project overview + open-credentials trend |
| `GET` | `/api/v1/projects/{owner}/{repo}/credentials` | The ledger; filter by `status`, `severity`, `exposure` |
| `PUT` | `/api/v1/projects/{owner}/{repo}/credentials/{fingerprint}` | Record a decision `{status, note, review_by}` |
| `GET` | `/api/v1/export/{id}/{json,csv,sarif,patch,remediation}` | Exports |
| `GET` | `/api/v1/stats` | Raw totals plus deduplicated exposure |
| `GET/POST/PATCH/DELETE` | `/api/v1/schedules…` | Cron schedules (UTC) |
| `GET` | `/health` | `{status, version, auth_required, demo}` |

---

## Tests and checks

```bash
cd backend && pytest tests/ -q          # 130 tests (SQLite)
TEST_DATABASE_URL=postgresql+asyncpg://user@host/cipherwatch_test pytest tests/ -q   # same suite on Postgres
cd .. && pytest test_scanner.py -q      # 19 tests for the legacy scanner module
cd frontend && npm run lint && npm run typecheck && npm run build
```

The suite drops every table in the database it uses, so it refuses a `TEST_DATABASE_URL` whose database name doesn't contain `test`.

Coverage highlights: fingerprint stability across checkouts, file moves, and legacy rows; triage persistence, waiver bounds and expiry; credential-level trend, diff, and alert suppression; the access token on every router and on the WebSocket handshake; spoof-resistant client IPs; rate, concurrency, and schedule limits; additive schema upgrades, including legacy data too long to index; demo-seeding safeguards; CLI exit codes, baselines (no secrets, key binding), and SARIF; size and vendored-directory limits; and the earlier hardening regressions (no raw secret in any response or export, zip-slip/zip-bomb limits, restart-safe schedules).

---

## Performance

Measured on a laptop with v2.1 of the engine; re-run before quoting.

| Metric | Value | How it was measured |
|---|---|---|
| Detection throughput | ~96K lines/sec | `scan_text` over this repo's source, median of 7 runs |
| GitHub repo scan, end to end | ~1.3 s | `pallets/flask`: download + extract + scan |
| Git-history de-duplication | 1,351 matches → 82 findings | This repo's 14-commit history at the time |
| Max event-loop stall during a scan | ~25–30 ms | After scanning moved to worker threads (was 458 ms / 21 s) |

There is no labelled evaluation set large enough for precision/recall figures; `evaluate_performance.py` checks 13 labelled secrets and is a smoke test, not a benchmark.

---

## Limitations

- **Single tenant.** One access token per deployment; no user accounts, roles, or per-user record of who made each decision.
- **GitHub only, public by default.** Private repositories can be downloaded with a `GITHUB_TOKEN` that has repo access, but history scans clone without the token, so they fail for private repos (the scan still completes with current-code results). This path hasn't been tested.
- **History depth.** History scans clone with `--depth=max_commits` (default 100); older commits aren't seen.
- **Project names are case-sensitive.** `github.com/Acme/API` and `github.com/acme/api` become two projects.
- **Additive migrations only.** Startup adds missing columns and indexes; anything destructive would need a migration tool such as Alembic. Legacy rows from before 2.1 (paste content stored in `source_ref`) are left as they are.
- **In-process limits.** Rate limits reset on restart and aren't shared across instances; the concurrency cap is checked before insert, so a simultaneous burst can briefly exceed it.
- **Render proxy assumption.** `TRUSTED_PROXY_HOPS=1` hasn't been verified on a live Render deployment.
- **Build-tool advisories.** `npm audit` reports 7 advisories in Tailwind CSS 3's build-time dependencies; `npm audit --omit=dev` (what ships to browsers) is clean. Clearing them needs a Tailwind 4 migration.

---

## Author

**Udit Agarwal**
MS Computer Science — Indiana University Bloomington
[github.com/Udit013](https://github.com/Udit013) · agarwaludit13@gmail.com
