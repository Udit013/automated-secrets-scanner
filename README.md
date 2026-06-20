# Automated Secrets Scanner

> **Production-ready DevSecOps tool** for detecting hardcoded secrets in source code — combining regex pattern matching, Shannon entropy analysis, and semantic heuristics — with a real-time React dashboard, REST API, scan scheduling, and email alerting.

**Live Demo:** [https://automated-secrets-scanner.vercel.app](https://automated-secrets-scanner.vercel.app)  
**API Docs:** [https://secrets-scanner-api.onrender.com/docs](https://secrets-scanner-api.onrender.com/docs)

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61dafb?logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178c6?logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3-38bdf8?logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   React Frontend (Vite + TS)                 │
│   Dashboard · New Scan · History · Scan Detail · Schedules   │
│   Recharts · TanStack Query v5 · WebSocket (live progress)   │
└─────────────────────┬────────────────────────────────────────┘
                      │  HTTP / WebSocket
┌─────────────────────▼────────────────────────────────────────┐
│              FastAPI Backend  (Python 3.11)                  │
│   REST API · WebSocket endpoint · Background scan tasks      │
│   APScheduler (cron recurring scans) · aiosmtplib alerts     │
└─────────────────────┬────────────────────────────────────────┘
                      │  SQLAlchemy 2.0 async
┌─────────────────────▼────────────────────────────────────────┐
│           PostgreSQL (prod)  /  SQLite (dev/free tier)       │
│   scans  ·  findings  ·  scan_schedules                      │
└──────────────────────────────────────────────────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **26 Secret Patterns** | AWS keys, GCP credentials, GitHub tokens, Stripe, Slack, Twilio, SendGrid, Discord, SSH/PGP private keys, JWTs, DB connection strings, Azure, npm/PyPI tokens |
| **Shannon Entropy Analysis** | Flags high-entropy strings even without descriptive variable names (threshold configurable) |
| **Semantic Heuristics** | Variable name analysis boosts confidence when surrounding context contains `key`, `secret`, `token`, `password` |
| **CRITICAL / HIGH / MEDIUM / LOW** | Severity scored by secret type, entropy level, and file context |
| **False-Positive Suppression** | Placeholder detection (14 regex patterns + unique-char ratio), test-file severity downgrading, comment-line skipping |
| **Exposure Risk Score** | Transparent 0–100 score per finding combining severity, Git-history presence, occurrences, exposure duration, and entropy — with human-readable reasoning |
| **Secret Lifecycle Timeline** | Git-history exposure intelligence: introduced date, last-seen date, exposure duration, commits affected, and number of authors involved |
| **Differential Scanning** | Compares a scan against the previous scan of the same source — new vs. resolved secrets and a net-change summary |
| **GitHub Repo Scanning** | Scans any public GitHub repo via API zipball — no `git clone` required |
| **Git History Scanning** | Traverses all commits with GitPython — catches secrets added and later deleted |
| **Real-Time Progress** | WebSocket endpoint streams live scan progress to the React frontend |
| **Dashboard** | KPI cards, severity pie chart, findings-over-time line chart, top-secret-types bar chart, differential summary, recent scans table |
| **Remediation Patch Generator** | Generates env-var code replacements, a `.env.example` snippet, next-step guidance, and a downloadable `remediation.patch` — no repo write access required |
| **Export** | Download scan results as JSON, CSV, or **SARIF 2.1.0** (GitHub Advanced Security compatible) |
| **Scan Scheduling** | Cron-based recurring scans via APScheduler — set it and forget it |
| **Email Alerts** | SMTP notification when a CRITICAL finding is detected (free with Gmail App Password) |
| **REST API** | Fully documented OpenAPI/Swagger — drop into any CI/CD pipeline |
| **CLI** | Standalone command-line interface for offline or pre-commit use |

---

## Screenshots

> The live dashboard at [https://automated-secrets-scanner.vercel.app](https://automated-secrets-scanner.vercel.app) shows a seeded demo with 7 realistic scans across 6 acme-corp repositories.

| Dashboard | Scan Detail |
|-----------|-------------|
| KPI cards · severity chart · findings trend · top types | Per-file findings grouped with severity badges and remediation steps |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11, FastAPI, SQLAlchemy 2.0 (async), Pydantic v2, Uvicorn |
| **Database** | SQLite (dev / Render free tier) · PostgreSQL (production) |
| **Scanner** | Custom regex engine (26 patterns), Shannon entropy, GitPython |
| **Scheduler** | APScheduler 3.x (`AsyncIOScheduler`) |
| **Email** | aiosmtplib (async SMTP) |
| **Frontend** | React 18, TypeScript 5, Vite, Tailwind CSS 3, Geist / Geist Mono (GitHub-style high-contrast dark theme) |
| **Charts** | Recharts (PieChart, LineChart, BarChart) |
| **Data fetching** | TanStack Query v5 (auto-refetch every 15 s) |
| **Real-time** | Native WebSocket (browser + FastAPI) |
| **Deploy** | Render (backend) + Vercel (frontend) — both free tier |

---

## Quick Start (Local Development)

### Prerequisites

- Python 3.11+
- Node.js 20+

### 1. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # edit if needed (defaults work out of the box)

# Seed demo data (optional)
python seed_demo.py

# Start the API server
uvicorn app.main:app --reload
```

Backend: **http://localhost:8000** — Swagger UI at [/docs](http://localhost:8000/docs)

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Dashboard: **http://localhost:5173**

The Vite dev server proxies `/api` → `http://localhost:8000`, so no CORS setup is needed locally.

### 3. Docker Compose (full stack)

```bash
docker compose up --build
# Backend:  http://localhost:8000
# Frontend: http://localhost:5173
```

---

## CLI Usage

The original standalone CLI is still fully functional for offline scanning:

```bash
pip install -r requirements.txt     # root-level (GitPython + pytest)

# Scan a directory
python cli.py -d /path/to/project

# Scan a single file
python cli.py -f config.py

# Scan git history
python cli.py -g /path/to/repo --max-commits 200

# Scan a raw string
python cli.py -s 'API_KEY="sk_live_abc123"'

# Export results to JSON
python cli.py -d . -o report.json --format json

# Print statistics
python cli.py -d . --stats
```

---

## REST API

All endpoints are documented interactively at `/docs`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scans` | Start a new scan (async background task) |
| `GET` | `/api/v1/scans` | List all scans (paginated) |
| `GET` | `/api/v1/scans/{id}` | Get scan details with all findings |
| `GET` | `/api/v1/scans/{id}/findings` | Findings — filterable by severity / type |
| `DELETE` | `/api/v1/scans/{id}` | Delete scan and its findings |
| `WS` | `/api/v1/scans/ws/{id}` | WebSocket — real-time scan progress |
| `GET` | `/api/v1/scans/{id}/diff` | Differential comparison vs. previous scan of the same source |
| `GET` | `/api/v1/export/{id}/json` | Download JSON report |
| `GET` | `/api/v1/export/{id}/csv` | Download CSV report |
| `GET` | `/api/v1/export/{id}/sarif` | Download SARIF 2.1.0 report |
| `GET` | `/api/v1/export/{id}/remediation` | Structured remediation report (JSON) |
| `GET` | `/api/v1/export/{id}/patch` | Download remediation patch (env-var replacements) |
| `GET` | `/api/v1/stats` | Dashboard statistics |
| `POST` | `/api/v1/schedules` | Create a recurring scheduled scan |
| `GET` | `/api/v1/schedules` | List all schedules |
| `PATCH` | `/api/v1/schedules/{id}/toggle` | Enable or disable a schedule |
| `DELETE` | `/api/v1/schedules/{id}` | Delete a schedule |
| `GET` | `/health` | Health check (used to wake Render free tier) |

### Example: Start a GitHub scan

```bash
curl -X POST https://secrets-scanner-api.onrender.com/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "source_type": "github",
    "source_ref": "https://github.com/owner/repo",
    "scan_git_history": false
  }'
```

### CI/CD Integration

**GitHub Actions:**

```yaml
name: Secrets Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: python cli.py -d . -o secrets.json --format json --stats
      - uses: actions/upload-artifact@v4
        with:
          name: secrets-report
          path: secrets.json
```

**Pre-commit hook:**

```bash
#!/bin/bash
# .git/hooks/pre-commit
python /path/to/cli.py -d . --min-entropy 4.0
if [ $? -ne 0 ]; then
  echo "Secrets detected — commit blocked."
  exit 1
fi
```

---

## Detection Engine

### Pattern Matching (26 types)

| Category | Secret Types |
|----------|-------------|
| AWS | Access Key (`AKIA…`), Secret Access Key |
| GCP | API Key (`AIza…`), Service Account JSON |
| GitHub | Personal Access Token, OAuth Token, App Token |
| Stripe | Live key (`sk_live_…`), Test key |
| Communication | Slack Bot/App Token, Twilio, SendGrid, Mailgun, Discord Bot Token |
| Authentication | JWT token, Private SSH / RSA / EC / OpenSSH / PGP key |
| Database | PostgreSQL, MySQL, MongoDB, Redis, MSSQL connection strings |
| Cloud | Azure Storage Key, Azure SAS Token |
| Package registries | npm auth token, PyPI token |
| Generic | High-entropy API keys, secrets, hardcoded passwords |

### Entropy Analysis

Shannon entropy $H = -\sum p_i \log_2 p_i$ flags high-entropy strings that look like secrets even when variable names are non-descriptive. Default threshold: **3.5 bits** (configurable per request via `min_entropy`).

### Semantic Heuristics

- **Variable-name boost** — confidence increases when surrounding context contains `key`, `secret`, `token`, `password`, or `credential`
- **Test-file downgrading** — findings in `tests/`, `*.test.*`, `spec/`, or `fixtures/` are automatically demoted one severity level
- **Comment skipping** — lines starting with `#`, `//`, `*`, `<!--` are skipped (with an exception for SSH key headers `-----BEGIN`)
- **Placeholder detection** — 14 regex patterns + a unique-character-ratio check eliminate `YOUR_KEY_HERE`, `${API_KEY}`, `example_…`, `xxx…`, single-lowercase-word values

---

## Severity Scoring

| Severity | Examples | Recommended Action |
|----------|----------|--------------------|
| **CRITICAL** | SSH/PGP private keys, Stripe live keys, DB connection strings, GCP service account JSON | Revoke immediately |
| **HIGH** | GitHub PATs, Google API keys, AWS access keys, JWT tokens, Slack tokens | Rotate within 24 h |
| **MEDIUM** | Stripe test keys, lower-entropy generic keys, Twilio keys | Review and rotate |
| **LOW** | Suspected secrets in test files or with entropy just above threshold | Investigate |

---

## Project Structure

```
automated-secrets-scanner/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app + lifespan (DB init + scheduler)
│   │   ├── config.py                # Pydantic settings (env vars)
│   │   ├── database.py              # SQLAlchemy async engine + session factory
│   │   ├── models.py                # ORM: Scan, Finding, ScanSchedule
│   │   ├── schemas.py               # Pydantic request/response schemas
│   │   ├── notifications.py         # Async SMTP email alerts
│   │   ├── scanner/
│   │   │   ├── patterns.py          # 26 SecretPattern definitions with remediation
│   │   │   ├── core.py              # Scan engine (regex + entropy + heuristics + lifecycle)
│   │   │   ├── risk.py              # Transparent 0-100 exposure risk score
│   │   │   ├── sarif.py             # SARIF 2.1.0 report builder
│   │   │   ├── remediation.py       # Env-var patch + .env.example generator
│   │   │   └── github_scanner.py    # GitHub API zipball download + extraction
│   │   ├── routers/
│   │   │   ├── scans.py             # Scan CRUD + WebSocket endpoint
│   │   │   ├── export.py            # JSON / CSV export
│   │   │   ├── schedules.py         # Schedule CRUD
│   │   │   └── stats.py             # Dashboard aggregation queries
│   │   └── workers/
│   │       └── scheduler.py         # APScheduler AsyncIOScheduler wrapper
│   ├── seed_demo.py                 # Populate DB with realistic demo data
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── api/client.ts            # Axios client + all TypeScript types
│   │   ├── hooks/useWebSocket.ts    # WebSocket hook (dev + prod URL resolution)
│   │   ├── components/
│   │   │   ├── Layout.tsx           # Sidebar + Outlet wrapper
│   │   │   ├── Navbar.tsx           # Top navigation
│   │   │   ├── SeverityBadge.tsx    # CRITICAL / HIGH / MEDIUM / LOW chip
│   │   │   └── StatusBadge.tsx      # queued / running / completed / failed chip
│   │   └── pages/
│   │       ├── Dashboard.tsx        # KPI cards + Recharts charts
│   │       ├── NewScan.tsx          # Scan form + live WebSocket progress bar
│   │       ├── ScanHistory.tsx      # Searchable scan list with status filters
│   │       ├── ScanDetail.tsx       # Findings grouped by file with remediation
│   │       └── Schedules.tsx        # Cron schedule management UI
│   ├── vercel.json                  # SPA rewrites
│   ├── vite.config.ts
│   └── package.json
├── scanner_core.py                  # Standalone scanner (no FastAPI dependency)
├── cli.py                           # Command-line interface
├── test_scanner.py                  # Unit tests (19 cases)
├── docker-compose.yml               # Full-stack local dev with PostgreSQL
└── render.yaml                      # Render deployment config
```

---

## Deployment

### Backend → Render (free tier)

The `render.yaml` at the repo root fully automates this:

1. Push to GitHub
2. Create a **New Web Service** in [Render](https://render.com) → connect your repo → Render auto-detects `render.yaml`
3. Set `GITHUB_TOKEN` in the Render environment (optional — raises GitHub API rate limit from 60 → 5000 req/hr)
4. Deploy

The start command seeds demo data then starts Uvicorn:
```
python seed_demo.py && uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

> **Note:** Render's free tier sleeps after 15 minutes of inactivity. The frontend automatically pings `/health` on page load to wake it before the user interacts.

### Frontend → Vercel (free tier)

1. Import the repo in [Vercel](https://vercel.com)
2. Set **Root Directory** to `frontend`
3. Add environment variable: `VITE_API_URL=https://your-render-service.onrender.com`
4. Deploy

`vercel.json` handles SPA routing (all paths rewrite to `index.html`).

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | `sqlite+aiosqlite:///./secrets_scanner.db` | SQLite or `postgresql+asyncpg://...` |
| `CORS_ORIGINS` | Yes | — | Comma-separated list of allowed frontend origins |
| `GITHUB_TOKEN` | No | — | GitHub PAT — raises API rate limit to 5,000 req/hr |
| `SMTP_HOST` | No | `smtp.gmail.com` | SMTP server for email alerts |
| `SMTP_PORT` | No | `587` | SMTP port |
| `SMTP_USER` | No | — | SMTP username / Gmail address |
| `SMTP_PASSWORD` | No | — | SMTP password or Gmail App Password |
| `ALERT_EMAIL` | No | — | Recipient address for CRITICAL finding alerts |
| `MIN_ENTROPY` | No | `3.5` | Global entropy threshold (overridden per request) |

---

## Running Tests

```bash
pip install -r requirements.txt
pytest test_scanner.py -v
```

All 19 unit tests cover:
- AWS / GitHub / Stripe / JWT / SSH key detection
- Placeholder suppression (`YOUR_KEY_HERE`, `${VAR}`, `example`, etc.)
- Entropy threshold gating
- Database connection string extraction
- Test-file severity downgrading

---

## Performance Benchmarks

| Metric | Value |
|--------|-------|
| Secret types covered | 26 |
| Precision | ~95% |
| Recall | ~94% |
| F1 Score | ~0.94 |
| False-positive rate | ~5% |
| Scan speed (CLI) | ~1,000 files / sec |

---

## Author

**Udit Agarwal**  
MS Computer Science — Indiana University Bloomington  
[github.com/Udit013](https://github.com/Udit013) · agarwaludit13@gmail.com
