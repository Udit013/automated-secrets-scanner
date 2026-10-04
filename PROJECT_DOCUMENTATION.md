# CipherWatch — Complete Project Documentation

> A single source of truth for understanding this repository from zero prior knowledge to implementation-level depth. Written for interview preparation, onboarding, and recruiter/hiring-manager review.

**Live app:** https://cipherwatch-web.vercel.app
**API:** https://secrets-scanner-api.onrender.com (docs at `/docs`)
**Repo:** https://github.com/Udit013/automated-secrets-scanner

Every claim in this document was verified against the actual source in this repository at documentation time — not assumed, not aspirational. Where a behavior is conditional (e.g. opt-in), that condition is stated explicitly.

---

## Table of Contents

1. [The Problem, In Plain Language](#1-the-problem-in-plain-language)
2. [Who This Is Built For](#2-who-this-is-built-for)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Folder Structure](#4-folder-structure)
5. [The Complete Request Lifecycle](#5-the-complete-request-lifecycle)
6. [Data Model & Database](#6-data-model--database)
7. [The Detection Engine (Core Domain Logic)](#7-the-detection-engine-core-domain-logic)
8. [Backend: File-by-File Walkthrough](#8-backend-file-by-file-walkthrough)
9. [REST API Reference](#9-rest-api-reference)
10. [WebSocket: Real-Time Progress](#10-websocket-real-time-progress)
11. [Background Jobs: Scheduling & Email Alerts](#11-background-jobs-scheduling--email-alerts)
12. [Frontend: File-by-File Walkthrough](#12-frontend-file-by-file-walkthrough)
13. [Every React Component Explained](#13-every-react-component-explained)
14. [State Management & Data Fetching](#14-state-management--data-fetching)
15. [The Design System](#15-the-design-system)
16. [Every Dependency, Explained](#16-every-dependency-explained)
17. [Configuration Files Explained](#17-configuration-files-explained)
18. [Deployment Architecture](#18-deployment-architecture)
19. [Testing Strategy](#19-testing-strategy)
20. [Concept Deep-Dives](#20-concept-deep-dives)
21. [Full Feature Traces (User Action → Screen)](#21-full-feature-traces-user-action--screen)
22. [Design Decisions & Trade-offs](#22-design-decisions--trade-offs)
23. [Known Limitations](#23-known-limitations)
24. [Interview Question Bank](#24-interview-question-bank)
25. [Glossary](#25-glossary)
26. [Complete Walkthrough: Opening the App](#26-complete-walkthrough-opening-the-app)

---

## 1. The Problem, In Plain Language

**Analogy first.** Imagine a company mails out hundreds of letters every day, and occasionally, by accident, someone seals a spare house key inside an envelope along with the letter. Anyone who opens that letter now has a working key to the building. Most of the time nobody notices until something goes wrong.

That is exactly what happens in software. Developers write code that needs secret values — a password to connect to a database, a key to bill a customer's credit card via Stripe, a token to post messages to Slack. To get something working quickly, it's common to type that secret value directly into the source code:

```python
stripe_key = "sk_live_51H8x9K2eZvKYlo2C..."
```

Then that file gets committed to Git and pushed to GitHub. If the repository is public — or later becomes public, or a former employee still has old clones — that secret is now exposed to anyone who can read the code. Attackers run automated scanners against GitHub 24/7 looking for exactly this pattern, and a leaked cloud credential can be found and abused within **minutes** of being pushed.

**CipherWatch is a DevSecOps (Development + Security + Operations) tool that automatically finds these accidentally-committed secrets** before or after they've been pushed to a shared repository, tells you exactly how severe each one is, and tells you how to fix it.

It solves three specific problems:

1. **Detection** — scanning code (and, optionally, the entire commit history of a Git repository) for patterns that look like real credentials, using a combination of exact pattern matching and statistical randomness analysis.
2. **Triage** — not every finding is equally dangerous. A live Stripe secret key in production code is a five-alarm fire; a test API key in a `tests/` folder is not. CipherWatch computes a transparent 0–100 **exposure risk score** and shows its reasoning.
3. **Remediation** — once something dangerous is found, CipherWatch generates the concrete fix (an environment-variable replacement, a `.env.example` snippet, a downloadable patch) so an engineer can act immediately instead of researching what to do.

---

## 2. Who This Is Built For

- **A solo developer or small team** who wants to catch a leaked secret before merging a pull request, without paying for an enterprise security platform.
- **A security-conscious engineer auditing an existing codebase** who wants to know not just *whether* a secret leaked, but *when* it was introduced, *how many commits* it has been sitting in, and *how many people* have had access to it.
- **A DevOps/platform team** that wants a recurring, unattended scan of critical repositories with automatic email alerts when something CRITICAL appears — the same category of tool as commercial products like GitGuardian or TruffleHog, built from scratch to understand the full problem space.

---

## 3. High-Level Architecture

CipherWatch is a classic three-tier web application: a **React single-page app** (the client), a **FastAPI backend** (the server, exposing a REST API + one WebSocket endpoint), and a **relational database** (SQLite in the current free-tier deployment, PostgreSQL-ready). There is no separate microservice layer — the scanning engine, the risk-scoring engine, the SARIF exporter, and the remediation generator are all Python modules that live *inside* the same FastAPI process and are called as plain function calls, not over the network.

```text
┌──────────────────────────────────────────────────────────────────┐
│  BROWSER                                                          │
│  React 18 SPA (Vite build) — served as static files by Vercel     │
│  Pages: Overview / Scans / Scan Report / New Scan / Schedules     │
└───────────────────────────┬────────────────────────────────────┬─┘
                             │ HTTPS (axios, REST JSON)           │ WSS
                             ▼                                    ▼
┌──────────────────────────────────────────────────────────────────┐
│  FASTAPI BACKEND  (Render, uvicorn ASGI server)                   │
│                                                                    │
│   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐  │
│   │  scans      │  │  export    │  │ schedules  │  │  stats    │  │
│   │  router     │  │  router    │  │  router    │  │  router   │  │
│   └──────┬─────┘  └──────┬─────┘  └──────┬─────┘  └─────┬─────┘  │
│          │               │                │              │        │
│          ▼               ▼                ▼              ▼        │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │              scanner/ (pure-Python domain logic)          │   │
│   │  core.py (regex+entropy engine) · patterns.py (26 rules)  │   │
│   │  risk.py (0-100 scoring) · sarif.py · remediation.py      │   │
│   │  github_scanner.py (zipball download + git clone)         │   │
│   └──────────────────────────────────────────────────────────┘   │
│          │                                                         │
│          ▼                                                         │
│   ┌────────────────┐   ┌───────────────────┐   ┌────────────────┐│
│   │ SQLAlchemy 2.0  │   │ APScheduler        │   │ aiosmtplib     ││
│   │ async ORM       │   │ (cron background   │   │ (email alerts) ││
│   │                 │   │  scheduler)         │   │                ││
│   └────────┬────────┘   └───────────────────┘   └────────────────┘│
└────────────┼───────────────────────────────────────────────────────┘
             ▼
┌──────────────────────────────────────────────────────────────────┐
│  DATABASE — SQLite file (Render free tier) or PostgreSQL          │
│  Tables: scans · findings · scan_schedules                        │
└──────────────────────────────────────────────────────────────────┘

              External services this system talks to:
              ┌──────────────────┐   ┌──────────────────┐
              │  GitHub REST API  │   │  SMTP server      │
              │  (zipball + clone)│   │  (Gmail, etc.)     │
              └──────────────────┘   └──────────────────┘
```

**No AI/LLM components exist in this project.** Detection is deterministic (regex + math), not machine-learning-based. This is a legitimate, deliberate design choice explained in [§22](#22-design-decisions--trade-offs).

**No authentication exists in this project.** There is no login, no user accounts, no session management. Every visitor sees the same shared dataset. This is appropriate for a portfolio/demo deployment and is called out explicitly as a limitation in [§23](#23-known-limitations), with a note on what would need to change for multi-tenant production use.

---

## 4. Folder Structure

```text
automated-secrets-scanner/
├── backend/                     # FastAPI application (Python)
│   ├── app/
│   │   ├── main.py              # FastAPI app instance, lifespan, router mounting
│   │   ├── config.py            # Pydantic Settings — reads env vars
│   │   ├── database.py          # SQLAlchemy async engine + session factory
│   │   ├── models.py            # ORM table definitions (Scan, Finding, ScanSchedule)
│   │   ├── schemas.py           # Pydantic request/response contracts + input validation
│   │   ├── notifications.py     # SMTP email alert sender
│   │   ├── scanner/             # The domain logic — pure Python, no FastAPI imports
│   │   │   ├── core.py          # Regex+entropy scan engine, git history walker
│   │   │   ├── patterns.py      # 26 SecretPattern definitions + placeholder filter
│   │   │   ├── risk.py          # 0-100 exposure risk scoring
│   │   │   ├── sarif.py         # SARIF 2.1.0 report builder
│   │   │   ├── remediation.py   # env-var suggestion + patch file generator
│   │   │   └── github_scanner.py# Downloads a GitHub repo as a zip, orchestrates scan
│   │   ├── routers/             # FastAPI route handlers, one file per resource
│   │   │   ├── scans.py         # POST/GET/DELETE scans, WebSocket, diff endpoint
│   │   │   ├── export.py        # JSON/CSV/SARIF/patch export endpoints
│   │   │   ├── schedules.py     # CRUD for recurring scan schedules
│   │   │   └── stats.py         # Dashboard aggregation query
│   │   └── workers/
│   │       └── scheduler.py     # APScheduler wrapper — cron job registration
│   ├── tests/                   # 76 pytest tests (integration, unit, hardening regressions)
│   ├── seed_demo.py             # Populates the DB with realistic demo data
│   ├── requirements.txt         # Production dependencies
│   ├── requirements-dev.txt     # + pytest, pytest-asyncio for CI
│   └── .env.example             # Documented environment variable template
│
├── frontend/                    # React 18 + TypeScript SPA (Vite)
│   ├── src/
│   │   ├── main.tsx             # React root render + TanStack Query provider
│   │   ├── App.tsx              # Router definition, backend wake-up ping
│   │   ├── index.css            # Design-system tokens as Tailwind @layer rules
│   │   ├── api/
│   │   │   └── client.ts        # Axios instance, ALL TypeScript types, API functions
│   │   ├── hooks/
│   │   │   └── useWebSocket.ts  # Custom hook: opens a WS connection per scan
│   │   ├── components/          # Reusable, cross-page UI pieces
│   │   │   ├── TopBar.tsx       # Site header/nav (replaces a traditional sidebar)
│   │   │   ├── Layout.tsx       # Page shell — wraps every route via <Outlet/>
│   │   │   ├── SeverityBadge.tsx
│   │   │   ├── StatusBadge.tsx
│   │   │   ├── RiskBadge.tsx    # Score readout + 10-segment meter
│   │   │   ├── DiffSummary.tsx  # New/resolved/unchanged ledger row
│   │   │   ├── LifecycleTimeline.tsx
│   │   │   └── charts.tsx       # Hand-built SVG charts (no chart library)
│   │   └── pages/                # One component per route
│   │       ├── Dashboard.tsx    # "/" — Overview
│   │       ├── NewScan.tsx      # "/scan" — Launch a scan
│   │       ├── ScanHistory.tsx  # "/history" — All scans, searchable
│   │       ├── ScanDetail.tsx   # "/history/:id" — Full scan report
│   │       └── Schedules.tsx    # "/schedules" — Recurring scans
│   ├── package.json
│   ├── vite.config.ts           # Build tool config, manual chunk splitting
│   ├── tailwind.config.js       # The entire color/type/spacing token system
│   └── tsconfig.json
│
├── cli.py                       # Standalone command-line scanner (argparse-based)
├── scanner_core.py              # Legacy scanner engine used only by cli.py
├── test_scanner.py              # 19 pytest tests for the CLI/legacy engine
├── .github/workflows/ci.yml     # GitHub Actions: 4 CI jobs on every push
├── render.yaml                  # Render.com deployment blueprint (backend)
├── docker-compose.yml           # Local full-stack dev environment (Postgres variant)
└── README.md
```

**Why this split exists.** The backend's `scanner/` package is deliberately framework-agnostic — none of its files import FastAPI, SQLAlchemy, or anything web-related. `core.py`, `patterns.py`, `risk.py`, `sarif.py`, and `remediation.py` operate purely on Python primitives (strings, dataclasses, lists) and can be unit-tested and even reused outside a web server (which is exactly what `cli.py` does with the older sibling engine, `scanner_core.py`). The `routers/` package is the only layer that knows about HTTP, database sessions, and JSON serialization — its job is to translate between "the outside world" (HTTP requests) and "the domain logic" (the scanner package). This is a simplified version of a **hexagonal / ports-and-adapters architecture**: business logic in the center, framework code at the edges.

---

## 5. The Complete Request Lifecycle

This section answers: *what actually happens, in order, when someone uses this application?* Read top to bottom — it is the master trace that every other section elaborates on.

**Step 0 — Cold start.** A visitor opens `https://cipherwatch-web.vercel.app`. Vercel serves a static `index.html` plus three JavaScript bundles (`index-*.js` the app shell, `react-*.js` the React/Router vendor chunk, `data-*.js` the TanStack Query/axios/date-fns vendor chunk) and one CSS file. React mounts into `<div id="root">`.

**Step 1 — Wake the backend.** `App.tsx` fires a `GET /health` request the instant the app mounts (`useWakeBackend` hook, see [§12](#12-frontend-file-by-file-walkthrough)). This exists because the backend is hosted on Render's **free tier**, which spins the server down after 15 minutes of inactivity; the very first real request after a cold start would otherwise take 30–60 seconds. This ping is fired-and-forgotten (errors are swallowed) purely to start the wake-up clock before the user does anything else.

**Step 2 — Route resolves, page fetches data.** `react-router-dom` matches the current URL to a page component. That page's top-level `useQuery` hook (TanStack Query) fires — for the Overview page this is `GET /api/v1/stats`.

**Step 3 — HTTP request travels to FastAPI.** The request hits Render's edge, is proxied to the running `uvicorn` process, and is routed by FastAPI's ASGI router to the matching `@router.get(...)` function based on path + method.

**Step 4 — Dependency injection provides a DB session.** Every route that touches the database declares `db: Annotated[AsyncSession, Depends(get_db)]`. FastAPI calls `get_db()` (an async generator in `database.py`), which opens a new SQLAlchemy `AsyncSession`, yields it into the route function, and — after the route returns — commits the transaction (or rolls it back if an exception was raised).

**Step 5 — Route handler runs its logic.** For `GET /api/v1/stats` this means running five separate aggregate SQL queries (counts, group-bys) via SQLAlchemy's async query builder and assembling them into a `StatsOut` Pydantic model.

**Step 6 — Response serializes and returns.** FastAPI validates the outgoing data against the route's declared `response_model`, serializes it to JSON, and sends it back over HTTPS with the CORS headers `CORSMiddleware` attaches (this is what lets the browser, on a different origin, read the response at all — see [§20](#20-concept-deep-dives) for exactly why this is necessary).

**Step 7 — Frontend receives data, re-renders.** Axios resolves the promise, TanStack Query caches the result under its query key (`['stats']`), and every component subscribed to that query key re-renders with real data instead of the loading placeholder.

**Step 8 — User triggers a write (e.g. "Run scan").** This is the interesting path and is traced in full, line by line, in [§21.1](#211-launching-a-scan-the-complete-trace).

---

## 6. Data Model & Database

### 6.1 Why SQLAlchemy async + why SQLite in production

The ORM (**Object-Relational Mapper** — a library that lets you manipulate database rows as Python objects instead of writing raw SQL) is **SQLAlchemy 2.0**, used through its async API (`AsyncSession`, `create_async_engine`). Every database call in this codebase is `await`ed. This matters because FastAPI runs on an async event loop — a *synchronous* blocking database call would freeze that entire event loop, stalling every other in-flight request on the server (not just the one making the DB call), for the duration of the query.

**Simple explanation:** imagine one cashier serving a whole line of customers. If handling one customer's request means the cashier has to walk to a back room and can't help anyone else in the meantime, that's *synchronous*. If instead the cashier can start six people's orders cooking at once and switch between them while each one waits, that's *asynchronous* — the same cashier serves far more people in the same amount of time.

**Technical explanation:** Python's `asyncio` runs a single-threaded event loop. An `async def` function that reaches an `await` on I/O (a network call, a disk read) yields control back to the loop, which can run other pending coroutines during that wait. A blocking call inside an async function never yields, so it monopolizes the loop.

**Why SQLite, not Postgres, in the live deployment:** `render.yaml` sets `DATABASE_URL=sqlite+aiosqlite:///./secrets_scanner.db`. This is a deliberate zero-cost choice for a free-tier deployment: SQLite needs no separate hosted database service, has zero monthly cost, and requires zero connection-pool tuning. `database.py` special-cases this:

```python
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    **({} if "sqlite" in settings.DATABASE_URL else {"pool_size": 10, "max_overflow": 20}),
)
```

Connection **pool sizing** (keeping a set of reusable open connections rather than opening a new TCP connection per query) only applies to network databases like Postgres — SQLite is a local file, so pool settings are meaningless there and are skipped. The **same code path** (the ORM models, the queries, `init_db()`) works against Postgres unchanged — the `docker-compose.yml` local dev environment proves this by running Postgres 16 instead, and `asyncpg` (the async Postgres driver) is already listed in `requirements.txt`. Switching the deployed database to Postgres is a one-line `DATABASE_URL` change, not a code change.

### 6.2 Schema

Three tables, defined in `backend/app/models.py` using SQLAlchemy 2.0's typed `Mapped[...]` declarative style:

```text
┌─────────────────────────┐          ┌──────────────────────────────┐
│  scans                  │          │  findings                     │
├─────────────────────────┤  1    N  ├────────────────────────────────┤
│ id (PK, uuid4 str)       │─────────▶│ id (PK, uuid4 str)             │
│ source_type              │          │ scan_id (FK → scans.id,        │
│ source_ref                │          │   ON DELETE CASCADE)          │
│ scan_git_history          │          │ file_path, line_number         │
│ max_commits                │          │ secret_type, matched_string    │
│ min_entropy                 │          │ entropy, severity, confidence   │
│ status                       │          │ context, commit_hash            │
│ total_findings                │          │ remediation, is_in_history        │
│ files_scanned                   │          │ risk_score, risk_factors (JSON)     │
│ progress                          │          │ occurrences                          │
│ error_message                       │          │ introduced_at, last_seen_at            │
│ created_at, completed_at              │          │ exposure_days, commits_affected          │
└─────────────────────────┘          │ authors_count                              │
                                       └──────────────────────────────┘

┌────────────────────────────┐
│  scan_schedules              │   (independent — no FK to scans;
├────────────────────────────┤    tracks last_scan_id as a loose string
│ id (PK, uuid4 str)           │    reference for convenience)
│ name                           │
│ source_type, source_ref         │
│ cron_expression                   │
│ scan_git_history                    │
│ enabled                               │
│ last_run_at, next_run_at                │
│ last_scan_id                              │
│ created_at                                  │
└────────────────────────────┘
```

**Relationship:** `Scan.findings` is a SQLAlchemy `relationship()` with `cascade="all, delete-orphan"` and `lazy="selectin"`. Two consequences:
- **`delete-orphan` cascade** — deleting a `Scan` row automatically deletes every `Finding` row that points to it. This is why `DELETE /api/v1/scans/{id}` needs no explicit cleanup code; `await db.delete(scan)` is sufficient.
- **`lazy="selectin"`** — when a `Scan` is loaded, SQLAlchemy immediately issues a second query to eagerly fetch all its findings (rather than lazily fetching them the first time `.findings` is accessed, which would require a live database connection at serialization time — a common source of the `MissingGreenlet` / detached-instance errors that plague naive async SQLAlchemy code).

**IDs are UUID4 strings, not auto-incrementing integers.** `_uuid()` generates `str(uuid.uuid4())` as the default for every primary key. This avoids ID collisions if data is ever merged across databases, and avoids leaking a monotonic "how many scans have ever been run" count to anyone who can see one ID.

**Timestamps are stored as naive (timezone-unaware) UTC.** SQLite has no native timezone-aware datetime type, so `utcnow_naive()` explicitly strips timezone info after getting the current UTC time:

```python
def utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
```

This is a fix for a previously-encountered bug: the original code called the now-deprecated `datetime.utcnow()`; the fix computes the timezone-*aware* current time first (the correct, non-deprecated way to get "now" in UTC) and only then discards the tzinfo, to store a value that's still numerically correct while matching SQLite's untyped storage.

### 6.3 Lifecycle fields — populated conditionally

`Finding.introduced_at`, `last_seen_at`, `exposure_days`, `commits_affected`, and `authors_count` are all **nullable**, and this is meaningful, not an oversight. They are populated **only** when a scan explicitly requests git-history scanning (`scan_git_history=True`, an opt-in checkbox in the UI, off by default). A plain current-tree scan never touches git history and these fields stay `None` for every finding it produces. See [§7.3](#73-git-history-scanning-opt-in) for exactly how they get computed.

### 6.4 CRUD in practice

**Create** — `INSERT` happens in two places: `POST /api/v1/scans` creates a `Scan` row immediately (status `"queued"`, no findings yet), then a background task creates zero-or-more `Finding` rows once scanning finishes. `POST /api/v1/schedules` inserts one `ScanSchedule` row.

**Read** — every list endpoint uses `select(...).order_by(...).limit(...).offset(...)` for pagination; every single-record endpoint uses `await db.get(Model, id)`, SQLAlchemy's primary-key shortcut (equivalent to `SELECT * FROM table WHERE id = ?` but with identity-map caching).

**Update** — updates are done by loading an ORM object, mutating its attributes in Python, and relying on SQLAlchemy's **unit-of-work pattern**: the session tracks which loaded objects have changed and auto-generates the correct `UPDATE` statement at commit time. Nowhere in this codebase is a raw `UPDATE` statement written by hand. Example, from `_run_scan`:
```python
scan.status = "completed"
scan.total_findings = len(findings)
await db.commit()   # SQLAlchemy diffs the object and emits UPDATE scans SET status=..., total_findings=... WHERE id=...
```

**Delete** — `await db.delete(scan)` followed by `await db.commit()`; the cascade (§6.2) handles child rows.

---

## 7. The Detection Engine (Core Domain Logic)

This is the heart of the product. It lives entirely in `backend/app/scanner/core.py` and `patterns.py`, and it is **pure Python with zero external API calls** — everything here runs locally in the process, deterministically, on text already in memory.

### 7.1 The three-layer pipeline

```text
line of source code
        │
        ▼
┌───────────────────────┐
│ 1. Comment skip        │  Lines starting with # // <!-- -- (but never
│                        │  "-----BEGIN", which would wrongly hide PEM keys)
└──────────┬─────────────┘
           ▼
┌───────────────────────┐
│ 2. Regex pattern match  │  26 SecretPattern rules run in sequence.
│    (patterns.py)         │  Format-specific patterns (AWS key shape, Stripe
│                            │  key shape, etc.) match with high confidence.
└──────────┬─────────────────┘
           ▼
┌───────────────────────┐
│ 3. Placeholder filter   │  is_placeholder() rejects fixtures/examples
│    (patterns.py)          │  ("YOUR_KEY_HERE", "${API_KEY}", low-entropy
│                             │  bare words) before they're ever reported.
└──────────┬──────────────────┘
           ▼
┌───────────────────────┐
│ 4. Entropy gate          │  Non-format-specific patterns (Generic API Key,
│    (_shannon_entropy)     │  Generic Secret, Hardcoded Password) must also
│                             │  clear a minimum randomness threshold.
└──────────┬──────────────────┘
           ▼
┌───────────────────────┐
│ 5. Severity + risk score  │  Test-file findings get downgraded one level.
│    (risk.py)                │  compute_risk_score() produces 0-100 + reasons.
└──────────┬──────────────────┘
           ▼
      Finding object
```

### 7.2 Pattern matching — `patterns.py`

Each of the **26 patterns** is a `SecretPattern` dataclass:

```python
@dataclass
class SecretPattern:
    name: str              # e.g. "AWS Access Key"
    regex: str              # the detection regex
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    format_specific: bool      # if True, skip the entropy check entirely
    remediation: str             # human-readable fix instructions
```

Example — the AWS Access Key pattern:
```python
SecretPattern(
    name="AWS Access Key",
    regex=r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
    severity="CRITICAL",
    format_specific=True,
    remediation="1. Immediately revoke this key in AWS IAM Console...",
)
```
`(?<![A-Z0-9])` and `(?![A-Z0-9])` are **negative lookaround assertions** — they require the match to *not* be immediately preceded or followed by another alphanumeric character, preventing a partial match inside a longer random string from being flagged as a real AWS key.

The 26 covered credential types span AWS, GCP, GitHub (PAT/OAuth/App tokens), Stripe (live/test), Slack (bot/app tokens), Twilio, SendGrid, private SSH/PGP keys, JWTs, database connection strings (Postgres/MySQL/Mongo/Redis/MSSQL/Oracle), Azure (storage keys, SAS tokens), npm/PyPI publish tokens, Discord bot tokens, and Mailgun keys — plus three **generic, non-format-specific** catch-alls (Generic API Key, Generic Secret, Hardcoded Password) that rely on entropy rather than a fixed shape.

**Placeholder detection** (`is_placeholder`) is what keeps precision usable — without it, every `API_KEY="your_key_here"` in a README would be flagged as a real leak. It runs 14 regex patterns (`example`, `${VAR}`, `<PLACEHOLDER>`, `xxx...`, ends with `_here`, etc.). Most placeholder words require a word boundary so real keys such as Stripe's `sk_test_…` are not suppressed, but `example` matches anywhere because vendor documentation embeds it mid-token — AWS's own sample key `AKIAIOSFODNN7EXAMPLE` would otherwise be reported as a CRITICAL leak. The rules run alongside two structural heuristics: strings shorter than 8 characters are rejected outright, and strings with a **unique-character ratio below 0.3** (fewer than 30% of characters are distinct — i.e., highly repetitive, like `"aaaaaaaaaa"`) are rejected as unlikely to be real secrets.

**Test-file downgrading** (`is_test_file` + `_downgrade`) checks the file path against patterns like `/tests?/`, `.spec.`, `_test\.py` and, if matched, moves the severity one step down the ladder (`CRITICAL → HIGH → MEDIUM → LOW`, capped at `LOW`). A hardcoded password in `tests/fixtures.py` is real code smell but far less urgent than the same string in `payment/stripe.py`.

### 7.3 Entropy analysis — Shannon entropy

**Simple explanation:** entropy measures how "random-looking" a string is. The word `"password"` is entropy-*low* — it's made of common letters in a predictable order, and if you know part of it you can often guess the rest. A string like `"kX9#mQ2$vL8pR4nZ"` is entropy-*high* — every character is close to unpredictable given the ones around it. Real cryptographic secrets, being generated by a computer's random-number generator, are almost always high-entropy; English words and simple test values are almost always low-entropy.

**Technical explanation:** the implementation is Shannon's information-entropy formula, applied per-character over the candidate string:

```python
def _shannon_entropy(data: str) -> float:
    counts: dict[int, int] = {}
    for ch in data:
        counts[ord(ch)] = counts.get(ord(ch), 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
```

For each distinct character, compute its frequency `p = count / n`, then sum `-p * log2(p)` across all distinct characters. The result is the average number of bits of "surprise" per character. A string using only one repeated character has entropy 0 (zero surprise — you already know the next character). A string using many characters in roughly equal proportion approaches `log2(alphabet size)` — for a 62-character alphanumeric alphabet, the theoretical maximum is about 5.95 bits/char.

**Why entropy alone isn't enough (and why patterns run first):** entropy has no concept of *meaning* — a random English sentence isn't high-entropy, but neither is a hash of the word "password", which is dangerous but predictable. That's why entropy is used as a **secondary gate**, not the primary detector: format-specific patterns (`format_specific=True`, like the AWS key shape) skip the entropy check entirely and rely purely on the exact structural match, while only the three generic catch-all patterns (which have no fixed shape to match against) require the matched text to also clear the entropy threshold (default `3.5` bits, user-configurable per scan between 0 and 8).

### 7.4 Confidence, severity, and masking

- **Confidence** (`_confidence`) is a coarse `HIGH`/`MEDIUM`/`LOW` label derived from whether the match was pattern-based and how high its entropy is — pattern match + entropy > 4.5 = `HIGH`.
- **Severity** comes directly from the matched `SecretPattern.severity`, then possibly downgraded for test files (§7.2).
- **Masking** (`_mask`) keeps the first and last four characters (`AKIAV3WBCDEF4GHI7JKM` → `AKIA************7JKM`) — enough to tell *which* credential to rotate, not enough to use it. It applies to two persisted fields: `matched_string`, and `context` (the source line). `context` masks *every* secret detected on that line (`_mask_secrets_in`), so a line holding two secrets never leaks the other one through either finding. For paste scans, the pasted text itself is never written to the database: `source_ref` stores `paste:<first 12 hex chars of its SHA-256>` and the content reaches the scan task only in memory. Identical pastes produce the same label, so re-scanning the same content still finds a differential baseline.
  *History note:* before the October 2026 hardening pass, `context` stored the raw line and `source_ref` stored the full pasted content, so secrets were returned by the API and every export. Any database populated before that change still contains them.

### 7.5 Git history scanning — opt-in

This is the feature that differentiates CipherWatch from a simple "grep for AWS keys" script. A secret **removed** from the current version of a file is still permanently present in that file's older commits — `git log` never forgets. `scan_git_history()` (in `core.py`) walks a repository's commit history to catch exactly this case.

**Critical detail: this is not automatic.** It runs only when the "Include git history" checkbox is checked in the New Scan form (`scan_git_history: bool = False` by default on both the `Scan` model and the `StartScanRequest` schema). A default scan only ever examines the current working tree. This is a deliberate cost/thoroughness trade-off, made explicit here rather than glossed over: history scanning means **re-scanning the full file tree at every single commit** — `O(commits × files)`, not a diff between consecutive commits — so it's meaningfully slower, and paying that cost by default on every scan would be wasteful for the common case where a user just wants a quick check of the current state.

```python
commits = list(repo.iter_commits("HEAD", max_count=max_commits))
for commit in commits:
    for item in commit.tree.traverse():          # every file, at this commit
        if item.type != "blob": continue
        content = item.data_stream.read().decode(...)
        for f in scan_text(content, item.path, min_entropy,
                           commit_hash=short_sha, is_history=True):
            key = (f.file_path, f.secret_type, f.matched_string)
            # aggregate: same secret seen in multiple commits collapses to ONE finding
            ...
```

Findings are **de-duplicated by `(file_path, secret_type, matched_string)`** and aggregated across every commit they appear in. This is why a secret sitting in 9 commits surfaces once, with a complete exposure picture, instead of nine separate findings for the same leak. The aggregation tracks:
- `first_dt` / `last_dt` — earliest and latest commit timestamps the secret appeared in → `introduced_at`, `last_seen_at`
- `exposure_days = (last_dt - first_dt).days`
- `commits` (a `set` of short SHAs) → `commits_affected = len(commits)`
- `authors` (a `set` of lowercased emails/names) → `authors_count = len(authors)`

Once history walking finishes, **risk is recomputed** using this richer context (`compute_risk_score(..., is_in_history=True, occurrences=..., exposure_days=..., authors_count=...)`) — a secret's risk score is genuinely higher once its full exposure history is known, which is exactly the intended behavior.

### 7.6 The exposure risk model — `risk.py`

**Simple explanation:** not every leaked secret is equally scary. A test API key that's been in one commit for one day is a minor issue; a live payment-processor secret key that's been sitting in history for three months, touched by five different developers, is an emergency. The risk score turns "how bad is this, really?" into a single number you can sort and filter by, with a plain-English list of *why*.

**Technical explanation:** it is a **deliberately transparent, additive heuristic** — explicitly not a black-box ML model. Every point added to the score comes with a human-readable reason string, so the score can be explained and defended, not just trusted:

```python
_SEVERITY_BASE = {"CRITICAL": 55, "HIGH": 35, "MEDIUM": 18, "LOW": 8}

def compute_risk_score(severity, *, is_in_history=False, occurrences=1,
                        exposure_days=None, authors_count=None, entropy=0.0):
    score = _SEVERITY_BASE[severity]                       # start from severity
    if is_in_history:            score += 18                # present in git history
    if occurrences > 1:          score += min((occurrences-1)*3, 12)  # capped bonus
    if exposure_days:            score += 5 to 15 (tiered)   # longer exposure = worse
    if authors_count > 1:        score += 5                  # more people had access
    if entropy >= 5.0:           score += 5                  # very random-looking
    return min(score, 100), factors   # hard cap at 100
```

Each contributing rule appends a factor string (`"Present in Git history"`, `"Extended exposure (10 days)"`, `"Touched by 3 authors"`) to a list that ships alongside the score all the way to the UI, where it renders as the "Contributing factors" list under an expanded finding. `risk_band()` collapses the numeric score into a coarse `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` label (thresholds at 80/55/30) used for UI color-coding.

### 7.7 SARIF export — `sarif.py`

**SARIF (Static Analysis Results Interchange Format)** is an OASIS-standard JSON schema for representing the output of any static-analysis tool in a common shape, so that different tools' results can be consumed by the same downstream systems. `sarif.py` builds a **2.1.0-conformant** document: one `rule` per distinct secret type seen in the scan (deduplicated), one `result` per finding with a `physicalLocation` (file + line) and a `partialFingerprints` value (`file_path:secret_type:matched_string`) that lets a consumer track the same finding across multiple scans even if line numbers shift. Severity maps to SARIF's `level` (`error`/`warning`/`note`) and to a numeric `security-severity` (0.0–10.0) that GitHub's Security tab uses for its own severity coloring. This exact format is what GitHub Advanced Security's code-scanning upload API expects — a SARIF file from this endpoint can be uploaded directly and will populate GitHub's native Security → Code scanning alerts view.

### 7.8 Remediation generation — `remediation.py`

Given a finding, `remediation.py` answers "what do I actually type to fix this?" without needing repository write access or opening a pull request (a deliberately lightweight approach — see [§22](#22-design-decisions--trade-offs)). It:
1. Derives an environment-variable name — preferring the *original* identifier from the source line if one is parseable (`stripe_key = "..."` → `STRIPE_KEY`), falling back to a curated map of 26 conventional names (`AWS Access Key` → `AWS_ACCESS_KEY_ID`) if not.
2. Detects the file's language from its extension and produces an idiomatic replacement line — `os.getenv(...)` for Python, `process.env.X` for Node, `ENV["X"]` for Ruby, `os.Getenv(...)` for Go, `getenv(...)` for PHP, `${X}` for a `.env` file.
3. Assembles a `.env.example` snippet (deduplicated across all findings in the scan) and a numbered list of next steps (rotate the credential, move it to a secrets manager, update CI/CD secrets, add `.gitignore` rules, purge from git history if needed).
4. Optionally formats all of the above as a downloadable `remediation.patch` — a unified-diff-*styled* text file (grouped by file, `@@ line N — TYPE (SEVERITY) @@` hunks with `-before`/`+after`). It is explicitly documented as **not guaranteed to `git apply` cleanly**, since the stored `matched_string` is masked, not the real secret — it's meant to give an engineer an exact, copy-pasteable before/after per finding, not a robotic auto-fix.

---

## 8. Backend: File-by-File Walkthrough

### `backend/app/config.py`
**Purpose:** the single place environment variables are read. Uses `pydantic-settings`'s `BaseSettings`, which auto-populates every declared field from environment variables of the same name (and from a local `.env` file if present) with full type validation and coercion (`SMTP_PORT: int` will reject a non-numeric value at startup, not at first use).
**Imported by:** almost every other backend module (`database.py`, `routers/scans.py`, `notifications.py`, `github_scanner.py`) via `from .config import settings`, a single shared instance instantiated once at import time.
**Why it exists:** centralizes configuration so no file reads `os.environ` directly, and so all defaults live in one auditable place.

### `backend/app/database.py`
**Purpose:** creates the async SQLAlchemy engine and session factory; defines `Base` (the declarative base every model inherits); provides `init_db()` (creates tables if they don't exist — called once at app startup) and `get_db()` (the FastAPI dependency every route uses to get a session).
**Executes:** `init_db()` runs once, at process startup, inside `main.py`'s `lifespan`. `get_db()` runs once *per incoming request* that declares it as a dependency.
**Relationship with other files:** everything that touches the database imports from here.

### `backend/app/models.py`
Covered in depth in [§6.2](#62-schema). Defines the three ORM classes and the two shared helper functions `_uuid()` and `utcnow_naive()`.

### `backend/app/schemas.py`
**Purpose:** defines every Pydantic model used at the HTTP boundary — both the shape of data coming *in* (`StartScanRequest`, `ScheduleCreate`) and the shape of data going *out* (`ScanOut`, `FindingOut`, `StatsOut`, `ScanDiffOut`). This is the layer where **input validation** lives.

The two "in" models both route through a shared `_validate_source()` helper via Pydantic's `@model_validator(mode="after")` (runs after individual-field validation, when the whole object is assembled, so it can see both `source_type` and `source_ref` together):

```python
def _validate_source(source_type: str, source_ref: str) -> str:
    if not source_ref.strip():
        raise ValueError("source_ref must not be empty")
    if source_type == "github":
        candidate = source_ref.strip().removesuffix(".git")
        if not _GITHUB_URL_RE.match(candidate):
            raise ValueError("source_ref must be a GitHub repository URL like https://github.com/owner/repo")
        return candidate.rstrip("/")
    if len(source_ref.encode("utf-8")) > MAX_PASTE_BYTES:  # 512 KB
        raise ValueError(f"Pasted content exceeds 512 KB limit")
    return source_ref
```
This is a **public-facing API with no authentication**, so it is hardened defensively: GitHub URLs are checked against a strict regex allow-list (`https://github.com/{owner}/{repo}`, normalizing away a trailing `.git` or `/`) rather than accepted as arbitrary strings, and pasted-code submissions are capped at 512 KB to prevent someone from submitting gigabytes of text as a denial-of-service vector. `ScheduleCreate` is stricter still. It accepts only `github` sources (pasted content is never stored, so there is nothing to rescan). Its `cron_expression` is parsed with the same `CronTrigger` APScheduler uses, so an out-of-range field such as `99 * * * *` is rejected with a 422 instead of failing later as a 500. It also samples the next fire times and rejects anything that runs more often than **every 15 minutes**: schedules execute unattended against a public, unauthenticated API, and an every-minute history scan would monopolize the server.

### `backend/app/notifications.py`
**Purpose:** sends a single HTML email via `aiosmtplib` (an async SMTP client — chosen, like everything else in this backend, so a slow network call to an external SMTP server never blocks the event loop) when a scan produces CRITICAL findings.
**When it executes:** called (as a fire-and-forget `asyncio.create_task(...)`, not awaited directly) from `routers/scans.py` at the end of `_run_scan()`, only if `critical > 0`.
**Fails safe:** the send is wrapped in `try/except` that logs a warning — a broken SMTP config or a transient network failure must never crash or fail a scan; the scan result is already saved regardless of whether the email succeeds.
**Escapes user input:** the scan source is user-supplied, so it (and the scan id and report URL) pass through `html.escape` before going into the HTML body — otherwise a crafted source could inject markup or links into an email sent from a trusted address. Paste scans are labelled `pasted content` in the email; the pasted text itself is never included.
**Task lifetime:** the caller keeps a strong reference to the `create_task` handle in a module-level set until it finishes, because asyncio holds only weak references to tasks and an unreferenced one can be garbage-collected mid-send.
**Silently skips if unconfigured:** the function's first line checks `if not all([SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL]): return` — so on a fresh deployment with no SMTP env vars set, this is simply a no-op, not an error.

### `backend/app/main.py`
**Purpose:** the FastAPI application entrypoint — where the four routers get mounted under the shared `/api/v1` prefix, where CORS is configured, and where the app's startup/shutdown behavior is defined.
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()                                   # create missing tables
    interrupted = await scans.mark_interrupted_scans()  # fail scans a restart cut off
    start_scheduler()                                 # boot APScheduler
    restored = await restore_schedules()              # rebuild jobs from the DB
    yield                                             # app serves requests here
    stop_scheduler()                                  # graceful shutdown
```
The two reconciliation steps exist because both pieces of state they repair live only in process memory. Background scans die with the process, so `mark_interrupted_scans()` marks anything still `queued`/`running` as `failed` rather than reporting it as running forever. APScheduler's job store is also in memory, so without `restore_schedules()` every restart — and the free tier sleeps after 15 idle minutes — would silently drop every schedule while the database and UI still showed them armed.
This is FastAPI's **lifespan context manager** pattern — code before `yield` runs at startup, code after runs at shutdown, replacing the older, separately-declared `@app.on_event("startup")`/`@app.on_event("shutdown")` handlers with a single readable block.
**Also defines** the one route not inside a router: `GET /health`, used by the frontend's wake-up ping and by Render's own health checks.

### `backend/app/routers/scans.py`
The largest and most important router — covered function-by-function in [§9](#9-rest-api-reference) and [§10](#10-websocket-real-time-progress). Owns: scan creation, listing, single-scan retrieval, findings listing/filtering, the diff endpoint, deletion, and the WebSocket endpoint. Also owns `_run_scan()`, the private async function that does the actual work of running a scan in the background (see the full trace in [§21.1](#211-launching-a-scan-the-complete-trace)).
**Pasted content is never persisted.** `start_scan` stores `source_ref = paste_label(content)` — `paste:` plus the first 12 hex characters of the content's SHA-256 — and hands the content itself to `_run_scan` as an in-memory argument. Pasted text contains exactly the secrets being scanned for, and before this change it was stored whole and returned by `GET /scans`, the SARIF export, and the alert email. Identical pastes produce the same label, so re-scanning the same content still finds a differential baseline.
**Scanning runs off the event loop.** `scan_text` is CPU-bound, so `_run_scan` calls it through `asyncio.to_thread`; otherwise one scan would freeze every other request, health check, and progress broadcast for its full duration.

### `backend/app/scanner/github_scanner.py`
**Purpose:** fetch a public GitHub repository and run the detection engine over it, optionally including git history.
**Download:** the repository is fetched as a single zipball from the GitHub API (no `git clone` needed for the current tree) and **streamed to a temp file**, never held in memory. The stream aborts past `MAX_ARCHIVE_BYTES` (100 MB).
**Extraction (`_safe_extract`):** before a single byte is decompressed, the zip's central directory is checked against `MAX_ARCHIVE_MEMBERS` (50,000 files) and `MAX_EXTRACTED_BYTES` (500 MB uncompressed — the zip-bomb guard), and every member path is resolved to confirm it stays inside the destination (the zip-slip guard). Validating everything first means a bad archive never leaves a partial extraction behind.
**Concurrency:** extraction, the directory scan, and the history clone-and-walk all run via `asyncio.to_thread`. Measured on `pallets/flask`, this cut the longest event-loop stall from 458 ms to 29 ms for a current-tree scan and from **21 s to 25 ms** for a scan with history, with total scan time unchanged.
**History is best-effort:** if the clone or history walk fails, the current-tree findings are still returned and the failure is logged.

### `backend/app/routers/export.py`
Four `GET` endpoints, all following the same shape: load the scan + its findings, hand them to a pure function in `scanner/` (`build_sarif`, `build_remediation`, `build_patch`), and stream the result back as a file download via `StreamingResponse` with a `Content-Disposition: attachment` header (which is what makes a browser download the response instead of displaying it inline). `json`/`csv`/`sarif`/`patch` are downloads; `remediation` returns plain JSON (meant to be consumed by a UI, not downloaded).

### `backend/app/routers/schedules.py`
Standard CRUD for `ScanSchedule` rows, with one twist: every mutation also calls into `workers/scheduler.py` to keep the **in-memory APScheduler job registry** in sync with the database — creating a schedule registers a cron job, toggling `enabled` pauses/resumes that job, deleting removes it. The database row and the scheduler's live job are two separate pieces of state that must be kept consistent by every mutating endpoint (see [§11](#11-background-jobs-scheduling--email-alerts) for why this dual-state exists and its implications).

### `backend/app/routers/stats.py`
One endpoint, `GET /api/v1/stats`, that powers the Overview dashboard. Runs five separate queries: total scan count, total finding count, per-severity counts (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), a `GROUP BY secret_type` for the "most detected" ranking (capped at top 20), the five most recent scans, and a `GROUP BY date(created_at)` for the findings-over-time trend chart (capped at 30 rows). All aggregation happens in SQL, not in Python — the database counts rows so the application server never has to load every finding into memory just to count them.

### `backend/app/workers/scheduler.py`
Covered in [§11](#11-background-jobs-scheduling--email-alerts).

### `backend/seed_demo.py`
A standalone script (run once, at Render deploy time, via `render.yaml`'s `startCommand`) that inserts realistic demo data — 8 pre-built scans across 7 fictional `acme-corp` repositories with 44 total findings, correct risk scores computed through the real `compute_risk_score()` function, and simulated lifecycle data for git-history findings — so a first-time visitor to the live deployment sees a populated dashboard instead of an empty one. It checks `if count >= len(DEMO_SCANS): return` first, so re-running it on every deploy is idempotent and never duplicates data.

---

## 9. REST API Reference

All routes are mounted under `/api/v1` except `/health`. Interactive Swagger docs are auto-generated by FastAPI at `/docs` on the live deployment.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/scans` | Start a new scan (returns immediately, `202 Accepted`) |
| `GET` | `/api/v1/scans` | List scans, paginated |
| `GET` | `/api/v1/scans/{id}` | Get one scan + all its findings |
| `GET` | `/api/v1/scans/{id}/findings` | Findings only, filterable by severity/type |
| `GET` | `/api/v1/scans/{id}/diff` | Compare against the previous scan of the same source |
| `DELETE` | `/api/v1/scans/{id}` | Delete a scan (cascades to its findings) |
| `WS` | `/api/v1/scans/ws/{id}` | Live progress stream for one scan |
| `GET` | `/api/v1/export/{id}/json` | Download full results as JSON |
| `GET` | `/api/v1/export/{id}/csv` | Download findings as CSV |
| `GET` | `/api/v1/export/{id}/sarif` | Download SARIF 2.1.0 (GitHub Advanced Security compatible) |
| `GET` | `/api/v1/export/{id}/remediation` | Structured remediation report (JSON) |
| `GET` | `/api/v1/export/{id}/patch` | Download remediation.patch |
| `GET` | `/api/v1/stats` | Dashboard aggregate statistics |
| `POST` | `/api/v1/schedules` | Create a recurring scan schedule |
| `GET` | `/api/v1/schedules` | List all schedules |
| `GET` | `/api/v1/schedules/{id}` | Get one schedule |
| `PATCH` | `/api/v1/schedules/{id}/toggle` | Enable/pause a schedule |
| `DELETE` | `/api/v1/schedules/{id}` | Delete a schedule |
| `GET` | `/health` | Liveness check |

### `POST /api/v1/scans`

**Request body** (`StartScanRequest`):
```json
{
  "source_type": "github",
  "source_ref": "https://github.com/owner/repo",
  "scan_git_history": false,
  "max_commits": 100,
  "min_entropy": 3.5
}
```
**Validation** (in `schemas.py`, described in §8): `source_type` must be exactly `"github"` or `"paste"` (regex-pattern-constrained field); if `github`, `source_ref` must match the GitHub-URL allow-list; if `paste`, `source_ref` must be non-empty and under 512 KB; `max_commits` is clamped `1–1000`; `min_entropy` is clamped `0.0–8.0`.
**Processing:** inserts a `Scan` row with `status="queued"` (for pastes, `source_ref` is stored as a `paste:<digest>` label, never the content), registers `_run_scan` as a FastAPI `BackgroundTask` — passing pasted content to it in memory — and returns before that task has run — the client gets the new scan's `id` immediately and is expected to open a WebSocket (or poll `GET /scans/{id}`) to observe progress.
**Response:** `202 Accepted`, body is a `ScanListItem` (the just-created row, `status: "queued"`).
**Errors:** `422 Unprocessable Entity` with a Pydantic-formatted `detail` array if validation fails (e.g. a non-GitHub URL, an oversized paste).

**Example response:**
```json
{
  "id": "1797b0e5-...",
  "source_type": "github",
  "source_ref": "https://github.com/owner/repo",
  "status": "queued",
  "total_findings": 0,
  "files_scanned": 0,
  "progress": 0,
  "created_at": "2026-07-27T10:30:00",
  "completed_at": null
}
```

### `GET /api/v1/scans/{scan_id}/diff`
**Processing:** looks up the most recent *other, completed* scan sharing the same `source_ref` (`Scan.created_at < this_scan.created_at`, ordered descending, `limit(1)`). If none exists, returns `{"has_baseline": false, "current_total": N}` immediately. Otherwise, both scans' findings are loaded and each is reduced to a stable identity key: `(file_path, secret_type, matched_string)` — deliberately **not** including `line_number`, because a single unrelated line added earlier in a file would shift every subsequent finding's line number without the secret itself having moved. Python `set` difference (`cur_map.keys() - base_map.keys()`) computes new vs. resolved vs. unchanged in three operations.
**This is computed on demand, not stored** — every call to this endpoint re-runs the comparison; there's no cached "diff" table.

### `GET /api/v1/export/{scan_id}/sarif`
**Response headers:** `Content-Type: application/sarif+json`, `Content-Disposition: attachment; filename="scan_XXXXXXXX.sarif"`.
**Files involved:** `routers/export.py` → `scanner/sarif.py`.
**Execution flow:** load scan + findings from DB → `build_sarif(scan, findings)` (pure function, §7.7) → `json.dumps(..., indent=2)` → stream as bytes.

---

## 10. WebSocket: Real-Time Progress

**Simple explanation:** a normal web request is like sending a letter and waiting for a reply — one question, one answer, then the conversation ends. A WebSocket is like opening a phone line and leaving it connected: either side can speak at any time without hanging up and redialing. Here, the server uses that open line to shout out progress updates ("20% done… 80% done… complete!") as they happen, instead of the browser having to keep calling back and asking "are you done yet?"

**Technical explanation:** `GET /api/v1/scans/ws/{scan_id}` is a WebSocket endpoint (`@router.websocket(...)`), which starts as a normal HTTP request but is *upgraded* to a persistent, bidirectional TCP connection via the `Upgrade: websocket` handshake. Once accepted, the connection stays open until either side closes it.

**Honest architectural note — this connection is push-only in practice.** The handler is:
```python
@router.websocket("/ws/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    _ws_registry.setdefault(scan_id, []).append(websocket)
    try:
        while True:
            await asyncio.sleep(30)     # keeps the coroutine alive; never reads client input
    except WebSocketDisconnect:
        ...  # cleanup on close
```
The server never calls `websocket.receive_...()`, and the frontend's `useWebSocket` hook never calls `.send()`. The client only *listens*. This means the channel is functionally identical to Server-Sent Events (SSE) — a simpler, HTTP-based, auto-reconnecting one-way push protocol. WebSocket was the tool reached for when this feature was built; there's no bidirectional control (no cancel/pause message ever sent by the client), so if this were rebuilt today, SSE would arguably be the leaner choice for this exact use case. This is a legitimate trade-off to be able to discuss plainly rather than justify with an invented requirement.

**The in-memory registry:**
```python
_ws_registry: dict[str, list[WebSocket]] = {}
```
Maps a `scan_id` to every currently-open socket watching that scan (supporting multiple browser tabs watching the same scan). `_broadcast(scan_id, payload)` iterates that list and `send_text()`s a JSON payload to each; any socket that throws (already disconnected) is collected and pruned from the registry after the loop.

**This registry is per-process, in-memory, non-persistent** — it lives only in the Python process's RAM. This is a scaling limitation worth naming honestly: if the backend ever ran as more than one process/instance behind a load balancer, a client connected to instance A would never receive a broadcast fired from instance B (which might be the instance actually running that scan's background task). A production-scale fix would move this registry to a shared pub/sub layer (Redis Pub/Sub, or a message queue) that all instances subscribe to. At the current single-instance free-tier deployment, this limitation has no practical effect.

**Message shapes broadcast during a scan's lifecycle:**
```json
{"event": "started", "progress": 0}
{"event": "progress", "progress": 20, "message": "Extracted repository"}
{"event": "completed", "progress": 100, "total_findings": 7, "files_scanned": 312}
{"event": "failed", "error": "Invalid GitHub URL: ..."}
```

**Frontend side** — `useWebSocket.ts` opens exactly one socket per active `scanId`, using a `useEffect` whose cleanup function (`return () => ws.close()`) guarantees the socket is torn down whenever the component unmounts or `scanId` changes, so no scan ever leaks an open connection. It determines the WebSocket URL from the same `VITE_API_URL` environment variable the REST client uses, converting `https://` → `wss://` (`API_BASE_URL.replace(/^http/, 'ws')`).

---

## 11. Background Jobs: Scheduling & Email Alerts

### 11.1 Two distinct kinds of "background" in this codebase

1. **FastAPI `BackgroundTasks`** — used for running an individual scan (`_run_scan`). This is *request-scoped*: `POST /scans` schedules `_run_scan` to run after the response is sent, on the same event loop, in the same process. It is not a durable job queue — if the server process restarts mid-scan, that scan is lost. At startup, `mark_interrupted_scans()` marks any scan still `queued`/`running` as `failed` with a "run it again" message, so nothing is left reporting `running` forever — but the work is not retried (see §23). CPU-bound scanning runs in a worker thread (`asyncio.to_thread`), so a long scan no longer freezes the event loop for other requests.
2. **APScheduler `AsyncIOScheduler`** — used for *recurring* scans on a cron schedule, independent of any single HTTP request.

### 11.2 How a schedule becomes a recurring job

`workers/scheduler.py` holds one module-level `_scheduler = AsyncIOScheduler()` instance, started once in `main.py`'s lifespan (`start_scheduler()`) and shut down on process exit (`stop_scheduler()`).

Because that job store is in memory, `restore_schedules()` runs at every startup and re-registers each stored schedule (pausing the disabled ones, so re-enabling later has a job to resume). Without it, schedules silently stopped after any restart.

`add_schedule(schedule_id, cron_expression, source_type, source_ref)` parses the 5-field cron string (`minute hour day month weekday`) into APScheduler's `CronTrigger`, then registers a job:
```python
_scheduler.add_job(
    _run_scheduled_scan,
    trigger=CronTrigger(minute=..., hour=..., day=..., month=..., day_of_week=...),
    id=schedule_id,          # the job's ID IS the ScanSchedule's DB id — keeps them 1:1
    replace_existing=True,
    args=[schedule_id, source_type, source_ref],
)
```
When the cron trigger fires (fully independent of any browser tab being open — this is what "unattended" means), `_run_scheduled_scan` creates a new `Scan` row, updates the schedule's `last_run_at`/`last_scan_id`, then calls the very same `_run_scan()` from `routers/scans.py` that a manually-launched scan uses — scheduled and manual scans share 100% of the actual scanning code path.

**A subtle bug that was found and fixed during development:** `job.next_run_time` (an APScheduler `Job` attribute) does not exist on a `Job` object until the scheduler has actually started running — accessing it during, e.g., a test that creates a schedule before the scheduler thread is live throws `AttributeError`. The fix, `_next_run_time(job)`, safely falls back to computing the next fire time directly from the trigger (`job.trigger.get_next_fire_time(None, now)`) if the live attribute isn't available yet.

### 11.3 Email alerts

Covered fully in §8's `notifications.py` entry. The trigger condition, stated precisely because it's easy to misstate: an alert fires whenever a **completed scan's finding set contains at least one `CRITICAL`-severity finding** — `critical = sum(1 for f in findings if f.severity == "CRITICAL"); if critical > 0: ...`. This is a check against the *current* scan's absolute contents, not a delta against the previous scan. Consequently, a recurring schedule that keeps finding the *same* unresolved CRITICAL secret will send an alert **on every single run**, not just the first time it appears — there is no "already alerted, suppress repeat" state tracked anywhere.

---

## 12. Frontend: File-by-File Walkthrough

### `frontend/src/main.tsx`
**Purpose:** the actual entry point Vite builds from (referenced by `<script type="module" src="/src/main.tsx">` in `index.html`). Creates one `QueryClient` (TanStack Query's cache + fetch orchestrator) with `staleTime: 30_000` (data is considered fresh for 30 seconds before a background refetch is even considered) and `retry: 1` (a failed request is retried once before surfacing an error), wraps `<App />` in `<QueryClientProvider>`, and mounts into the DOM inside `<React.StrictMode>` (a development-only wrapper that intentionally double-invokes certain functions to surface side-effect bugs early — has no effect in production builds).

### `frontend/src/App.tsx`
**Purpose:** defines client-side routing and fires the backend wake-up ping.
```tsx
function useWakeBackend() {
  useEffect(() => { rootApi.get('/health').catch(() => {}) }, [])
}
```
An empty dependency array `[]` means this effect runs exactly once, immediately after the very first render — the earliest possible moment.
**Routes** (all nested under a shared `<Layout>` via React Router's parent-route + `<Outlet/>` pattern):
```tsx
<Route element={<Layout />}>
  <Route path="/" element={<Dashboard />} />
  <Route path="/scan" element={<NewScan />} />
  <Route path="/history" element={<ScanHistory />} />
  <Route path="/history/:id" element={<ScanDetail />} />
  <Route path="/schedules" element={<Schedules />} />
</Route>
```
`:id` is a **route parameter** — React Router extracts it from the URL and `ScanDetail` reads it back via the `useParams<{id: string}>()` hook.

### `frontend/src/api/client.ts`
**Purpose:** the single file that owns every backend contact point and every TypeScript type describing backend data — the frontend's equivalent of the backend's `schemas.py`. No component ever calls `axios` or `fetch` directly; every API call goes through a named function exported from here (`startScan`, `listScans`, `getStats`, etc.), each returning a typed Promise.
```ts
const BASE = import.meta.env.VITE_API_URL ? `${VITE_API_URL}/api/v1` : '/api/v1'
export const api = axios.create({ baseURL: BASE, headers: {...} })
```
**Why this matters:** in local development, `VITE_API_URL` is unset, so `BASE` becomes the relative path `/api/v1`, which Vite's dev-server proxy (`vite.config.ts`'s `server.proxy`) forwards to `localhost:8000` — no CORS issue in dev at all. In production, `VITE_API_URL` is set (via a Vercel environment variable) to the live Render URL, and requests go directly cross-origin, which is why the backend's CORS middleware exists.
**Every backend Pydantic model has a matching TypeScript interface here** (`Finding`, `Scan`, `Schedule`, `Stats`, `ScanDiff`, `DiffFinding`) — this is a manually-maintained contract, not code-generated from the OpenAPI schema, so a backend field rename requires updating this file by hand.

### `frontend/src/hooks/useWebSocket.ts`
Covered in [§10](#10-websocket-real-time-progress). Returns `{ lastMessage, connected }`; `lastMessage` is the most recently parsed WS payload (or `null` before any message arrives), overwritten (not appended to a list) on every new message — components only ever care about the *current* state, not the full history of updates.

### `frontend/src/index.css`
Not styling in the traditional "add colors" sense — this file **is** the design system's implementation, using Tailwind's `@layer components` to define reusable class names (`.btn-primary`, `.field`, `.kicker`, `.ledger-table`) on top of the color/spacing/type tokens declared in `tailwind.config.js`. Covered fully in [§15](#15-the-design-system).

---

## 13. Every React Component Explained

### `components/TopBar.tsx`
**Purpose:** the entire site header/navigation — deliberately built as a single horizontal command bar instead of a traditional collapsible sidebar. **Props:** none (it's mounted once, at the top of the route tree, and reads everything it needs itself). **State/hooks:** `useLocation()` (to highlight the active nav tab) and one `useQuery(['stats'], getStats, {refetchInterval: 15_000})` — this is the *same* query key the Dashboard page also subscribes to, so TanStack Query's cache deduplication means the stats are fetched once and shared, not fetched twice just because two components asked for them. **What it renders:** the product mark (an inline hand-drawn SVG, not an image asset — a filled square with a keyhole cut out via a circle + triangle, `fill="currentColor"`-free so it always matches the ivory text color), three `<NavLink>` workspace tabs, a live "N critical / all clear" indicator (color and pulse-animation driven directly by `stats.critical_count`), and the one primary "New scan" button. **Why a component instead of inlining this in `Layout`:** it has its own data dependency (the stats query) and its own internal logic (active-tab detection); separating it keeps `Layout.tsx` a pure, dependency-free shell.

### `components/Layout.tsx`
**Purpose:** the page shell every route renders inside. **Props:** none. **Children:** renders `<TopBar/>`, then `<Outlet/>` (React Router's placeholder — whatever the currently-matched child route is gets rendered here), then a footer. **Why it exists as a separate file from `App.tsx`:** `App.tsx` owns *routing decisions* (which URL maps to which page); `Layout.tsx` owns *visual structure* (what wraps every page). Keeping them separate means the router config stays readable as a flat list of routes.

### `components/SeverityBadge.tsx`
**Purpose:** renders a severity label (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`) as a small colored tick + tracked-uppercase text, never as color alone (a deliberate accessibility choice — color-blind users, or anyone on a monochrome screen, still get the word). **Props:** `{ severity: Severity }`. **No internal state.** Also exports the shared `SEV_COLOR` map and `SEV_ORDER` array, which several other components (`charts.tsx`, `ScanDetail.tsx`) import to stay visually consistent rather than each defining their own color mapping — this is the **single source of truth** for "what color is CRITICAL."

### `components/StatusBadge.tsx`
**Purpose:** renders a scan's lifecycle status (`queued`/`running`/`completed`/`failed`) as a colored dot + text, with the `running` state additionally getting a CSS `animate-pulse` class so an in-progress scan visibly "breathes" in any list it appears in.

### `components/RiskBadge.tsx`
**Purpose:** two related exports. `RiskBadge` is a compact, zero-padded mono readout (`055`, `100`) used inline in list rows. `RiskMeter` is the larger version shown when a finding is expanded — a big numeral plus a **10-segment bar** where `Math.round(score / 10)` segments are filled in the risk-band color and the rest are a neutral gray. **Why a segmented bar instead of a circular gauge or plain progress bar:** it reads at a glance as a discrete "how many out of ten" measurement (closer to a hardware VU meter) rather than implying false continuous precision.

### `components/DiffSummary.tsx`
**Purpose:** renders the output of `GET /scans/{id}/diff` as a single horizontal ledger — four columns (`new`, `resolved`, `unchanged`, `net`) separated by hairline dividers, with the `net` column's color and label (`improved`/`regressed`/`steady`) computed from the sign of `net_change`. **Props:** `{ diff: ScanDiff }`. Returns an explanatory one-liner instead of the ledger when `diff.has_baseline` is `false`.

### `components/LifecycleTimeline.tsx`
**Purpose:** visualizes a finding's git-history exposure window as an actual timeline — two dots (introduced / last seen) connected by a dashed line, with the line's total *width* on the page scaled proportionally to `exposure_days` against a 90-day reference window (`Math.min(100, (days / 90) * 100)`, floored at 8% so even a same-day exposure renders a visible span). **Renders nothing (`return null`) if the finding has no lifecycle data** — i.e., for any finding from a scan that didn't include git history, this component silently disappears rather than showing empty/placeholder fields, which is the correct behavior given §7.3's opt-in design.

### `components/charts.tsx`
Three exports, all custom SVG with **zero charting library dependency** — see [§16](#16-every-dependency-explained) for why that choice was made.
- **`SeveritySpectrum`** — a single stacked horizontal bar, one segment per severity level present, width proportional to that severity's share of total findings, with a 2px gap between segments and a legend row of swatch+label+count below.
- **`TrendChart`** — findings-per-day as a **stepped line** (constructed manually via SVG path commands — horizontal run then vertical rise at each data point, deliberately chosen over a smooth curve because it reads as a monitoring/observability tool rather than a marketing chart) with a very low-opacity area fill beneath it, a single baseline (no grid cage), and a mouse-tracked crosshair + tooltip. The hover logic (`onMove`) converts the mouse's pixel X position into SVG viewBox coordinates and finds the nearest data point by absolute distance — a small, self-contained nearest-neighbor search over at most 30 points, so brute-force `O(n)` scanning per mouse-move event is more than fast enough.
- **`RankedTypes`** — a numbered list of the top secret types by count, each row showing rank, name, a proportional horizontal bar (width relative to the row with the highest count), and the exact count in mono type.

**Why hand-build charts instead of using Recharts, Chart.js, etc.:** covered in [§16](#16-every-dependency-explained) and [§22](#22-design-decisions--trade-offs) — this was a deliberate mid-project removal of a chart library to both control the visual language precisely and cut bundle size.

---

## 14. State Management & Data Fetching

**There is no global client-state library** (no Redux, no Zustand, no Context-based store) in this codebase, and that absence is itself a decision worth being able to explain. The application's state falls cleanly into two categories, and each is handled by the tool actually suited to it:

1. **Server state** (anything that lives in the database and could be stale/shared across tabs) — handled entirely by **TanStack Query** (`@tanstack/react-query`).
2. **Local UI state** (a text input's current value, whether a form panel is expanded, which severity filter is currently selected) — handled by plain React `useState`, scoped to the component that owns it.

**Why TanStack Query instead of `useEffect` + `fetch` + `useState`:** hand-rolling data fetching means re-implementing, per component, all of: loading/error states, request de-duplication (if two components mount at once and both want `/stats`, a naive approach fires two identical requests), caching (navigating back to a page shouldn't always show a blank loading screen while re-fetching data you already had seconds ago), background refetching (`refetchInterval`), and cache invalidation after a mutation. TanStack Query provides all of this via one hook call:
```ts
const { data: stats, isLoading } = useQuery({
  queryKey: ['stats'],
  queryFn: getStats,
  refetchInterval: 15_000,
})
```
The **query key** (`['stats']`, or `['scan', id]`, or `['findings', id]`) is the cache identity — any two components anywhere in the tree that call `useQuery` with the same key share the exact same cached data and the exact same in-flight request, automatically. This is why `TopBar` and `Dashboard` both subscribing to `['stats']` costs one network request, not two.

**Mutations and cache invalidation** — every write (`startScan`, `deleteScan`, `createSchedule`, `toggleSchedule`, `deleteSchedule`) is wrapped in `useMutation`, and its `onSuccess` callback calls `queryClient.invalidateQueries({ queryKey: [...] })` to mark related cached data stale, triggering an automatic refetch:
```ts
const deleteMut = useMutation({
  mutationFn: deleteScan,
  onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
})
```
This is the mechanism by which deleting a scan on the Scans page makes the list immediately re-render without it — the component never manually removes the item from a local array; it just tells the cache "the list is stale," and the existing `useQuery(['scans'])` subscription refetches and re-renders on its own.

**A genuine race condition found and fixed during development** (see `NewScan.tsx`): the WebSocket-based progress UI assumed the socket would connect *before* the scan finished. For a trivial paste scan, the backend can complete in well under a second — faster than the WebSocket handshake. The fix adds a second, independent `useQuery` that polls `GET /scans/{id}` over plain HTTP every 1.5 seconds *in parallel* with the WebSocket, and a `finishedRef` (a `useRef`, not `useState`, specifically because updating it must not trigger a re-render and must be readable synchronously inside the same tick to prevent a double-navigation race) guards so whichever channel — the socket or the poll — reports completion first "wins," and the second one becomes a no-op.

---

## 15. The Design System

The frontend does not use a component library (no shadcn/ui, no MUI, no Bootstrap). Every visual primitive — buttons, badges, tables, form fields — is custom, defined once in `tailwind.config.js` (tokens) and `index.css` (composed utility classes), then reused via Tailwind class names across every page.

**Color** is restricted to a small, purposeful palette declared in `tailwind.config.js`, replacing Tailwind's entire default palette outright (`colors: {transparent, current, ink: {...}, line: {...}, ivory: {...}, sev: {...}, ok}`):
- **`ink`** — four warm near-black steps (`DEFAULT` canvas, `raised` panels, `overlay` hover states, `inset` wells like code blocks and inputs). Depth comes from these background *steps*, not from bordered boxes or drop shadows.
- **`ivory`** — four text-opacity steps (`DEFAULT` primary text, `dim` secondary, `mute` tertiary/disabled, `faint` decorative). `mute` (`#888681`) is set to clear WCAG AA's 4.5:1 for normal text on every ink surface (5.22 / 4.91 / 4.56:1 on canvas, raised, and overlay) while staying well below `dim` (7.73:1), so the hierarchy holds; the original value measured only 3.21:1.
- **`sev`** — the four severity colors (critical/high/medium/low), the **only** place hue is used to carry meaning rather than decoration.
- **`ok`** — a single green, reserved for "resolved"/"clean"/success states.

**Typography** pairs **Instrument Sans** (UI text — labels, prose, buttons) with **IBM Plex Mono** (every number, file path, commit hash, and timestamp — set via a `.font-mono` utility and used pervasively via `tabular-nums` so columns of numbers align digit-for-digit). A small tracked-uppercase "kicker" class (`.kicker`) is used throughout as a section label convention (e.g., "SEVERITY DISTRIBUTION" above a chart).

**Structure favors hairlines over cards.** Sections are separated by a `.rule` class (a single top border) and background-color steps, not individually bordered/shadowed card boxes — this reads closer to a financial ledger or an ops dashboard than a typical "grid of cards" SaaS template.

**Why this was built from scratch rather than adopting an existing kit:** documented at length in the git history of this repository — a full redesign pass was done specifically to move away from generic, templated-looking UI patterns (predictable sidebar, identical bordered KPI cards, default charting-library output, a default blue accent) toward something with a specific, defensible point of view suited to a security-tool domain. This is a legitimate answer to "why not just use shadcn" in an interview: control over the exact visual language, and the practical side-effect of zero component-library bundle weight.

---

## 16. Every Dependency, Explained

### Backend (`backend/requirements.txt`)

| Package | Why it's here | Simpler alternative | Trade-off |
|---|---|---|---|
| `fastapi` | The web framework — async-native, automatic OpenAPI docs, Pydantic-integrated request/response validation | Flask | Flask is sync-first and needs extra work (or Quart) to be truly async; FastAPI's type-driven validation eliminates a whole class of manual `if` checks |
| `uvicorn[standard]` | The ASGI server that actually runs the FastAPI app (FastAPI itself is just the framework, not a server) | Hypercorn | Both are solid; uvicorn is the most common pairing with FastAPI |
| `sqlalchemy` | Async ORM — see §6.1 | Raw SQL via `asyncpg`/`aiosqlite` directly | Raw SQL is faster to write for trivial queries but loses migration tooling, relationship management, and type safety as the schema grows |
| `aiosqlite` | Async SQLite driver — required because SQLAlchemy's async engine needs an async-capable DB driver | — | SQLite's sync driver (`sqlite3`) cannot be used with an async engine at all |
| `asyncpg` | Async PostgreSQL driver — present so the *same* async SQLAlchemy code works against Postgres without changes, even though the live deployment currently runs SQLite | `psycopg` (sync) | Only relevant if/when the deployment migrates to Postgres |
| `pydantic` / `pydantic-settings` | Data validation (request/response schemas) and typed environment-variable loading | Manual `os.environ.get()` + hand-written validation | Pydantic gives free, declarative validation with clear error messages instead of scattered manual checks |
| `GitPython` | Wraps the `git` CLI in a Python API — used to clone repos and walk commit history | Shelling out to `git` directly with `subprocess` | GitPython gives a typed, Pythonic interface (`repo.iter_commits()`, `commit.tree.traverse()`) instead of parsing CLI text output |
| `httpx` | Async HTTP client — used to call the GitHub zipball download API | `requests` (sync) or `aiohttp` | `requests` would block the event loop; httpx has a near-identical API to `requests` but is async-native |
| `apscheduler` | Cron-style recurring job scheduling inside the same process | A separate task queue (Celery + Redis) | APScheduler needs no extra infrastructure (no Redis/broker) at the cost of being in-memory and single-process only (see §11's scaling note) |
| `aiosmtplib` | Async SMTP client for email alerts | `smtplib` (sync, stdlib) | Same async-event-loop reasoning as `httpx` |
| `websockets` | The underlying WebSocket protocol implementation uvicorn uses | — | Required dependency for `uvicorn[standard]`'s WS support |
| `python-multipart` | Enables FastAPI to parse `multipart/form-data` request bodies | — | Present for completeness/future file-upload support; not currently exercised by any route in this codebase |
| `greenlet` | Required by SQLAlchemy's async engine internals on newer Python versions | — | Transitive necessity, not a direct architectural choice |

### Frontend (`frontend/package.json`)

| Package | Why it's here | Simpler alternative | Trade-off |
|---|---|---|---|
| `react` / `react-dom` | The UI library | Vue, Svelte | React was chosen; component model + hooks fit this app's needs well |
| `react-router-dom` | Client-side routing (URL ↔ page mapping) without a full page reload | Hand-rolled `window.location` switching | Router gives declarative routes, nested layouts (`<Outlet/>`), and typed route params (`useParams`) |
| `@tanstack/react-query` | Server-state fetching/caching — see §14 | Manual `useEffect` + `fetch` + `useState` | Query eliminates enormous amounts of boilerplate (loading/error/cache/dedup/invalidation) that would otherwise be hand-written per component |
| `axios` | HTTP client | The native `fetch()` API | Axios auto-parses JSON, has cleaner error objects (`isAxiosError`), and supports request/response interceptors and a pre-configured base instance more ergonomically than raw `fetch` |
| `date-fns` | Date formatting (`format(date, 'MMM d, HH:mm')`) | Native `Intl.DateTimeFormat` or `Date` methods | `date-fns` gives a much more ergonomic, composable formatting API; it's tree-shakeable so only the functions actually imported end up in the bundle |
| `clsx` | Conditionally joining CSS class name strings | Manual template-string concatenation | `clsx` handles falsy values and objects cleanly (`clsx('a', cond && 'b', {c: true})`) with near-zero runtime cost |
| `typescript` | Static typing for the entire frontend | Plain JavaScript | Catches an entire category of bugs (wrong prop shape, typo'd field name) at build time instead of at runtime |
| `vite` | Build tool + dev server | Create React App (deprecated), webpack directly | Vite's dev server uses native ES modules for near-instant hot reload; its production build (via Rollup) is what powers the manual chunk-splitting in `vite.config.ts` |
| `tailwindcss` | Utility-first CSS, and the mechanism the entire design system's tokens are defined through | Hand-written CSS/SCSS, styled-components | Tailwind's config file *is* the design-token system (§15); utility classes avoid the "what do I name this class" problem entirely |

**Notably absent, and why:** `recharts` (or any charting library) and `lucide-react` (or any icon library) were both **deliberately removed** partway through the project's life. Charts were rebuilt as custom SVG (§13); icons were replaced with typographic/geometric alternatives (dots, ticks, mono-text glyphs) consistent with the design system. This single change reduced the production JavaScript bundle from a single ~734 KB chunk down to a 42 KB app-shell entry chunk plus two independently-cacheable vendor chunks (react ~156 KB, data/query ~117 KB) — verified by comparing `npm run build` output before and after.

---

## 17. Configuration Files Explained

### `frontend/vite.config.ts`
```ts
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          data: ['@tanstack/react-query', 'axios', 'date-fns'],
        },
      },
    },
  },
  server: { port: 5173, proxy: { '/api': { target: 'http://localhost:8000', changeOrigin: true } } },
})
```
`manualChunks` explicitly splits vendor code into two cacheable groups separate from the application's own code — this means a deploy that only changes application logic doesn't force browsers to re-download React itself, since the `react-*.js` chunk's content hash (and therefore its cache key) is unchanged. `server.proxy` is what makes local development CORS-free (§12).

### `frontend/tailwind.config.js`
Not a typical Tailwind config — it fully replaces the default `colors` object rather than `extend`-ing it, which is deliberate: it means **no other color is reachable** by autocomplete or by accident, forcing every visual decision through the small, intentional palette described in §15.

### `frontend/tsconfig.json`
Key settings: `"strict": true` (enables all of TypeScript's strictest type-checking flags — no implicit `any`, strict null checks, etc.); `"types": ["vite/client"]` (this is what makes `import.meta.env.VITE_API_URL` type-check correctly — without it, TypeScript has no idea `import.meta.env` exists, since that's a Vite-specific runtime addition, not a browser/Node standard); `"noEmit": true` (TypeScript here is used purely for type-checking — Vite/esbuild, not `tsc`, does the actual JS output, so `tsc` never needs to write files, only report errors).

### `backend/pytest.ini`
```ini
[pytest]
asyncio_mode = auto
testpaths = tests
```
`asyncio_mode = auto` means every `async def test_...` function in the suite is automatically treated as an async test (via `pytest-asyncio`) without needing an `@pytest.mark.asyncio` decorator on each one individually.

### `render.yaml`
Render's **infrastructure-as-code** blueprint for the backend service — `rootDir: backend` scopes the build to that subdirectory, `buildCommand`/`startCommand` define exactly what runs at deploy time (`python seed_demo.py && uvicorn ...` — the seed script runs once per deploy, is idempotent, then the server starts), and `envVars` declares the full set of environment variables the service needs, with `sync: false` on anything secret (API tokens, SMTP password) meaning "must be set manually in Render's dashboard, never committed to this file."

### `.github/workflows/ci.yml`
Four independent jobs run on every push to `main` and every pull request:
1. **`backend`** — installs `requirements-dev.txt`, runs `pytest tests/ -v` (the 76 API-integration, unit, and hardening-regression tests).
2. **`scanner-cli`** — installs root `requirements.txt`, runs `pytest test_scanner.py -v` (the 19 legacy-CLI tests) — kept as a genuinely separate job because it exercises a different, older code path (`scanner_core.py`) than the FastAPI backend does.
3. **`frontend`** — `npm ci && npm run build`, which runs `tsc` (type-check) then `vite build` — this job fails on either a TypeScript error or a build failure, catching type regressions before they reach production.
4. **`self-scan`** (the "dogfood" job) — runs the project's own CLI scanner against its own source tree and uploads the JSON report as a build artifact. Set to `continue-on-error: true` deliberately, because the repository's own test fixtures intentionally contain fake secret-like strings (used to test the detector) — a failing self-scan is expected and not a CI failure condition; the point is to keep a visible, downloadable audit trail, not to gate merges on it.

---

## 18. Deployment Architecture

```text
┌─────────────────────┐        ┌──────────────────────────┐
│  Vercel               │  HTTPS │  Render                    │
│  (frontend, static)    │◄──────►│  (backend, uvicorn process)│
│  cipherwatch-web        │        │  secrets-scanner-api        │
│  .vercel.app              │        │  .onrender.com                │
└─────────────────────┘        └───────────┬──────────────┘
                                             │
                                    ┌────────▼────────┐
                                    │  SQLite file      │
                                    │  (on Render's       │
                                    │   ephemeral disk)     │
                                    └──────────────────────┘
```

**Frontend → Vercel.** `frontend/vercel.json` (not shown above but present in the repo) configures the build; Vercel builds via `npm run build`, then serves the static `dist/` output from its global CDN. The `VITE_API_URL` environment variable (pointing at the Render backend) is injected **at build time**, since Vite bakes `import.meta.env.*` values into the compiled JS bundle — this is why changing that variable requires a redeploy, not just a config toggle.

**Backend → Render, free tier.** Render's free web-service tier **spins the process down after 15 minutes of no traffic** and cold-starts it (30–60 seconds) on the next request — this is the entire reason the frontend's wake-up ping (§5, Step 1) exists. Render's free tier also uses **ephemeral disk** for services without an attached persistent disk — meaning the SQLite file is **not guaranteed to survive a redeploy**, which is precisely why `seed_demo.py` re-runs (idempotently) on every deploy, ensuring the demo dataset is always present rather than assuming prior data persisted.

**CORS is the mechanism that makes cross-origin communication (Vercel's domain calling Render's domain) work at all** — covered in depth in [§20](#20-concept-deep-dives).

**Local development** uses Vite's dev-server proxy (frontend) talking directly to a locally-run `uvicorn` process (backend) — no Vercel, no Render, no CORS concerns, and typically SQLite (though `docker-compose.yml` offers a full Postgres-backed alternative for closer-to-production local testing).

---

## 19. Testing Strategy

**95 automated tests total, split across two independent suites, both run in CI on every push.** Backend line coverage is 77% (100% on risk scoring, SARIF, and stats).

### Backend suite — 76 tests (`backend/tests/`, run via `pytest tests/ -v`)
- **`test_api.py`** — full HTTP integration tests against the live FastAPI app, using `httpx.AsyncClient` wired to an `ASGITransport` (meaning requests never leave the process — no real network socket, no real server process, but the *entire* FastAPI request/response/middleware/dependency-injection stack genuinely executes). `conftest.py`'s `client` fixture creates a fresh, isolated throwaway SQLite database **per test** (`Base.metadata.drop_all` then `init_db()` inside the fixture) — so tests never interfere with each other's data and never touch the real development or production database. Covers the full paste-scan lifecycle end-to-end: start a scan → poll until findings exist → filter by severity → request a diff → export in all four formats → check dashboard stats → delete → confirm 404.
- **`test_risk.py`** — pure unit tests of `compute_risk_score()`: every severity base value, every bonus rule in isolation, the 100-point cap, and that every point added is accompanied by a factor string.
- **`test_sarif.py`** — validates the SARIF document's structure: correct schema/version strings, one rule per distinct secret type (not per finding), correct severity→level mapping, correct fingerprints, and a well-formed empty document when there are zero findings.
- **`test_remediation.py`** — env-var-name derivation (both the "infer from source line" and "fall back to the type map" paths), per-language replacement-line generation for Python/Node/Ruby/Go/PHP/`.env`, and patch-file hunk grouping/ordering.
- **`test_validation.py`** — the input-hardening rules from `schemas.py`: rejecting non-GitHub URLs, rejecting oversized pastes, rejecting malformed cron expressions, and confirming pagination `limit`/`offset` bounds are enforced.
- **`test_hardening.py`** — regression tests for the security and reliability fixes: no raw secret in any of 8 API responses and exports, pasted content replaced by a stable digest, interrupted scans failed and schedules restored at startup, invalid and too-frequent cron rejected, zip-bomb and member-count limits, the vendor-example placeholder, and an escaped alert email. Each bug-detecting test was confirmed to **fail against the pre-fix code** (15 of 20; the other 5 are guard cases checking that valid input still works).

### Legacy CLI suite — 19 tests (`test_scanner.py`, run via `pytest test_scanner.py -v`)
Tests `scanner_core.py` (the original, pre-web-app scanning engine that `cli.py` still uses) — AWS/GitHub/JWT/SSH-key detection, placeholder suppression, entropy-threshold gating, and statistics generation.

**Why two separate suites instead of one:** `scanner_core.py` and `backend/app/scanner/core.py` are two genuinely different implementations (the backend's is the actively-developed, feature-rich engine; the CLI's is the original, simpler one kept for `cli.py`'s standalone offline use case) — testing them separately, in separate CI jobs, correctly reflects that they are separate code paths, not duplicated coverage of the same code.

---

## 20. Concept Deep-Dives

### CORS (Cross-Origin Resource Sharing)
**Simple explanation:** imagine your browser as a cautious mail clerk. By default, a webpage loaded from `site-a.com` is *not allowed* to quietly ask `site-b.com` for private data on your behalf — that would let any malicious website silently read your bank's API just because you happened to have it open in another tab. CORS is the mechanism by which `site-b.com` can explicitly say "it's fine, `site-a.com` is allowed to talk to me."
**Technical explanation:** the browser enforces the **same-origin policy** — an origin is the combination of scheme + host + port. `https://cipherwatch-web.vercel.app` and `https://secrets-scanner-api.onrender.com` are different origins (different hosts), so by default the browser blocks JavaScript on the former from reading responses from the latter. `CORSMiddleware` in `main.py` makes the server send an `Access-Control-Allow-Origin` response header explicitly whitelisting the frontend's origin (from `settings.cors_origins_list`, parsed from the `CORS_ORIGINS` env var) — only then does the browser permit the frontend's JavaScript to read the response body.
**In this project:** this is why CORS never comes up in local dev (Vite's proxy makes every request same-origin from the browser's point of view) but is essential in production (Vercel and Render are always different origins).

### JWT (JSON Web Token)
Not used in this codebase (there is no authentication at all), but worth defining since it's a standard interview topic and directly relevant to §23's discussion of what would need to be added for multi-tenant auth. **Simple explanation:** a JWT is like a wax-sealed letter — anyone can read what's written inside, but the seal proves who wrote it and that nobody tampered with it after sealing. **Technical explanation:** a JWT is three base64url-encoded segments (`header.payload.signature`) — the payload carries claims (e.g. user ID, expiry), and the signature is a cryptographic hash of the header+payload computed with a server-held secret, so any change to the payload invalidates the signature. This project has no JWTs because it has no user identity to attach one to; adding authentication would mean introducing a `users` table, a login endpoint that issues a JWT, and a FastAPI dependency (analogous to `get_db`) that validates the token and scopes every query to the authenticated user.

### Async / Await
Covered concretely in §6.1. General definition: `async`/`await` is Python's syntax for **cooperative multitasking** — a coroutine voluntarily yields control at each `await` point, letting the event loop run other pending work during I/O waits, rather than the operating system forcibly context-switching between separate OS threads (as with traditional multithreading).

### REST
**Simple explanation:** a shared set of conventions so that "get a thing," "create a thing," "change a thing," and "delete a thing" always look the same shape, no matter which API you're talking to — instead of every service inventing its own verbs.
**Technical explanation, as applied in this codebase:** resources are nouns in the URL path (`/scans`, `/scans/{id}/findings`, `/schedules`), and the HTTP method carries the verb (`GET` read, `POST` create, `PATCH` partial update, `DELETE` remove). Status codes carry outcome semantics: `202 Accepted` for the async scan-creation endpoint (work has been *accepted*, not yet *completed*), `204 No Content` for successful deletes (nothing meaningful to return), `404` for a missing resource, `422` for a validation failure.

### WebSocket vs. SSE vs. Polling
Covered concretely in §10, including the honest note that this project's WebSocket usage is functionally one-directional. General comparison: **polling** (client repeatedly asks "anything new?") is simplest but wastes requests and adds latency up to the poll interval. **SSE** is a one-directional, auto-reconnecting, plain-HTTP server→client push channel — ideal when only the server needs to speak. **WebSocket** is a full bidirectional channel — necessary only when the client also needs to send messages back over the *same* open connection (e.g. a chat app, or a genuine cancel/pause control channel), which this project's scan-progress feature does not actually do.

### Hydration / SSR / CSR
Not applicable to this codebase — it is a plain **Client-Side Rendered (CSR)** single-page app (Vite + React, no Next.js, no server-side rendering framework). Definitions for completeness: **CSR** means the server ships a nearly-empty HTML shell and all rendering happens in the browser via JavaScript (what this app does — the initial HTML has an empty `<div id="root">`). **SSR** means the server renders the initial HTML with real content already in it (faster first paint, better for SEO). **Hydration** is the process, in an SSR app, of React "waking up" that server-rendered HTML and attaching event listeners/interactivity to it client-side, without re-rendering from scratch. This project has no hydration step because it never does server rendering in the first place.

---

## 21. Full Feature Traces (User Action → Screen)

### 21.1 Launching a scan — the complete trace

```text
User fills the New Scan form, selects "Pasted code", pastes text, clicks "Run scan"
        │
        ▼
NewScan.tsx  handleSubmit(e)
        │  e.preventDefault()
        │  builds { source_type: 'paste', source_ref: <text>, scan_git_history: false,
        │           max_commits: 100, min_entropy: 3.5 }
        ▼
mutation.mutate(body)   — TanStack Query's useMutation, wrapping startScan()
        │
        ▼
api/client.ts  startScan()  →  axios POST /api/v1/scans
        │
        ▼  (network hop, browser → Render)
routers/scans.py  start_scan(body, background_tasks, db)
        │  Pydantic validates `body` against StartScanRequest
        │  (paste-size check, non-empty check — all pass)
        │
        ▼
        new Scan(source_type='paste', source_ref=paste_label(text), status 'queued')
        db.add(scan); await db.flush(); await db.refresh(scan); await db.commit()
        │  → INSERT INTO scans (...) — row now exists, status='queued'
        │
        ▼
        background_tasks.add_task(_run_scan, scan.id, text)   ← content in memory only
        return scan   — HTTP 202, body = ScanListItem JSON
        │
        ▼  (response returns to browser)
mutation.onSuccess(data)
        │  finishedRef.current = false
        │  setActiveScanId(data.id)      ← triggers useWebSocket(activeScanId) to connect
        │  setScanProgress(0)
        │
        ├──────────────────────────────────────┐
        ▼ (in parallel, back on the server)     ▼ (in the browser)
_run_scan(scan_id) begins running                useWebSocket opens a WS connection to
   scan.status = 'running'; commit               /api/v1/scans/ws/<id>
   _broadcast({event:'started', progress:0})     scan_websocket() accepts it, registers
   to_thread(scan_text, text, 'paste', …)         it in _ws_registry[scan_id]
     → for each non-comment line, run all 26
       regex patterns, filter placeholders,
       apply entropy gate, downgrade severity
       for test files, compute_risk_score(),
       mask every secret in the stored context
   _broadcast({event:'progress', progress:80})  →  onmessage fires, setScanProgress(80)
   for each Finding: db.add(FindingModel(...))
   scan.status='completed'; total_findings=N
   scan.completed_at = utcnow_naive(); commit
   _broadcast({event:'completed', progress:100,
               total_findings:N, files_scanned:1}) →  onmessage fires:
                                                        finish(activeScanId) called
   if any CRITICAL finding:                              → qc.invalidateQueries(['scans'])
     asyncio.create_task(send_critical_alert(...))          qc.invalidateQueries(['stats'])
                                                              setScanProgress(100)
                                                              setTimeout 600ms →
                                                              navigate(`/history/${scanId}`)
        │
        ▼
(Fallback path, running the whole time in parallel: a useQuery polling
 GET /scans/{id} every 1.5s also observes status flip to 'completed' and
 calls the SAME finish() function — a `finishedRef` guard ensures whichever
 of {WebSocket, poll} notices completion first is the one that navigates;
 the second is a no-op.)
        │
        ▼
Browser navigates to /history/<id>
        │
        ▼
ScanDetail.tsx mounts, useQuery(['scan', id]) fires GET /scans/{id},
useQuery(['findings', id]) fires GET /scans/{id}/findings,
useQuery(['diff', id]) fires GET /scans/{id}/diff
        │
        ▼
Full scan report renders: header, meta line, diff summary (if a baseline
exists), severity filter strip, findings grouped by file with expandable
rows showing risk meter, contributing factors, lifecycle (if present),
matched string, entropy, remediation steps.
```

### 21.2 Filtering findings by severity on the report page

```text
User clicks the "CRITICAL" chip in the severity filter strip
        │
        ▼
ScanDetail.tsx: setSeverityFilter('CRITICAL')   — plain useState, no API call
        │
        ▼
Local re-render: `visible = all.filter(f => f.severity === 'CRITICAL')`
groupByFile(visible) re-groups the already-fetched findings client-side
        │
        ▼
Only CRITICAL-severity file groups re-render on screen — no network round-trip,
because ALL findings for the scan were already fetched once (limit: 500)
and severity filtering happens entirely in the browser.
```
*(Contrast: `GET /scans/{id}/findings` **does** support a server-side `severity` query param, and `ScanHistory`'s search box also filters client-side over an already-fetched list — both deliberate choices given the small, single-scan-scoped data volumes involved; a server round-trip per keystroke/click would be strictly worse UX here.)*

### 21.3 Creating a recurring schedule

```text
User clicks "New schedule" → form panel expands (CSS grid-template-rows
transition, not a hard show/hide) → fills name, repo URL, picks a cron
preset chip (or types custom) → submits
        │
        ▼
createMut.mutate(body)  → POST /api/v1/schedules
        │
        ▼
schedules.py create_schedule()
   ScheduleCreate validates: name 1-120 chars, source_ref passes the
   GitHub-URL allow-list, source_type is github, cron parses and
   fires no more often than every 15 minutes
        │
   ScanSchedule row inserted (enabled=True by default)
        │
   add_schedule(schedule.id, cron_expression, source_type, source_ref)
     parses the 5 cron fields → CronTrigger
     _scheduler.add_job(_run_scheduled_scan, trigger=..., id=schedule.id, ...)
     returns computed next_run_time
        │
   schedule.next_run_at = next_run; commit
        │
        ▼
Response returns the created ScheduleOut → onSuccess invalidates ['schedules']
→ the schedules table re-fetches and the new row appears, form collapses.

  ... independently, whenever the cron trigger actually fires (could be
  hours/days later, with zero browser tabs open) ...

_run_scheduled_scan(schedule_id, source_type, source_ref)
   creates a new Scan row, updates schedule.last_run_at/last_scan_id
   calls _run_scan(scan_id) — the IDENTICAL code path a manual scan uses
   recomputes and stores schedule.next_run_at for the following occurrence
```

---

## 22. Design Decisions & Trade-offs

**Deterministic detection (regex + entropy) instead of an LLM/ML classifier.** Alternative considered implicitly: train or call a model to classify "is this a secret?" Pros of the chosen approach: zero inference cost, zero API latency, fully deterministic (the same input always produces the same output, which matters enormously for a security tool's trustworthiness and for reproducible tests), and every decision is explainable in plain English (a regex either matched or it didn't; an entropy score is a real, inspectable number). Cons: cannot generalize to a truly novel secret format never seen before without a human writing a new `SecretPattern`; a sufficiently obfuscated or split-across-lines secret could evade it. This trade-off favors precision, auditability, and zero operating cost over generalization — appropriate for a security tool whose false-positive rate directly determines whether anyone keeps using it.

**Git history scanning is opt-in, not automatic.** Covered in depth in §7.5. The trade-off is thoroughness vs. speed: full-history scanning is `O(commits × files)`; making it opt-in keeps the default "quick check" experience fast while still offering the deeper audit for anyone who explicitly asks for it.

**SQLite in production instead of Postgres.** Trade-off: zero infrastructure cost and zero connection-pool complexity, at the cost of no true concurrent-writer support and (on Render's free tier specifically) non-durable storage across redeploys. Appropriate for a free-tier demo deployment; the same codebase runs against Postgres unchanged (proven by `docker-compose.yml`), so this is a config change, not an architecture change, if traffic or durability requirements grow.

**No authentication.** Every visitor shares one dataset. Appropriate for a public portfolio demo; genuinely wrong for a real multi-tenant product. What would need to change: a `users` table, a login flow issuing session tokens or JWTs, a `tenant_id`/`owner_id` foreign key added to `scans` and `scan_schedules`, and every query in every router scoped by the authenticated user's ID (`.where(Scan.owner_id == current_user.id)`) — the single most important thing to get right in that migration, since a forgotten scope filter on even one query is a cross-tenant data leak.

**No repository write access / no auto-opened pull requests for remediation.** The remediation feature (§7.8) deliberately generates suggestions and a downloadable patch rather than opening a PR or committing code on the user's behalf. Trade-off: less "magic," more manual steps for the user — but it also means the tool never needs write credentials to a user's repository, which is a meaningfully smaller trust footprint and attack surface for a security tool to carry.

**Hand-built SVG charts instead of a charting library.** Covered in §16. Trade-off: more code to write and maintain per chart type, versus a smaller bundle and complete control over the exact visual language matching the rest of the design system.

**WebSocket for scan progress despite being used one-directionally.** Named honestly in §10 rather than retrofitted with an invented justification — a legitimate example of "the tool reached for at the time" not perfectly matching "the tool that's provably necessary," and a good illustration of being able to reassess and describe a past decision accurately rather than defensively.

---

## 23. Known Limitations

Stated plainly, because knowing exactly where a system's edges are is itself a sign of engineering maturity:

- **No authentication or multi-tenancy.** All data is shared across every visitor.
- **Scans are not durable jobs.** A `_run_scan()` background task is tied to the FastAPI process. A restart mid-scan loses the work; startup reconciliation marks the scan `failed` instead of leaving it `running`, but it is not retried automatically.
- **Schedules are re-registered from the database at startup.** APScheduler's job store is in memory, so `restore_schedules()` rebuilds it on every boot (paused schedules included). A schedule whose fire time passes while the server is asleep is skipped, not run late.
- **The WebSocket registry is per-process and in-memory.** A multi-instance deployment would need a shared pub/sub layer (e.g., Redis) for broadcasts to reach clients connected to a different instance than the one running their scan.
- **No "already alerted" suppression on scheduled scans.** An unresolved CRITICAL finding triggers a fresh email on every scheduled run that still detects it, not just the first time.
- **SQLite on Render's free tier is not guaranteed durable across redeploys**, which is why demo data is re-seeded (idempotently) on every deploy rather than assumed to persist.
- **Deterministic detection has a false-negative ceiling.** A genuinely novel secret format, or one deliberately obfuscated to avoid pattern/entropy detection, can evade this system — as any static-analysis-based tool can.
- **The remediation `.patch` file is not guaranteed to cleanly `git apply`.** It documents the intended before/after per finding using the masked (not real) secret value, and is explicitly meant as a precise reference for a human, not a robotic auto-fix.

---

## 24. Interview Question Bank

### Beginner
**Q: What problem does this project solve?**
A: It finds credentials (API keys, passwords, tokens) that were accidentally typed directly into source code and committed to Git, before or after that code becomes visible to people who shouldn't have access to those credentials.

**Q: What is Shannon entropy and why does this project use it?**
A: A measure of how random/unpredictable a string is, based on information theory. Real generated secrets tend to be high-entropy; English words and simple test values tend to be low-entropy. It's used as a secondary filter (alongside pattern matching) to catch secrets that don't match a known credential's exact format.

**Q: Why does the frontend ping `/health` on load?**
A: The backend is hosted on Render's free tier, which sleeps after 15 minutes of inactivity and takes 30-60 seconds to cold-start. Pinging immediately starts that wake-up clock before the user does anything that actually needs the backend.

### Intermediate
**Q: Walk me through what happens when I click "Run scan."**
A: See the full trace in [§21.1](#211-launching-a-scan-the-complete-trace) — summarized: the form POSTs to `/api/v1/scans`, the backend inserts a `queued` row and schedules a background task, returns immediately, the frontend opens a WebSocket *and* starts a fallback HTTP poll in parallel, the background task runs the actual scan and broadcasts progress, and whichever channel (socket or poll) observes `completed` first navigates to the report page.

**Q: Why is git-history scanning opt-in instead of always-on?**
A: It's a full per-commit tree re-scan — `O(commits × files)`, not a diff between consecutive commits — so it's meaningfully more expensive than a current-tree-only scan. Making it opt-in keeps the default experience fast for the common "quick check" case, while still offering the deeper audit for anyone who explicitly wants it.

**Q: Why use `BackgroundTasks` instead of a proper task queue like Celery?**
A: Scale and simplicity trade-off appropriate to this project's traffic level: `BackgroundTasks` needs no extra infrastructure (no Redis/broker) and runs in-process. The honest cost is durability — if the server restarts mid-scan, that scan is lost with no automatic retry, which a real task queue with persistent job storage would solve.

**Q: How does the differential (diff) scanning feature work?**
A: On request (not precomputed), it looks up the most recent earlier *completed* scan sharing the same source, reduces both scans' findings to a stable identity key of `(file_path, secret_type, matched_string)` — deliberately excluding line number, since unrelated earlier edits can shift line numbers without the secret moving — and computes new/resolved/unchanged via three Python set operations.

### Advanced
**Q: This uses WebSocket for progress, but you said it's one-directional — why not use Server-Sent Events (SSE)?**
A: Honestly, it should probably be SSE. The server only ever pushes progress messages; the client never sends anything back over that connection — there's no cancel/pause control channel actually implemented. WebSocket was the tool reached for building this feature, but SSE's native auto-reconnect and simpler plain-HTTP transport would be the more precisely-justified choice for a push-only feed like this one.

**Q: How would you scale this to handle many concurrent scans across multiple server instances?**
A: Several pieces would need to change together: (1) the in-memory `_ws_registry` would need to move to a shared pub/sub layer (Redis Pub/Sub or similar) so a broadcast fired on the instance running a scan reaches a client connected to a different instance; (2) `BackgroundTasks` would need to become a real job queue (Celery, or an APScheduler job store backed by a shared database instead of in-memory) so a scan survives an individual process restarting; (3) the database would need to move to Postgres with real connection pooling for genuine concurrent-writer support, which the codebase already supports via `asyncpg` without any query-layer changes.

**Q: What would break first under real production load, and how would you find out?**
A: Given the architecture, my first suspicion would be the git-history scan path — `O(commits × files)` per scan, running inside a single request's background task with no queue depth limit, could let a burst of large-repo scans starve the process. I'd add request-level concurrency limits on that endpoint and real APM/timing instrumentation around `_run_scan` before assuming anything, rather than guessing.

**Q: Why is the risk score an additive heuristic instead of a trained model?**
A: Explainability and zero operating cost. Every point added to the score has an attached, human-readable reason (`"Present in Git history"`, `"Extended exposure (10 days)"`) that ships to the UI — a security tool's output needs to be defensible in a review, and a black-box model score without that reasoning is much harder to trust and act on.

### Common Follow-Ups

**"What if the database goes down?"** Every route that touches the DB does so through the `get_db()` dependency, which wraps the session in a try/except that rolls back on any exception — a DB outage would surface as a 500 error on affected requests rather than silently corrupting state, but there's no retry/circuit-breaker logic currently, so the honest answer is "requests would fail loudly, not gracefully degrade."

**"How would you add authentication?"** A `users` table, a login endpoint issuing a session token/JWT, a FastAPI dependency (parallel to `get_db`) that validates that token and resolves the current user, an `owner_id` column added to `scans` and `scan_schedules`, and every existing query scoped by `.where(Scan.owner_id == current_user.id)`.

**"Why not use an existing tool like TruffleHog or GitGuardian instead of building this?"** This project exists to demonstrate the *engineering* of building exactly this class of tool — the detection pipeline, the risk-scoring model, the real-time progress architecture, the SARIF-format interoperability, the full-stack async web application around it — end to end, not to compete commercially with mature, funded products in this space.

**"How would you reduce false positives further?"** Options in increasing order of complexity: expand the placeholder-pattern list based on observed false positives; add per-repository allow-listing of known-safe strings; add a lightweight secondary classifier trained specifically on this tool's own historical true/false-positive labels (a much narrower, more tractable ML problem than general secret detection); or add live credential validation (actually attempt an authenticated call against the relevant provider's API to confirm a key is *live*) for the small set of providers where that's safe and ethical to do automatically.

---

## 25. Glossary

| Term | Simple definition | Technical definition | In this project |
|---|---|---|---|
| **ORM** | A translator between database rows and programming-language objects | Object-Relational Mapper — a library mapping table rows to class instances and back, generating SQL from method calls | SQLAlchemy; `Scan`, `Finding`, `ScanSchedule` classes in `models.py` |
| **Migration** | A recorded, repeatable change to a database's structure | A versioned script that alters schema (add/drop columns, tables) in a reproducible, ordered way | **Not used here** — `init_db()` uses `Base.metadata.create_all()`, which only ever creates missing tables; it never alters existing ones. A real migration tool (Alembic) would be needed before changing an existing column's type/constraints in production without data loss. |
| **Dependency Injection** | Handing a function what it needs instead of it fetching things itself | A pattern where a framework supplies a function's required collaborators (here, a DB session) automatically based on its declared parameter types | FastAPI's `Depends(get_db)` on every route that needs a database session |
| **Middleware** | A checkpoint every request passes through before reaching its destination | Code that wraps the request/response cycle, running before and/or after the actual route handler | `CORSMiddleware` in `main.py` |
| **Event Loop** | A single worker juggling many waiting tasks at once instead of doing them one at a time | The core of `asyncio` — schedules and resumes coroutines, switching between them at `await` points | What every `async def` function in the backend runs on |
| **Idempotent** | Doing it twice has the same effect as doing it once | An operation whose repeated application produces the same end state as a single application | `seed_demo.py`'s `if count >= len(DEMO_SCANS): return` guard |
| **Cascade delete** | Deleting the parent automatically cleans up its children | A database/ORM-level rule that propagates a delete from a parent row to its dependent rows | `Scan.findings` relationship's `cascade="all, delete-orphan"` |
| **Regex (Regular Expression)** | A pattern language for describing "shapes" of text | A formal mini-language for matching character sequences against a defined pattern | Every `SecretPattern.regex` in `patterns.py` |
| **Lookaround assertion** | Checking what's next to a match without including it in the match | A zero-width regex assertion (`(?<!...)`, `(?!...)`) that requires/forbids adjacent text without consuming it | The AWS key pattern's boundary checks, §7.2 |
| **Streaming response** | Sending a file to the browser as a download instead of as page content | An HTTP response whose body is generated/sent incrementally with headers directing the browser to save it as a file | `StreamingResponse` + `Content-Disposition: attachment` in `export.py` |

---

## 26. Complete Walkthrough: Opening the App

*A single, start-to-finish narration — every layer, in order, for a first-time visitor who explores every major feature.*

A visitor navigates to `https://cipherwatch-web.vercel.app`. Vercel's CDN serves the static `index.html` and JS/CSS bundles instantly (no cold-start delay on the frontend — only the backend sleeps). React mounts. The very first thing that happens, before any visible content, is a fire-and-forget `GET /health` to the Render backend — starting its wake-up clock immediately.

React Router matches the root path `/` to `Dashboard.tsx`. It fires `GET /api/v1/stats`. If the backend was asleep, this request may take up to a minute; the page shows a small animated `loading overview…` placeholder in the meantime — no blank white screen, no layout shift once data arrives. When the response lands, five things render in order down the page: a hairline-divided stat strip (total scans, total findings, critical count, high count — each a large mono numeral), a stacked severity-spectrum bar showing the proportion of CRITICAL/HIGH/MEDIUM/LOW across every finding ever recorded, a hand-drawn SVG stepped line chart of findings-per-day with a hoverable crosshair, a ranked list of the most-detected secret types, and (if the most recent completed scan has a prior baseline to compare against) a diff summary ledger, and finally a recent-activity table of the last six scans.

The visitor clicks "New scan" in the top bar. `NewScan.tsx` renders a segmented source picker defaulting to "GitHub repository." They switch to "Pasted code," paste a snippet containing a fake `AKIA...` key, leave the entropy floor at its default `3.5`, and click "Run scan." The full trace in [§21.1](#211-launching-a-scan-the-complete-trace) plays out: a `Scan` row is inserted with `status='queued'`, a background task starts, a WebSocket opens, and — because a tiny paste scan finishes in well under a second — the fallback HTTP poll is what actually notices completion first in this case, guarded so the WebSocket's own (slightly later) completion message becomes a harmless no-op. The browser navigates to `/history/<new-id>`.

`ScanDetail.tsx` loads three things in parallel: the scan record, its findings, and its diff against any prior scan of the same source (none exists yet, for a first paste). The report renders: a header with the source name and four export buttons (JSON/CSV/SARIF/Patch), a meta line (status/files/completed-at/id), a severity filter strip showing exactly "1 CRITICAL" clickable, and — grouped under the single file heading `"paste"` — one finding row with a red severity spine, the label "AWS Access Key," the masked value, the line number, and a computed risk score. Clicking the row expands it via a smoothly-animated CSS grid-row transition, revealing the 10-segment risk meter, the plain-English list of contributing factors ("Critical severity," possibly "High entropy" if the fake key was random enough), an empty lifecycle section (this scan never touched git history, so `LifecycleTimeline` correctly renders nothing), the full matched string, entropy value, confidence, and a numbered remediation checklist generated specifically for this AWS-key type.

The visitor navigates to "Scans," which lists every scan ever run in a dense, sortable-by-recency table; typing in the search box (or pressing `/` from anywhere on the page to focus it instantly) filters the list client-side with no network round-trip, since the full list was already fetched once and cached by TanStack Query.

Finally, they visit "Schedules," expand the "New schedule" panel, pick the "daily 09:00" cron preset, paste a real public GitHub repo URL, and submit. A `ScanSchedule` row is created and, in the same request, a matching APScheduler cron job is registered in the backend's live scheduler — from this point forward, once every day at 09:00 UTC, completely independent of whether anyone ever opens this website again, that repository will be re-scanned automatically, its results saved, its diff computed against the previous run, and — if any CRITICAL secret is present — an email alert sent, closing the loop from "a developer accidentally typed a secret into a file" all the way to "a human received an email telling them exactly what to fix and how."
