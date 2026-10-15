# CipherWatch — Technical Handbook

> The reference for how CipherWatch 3.0 works, why it is built the way it is, how to run and deploy it, and where its edges are. Written for onboarding, code review, and interview preparation.

**Repo:** https://github.com/Udit013/automated-secrets-scanner
**Hosted demo:** https://cipherwatch-web.vercel.app (API: https://secrets-scanner-api.onrender.com/docs). Both deploy from `main`; `/health` on the API reports the running version.

Claims in this handbook were checked against the source. Where something has **not** been verified (for example, behaviour that only shows up on a live Render deployment), it is labelled as such. [§18](#18-testing-and-verification) lists exactly what was run and what was not.

---

## Table of contents

1. [What CipherWatch is](#1-what-cipherwatch-is)
2. [Architecture](#2-architecture)
3. [Repository layout](#3-repository-layout)
4. [Data model and migrations](#4-data-model-and-migrations)
5. [The detection engine](#5-the-detection-engine)
6. [The credential ledger](#6-the-credential-ledger)
7. [REST API reference](#7-rest-api-reference)
8. [Authentication and private mode](#8-authentication-and-private-mode)
9. [Abuse limits](#9-abuse-limits)
10. [Real-time progress (WebSocket)](#10-real-time-progress-websocket)
11. [Background work: scans, schedules, alerts](#11-background-work-scans-schedules-alerts)
12. [The CLI](#12-the-cli)
13. [The GitHub Action and CI](#13-the-github-action-and-ci)
14. [The console (frontend)](#14-the-console-frontend)
15. [Configuration reference](#15-configuration-reference)
16. [Deployment](#16-deployment)
17. [Security model](#17-security-model)
18. [Testing and verification](#18-testing-and-verification)
19. [Troubleshooting](#troubleshooting)
20. [Design decisions and trade-offs](#20-design-decisions-and-trade-offs)
21. [Known limitations](#21-known-limitations)
22. [Interview question bank](#22-interview-question-bank)
23. [Glossary](#23-glossary)

---

## 1. What CipherWatch is

### 1.1 The problem

Developers sometimes paste a credential straight into code, such as `stripe_key = "sk_live_…"`, and commit it. Once pushed, anyone with read access to the repository, or any clone of it, has that credential, and deleting the line later doesn't remove it from git history. Automated scrapers search public GitHub for exactly this.

Detection alone doesn't close the loop. GitGuardian's [State of Secrets Sprawl 2025](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/) reports that **70% of secrets leaked in 2022 were still valid**: the leaks were found but never rotated. A line-level scanner report also can't answer the questions that matter afterwards: *which credentials* are exposed (one key copied into five files is one problem), which have been handled, and whether the latest scan found anything *new*.

### 1.2 The product

CipherWatch is a **credential exposure ledger**:

1. **Detect** credentials in a GitHub repository's current code and, optionally, its git history (26 patterns plus entropy analysis).
2. **Deduplicate** every occurrence into one *credential*, identified by a keyed HMAC fingerprint that never contains the secret.
3. **Decide** what each credential's status is: `open`, `rotated`, `false_positive`, or `accepted_risk` with a mandatory review date. Decisions persist across scans.
4. **Gate** CI on *new* credentials only, via a CLI and a composite GitHub Action that compare against a committed baseline of fingerprints, and emit SARIF for GitHub code scanning.

### 1.3 Positioning and scope

Free, mature detectors already exist ([Gitleaks vs. TruffleHog](https://appsecsanta.com/gitleaks-vs-trufflehog)), and Gitleaks' [baseline workflow](https://tessl.io/registry/testland/gitleaks-scanning/files/references/baseline.md) shows that teams want "fail only on new". CipherWatch's opportunity is the **post-detection lifecycle**, not raw detection. Out of scope on purpose:

- **Live key verification.** Calling a provider's API with a leaked key means using someone else's credential. CipherWatch treats every detection as live until a person decides otherwise.
- **Cloud posture, dependency, or IaC scanning.** These are different products.
- **AI or LLM features.** Detection is deterministic and explainable, and the zero-cost requirement rules out paid inference.

### 1.4 Who it's for

- A **solo developer or small team** that wants CI to block new leaks without paying for an enterprise platform.
- An **engineer auditing an existing codebase** who needs to know what is exposed, for how long, and which items are already dealt with.
- A **platform team** that wants unattended rescans and an email only when something new and critical appears.

---

## 2. Architecture

```text
                    ┌──────────────────────────────────────────────┐
  CLI / Action  ───▶│ backend/app/scanner  (pure Python)           │
  (no server)       │  patterns · entropy · placeholders · history │
                    │  fingerprints · risk score · SARIF · patch   │
                    └──────────────────────┬───────────────────────┘
                                           │ same engine, imported
┌──────────────────────────────────────────▼──────────────────────────────────┐
│ FastAPI app (uvicorn)                                                        │
│  routers: scans · projects · export · schedules · stats      + /health       │
│  security.py: require_access (bearer / WS subprotocol) · rate limiter        │
│  services/inventory.py: credentials, triage state, trend, diff, alerts       │
│  workers/scheduler.py: APScheduler (UTC cron)   notifications.py: aiosmtplib │
└──────────────────────────────────────────┬──────────────────────────────────┘
                                           │ SQLAlchemy 2.0 async (aiosqlite / asyncpg)
             SQLite (local, demo)  or  PostgreSQL (Docker Compose, Neon free tier)
             scans · findings · credential_states · scan_schedules · app_settings

React 18 SPA (Vite 6, React Router 7, TanStack Query 5, Tailwind CSS 3)
  served by Vercel, by nginx (Docker), or by the Vite dev server (local)
External: GitHub REST API (zipball) + git clone (history) · SMTP (optional)
```

- **One process.** Scanning, scoring, exports, and scheduling run inside the FastAPI process. There is no queue, worker fleet, or cache service, which keeps hosting free.
- **Framework-free core.** `backend/app/scanner/` imports nothing from FastAPI or SQLAlchemy. The CLI imports it directly and needs only GitPython; the web layer wraps it.
- **No AI components.** Every decision the engine makes is a regex match, an entropy number, or an additive score with stated reasons.

---

## 3. Repository layout

```text
automated-secrets-scanner/
├── action.yml                    # Composite GitHub Action (CI gate)
├── cli.py                        # CLI entry point: translates pre-3.0 flags, calls backend/app/cli.py
├── .cipherwatch-baseline.json    # This repo's own baseline (deliberate fixtures and demo data)
├── .github/workflows/ci.yml      # backend · legacy-scanner · frontend · self-scan jobs
├── docker-compose.yml            # Postgres 16 + API + nginx console
├── render.yaml                   # Render blueprint for the API
├── scanner_core.py, test_scanner.py   # Legacy pre-web engine and its 19 tests (unused by the product)
├── backend/
│   ├── Dockerfile, .dockerignore # python:3.11-slim + git, non-root user (uid 10001)
│   ├── requirements.txt, requirements-dev.txt, pytest.ini, .env.example
│   ├── seed_demo.py              # Sample projects with fake credentials and triage (guarded)
│   ├── app/
│   │   ├── main.py               # App, CORS, router mounting behind require_access, /health, lifespan
│   │   ├── config.py             # pydantic-settings: every environment variable
│   │   ├── database.py           # Engine, sessions, init_db, additive upgrades, fingerprint key
│   │   ├── models.py             # Scan, Finding, ScanSchedule, CredentialState, AppSetting
│   │   ├── schemas.py            # Request/response models and input validation
│   │   ├── security.py           # Access token, client IP, sliding-window limiter
│   │   ├── cli.py                # `scan` and `baseline` subcommands
│   │   ├── notifications.py      # SMTP alert (escaped HTML; never includes pasted text)
│   │   ├── scanner/              # core.py · patterns.py · risk.py · sarif.py · remediation.py · github_scanner.py
│   │   ├── services/inventory.py # Credential grouping, triage, trend, exposure totals, alert selection
│   │   ├── routers/              # scans.py · projects.py · export.py · schedules.py · stats.py
│   │   └── workers/scheduler.py  # APScheduler wrapper (UTC)
│   └── tests/                    # 130 tests (see §18)
└── frontend/
    ├── Dockerfile, nginx.conf    # Static build behind nginx; proxies /api (incl. WebSocket) and /health
    ├── vercel.json               # SPA rewrites for Vercel
    ├── .eslintrc.cjs, vite.config.ts, tailwind.config.js, tsconfig.json
    └── src/
        ├── main.tsx, App.tsx, index.css
        ├── api/client.ts         # axios client, types, API functions, parseUtc, downloads
        ├── api/auth.ts           # Token store (sessionStorage / localStorage)
        ├── hooks/                # useHealth, useWebSocket
        ├── lib/                  # severity colours, risk bands, status labels
        ├── components/           # Gate, Layout, TopBar, Mark, ui, credentials, charts, badges, DiffSummary, LifecycleTimeline
        └── pages/                # Landing, Dashboard (Overview), Projects, ProjectDetail, NewScan, ScanHistory, ScanDetail, Schedules
```

`knowledge_doc.md` at the repo root is a personal notes file that is git-ignored and not part of the product.

---

## 4. Data model and migrations

### 4.1 Tables

All models live in `backend/app/models.py`, written in SQLAlchemy 2.0's typed `Mapped[...]` style. Primary keys are UUID4 strings. Timestamps are **naive UTC** (`utcnow_naive()`), the convention everywhere, because SQLite has no timezone-aware type; see §11.2 for the bug this convention caught on Postgres.

| Table | Purpose | Key columns |
|---|---|---|
| `scans` | One scan run | `source_type` (`github`/`paste`), `source_ref` (`VARCHAR(300)`, indexed: a normalized GitHub URL or a `paste:<12 hex>` label), `scan_git_history`, `max_commits`, `min_entropy`, `status` (`queued`/`running`/`completed`/`failed`), `progress`, `total_findings`, `files_scanned`, `error_message`, `created_at`, `completed_at` |
| `findings` | One detection at one location | `scan_id` (FK, cascade delete), `file_path`, `line_number`, `secret_type`, `matched_string` (**masked**), `entropy`, `severity`, `confidence`, `context` (line with **every** secret masked), `commit_hash`, `remediation`, `is_in_history`, `risk_score`, `risk_factors` (JSON), lifecycle fields (`introduced_at`, `last_seen_at`, `exposure_days`, `commits_affected`, `authors_count`), `fingerprint` (`VARCHAR(32)`, indexed, nullable) |
| `credential_states` | Triage decision per credential per project | `source_ref`, `fingerprint`, `status`, `note`, `review_by`, `updated_at`; **unique** on (`source_ref`, `fingerprint`) |
| `scan_schedules` | Recurring scans | `name`, `source_type` (`github` only), `source_ref`, `cron_expression` (UTC), `scan_git_history`, `enabled`, `last_run_at`, `next_run_at`, `last_scan_id` |
| `app_settings` | Install-level key/value | `fingerprint_key` (hex, when not supplied by env), `demo_seeded` marker |

`Scan.findings` uses `cascade="all, delete-orphan"` (deleting a scan deletes its findings) and `lazy="selectin"` (findings are loaded eagerly, avoiding async lazy-load errors at serialization time). Triage state lives in its own table, keyed by fingerprint rather than by finding row, which is what lets it survive rescans.

### 4.2 Migrations: additive upgrades at startup

There is no Alembic. `init_db()` runs on every start:

1. `Base.metadata.create_all` creates any missing tables. That's how pre-3.0 databases gain `credential_states` and `app_settings`.
2. `_apply_additive_upgrades()` inspects existing tables and, idempotently:
   - adds `findings.fingerprint` if it's missing, plus the index `ix_findings_fingerprint`;
   - creates `ix_scans_source_ref`, **unless** some `source_ref` value is longer than 300 characters. Databases from before 2.1 stored whole pastes in `source_ref`, and PostgreSQL refuses btree index entries over about 2.7 KB (`ProgramLimitExceededError`), which would stop the server from starting. In that case the index is skipped with a logged warning. It is only a speed-up, so correctness is unaffected, and the legacy rows are left untouched.
3. `_load_fingerprint_key()` configures the HMAC key (§5.6).

Only nullable columns and indexes are ever added; nothing is dropped or rewritten. Verified on SQLite and PostgreSQL 18, including the oversized-legacy-row case (§18). Anything destructive would need a real migration tool.

**Legacy rows.** Findings written before 3.0 have no fingerprint. The inventory service gives them a stand-in key, `"l"` followed by 31 hex characters of `sha256(secret_type|matched_string|file_path)`, so they still group and can still be triaged (tested). Pre-2.1 rows may also contain unmasked context or pasted content; 3.0 doesn't rewrite them (see §21).

---

## 5. The detection engine

Everything in this section lives in `backend/app/scanner/` and runs in memory, deterministically, with no network calls except fetching the repository itself.

### 5.1 Pipeline per line

```text
line ─▶ comment skip ─▶ 26 regex patterns ─▶ placeholder filter ─▶ entropy gate ─▶ severity + risk ─▶ Finding
        (#, //, *, <!--;          (patterns.py)    (is_placeholder)     (generic patterns   (test paths downgrade
         never "-----BEGIN")                                             only)               one level)
```

### 5.2 Patterns

`SecretPattern` fields: `name`, `regex`, `severity`, `format_specific` (if true, the entropy gate is skipped), `remediation`, `marker` (the match is a fixed header, not the secret), and `rotation_url`.

The 26 patterns are: AWS Access Key, AWS Secret Access Key, GitHub Personal Access Token, GitHub OAuth Token, GitHub App Token, Google API Key, GCP Service Account Key (marker), Stripe Live / Test Secret Key, Slack Bot / App Token, Twilio API Key, SendGrid API Key, Private SSH Key (RSA/DSA/EC/OpenSSH header; marker), PGP Private Key (marker), JWT Token, Database Connection String, Generic API Key, Generic Secret, Hardcoded Password, Azure Storage Key, Azure SAS Token (marker), npm Auth Token, PyPI API Token, Discord Bot Token, and Mailgun API Key.

**Rotation URLs:** 19 patterns across 12 providers link to the provider page where the key is revoked: AWS IAM, GitHub token settings, Google Cloud credentials and service accounts, Stripe API keys, Slack apps, Twilio, SendGrid, Azure storage accounts, PyPI, Discord, Mailgun, and npm's revocation guide. Each URL was checked to resolve (usually via a login redirect); npm's site rejects non-browser clients, so it links to `docs.npmjs.com/revoking-access-tokens` instead.

**Placeholders.** `is_placeholder()` rejects `YOUR_KEY_HERE`, `${VAR}`, `<PLACEHOLDER>`, `xxx…`, `changeme`, and words such as `test`, `demo`, `sample`, `mock`, `dummy` when they start at a word boundary, strings under 8 characters, and strings with a unique-character ratio below 0.3. `example` matches anywhere, because vendor docs embed it mid-token (AWS's `AKIAIOSFODNN7EXAMPLE`).

**Test-path downgrade.** Paths matching `tests/`, `.spec.`, `_test.py`, `fixtures/`, and similar drop one severity level.

### 5.3 Entropy

Shannon entropy, `H = −Σ pᵢ log₂ pᵢ` over characters, measures how random a string looks. Format-specific patterns skip it, since their shape is evidence enough. The three generic patterns (Generic API Key, Generic Secret, Hardcoded Password) must clear the floor (default 3.5 bits, configurable 0–8 per scan).

### 5.4 File selection

- **Extensions:** source and config types, plus `.pem`, `.key`, `.cfg`, and `.ipynb`.
- **Exact filenames:** `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.dockercfg`, `Dockerfile`, `credentials`, plus anything starting with `.env`.
- **Skipped:** `IGNORE_DIRS` (`.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `build`, `dist`, `target`, `.tox`, caches, …), symlinks, and files over **5 MB** (`MAX_FILE_BYTES`). Git-history scans apply the same directory and size rules (both tested).
- **Paths are repo-relative POSIX** (`iter_scannable_files`). GitHub zipballs wrap the tree in `{owner}-{repo}-{sha}/`, and the scanner descends into that directory first. Without this, location-scoped fingerprints would change on every scan.

### 5.5 Git history (opt-in)

`scan_git_history()` walks `iter_commits("HEAD", max_count=max_commits)` and scans every scannable blob at every commit. That's `O(commits × files)`, which is why it is opt-in. Matches are aggregated per `(file_path, secret_type, fingerprint)` across commits into one finding with `introduced_at`, `last_seen_at`, `exposure_days`, `commits_affected`, and `authors_count`, and the risk score is recomputed with that context. For GitHub scans the repository is cloned with `--depth=max_commits`. History is best-effort: a clone failure is logged and the current-tree results are still returned.

### 5.6 Masking and fingerprints

**Masking.** `_mask` keeps the first and last four characters and stars the rest (`AKIAV3WBCDEF4GHI7JKM` becomes `AKIA************7JKM`); values of 8 characters or fewer are fully starred. (The seeded demo data uses a shorter `AKIA***...***JKM` style.) `context` masks *every* secret detected on its line (`_mask_secrets_in`), so a line holding two secrets never leaks either. Pasted text is passed to the scan task in memory only; `source_ref` stores `paste:` plus 12 hex characters of its SHA-256.

**Fingerprints** identify a *credential* rather than a line:

```python
def fingerprint(raw, pattern, file_path, masked) -> str:
    if pattern.marker or not pattern.format_specific:
        material = f"loc\x00{pattern.name}\x00{file_path}\x00{masked}"   # location-scoped
    else:
        material = f"val\x00{raw}"                                        # value-scoped
    return hmac.new(_fingerprint_key, material.encode(), hashlib.sha256).hexdigest()[:32]
```

- **Value-scoped** for format-specific patterns: the same AWS key anywhere in the repo, in any commit, is one credential.
- **Location-scoped** for markers, where the match is a shared header and not the secret, and for generic patterns, whose values can be low-entropy enough (`Summer2024!`) that even a keyed hash of the value is best avoided.
- **The key.** On the server, `FINGERPRINT_KEY` (UTF-8 bytes) wins; otherwise a random 32-byte key is generated once, stored as hex in `app_settings`, and loaded with `bytes.fromhex`. The CLI uses `FINGERPRINT_KEY` (UTF-8) if set, or else the public constant `cipherwatch-fingerprint-v1`. **CLI and console fingerprints therefore match only when both get the same `FINGERPRINT_KEY` from the environment** (tested). Changing the server's key re-keys every new finding, and existing triage decisions stop matching new scans.
- `fingerprint_key_id()` is a 12-hex HMAC of a constant under the active key. Baselines record it so a mismatched key is detected instead of silently treating everything as new.

### 5.7 Risk score (`risk.py`)

An additive, explainable heuristic, capped at 100. Severity sets the base (CRITICAL 55, HIGH 35, MEDIUM 18, LOW 8). Bonuses: present in git history +18; extra occurrences up to +12; exposure duration +5 to +15; more than one author +5; entropy ≥ 5.0 +5. Every point appends a reason string that the console shows. `riskBand` thresholds are 80, 55, and 30.

### 5.8 SARIF and remediation

- **`sarif.py`** builds SARIF 2.1.0: one rule per secret type, one result per finding, `security-severity` for GitHub's UI, and two `partialFingerprints`: the legacy `secretsScanner/v1` (`file:type:masked`), and `cipherwatch/credential/v1` (the credential fingerprint, when present), so a key that moves files is recognised as the same alert.
- **`remediation.py`** derives an environment-variable name (from the source line, or a type map), writes idiomatic replacement lines (Python, Node, Ruby, Go, PHP, `.env`), a `.env.example` snippet, next steps, and a unified-diff-*styled* `remediation.patch`. The patch uses masked values, so it is a reference for a human, not something guaranteed to `git apply`.

---

## 6. The credential ledger

`backend/app/services/inventory.py` turns findings into credentials. All routers that show credentials go through it.

### 6.1 Grouping

`group_credentials(findings, states, first_seen=None)` groups findings by `credential_key` (the fingerprint, or the legacy stand-in) and returns one record per credential:

| Field | Meaning |
|---|---|
| `severity`, `secret_type`, `risk_factors`, `masked_value`, `remediation` | from the most severe, highest-risk occurrence |
| `risk_score` | max across occurrences |
| `exposure` | `history_only` if no occurrence is in the current tree, else `working_tree` |
| `locations`, `location_count` | distinct (file, line, in_history, commit) tuples |
| `first_seen` | earliest of the first completed scan containing it and the earliest `introduced_at` |
| `exposure_days`, `commits_affected`, `authors_count` | max across occurrences |
| `status`, `stored_status`, `review_overdue`, `review_by`, `note`, `triaged_at` | from `credential_states` via `effective_status()` |
| `rotation_url` | from the pattern |

Credentials sort by status (open first), then severity, then risk.

### 6.2 Triage

- **Statuses.** `open` is the default when there's no row; then `rotated`, `false_positive`, and `accepted_risk`.
- **Waivers expire.** `accepted_risk` *requires* `review_by`, which must be in the future and at most 366 days out (`TriageRequest` validator, converted to naive UTC). Once it passes, `effective_status()` reports `open` with `review_overdue: true`, while `stored_status` still shows the original decision. For other statuses, `review_by` is cleared.
- **Endpoint.** `PUT /projects/{owner}/{repo}/credentials/{fingerprint}`:
  1. rejects a malformed fingerprint (`422`, regex `^[0-9a-fl][0-9a-f]{31}$`);
  2. looks the credential up among the project's completed-scan findings with an indexed query on `fingerprint`, or for an `l…` legacy key, among rows without a fingerprint; `404` if absent, so state can't be planted for credentials a project never produced;
  3. upserts the `credential_states` row, retrying as an update if a concurrent first decision wins the unique-constraint race.

### 6.3 Project views

- **Projects** are distinct `github` `source_ref`s matching `https://github.com/{owner}/{repo}`. Pastes are never projects.
- **`project_inventory()`** returns the latest completed scan's credentials, with `first_seen` (which walks every scan of the project, selecting only five columns).
- **`project_overview()`** and **`exposure_totals()`** skip `first_seen`, because counts don't depend on it. This matters: `/stats` is polled every 15 s by the top bar and Overview.
- **`project_trend()`** gives up to 30 completed scans, oldest first, with `credentials`, `open`, `critical_open`, `new`, and `removed`. Triage is applied with today's decisions, so the trend reflects current understanding.

### 6.4 Diff and alerts

- **`GET /scans/{id}/diff`** compares credential sets with the previous completed scan of the same source. A key that moved files is *unchanged*. New and resolved lists are sorted by risk.
- **`new_open_critical(db, scan)`** returns CRITICAL credentials in this scan that are **absent from the previous completed scan** and **not triaged**. Email alerts fire only for these. A credential that disappears and later reappears counts as new again.

---

## 7. REST API reference

All `/api/v1` routers are mounted with `dependencies=[Depends(require_access)]` (§8). `/health` is public. Swagger UI is at `/docs`.

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/v1/scans` | `202`. Rate limit (per IP) + concurrency cap. Body `StartScanRequest` |
| `GET` | `/api/v1/scans?limit&offset` | Scan list (no findings, no `error_message`) |
| `GET` | `/api/v1/scans/{id}` | Scan + findings |
| `GET` | `/api/v1/scans/{id}/findings?severity&secret_type&limit&offset` | Findings |
| `GET` | `/api/v1/scans/{id}/diff` | Credential-level diff |
| `DELETE` | `/api/v1/scans/{id}` | `204`, cascades findings |
| `WS` | `/api/v1/scans/ws/{id}` | Progress events (§10) |
| `GET` | `/api/v1/projects` | Projects with summaries, most urgent first |
| `GET` | `/api/v1/projects/{owner}/{repo}` | Overview + trend; `404` if never scanned |
| `GET` | `/api/v1/projects/{owner}/{repo}/credentials?status&severity&exposure` | The ledger |
| `PUT` | `/api/v1/projects/{owner}/{repo}/credentials/{fingerprint}` | Body `{status, note?, review_by?}` |
| `GET` | `/api/v1/export/{id}/json`, `/csv`, `/sarif`, `/patch` | Downloads (`Content-Disposition`) |
| `GET` | `/api/v1/export/{id}/remediation` | Structured remediation JSON |
| `GET` | `/api/v1/stats` | Raw totals + `exposure` (deduplicated, net of triage) |
| `POST` | `/api/v1/schedules` | `201`; `409` beyond `MAX_SCHEDULES` |
| `GET` | `/api/v1/schedules`, `/schedules/{id}` | List / get |
| `PATCH` | `/api/v1/schedules/{id}/toggle` | Pause/resume |
| `DELETE` | `/api/v1/schedules/{id}` | `204` |
| `GET` | `/health` | `{status, version, auth_required, demo}` |

**Validation highlights (`schemas.py`):**
- GitHub URLs must match `https://github.com/{owner}/{repo}` and are normalized: a trailing `.git` or `/` is removed, giving at most ~160 characters.
- Pastes are at most 512 KB; `max_commits` is 1–1000 and `min_entropy` 0–8.
- Schedules accept GitHub only. Cron is parsed by APScheduler's `CronTrigger`, so bad fields get `422`, and anything running more often than every 15 minutes is rejected.
- Triage notes are at most 2,000 characters.

**Error shapes:** `401` (`WWW-Authenticate: Bearer`), `404`, `409`, `422` (Pydantic detail array), `429` (`Retry-After` header, human-readable `detail`).

---

## 8. Authentication and private mode

`security.py` defines the access check:

- **`ACCESS_TOKEN` unset: demo mode.** `require_access` is a no-op and every endpoint is public, protected only by §9.
- **`ACCESS_TOKEN` set: private workspace.** Every `/api/v1` request must present the token:
  - HTTP: `Authorization: Bearer <token>`.
  - WebSocket: browsers can't set headers on a handshake, so the client offers subprotocols `cipherwatch.v1, bearer.<token>`. The server reads the `bearer.` entry and, once authorized, accepts with `cipherwatch.v1` (a browser drops the connection unless the server selects one of the offered protocols). A query parameter would also work, but it would be written to uvicorn's and every proxy's access log. A failed check is denied with an HTTP `401` before the socket is accepted (tested at the ASGI level).
  - Comparison uses `hmac.compare_digest`.
- **`/health` stays public** and reports `auth_required`, so the console knows whether to show its unlock screen.

**Console flow.**
1. `<Gate>` waits for `/health`; if `auth_required` and no token is stored, it shows the unlock screen.
2. The token is checked with `GET /api/v1/stats` before being stored: in `sessionStorage` by default, or `localStorage` if "Remember on this device" is ticked.
3. An axios request interceptor adds the header, and any `401` response clears the token and relocks.
4. "Lock" in the top bar forgets the token.
5. Exports download through axios as blobs, since a plain `<a href>` can't carry the header.

**Scope.** This is one shared secret per deployment: there are no users, roles, or per-user audit trail. Generate it with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.

---

## 9. Abuse limits

| Limit | Default | Behaviour |
|---|---|---|
| Scan creation rate | 10 per 600 s per client IP (`SCAN_RATE_LIMIT`, `SCAN_RATE_WINDOW_SECONDS`) | `SlidingWindowLimiter`; `429` + `Retry-After`; message like "Try again in 10 min" |
| Concurrent scans | 3 queued/running (`MAX_CONCURRENT_SCANS`) | `429` + `Retry-After: 60`. Check-then-insert, so a simultaneous burst can briefly exceed it (soft cap) |
| Schedules | 25 (`MAX_SCHEDULES`) | `409` |
| Paste size | 512 KB | `422` |
| Repository archive | 100 MB download, 500 MB uncompressed, 50,000 members | Scan fails with a clear message |
| Scanned file size | 5 MB | Larger files are skipped |

- **Client IP.** `client_ip()` uses the socket peer unless `TRUSTED_PROXY_HOPS > 0`. Then it takes the entry that many positions from the **right** of `X-Forwarded-For`, which is the last address a trusted proxy appended, so anything a client prepends is ignored (tested).
- **Memory.** The limiter tracks at most 10,000 clients, evicting idle ones.
- **Per-process state.** Limits are in-process: they reset on restart and aren't shared between instances.

---

## 10. Real-time progress (WebSocket)

`/api/v1/scans/ws/{scan_id}` is push-only. The server broadcasts JSON events and reads only to notice disconnects:

```json
{"event": "started", "progress": 0}
{"event": "progress", "progress": 20, "message": "Extracted repository"}
{"event": "completed", "progress": 100, "total_findings": 7, "files_scanned": 312}
{"event": "failed", "error": "…"}
```

- **Registry.** `_ws_registry` maps a scan ID to its open sockets and is pruned on disconnect and when the scan ends. It is per-process, so a multi-instance deployment would need shared pub/sub.
- **Client.** `useWebSocket` opens one socket per active scan (sending the token as a subprotocol in private mode) and closes it on unmount.
- **Fallback.** Fast scans can finish before the socket connects, so `NewScan` also polls `GET /scans/{id}` every 1.5 s. A single `settle` handler, guarded by `finishedRef`, ensures exactly one navigation, whichever channel reports the terminal state first.
- **Design note.** Because the channel is one-directional, Server-Sent Events would be a leaner fit; WebSocket is what was built, and it works through nginx (verified).

---

## 11. Background work: scans, schedules, alerts

### 11.1 Scans

`POST /scans` inserts a `queued` row and schedules `_run_scan()` as a FastAPI `BackgroundTask`.
- **Off the event loop.** CPU and disk work runs in `asyncio.to_thread`: extraction, the directory scan, and the history walk. The measured worst event-loop stall dropped from 21 s to about 25 ms on a history scan of `pallets/flask` (v2.1 measurement).
- **Not durable.** At startup, `mark_interrupted_scans()` marks leftover `queued`/`running` scans `failed`. They aren't retried.
- **Alert evaluation** runs after the scan is saved as completed, inside a `try` block, so an alerting error can't mark a completed scan failed.

### 11.2 Schedules

- **Scheduler.** `workers/scheduler.py` uses one `AsyncIOScheduler(timezone=utc)`, and `CronTrigger`s are pinned to UTC.
- **Restart-safe.** The job store is in memory, so `restore_schedules()` re-registers every stored schedule at startup, pausing disabled ones so they can be resumed later.
- **Shared code path.** A fire creates a `Scan` and calls the same `_run_scan()` a manual scan uses.
- **UTC normalization.** `_next_run_time()` converts APScheduler's timezone-aware datetimes to naive UTC. Without it, PostgreSQL rejected schedule creation outright; SQLite had silently accepted the value. Found by running the suite on Postgres.
- **Missed runs.** A fire time that passes while the server is asleep is skipped, not run late.

### 11.3 Alerts

`notifications.send_critical_alert` sends one escaped HTML email via `aiosmtplib`. It does nothing unless `SMTP_USER`, `SMTP_PASSWORD`, and `ALERT_EMAIL` are all set. It fires for the credentials selected by `new_open_critical` (§6.4), labels pastes as "pasted content", and never includes their text. The task handle is kept in a module-level set so it isn't garbage-collected mid-send.

---

## 12. The CLI

```bash
python cli.py scan PATH [--history] [--max-commits N] [--min-entropy X]
                        [--format text|json|sarif] [-o FILE] [--sarif FILE]
                        [--baseline FILE] [--fail-on critical|high|medium|low|none]
python cli.py baseline PATH [--history] [-o .cipherwatch-baseline.json]
```

- **Dependencies.** `cli.py` adds `backend/` to `sys.path` and calls `app.cli.main`, which imports only the scanner package. It needs Python 3.11+, GitPython, and the `git` binary for `--history`; no server, database, or FastAPI.
- **Exit codes.** `0` means no new credential at or above `--fail-on` (default `low`), `1` means at least one, and `2` means a usage or I/O error (missing path, unsupported baseline version, key mismatch).
- **Output.**
  - `text`: a summary line, then one row per credential, tagged `NEW` or `base`.
  - `json`: one entry per credential, with `baselined`.
  - `sarif`: only credentials not in the baseline.
  - `--sarif FILE`: writes SARIF *alongside* any format, so CI scans once.
- **Baseline v1.**

  ```json
  {"version": 1, "key_id": "36e1268d47c0", "generated_at": "…", "note": "…",
   "credentials": [{"fingerprint": "…", "secret_type": "…", "file_path": "…"}]}
  ```

  It contains no secret values (tested), so it's safe to commit. Review the entries and rotate anything real before committing.
- **Fingerprint key.** `FINGERPRINT_KEY` from the environment, otherwise the public default (§5.6).
- **Legacy flags.** `-d DIR` / `-f FILE` map to `scan PATH`, `-g REPO` maps to `scan REPO --history`, `--format console` maps to `text`, and `--stats`, `--recursive`, and `--verbose` are ignored.

---

## 13. The GitHub Action and CI

### 13.1 `action.yml` (composite)

| Input | Default |
|---|---|
| `path` | `.` |
| `fail-on` | `high` |
| `baseline` | `.cipherwatch-baseline.json` (used only if the file exists) |
| `history` | `"false"` (needs `actions/checkout` with `fetch-depth: 0`) |
| `max-commits` | `100` |
| `sarif-file` | `cipherwatch.sarif` (also an output) |

Steps:
1. `actions/setup-python@v5` with `update-environment: false`. The action gets its own Python 3.11 and doesn't change `PATH` for the caller's later steps.
2. Create a virtualenv in `$RUNNER_TEMP` and install `GitPython>=3.1.40,<4`.
3. One scan: a masked summary in the log, SARIF on disk, and the exit code as the gate.

**Script-injection safety.** Inputs are passed through `env:` and referenced as `"$CW_…"`, never as `${{ inputs.… }}` inside `run:`.

**Runners.** Linux and macOS only: the private virtualenv is invoked as `$RUNNER_TEMP/cipherwatch-venv/bin/python`, a path that doesn't exist on Windows runners.

**Verification status.** Both script steps were run locally exactly as written, under `bash -eo pipefail`: a clean tree exits 0 with an empty SARIF, and an injected token exits 1 with one SARIF result. On GitHub (CI run for commit `7a8a228`), the `self-scan` job ran the action on `ubuntu-latest`: 100 files, 45 credentials, 0 new, and the SARIF upload to code scanning validated and processed.

### 13.2 `.github/workflows/ci.yml`

| Job | What it runs |
|---|---|
| `backend` | `pip install -r requirements-dev.txt`, `pytest tests/` (Python 3.11) |
| `legacy-scanner` | Root `requirements.txt`, `pytest test_scanner.py` |
| `frontend` | `npm ci`, `npm run lint` (zero warnings allowed), `npm run build` (tsc + vite) |
| `self-scan` | `uses: ./` with `fail-on: high` against `.cipherwatch-baseline.json`; SARIF uploaded to code scanning on pushes |

The repository's own baseline records its 45 deliberate fixtures (test inputs, demo files, pattern definitions), so `self-scan` fails only when a new credential appears. Regenerate it from a clean copy of tracked files when fixtures change on purpose (§19).

---

## 14. The console (frontend)

### 14.1 Routes

| Path | Page | Notes |
|---|---|---|
| `/` | `Landing` | Public; explains the product, CI usage, and principles; CTA into the console |
| `/overview` | `Dashboard` | Open credentials, critical open, history-only, overdue reviews, projects; severity spectrum; needs-attention list; raw detections per day; top types; recent scans |
| `/projects` | `Projects` | Table sorted by urgency |
| `/projects/:owner/:repo` | `ProjectDetail` | The ledger: stats, overdue banner, trend, status tabs, severity and exposure filters, expandable credentials with facts, locations, risk factors, remediation, rotation link, and `TriageForm`; rescan; `404` shows "not scanned" |
| `/scan` | `NewScan` | GitHub or paste; history, depth, and entropy options; progress; public-workspace notice; rate-limit messages |
| `/history`, `/history/:id` | `ScanHistory`, `ScanDetail` | Scan list and report (diff, findings by file, exports, link to the ledger) |
| `/schedules` | `Schedules` | Create, pause, delete; cron presets; UTC |
| `*` | `EmptyState` | Not found |

Everything except `/` is wrapped in `<Gate><Layout/></Gate>`. `/dashboard` redirects to `/overview`.

### 14.2 Data layer

- **`api/client.ts`.** An axios instance at `${VITE_API_URL}/api/v1` (relative in dev, where Vite proxies `/api` and `/health` to `:8000`), plus the auth interceptor, typed API functions, and these helpers:
  - `apiErrorMessage` turns FastAPI `detail`, 429 waits, network errors, and 5xx into sentences.
  - `parseUtc` marks the API's naive UTC timestamps as UTC before `new Date()`; otherwise browsers would read them as local time.
  - `downloadExport` fetches with the token and names the file from `Content-Disposition`.
  - `shortRef` and `projectSlug` shorten and parse GitHub references.
- **TanStack Query** owns server state. `retry` covers network and 5xx errors up to twice but never 4xx; `staleTime` is 30 s; `/stats` is refetched every 15 s. Mutations invalidate the related keys: triage invalidates `credentials`, `project`, `projects`, and `stats`.
- **Local UI state** is plain `useState`. The token store (`api/auth.ts`) is a tiny external store read with `useSyncExternalStore`.

### 14.3 UX states and accessibility

- **States.** Shared `ui.tsx` primitives (`PageHeader`, `LoadingRows`, `EmptyState`, `ErrorState`, `InlineError`, `Stat`) give every data view loading, empty, and error states. A 404 project shows a "not scanned" state instead of an error.
- **Keyboard.** A skip link, visible `:focus-visible` outlines, and real links in table rows, so they work without a mouse. Collapsed panels are `invisible`, which takes them out of the tab order and the accessibility tree. Filters are toggle buttons (`aria-pressed`), and expanders use `aria-expanded`/`aria-controls`.
- **Announcements.** Status changes use `role="status"` / `aria-live`, and errors use `role="alert"`.
- **Colour.** Severity is never shown by colour alone, and `ivory-mute` text meets WCAG AA (4.5:1+) on every surface.
- **Layout.** Checked at 375 px with no horizontal page overflow (wide tables scroll inside their container). Motion is reduced under `prefers-reduced-motion`.

### 14.4 Design system

There is no component library. `tailwind.config.js` *replaces* Tailwind's palette:
- **Colours:** `ink` surfaces (4 steps), `line` hairlines, `ivory` text (4 steps), `sev` (critical/high/medium/low, the only meaningful hues), and `ok`.
- **Type:** Instrument Sans for UI text; IBM Plex Mono for every number, path, hash, and timestamp.
- **Structure:** sections separate with hairline rules and background steps rather than bordered cards.
- **Charts** are hand-built SVG (`SeveritySpectrum`, a stepped `TrendChart` that measures its container with `ResizeObserver`, `RankedTypes`), so there is no chart-library weight.

---

## 15. Configuration reference

Backend settings (`backend/app/config.py`, read from the environment or `backend/.env`):

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./secrets_scanner.db` | `postgresql+asyncpg://…` for Postgres (pool 10 + 20 overflow) |
| `ACCESS_TOKEN` | empty | Empty = demo mode; set = private workspace |
| `FINGERPRINT_KEY` | empty | Empty = generated and stored in `app_settings`; set it in production and keep it stable |
| `SCAN_RATE_LIMIT`, `SCAN_RATE_WINDOW_SECONDS` | `10`, `600` | Per client IP |
| `MAX_CONCURRENT_SCANS` | `3` | Soft cap |
| `MAX_SCHEDULES` | `25` | |
| `TRUSTED_PROXY_HOPS` | `0` | `1` behind exactly one appending proxy |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000` | Comma-separated |
| `GITHUB_TOKEN` | empty | 60 → 5,000 GitHub API requests/hour |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `ALERT_EMAIL` | `smtp.gmail.com`, `587`, empty… | Alerts are disabled unless user, password, and recipient are set |
| `BACKEND_URL` | `http://localhost:8000` | Links in emails |

Other variables:

| Variable | Where | Notes |
|---|---|---|
| `SEED_DEMO` | `render.yaml` start command | `1` runs `seed_demo.py` before uvicorn |
| `VITE_API_URL` | console build | API origin when the console is hosted separately; baked in at build time |
| `TEST_DATABASE_URL` | test suite | Run the backend tests on another database; the name must contain `test` |
| `FINGERPRINT_KEY` | CLI | Same meaning as on the server |

Annotated template: `backend/.env.example`.

---

## 16. Deployment

All options below cost $0 to run.

### 16.1 Local

See the README quick start. The backend and console run separately; Vite proxies `/api` and `/health`. `python seed_demo.py` adds sample data. It writes nothing if any scan exists or if `ACCESS_TOKEN` is set.

### 16.2 Docker

- **`backend/Dockerfile`:** `python:3.11-slim`, `git` installed, dependencies from `requirements.txt`, and a non-root user (uid 10001). `.dockerignore` keeps `.venv`, local databases, `.env`, coverage files, and tests out of the image.
- **`docker-compose.yml`:** Postgres 16 (development password, local only), the API (with `--reload` and `./backend` mounted), and the console built and served by nginx on `localhost:5173`. nginx proxies `/api` (with WebSocket upgrade headers) and `/health` to the API.

Verified: the image builds and runs as uid 10001, `/health` answers, a paste scan completes, and a GitHub history scan completes inside the container. The full Compose stack served the SPA (including deep links), `/health`, and the API, and accepted the WebSocket with subprotocol negotiation through nginx, on Postgres.

### 16.3 Render + Vercel (+ Neon)

- **API on Render (free).** `render.yaml` runs `pip install -r requirements.txt`. Its start command is `sh -c 'if [ "$SEED_DEMO" = "1" ]; then python seed_demo.py; fi; exec uvicorn …'`, with `healthCheckPath: /health`. Secrets are `sync: false`, meaning they're set in the dashboard, never committed. The free tier sleeps after about 15 idle minutes; the console's `<Gate>` explains the wait.
- **Database.** By default, SQLite on Render's ephemeral disk, which resets on every redeploy; that's fine for the public demo, which reseeds. For durable data, use a free **Neon** Postgres via `DATABASE_URL`.
- **Console on Vercel (free).** Root directory `frontend`, `VITE_API_URL=https://<api>.onrender.com`; `vercel.json` rewrites all paths to `index.html`.

**Private-workspace checklist (Render):**
1. `ACCESS_TOKEN`: a long random value.
2. `FINGERPRINT_KEY`: a long random value; never change it afterwards.
3. `SEED_DEMO=0`. The seeder also refuses on its own when `ACCESS_TOKEN` is set.
4. `DATABASE_URL`: the Neon `postgresql+asyncpg://…` URL.
5. `CORS_ORIGINS`: your console origin.
6. Optional: `GITHUB_TOKEN`, SMTP variables.
7. After the first deploy, verify `TRUSTED_PROXY_HOPS=1` (see Troubleshooting).

**Deployed and checked (Oct 2026):** pushing to `main` auto-deploys both services. Render served `3.0.0` about a minute after the push, with `demo: true`; Vercel reported a successful production deployment. Live checks passed: projects, deduplicated exposure, ledger, triage round trip, CORS limited to the console origin, `wss://` progress with subprotocol negotiation, a paste scan storing only a label and masked value, and SARIF export with a readable filename.

**Still unverified:** the `TRUSTED_PROXY_HOPS=1` assumption (that Render's proxy appends exactly one `X-Forwarded-For` entry), and Neon/private mode on Render (the production demo runs SQLite in public mode).

---

## 17. Security model

| Threat | Control |
|---|---|
| Stored secrets leaking via the API, exports, or logs | Masked `matched_string`; every secret on a line masked in `context`; pastes never persisted (digest label); baselines hold fingerprints only. Tests assert that no raw secret appears in API responses, exports, or baselines. |
| Fingerprints revealing secrets | HMAC-SHA256 with a per-install key (server). Generic, low-entropy values are never fingerprinted by value. The CLI's default key is public, but value-scoped fingerprints apply only to high-entropy, format-specific credentials. |
| Unauthorized access to a private workspace | Bearer token on every `/api/v1` route, including the WebSocket; constant-time comparison; `401` before the handshake is accepted. |
| Token exposure | Never in URLs (WebSocket uses the subprotocol); `sessionStorage` by default; the console sends it only to the API origin. |
| Abuse of the public demo | Rate limit, concurrency cap, schedule cap, paste/archive/file-size caps, a 15-minute minimum schedule interval. |
| IP spoofing to dodge limits | `X-Forwarded-For` trusted only `TRUSTED_PROXY_HOPS` entries from the right. |
| Malicious repositories | Streamed download cap; zip-slip and zip-bomb checks before extraction; symlinks not followed; 5 MB file cap; worker threads; non-root container. |
| Cross-project state tampering | Triage rows keyed by (project, fingerprint); fingerprint must exist in that project's findings; path segments regex-validated. |
| Cross-origin abuse | Explicit CORS origins; no credentialed CORS; explicit methods and headers. |
| Email injection | Alert HTML is escaped; paste content never included. |
| CI script injection | Action inputs go through `env:` only. |
| Mixing demo data into real data | Seeder refuses when any scan exists or `ACCESS_TOKEN` is set; `SEED_DEMO` gate on Render. |
| Test suite wiping a real database | Refuses `TEST_DATABASE_URL` without `test` in the database name. |
| Dependency vulnerabilities | `pip-audit` clean; `npm audit --omit=dev` clean. Seven build-time advisories remain in Tailwind 3's dependency chain (§21). |

**Not defended:** multi-user isolation, per-user audit trails, CSRF (not applicable: there are no cookies), and verification that a detected key is live (deliberately out of scope).

---

## 18. Testing and verification

### 18.1 Automated suites

| Suite | Count | Contents |
|---|---|---|
| `tests/test_api.py` | 13 | Full paste-scan lifecycle over HTTP (ASGI transport): scan, findings, filters, diff, all exports, stats, delete |
| `tests/test_hardening.py` | 20 | No raw secret in 8 responses and exports; paste digest; interrupted scans and restored schedules; cron validation; zip bomb and member cap; placeholder edge case; escaped email |
| `tests/test_inventory.py` | 26 | Fingerprints; ledger grouping and exposure; projects; triage persistence, bounds, expiry, legacy rows, rejection; trend; diff; alert selection; deduplicated stats; stable paths; symlinks; 5 MB cap; vendored dirs in history |
| `tests/test_security.py` | 18 | Token on every router; public `/health`; client IP; sliding window; rate, concurrency, and schedule caps; additive upgrade (incl. oversized legacy rows); WebSocket auth via ASGI handshake (accept / `401`); demo-seeding safeguards |
| `tests/test_cli.py` | 9 | History-only detection; baseline suppression; no secrets in baselines; `--fail-on`; SARIF only unbaselined; JSON per credential; exit 2; key-bound baselines; CLI/server fingerprint agreement; single-run `--sarif` |
| `tests/test_risk.py` | 13 | Score bases, bonuses, cap, reasons |
| `tests/test_sarif.py` | 9 | Structure, rule dedup, levels, fingerprints (incl. the credential fingerprint), empty doc |
| `tests/test_remediation.py` | 13 | Env-var names, per-language replacements, patch hunks |
| `tests/test_validation.py` | 9 | URL allow-list, paste size, cron, pagination |
| **Backend total** | **130** | |
| `test_scanner.py` (root) | 19 | Legacy `scanner_core.py` module |

The `client` fixture gives each test a fresh schema (`drop_all` + `init_db`), resets the rate limiter, and disposes the engine pool after each test; asyncpg connections are bound to the event loop that opened them. With `TEST_DATABASE_URL`, the same suite runs on Postgres. WebSocket tests drive the ASGI handshake on the test's own event loop: Starlette's `TestClient` would run the app on a second loop, which the asyncpg pool can't share. That was the cause of three Postgres-only failures, fixed in this release.

### 18.2 What was run for this release

| Check | Result |
|---|---|
| Backend suite, SQLite, Python 3.14 | 130 passed |
| Backend suite, PostgreSQL 18 (local), Python 3.14 | 130 passed |
| Backend suite, Python 3.11 (`python:3.11-slim` container, matching CI) | 130 passed; legacy suite 19 passed |
| Legacy suite | 19 passed |
| Frontend `npm run lint` / `typecheck` / `build` | 0 problems / pass / pass |
| `pip-audit -r backend/requirements.txt` | No known vulnerabilities |
| `npm audit --omit=dev` | 0 vulnerabilities; full audit: 7 (Tailwind 3 build chain) |
| Legacy-database upgrade on PostgreSQL with a 12 KB `source_ref` | Unguarded index fails (`ProgramLimitExceededError`); guarded upgrade completes and leaves data intact |
| Docker image build + run; Compose stack through nginx | Verified (§16.2) |
| Action scripts under `bash -eo pipefail` | Clean tree exit 0; new leak exit 1 with 1 SARIF result |
| Browser checks (demo data) | Landing, overview, projects, ledger triage, scan report, exports, unlock/lock in private mode, rate-limit message, 375 px layout |
| GitHub Actions CI (commit `7a8a228`) | All 4 jobs passed: backend 130 tests, legacy, frontend lint + typecheck + build, self-scan via the composite action with SARIF upload |
| Production (Render + Vercel) | `/health` 3.0.0; live API, UI, WebSocket, triage, and export checks passed (§16.3) |

### 18.3 Not verified

- `TRUSTED_PROXY_HOPS=1` on Render (whether the per-IP limit sees real client addresses).
- Private mode and Neon Postgres on a hosted deployment (production runs the public SQLite demo).
- Email delivery (SMTP was never configured during testing).
- Private-repository scanning with a `GITHUB_TOKEN`.

---

## Troubleshooting

**The console says "connecting to the CipherWatch API…" for a long time.** A sleeping free-tier backend can take up to a minute to start. If it then shows an error, check `VITE_API_URL` (it is baked in at build time, so redeploy after changing it), confirm `/health` loads in a browser, and check `CORS_ORIGINS` contains the console's exact origin (scheme + host, no trailing slash).

**Every request returns 401.** The server has `ACCESS_TOKEN` set. Unlock in the console, or send `Authorization: Bearer <token>`. If the token changed, use "Lock" and unlock again.

**Live progress never updates, but scans complete.** The WebSocket is blocked, typically by a proxy without upgrade headers. The console falls back to polling, so this is cosmetic. Behind nginx, keep the `Upgrade`/`Connection` headers from `frontend/nginx.conf`.

**`429 Scan limit reached`.** The per-IP window is full; wait for `Retry-After`, or raise `SCAN_RATE_LIMIT` on a private instance. If *every* user hits it at once behind a proxy, `TRUSTED_PROXY_HOPS` is probably `0`, so all requests appear to come from the proxy's address.

**Verifying `TRUSTED_PROXY_HOPS` on Render.** Temporarily log `request.headers.get("x-forwarded-for")` and `request.client.host` in a route, make a request, and confirm that the entry `TRUSTED_PROXY_HOPS` positions from the right is your public IP. If Render (or Cloudflare in front of it) appends two entries, set the value to `2`.

**Startup log: "Not indexing scans.source_ref".** The database has pre-2.1 paste rows with long `source_ref` values. Everything works; lookups by source are just unindexed. Deleting those old paste scans and restarting creates the index.

**CI `self-scan` fails on fixtures you added on purpose.** Regenerate the baseline from a clean copy of tracked files and review the diff before committing:

```bash
git ls-files -co --exclude-standard -z | rsync -a --from0 --files-from=- ./ /tmp/cw-clean/
python cli.py baseline /tmp/cw-clean -o .cipherwatch-baseline.json
```

**`cipherwatch: … was created with a different FINGERPRINT_KEY` (exit 2).** The baseline's `key_id` doesn't match the key in use. Run with the same `FINGERPRINT_KEY` that created it, or regenerate the baseline.

**CLI fingerprints don't match the console's.** The server must get its key from the `FINGERPRINT_KEY` environment variable (a server-generated key isn't shared), and the CLI must have the same value.

**Schedules didn't run overnight.** On a free tier, the server sleeps when idle and missed fire times are skipped. Use an external free uptime pinger, or accept best-effort scheduling.

**`pytest` exits with "TEST_DATABASE_URL must name a disposable database".** The guard refuses database names without `test`. Point it at a throwaway database such as `cipherwatch_test`.

**Postgres tests fail with "attached to a different loop".** Something started a second event loop, for example Starlette's `TestClient`. Use the ASGI-level helper pattern in `TestWebSocketAuth`.

---

## 20. Design decisions and trade-offs

- **Ledger over detector.** Detection is commoditized; post-detection tracking isn't. The cost is more state (`credential_states`), with identity rules that must be stable, hence the work on repo-relative paths and key handling.
- **HMAC fingerprints, value- vs. location-scoped.** Value scoping gives true deduplication for high-entropy, format-specific keys. Location scoping avoids keyed hashes of guessable values and copes with marker patterns. The trade-off: a generic password moved to another file looks like a new credential.
- **Triage keyed by fingerprint, not by finding.** Decisions survive rescans and moves. Waivers must expire, so "accepted" can't quietly become permanent.
- **Additive startup upgrades instead of Alembic.** Zero tooling and safe on both databases for the changes made so far; the limit is anything destructive.
- **Single process, in-process limits and scheduler.** Free to host and simple to reason about; not horizontally scalable (WebSocket registry, limiter, and scheduler are all per-process).
- **Token-based private mode instead of user accounts.** Enough to keep a personal or team workspace private at zero cost; no per-user attribution.
- **Subprotocol for WebSocket auth.** Keeps tokens out of logs, at the cost of a less common pattern that needs the server to echo `cipherwatch.v1`.
- **Deterministic detection, no ML.** Explainable, reproducible, and free; can't generalize to unseen formats without new patterns.
- **No live verification.** Ethical and authorization boundary; every finding is treated as live.
- **SARIF with two partial fingerprints.** Keeps continuity with alerts created by earlier versions while letting code scanning follow a moved key.
- **Hand-built charts and design system.** Precise control and no chart or component-library weight; more code to maintain.
- **Remediation as suggestions and a patch, not auto-PRs.** The tool never needs write access to a repository.

---

## 21. Known limitations

- **Single tenant.** Demo mode shares everything with every visitor; private mode is one shared token, with no users, roles, or per-user audit of decisions.
- **GitHub only; private repos untested.** A `GITHUB_TOKEN` with repo access lets the archive download work, but history clones don't use the token, so history scans of private repos fail (current-code results are still returned).
- **Case-sensitive projects.** `Acme/API` and `acme/api` are separate projects.
- **History depth.** Clones use `--depth=max_commits` (default 100).
- **Scans aren't durable jobs.** A restart mid-scan fails it; there are no retries. Missed schedule fire times are skipped.
- **Per-process state.** The WebSocket registry, rate limiter, and scheduler don't work across multiple instances; the concurrency cap is soft.
- **Additive migrations only.** Pre-2.1 rows (unmasked context, raw paste `source_ref`) are left as they were; delete those scans to remove them.
- **Generic credentials are location-scoped**, so moving a generic password to another file creates a new credential (with no triage carried over).
- **Changing `FINGERPRINT_KEY` re-keys everything**; existing triage stops matching new scans.
- **Detection ceiling.** Novel formats, or secrets split or obfuscated across lines, can be missed.
- **Remediation patch** uses masked values and isn't guaranteed to `git apply`.
- **Render specifics unverified** (`TRUSTED_PROXY_HOPS=1`, cold starts with this release).
- **Build-tool advisories.** 7 `npm audit` advisories in Tailwind CSS 3's build-time dependencies (`braces`, `micromatch`, `chokidar`, `fast-glob`, `postcss-selector-parser`, `postcss-nested`, `tailwindcss`). None ship to the browser; clearing them needs a Tailwind 4 migration.
- **Legacy module.** `scanner_core.py` and `test_scanner.py` remain but are unused by the product; a candidate for removal.

---

## 22. Interview question bank

**What does CipherWatch do that a scanner doesn't?**
It tracks credentials, not lines. Every occurrence of a key collapses into one record with a persistent decision (rotated, false positive, or accepted risk with an expiry), history-aware exposure, and a trend. CI fails only on credentials that aren't in a committed baseline.

**How do you deduplicate without storing the secret?**
An HMAC-SHA256 of the value under a per-install key, truncated to 128 bits. It's one-way, so the database and baselines never hold the secret. Low-entropy generic values and marker patterns are fingerprinted by pattern + path + masked match instead, so a guessable password is never hashed by value.

**Why must accepted risks expire?**
Without an expiry, "accepted" becomes a permanent mute. A required review date (at most 366 days) makes the waiver reopen on its own and show as overdue.

**How does WebSocket auth work without headers?**
The browser offers subprotocols `cipherwatch.v1, bearer.<token>`. The server validates the bearer entry in the router dependency, before accepting, and selects `cipherwatch.v1`. A query parameter would leak the token into access logs.

**Why did three tests fail only on Postgres?**
Starlette's `TestClient` runs the app on its own event loop in a thread, and asyncpg connections can't be used across loops; SQLite didn't care. The fix drives the ASGI handshake directly on the test's loop, which still exercises the real dependency and endpoint.

**What was the Postgres-only production bug?**
Timezone-aware datetimes from APScheduler written into a naive `DateTime` column: SQLite stored them, asyncpg rejected them, so schedule creation would have failed on Neon. Pinning the scheduler to UTC and normalizing to naive UTC fixed it, and running the suite on Postgres found it.

**How would you scale this?**
- Move scans to a durable queue.
- Use shared pub/sub for progress.
- Move rate limiting to a shared store.
- Use a persistent scheduler job store.
- Adopt Alembic.
- Add users and tenancy, with every query scoped by tenant.

All of it is deliberately avoided today to stay at $0.

**How do you prevent CI script injection in a composite action?**
Never interpolate `${{ inputs.* }}` into `run:` scripts. Pass values via `env:` and quote them in shell.

**Why not verify keys against providers?**
It means using credentials you don't own. It's an authorization and ethics line, and treating every detection as live is the safe default.

**What would you do next?**
Users and tenancy, durable jobs, Alembic, case-insensitive project identity, a Tailwind 4 migration, and SSE instead of WebSocket.

---

## 23. Glossary

| Term | Meaning here |
|---|---|
| **Credential** | One secret value (or, for generic and marker patterns, one location), however many findings mention it |
| **Finding** | One detection at one file/line (or one aggregated history entry) |
| **Fingerprint** | 32-hex HMAC identifying a credential; never contains the secret |
| **Key ID** | 12-hex HMAC of a constant under the fingerprint key; detects mismatched keys |
| **Baseline** | Committed JSON of known credential fingerprints; CI fails only on others |
| **Triage / decision** | A credential's status: `open`, `rotated`, `false_positive`, `accepted_risk` |
| **Waiver** | An `accepted_risk` decision with a mandatory `review_by` |
| **Exposure** | `working_tree` (in the current code) or `history_only` |
| **Marker pattern** | A pattern whose match is a fixed header (e.g. `-----BEGIN RSA PRIVATE KEY-----`), not the secret |
| **Demo mode / private mode** | `ACCESS_TOKEN` unset / set |
| **Additive upgrade** | Idempotent startup DDL that only adds nullable columns and indexes |
| **SARIF** | Static Analysis Results Interchange Format 2.1.0, consumed by GitHub code scanning |
| **Shannon entropy** | Average bits of unpredictability per character |
| **Sliding-window limiter** | Counts requests in the trailing window per key |
