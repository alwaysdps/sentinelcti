# SentinelCTI

A defensive **Cyber Threat Intelligence platform** for safely triaging suspicious files, URLs, domains, IP addresses and file hashes.

Submit an indicator, get back a **threat report** that shows a risk score, the named findings that produced it, threat-intelligence results and potential MITRE ATT&CK associations — with every point traceable to a specific, human-readable check.

```
Verdict          SUSPICIOUS
Risk Score       50 / 100
Indicator        http://secure-login.paypal.account-verify.example/session/renew

Why was this flagged?
  ⚠  Brand name in subdomain (paypal)                            +25   T1566.002, T1036
  ⚠  Credential-themed keywords in host (account, login, ...)    +15   T1566.002
  •  Plaintext HTTP                                              +10
  ✓  Valid hostname syntax                                        —
```

---

## Table of contents

1. [What it is and why it exists](#1-what-it-is-and-why-it-exists)
2. [Safety model](#2-safety-model)
3. [Architecture](#3-architecture)
4. [Technologies](#4-technologies)
5. [How the analysis engine works](#5-how-the-analysis-engine-works)
6. [Threat scoring methodology](#6-threat-scoring-methodology)
7. [Security decisions](#7-security-decisions)
8. [Installation](#8-installation)
9. [Using Supabase (PostgreSQL)](#9-using-supabase-postgresql)
10. [Running locally](#10-running-locally)
11. [Running with Docker](#11-running-with-docker)
12. [Deploying behind Cloudflare](#12-deploying-behind-cloudflare)
13. [Running the tests](#13-running-the-tests)
14. [API documentation](#14-api-documentation)
15. [Limitations](#15-limitations)
16. [Future research & development](#16-future-research--development)

---

## 1. What it is and why it exists

When a suspicious link, attachment or IP address turns up, the first question is always the same: *is this worth escalating?* Answering it usually means pasting the indicator into a third-party service — which uploads potentially sensitive artefacts to someone else's infrastructure, and returns a verdict with no visible reasoning.

SentinelCTI addresses both problems:

- **It runs entirely on your own infrastructure.** The default configuration needs no API keys and no internet access. Everything works air-gapped.
- **It explains itself.** There is no opaque score. Every point is attached to a named check with a written rationale, and the report shows the arithmetic.
- **It never touches the target.** Files are not executed. URLs are not fetched. IP addresses are not contacted. Analysis is strictly static.

It is a portfolio and university project, built to demonstrate secure backend engineering, API design, data modelling, static analysis, networking fundamentals and defensive security thinking — not to compete with commercial sandboxes.

## 2. Safety model

This is the section to read first, because every design decision below follows from it.

| Guarantee | How it is enforced |
|---|---|
| Uploaded files are **never executed** | The file analyzer only ever calls `open(path, "rb")`. No `subprocess`, no `exec`, no interpreter, no archive extraction, no format library that acts on embedded content. |
| Uploads are **never web-reachable** | Quarantine lives outside every static mount, under a random name with mode `0600`. No route returns file bytes. |
| Uploads are **not retained** | Bytes are deleted in a `finally` block after analysis — even if analysis raised. Hashes and metadata remain. |
| Submitted URLs are **never requested** | URL analysis is pure parsing. Active fetching sits behind `ENABLE_ACTIVE_URL_FETCH`, off by default. |
| Submitted IPs are **never contacted** | No ping, no port scan, no connection. Classification comes from the IANA registries encoded in Python's `ipaddress` module. |
| DNS **does not leak to the target** | Resolution queries the configured resolver, not the indicator's infrastructure. Bounded by a timeout and disableable entirely. |
| A failing provider **cannot break an analysis** | `safe_lookup` converts timeouts and exceptions into an `ERROR` result; the analysis is marked `partial` and continues. |
| A hostile sample **cannot exhaust the service** | Linear-by-construction extraction, a cooperative time budget, a concurrency gate and a quarantine disk ceiling. See [Availability](#availability-is-part-of-the-safety-model). |
| Sample content **cannot deceive the operator** | Extracted text is stripped of control characters and bidi overrides, and network indicators are defanged and never rendered as links. |

### Availability is part of the safety model

"Cannot harm the host" is not only about execution. A sample that makes the
analyzer burn unbounded CPU takes the service down just as effectively as one
that runs code, and it needs no exploit to do it — only a pathological byte
sequence.

This was not theoretical. The original whole-blob domain regex
(`(?:label\.)+tld`) was measured at **O(n²)**: 16 KB of `a.a.a.a…` took 4.5 s,
so the 2 MB scan window would have taken hours. A ~1 KB upload could pin a
worker indefinitely — and because file analysis also ran inline on the event
loop, that single upload took the **entire API** down with it.

Four mechanisms close it, and `tests/test_hostile_uploads.py` holds them shut:

| Mechanism | What it prevents |
|---|---|
| **Tokenise, bound, then match** (`analyzers/extract.py`) — split on characters that cannot appear in the indicator, discard tokens longer than the RFC maximum, then match with an *anchored* pattern | The quadratic scan. One bounded attempt per token instead of one per character offset. Measured: 512 KB in 87 ms, linear. |
| **Cooperative deadline** (`AnalysisBudget`) threaded through every loop | Any residual pathological case degrades into a truncated, explicitly-labelled report instead of a hung worker |
| **Thread offload + concurrency gate** | One slow sample can no longer stall the event loop; a burst cannot exhaust the threadpool |
| **Quarantine disk ceiling** | Concurrent uploads cannot fill the disk and take the database and logs with them |

A truncated sweep is always reported (`file_analysis_truncated`, status
`partial`). Silently shortening the scan would let a crafted sample suppress
findings and appear clean — the opposite of the intended behaviour.

### Sample content is treated as hostile output, not just hostile input

Extracted strings leave the process through three channels, each with its own
failure mode, all handled in `analyzers/sanitize.py`:

- **To the browser.** React escapes interpolated text, so markup cannot
  execute. What it does *not* stop is a bidirectional override (U+202E)
  reversing how the rest of a line renders — the same trick the analyzer flags
  in filenames. Those characters are stripped.
- **To the log.** ANSI escape sequences and carriage returns let attacker text
  repaint or forge lines in an operator's terminal.
- **To the database.** PostgreSQL rejects NUL bytes in text columns, so leaving
  them in would turn a hostile sample into a failed insert.

Network indicators are additionally **defanged** (`hxxp://`, `1.2.3[.]4`) and
are never rendered as links. A threat intelligence report must not be one
mis-click away from resolving the infrastructure it is describing.

**Not implemented, deliberately:** malware execution or detonation, credential harvesting, keylogging, persistence, exploitation, vulnerability scanning, DDoS tooling, file encryption, or unauthorised network scanning. This platform analyses indicators; it does not attack anything.

## 3. Architecture

```mermaid
flowchart TB
    subgraph Browser
        UI["React + TypeScript SPA<br/>Dashboard · Analyze · History · Report"]
    end

    subgraph API["FastAPI backend"]
        MW["Middleware<br/>size limit → rate limit → security headers"]
        R["Routers<br/>/api/analyze · /api/analyses · /api/stats"]
        SVC["Services<br/>orchestration · quarantine · queries"]
        AN["Analyzers<br/>url · domain · ip · hash · file"]
        RE["Risk engine<br/>weighted, explainable scoring"]
        PR["Provider registry<br/>ThreatIntelProvider implementations"]
    end

    DB[("SQLite / PostgreSQL<br/>via SQLAlchemy ORM")]
    Q[["Quarantine<br/>outside the web root<br/>deleted after analysis"]]
    EXT["Optional external intel<br/>VirusTotal · AbuseIPDB · MISP"]

    UI -->|"JSON over same-origin /api"| MW --> R --> SVC
    SVC --> AN --> RE
    SVC --> PR --> EXT
    PR --> LOCAL["Local Engine<br/>offline, no API key"]
    SVC --> DB
    SVC -.->|"file submissions only"| Q
    RE --> SVC
```

Layering rule: **routes validate and delegate; services orchestrate; analyzers observe; the risk engine scores.** Analyzers know nothing about HTTP or the database, which is why they are directly unit-testable without a running application.

```
sentinelcti/
├── backend/
│   ├── app/
│   │   ├── analyzers/      # one module per indicator type + shared patterns
│   │   ├── api/            # thin HTTP adapters
│   │   ├── core/           # config, error envelope, middleware
│   │   ├── database/       # engine, session, declarative base
│   │   ├── models/         # SQLAlchemy models + domain enums
│   │   ├── providers/      # ThreatIntelProvider interface + local engine
│   │   ├── schemas/        # Pydantic request/response contracts
│   │   ├── services/       # orchestration, quarantine, queries, risk engine
│   │   └── main.py
│   ├── scripts/seed.py     # synthetic demo data via the real pipeline
│   └── tests/              # 202 tests
├── frontend/
│   └── src/{components,pages,services,hooks,types,lib}
├── docker-compose.yml
└── .env.example
```

## 4. Technologies

| Layer | Choice | Why |
|---|---|---|
| Frontend | React 19, TypeScript, Vite, Tailwind CSS 4 | Strict TS means a backend contract change fails the build rather than the page. |
| Charts | Recharts | Declarative, small, no imperative canvas code. |
| Backend | Python 3.11+, FastAPI, Pydantic v2 | Validation at the boundary; OpenAPI docs generated from the same models. |
| Database | SQLAlchemy 2.0 ORM, SQLite or PostgreSQL/[Supabase](#9-using-supabase-postgresql) | ORM-only access means parameterised queries everywhere and a backend switch that is one environment variable. |
| Testing | pytest | 459 tests over analyzers, scoring, storage, hostile uploads, workspace isolation, retention, PostgreSQL portability and the API. |
| Packaging | Docker + Compose, nginx | Single-origin deployment; no CORS grant required in production. |

**Dependencies are deliberately few.** File type identification, string extraction, entropy, the public-suffix split, rate limiting and the async-state hooks are all implemented directly — each is short, and each is logic a reviewer of this project should be able to read.

## 5. How the analysis engine works

Every indicator follows one pipeline:

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API route
    participant S as analysis_service
    participant Z as Analyzer
    participant P as Providers
    participant R as Risk engine
    participant D as Database

    C->>A: POST /api/analyze/{type}
    A->>A: Pydantic validation
    A->>S: delegate
    S->>Z: analyze(value)
    Z-->>S: AnalyzerResult(signals[], details{})
    S->>P: lookup_all() — concurrent, failure-isolated
    P-->>S: ProviderLookup[]
    S->>R: assess(analyzer signals + provider signals)
    R-->>S: score, verdict, breakdown
    S->>D: persist findings, details, ATT&CK, timing
    S-->>C: 201 + full report
```

The unit of analysis is a **signal**: one named, explainable observation carrying the points it contributes. Analyzers never compute a score — that separation is what makes the number auditable.

### What each analyzer checks

**URL** — syntax and scheme; HTTPS; IP-literal hosts; punycode (with the Unicode form it renders as); registrable-domain and subdomain decomposition; excessive subdomain depth; brand names in subdomains the brand does not own; credential keywords; embedded `user:pass@` credentials and bare `@` in the authority; nested URLs (open-redirect abuse); heavy percent-encoding; control characters and backslashes; non-standard ports; directly linked executables and archives; double extensions; high-abuse TLDs; URL shorteners.

**Domain** — RFC 1123 validation; registrable domain vs subdomain (curated multi-label public-suffix set); punycode; **Shannon entropy on the second-level label** to flag DGA-like names; digit ratio and hyphen density; brand and keyword heuristics; high-abuse TLDs; optional passive A/AAAA resolution.

**IP** — IPv4/IPv6 validation; scope classification against the IANA special-purpose registries, separating **documentation ranges** (RFC 5737/3849) from RFC 1918 space, which Python's `ipaddress` conflates; IPv4-mapped and Teredo detection; optional PTR lookup with hosting-provider identification.

**Hash** — length-based algorithm identification; collision-resistance caveats for MD5 and SHA-1 (both have practical collision attacks, so they identify a file only weakly); recognition of well-known digests such as the empty file; provider lookup.

**File** — streaming MD5/SHA-1/SHA-256 in a single pass; **content-based type identification from magic bytes** (never the extension or declared Content-Type, both attacker-controlled); OOXML/JAR/APK disambiguation by reading central-directory names without extracting; Shannon entropy for packing and encryption; printable-string extraction; ~18 suspicious-pattern families (PowerShell `-EncodedCommand`, IEX, certutil abuse, LOLBins, Run-key persistence, scheduled tasks, shadow-copy deletion, macro autorun, script eval-over-decode); embedded URLs, IPs, emails and paths; base64 and hex blob detection; extension/content mismatch; double extensions; RTL-override characters.

### MITRE ATT&CK

Findings carry technique IDs, resolved into a report section labelled **potential technique association**. The wording is load-bearing: a string in a file shows a capability is *referenced*, never that the technique *executed*. Nothing here claims otherwise.

## 6. Threat scoring methodology

```
raw   = Σ(points of triggered signals) + corroboration bonus
score = min(100, max(raw, highest score floor))
```

| Range | Verdict | Meaning |
|---|---|---|
| 0–19 | **Clean** | No meaningful risk indicators found. |
| 20–49 | **Low Risk** | Minor or ambiguous indicators; likely benign. |
| 50–69 | **Suspicious** | Multiple indicators warrant manual review. |
| 70–89 | **High Risk** | Strong indicators of malicious intent. |
| 90–100 | **Critical** | Severe, corroborated indicators. Treat as hostile. |

Three deliberate design choices:

1. **Saturating, not averaging.** Ten weak signals can reach a high score. Averaging would let a pile of benign checks dilute one severe finding.
2. **Corroboration bonus.** Each additional distinct high-severity finding adds +5 (capped at +15). Independent evidence agreeing is stronger than the same evidence counted twice.
3. **Score floors.** Heuristics and identifications are different kinds of evidence and must not share one scale. "This URL is long" is a weak prior; "a provider has this exact hash on file as malicious" is a positive identification. A provider verdict of `malicious` therefore sets a *minimum* of 70, and `suspicious` a minimum of 50, rather than adding points. Without this, a known-malicious hash would land in Low Risk purely because a bare hash offers nothing else to accumulate points from — exactly backwards. When a floor lifts the score the report says so, and still reports the heuristic total honestly.

### It is a Risk Score, not a malware probability

This is stated in the API description, on every report page, and here. The score is a reproducible weighted sum of documented heuristics. It is **not** calibrated against a labelled corpus and carries no claim of statistical accuracy. It is a triage prioritisation aid. Equally: a Clean verdict reflects the *absence of detected indicators*, which is not proof of safety.

## 7. Security decisions

**Uploads.** Size enforced while streaming, not from `Content-Length` (attacker-controlled); the partial file is deleted the instant the limit is crossed. Storage names come from `secrets.token_hex` — the client's filename is never used as a path, so a sanitiser bug cannot become a write primitive. The resolved path is asserted to be inside the quarantine root anyway. Filenames are still sanitised for display and logging: directory components, NT stream syntax, control characters, dot runs and Windows reserved device names are all handled.

**API.** Pydantic validation at the boundary with explicit length bounds. In-process sliding-window rate limiting. Request size caps before routing. Explicit CORS origins, never `*` — the API is credential-free today, but a wildcard becomes a hole the moment authentication lands. Baseline hardening headers, with a strict `default-src 'none'` CSP on the JSON API (relaxed only for the docs pages, which legitimately load scripts).

**Errors.** A structured envelope `{ error: { code, message } }`. In production, unhandled exceptions return an opaque message plus an incident ID that correlates to the full server-side trace — stack traces disclose library versions, file paths and SQL fragments, and never cross the boundary.

**Database.** Every query goes through the SQLAlchemy ORM/Core expression layer, which parameterises values. No SQL is built by string concatenation anywhere, so a submitted indicator can never be interpreted as SQL.

**Secrets.** Configuration comes from `.env` via `pydantic-settings`; nothing reads `os.environ` directly. `.env` is git-ignored, `.env.example` ships placeholders only, and `/api/config` reports *whether* a provider is configured but never what configures it.

**Containers.** The backend runs as an unprivileged user (uid 10001) — it handles attacker-supplied files, so root is exactly the wrong default. The frontend ships as static assets on nginx; Node and the toolchain stay in the build stage. The backend port is published on loopback only, because the API has no authentication.

### Session-scoped history

Submissions to this tool are suspicious URLs, internal hostnames and files under investigation. Two properties follow from that, and neither is the default you get for free.

**Nothing is shared.** The browser generates a 256-bit key per session and sends it as `X-Owner-Key`; every read is filtered by it through a single predicate, `query_service.visible_to`. A first-time visitor sees an empty history.

Seeded `is_demo` rows used to be exempt, so a new dashboard was not blank. That exemption is gone. A visitor cannot distinguish a deliberately shared record from a leak of somebody else's history — and a user reported exactly that, as a privacy bug, which is the clearest evidence the old default was wrong. An empty first screen is the cheaper mistake.

**Nothing outlives the visit.** The key lives in `sessionStorage`, so it dies with the tab, and the page asks the API to delete its rows on `pagehide` (`fetch` with `keepalive` — an ordinary fetch is cancelled when the document is torn down).

An unload handler is best-effort: a crashed tab, a killed browser or a dead network sends nothing. So the server expires rows independently after `ANALYSIS_RETENTION_HOURS` (default 24), swept opportunistically on write traffic since serverless has no long-running process to schedule from. Without that backstop every abandoned session would leave rows nobody holds a key to — invisible to everyone, deletable by nobody, accumulating forever.

The window runs from row creation, not last activity. A session open longer than it loses its earliest analyses; measuring from last use would mean tracking activity, which stores more about a visitor rather than less.

| | |
|---|---|
| Purge on demand | `POST /api/analyses/purge` — deletes only rows matching the presented key. **POST, not DELETE**: deployments commonly gate `DELETE` behind `ACCESS_PROTECTED_METHODS`, and this operation needs no such gate, since the key you hold is the only thing it can act on. |
| Retention backstop | `ANALYSIS_RETENTION_HOURS` (0 disables), swept at most every `RETENTION_SWEEP_INTERVAL_SECONDS` per process. |
| Failure mode | A failed sweep is logged and retried on a later request. Housekeeping never fails the analysis that triggered it. |

## 8. Installation

**Prerequisites:** Python 3.11+ and Node 18+ (or just Docker).

```bash
git clone <repository-url> sentinelcti
cd sentinelcti
cp .env.example backend/.env
```

```bash
cd backend && pip install -r requirements-dev.txt
```

```bash
cd frontend && npm install
```

## 9. Using Supabase (PostgreSQL)

SQLite is the zero-config default and needs nothing set. To use Supabase
instead, only `DATABASE_URL` changes — every query already goes through the
SQLAlchemy ORM, so no application code differs between the two backends.

### Setup

**1. Create a project** at [supabase.com](https://supabase.com) (the free tier
is sufficient) and note the database password you set.

**2. Copy the connection string** from **Project Settings → Database →
Connection string → URI**, choosing the **Transaction pooler** tab.

**3. Put it in `backend/.env`**, changing the `postgresql://` prefix to
`postgresql+psycopg://` so SQLAlchemy selects the psycopg 3 driver:

```
DATABASE_URL=postgresql+psycopg://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres
```

**4. Verify and create the schema:**

```bash
cd backend && python -m scripts.check_db --create
```

```
Backend : postgresql (supabase, transaction pooler)
URL     : postgresql+psycopg://postgres.abcd...:***@aws-0-eu-west-2.pooler.supabase.com:6543/postgres
Pooler  : transaction (prepared statements off)
SSL     : require

[ ok ] Connected
       PostgreSQL 15.8 on aarch64-unknown-linux-gnu...
[ ok ] Schema present (analyses)
[ ok ] Read query succeeded - 0 analyses stored
```

`check_db` maps driver errors onto the specific thing to change rather than
printing a raw traceback — wrong username form, IPv6-only endpoint, TLS
failure, unencoded password character, prepared-statement clash.

### Which endpoint to use

Supabase exposes three, and the choice changes what the driver may do:

| Endpoint | Port | Network | Use it? |
|---|---|---|---|
| **Transaction pooler** | 6543 | IPv4 | **Recommended.** Scales well; the app auto-detects it. |
| Session pooler | 5432 (`*.pooler.supabase.com`) | IPv4 | If you need session features such as `LISTEN`/`NOTIFY`. |
| Direct | 5432 (`db.<ref>.supabase.co`) | **IPv6 only** | Avoid — fails on IPv4-only hosts and most CI runners. |

The transaction pooler is PgBouncer in transaction mode, which **cannot support
server-side prepared statements**. psycopg 3 creates them automatically after a
few executions, which surfaces as sporadic `DuplicatePreparedStatement` errors
under load — an unpleasant bug to diagnose in production. The app detects port
6543 and sets `prepare_threshold=None` automatically. Override the detection
with `DATABASE_TRANSACTION_POOLER` if your topology is unusual.

A **client-side pool is still used** in front of the Supabase pooler, which is
worth explaining because the instinct is to disable it. Measured against
`ap-southeast-1`, a fresh connection costs **~1 s** of TCP+TLS handshake. With
pooling off, SQLAlchemy returns the connection after every commit, so a batch
of writes pays that cost repeatedly — seeding 21 records failed outright with
`ConnectionTimeout`. Pooling is safe here because PgBouncer multiplexes at the
transaction boundary and the client pool only ever holds pooler-side
connections; the one thing it must not do — server-side prepared statements —
is already disabled. Set `DATABASE_DISABLE_POOLING=true` for genuinely
short-lived processes (serverless, one-shot jobs), where a pool cannot be
reused before the process exits.

### Two things that cause almost every failed first attempt

- The pooler username is **`postgres.<project-ref>`**, not plain `postgres`.
- If the password contains `@ : / ? #` or `%`, it must be **percent-encoded**
  in the URL (`@` → `%40`, `#` → `%23`).

### What changes on PostgreSQL

| | SQLite | PostgreSQL |
|---|---|---|
| JSON columns | `JSON` (text) | `JSONB` — binary, smaller, queryable with containment operators |
| Timestamps | text | `TIMESTAMP WITH TIME ZONE` |
| Day bucketing | `date(x)` | `date_trunc('day', x)` |
| Pooling | n/a | `pool_pre_ping` + recycle; prepared statements disabled behind the transaction pooler |

Those are the only genuine differences, and
`tests/test_postgres_compat.py` compiles every application query against the
real PostgreSQL dialect so a statement that only works on SQLite fails in CI
rather than on first deploy.

### Why Supabase Storage is *not* used for samples

Uploaded files stay in the local quarantine directory and are deleted after
analysis. Putting them in Supabase Storage would give hostile bytes a hosted,
signed URL — re-introducing precisely the "uploads must never be web-reachable"
property the [safety model](#2-safety-model) exists to guarantee. Supabase is
used for structured analysis records only.

Supabase Auth is likewise not wired in: the MVP has no authentication at all
(see [Limitations](#15-limitations)), and half-adopting an auth provider would
imply a control that is not there.

## 10. Running locally

Terminal 1 — backend:

```bash
cd backend && uvicorn app.main:app --reload --port 8000
```

Terminal 2 — frontend:

```bash
cd frontend && npm run dev
```

Open **http://localhost:5173**. The Vite dev server proxies `/api` to the backend, so the browser stays on one origin.

Optionally populate the dashboard with synthetic demo data:

```bash
cd backend && python -m scripts.seed --reset
```

The seed script runs the **real** analysis pipeline over reserved, non-routable indicators (RFC 2606 `.example` names, RFC 5737 TEST-NET addresses, the public EICAR test hashes). It fabricates no scores — every seeded report is reproducible by submitting the same indicator through the UI.

> **Seeded rows are no longer visible in the UI.** They are flagged `is_demo` and belong to no workspace, and [session-scoped history](#session-scoped-history) shows a visitor only their own submissions. The script remains useful for exercising the pipeline and inspecting the database directly; it will not populate anyone's dashboard.

Because they are invisible and no API route can remove them — an endpoint able to delete rows nobody owns could empty the database for everyone — clearing them out is a maintenance task:

```bash
cd backend && python -m scripts.purge_demo        # report only
cd backend && python -m scripts.purge_demo --yes  # delete them
```

It reports before it acts, prints the database it is pointed at with the password redacted, and matches on `is_demo` alone, so a real visitor's analysis cannot be caught by it.

> The EICAR test file is seeded as a *hash*, never written to disk: EICAR exists precisely so endpoint protection fires on it, and on a machine with real-time scanning the write is intercepted.

### Try it

1. **Dashboard** → *Analyze Indicator*
2. Submit `http://paypal.secure.login.account-verify.xyz/webscr/confirm.php` → expect **Suspicious/High Risk** with brand-impersonation and credential-keyword findings
3. Submit hash `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` → EICAR, **High Risk** via the score floor
4. Upload any small text file → SHA-256, magic-byte type identification, string analysis
5. **History** → filter, sort, open any report

## 11. Running with Docker

```bash
docker compose up --build
```

- Application: **http://localhost:8080**
- API docs: **http://localhost:8080/docs**

nginx serves the SPA and reverse-proxies `/api` and `/docs` to the backend, so the browser only ever talks to one origin and no CORS grant is needed. The database and quarantine directory live in a named volume.

Seed demo data into the running stack:

```bash
docker compose exec backend python -m scripts.seed --reset
```

**Using Supabase with Docker**: put `DATABASE_URL` in `backend/.env` and Compose picks it up via `env_file` — no service to add, since Supabase is a hosted endpoint. See [section 9](#9-using-supabase-postgresql). To run PostgreSQL locally instead, uncomment the `db` service in `docker-compose.yml`.

## 12. Deploying behind Cloudflare

Cloudflare gives this deployment DDoS absorption, a WAF, edge rate limiting, TLS
termination and — via Access — the authentication the application itself does
not implement. Two things have to be true for any of that to be worth having,
and the second is the one people skip.

### 12.1 The application must know who the client is

Behind a CDN every request arrives from a Cloudflare edge address. Left alone,
the rate limiter would put the entire internet into a handful of buckets: one
busy visitor would throttle everyone.

Cloudflare supplies the real client in `CF-Connecting-IP`. Two settings:

```
TRUSTED_PROXIES=cloudflare
CLIENT_IP_HEADER=cf-connecting-ip
```

The `cloudflare` token expands to Cloudflare's published edge ranges
(`app/core/cloudflare.py`), so there is no list of CIDRs to paste, mistype, or
forget to update.

> **Tunnel deployments need a different value.** The setting lists whoever
> connects to the origin *socket*, and with a Tunnel that is the local
> `cloudflared` process, never a Cloudflare edge address — so
> `TRUSTED_PROXIES=cloudflare` would match nothing and every client would be
> attributed to `cloudflared` itself. Use the address cloudflared connects
> from instead:
>
> | Deployment | `TRUSTED_PROXIES` |
> |---|---|
> | Proxied DNS (orange cloud), origin exposed | `cloudflare` |
> | Cloudflare Tunnel, cloudflared on the host | `127.0.0.1/32` |
> | Cloudflare Tunnel, cloudflared in Compose | `172.16.0.0/12` (the bridge network) |
>
> `CLIENT_IP_HEADER=cf-connecting-ip` is the same either way — cloudflared
> forwards the header it received from the edge. The Settings page shows the
> resolved source, so you can confirm which case you are in rather than guess.

Refresh the pinned edge ranges with:

```bash
cd backend && python -m scripts.refresh_cloudflare_ips --write
```

They are pinned in source rather than fetched at boot deliberately: the trust
list is a security control, so a change to it should show up as a reviewable
diff, not happen invisibly at startup.

**Why the header alone is not enough.** `CF-Connecting-IP` is just a header —
anyone can set it. It is honoured only when the *socket peer* (which cannot be
forged over TCP) is inside a Cloudflare range. Without that check, rotating a
fake header per request grants unlimited rate-limit quota. Measured against the
running API at 60 requests/minute:

```
fixed    spoofed header  ->  60 allowed, 10 rejected   (correct)
rotating spoofed header  ->  69 allowed,  1 rejected   (bypassed)
```

With no trusted proxies configured — the default — forwarding headers are
ignored entirely and the socket peer is always used. The safe configuration is
the one you get by doing nothing.

**Half-configuring this is the realistic mistake**, and it has no runtime
symptom: rate limiting still runs, it just stops distinguishing clients. So the
**Settings page reports the resolved source** and flags the two incoherent
states — a header named with no trusted proxies (header silently ignored), and
trusted proxies with no header named (every client in one bucket).

```
Client address read from   'cf-connecting-ip' header, trusted from the Cloudflare edge
Forwarding headers          Trusted from listed proxies only
Behind Cloudflare           Yes — edge ranges trusted
Trusted proxy ranges        22
```

### 12.2 The origin must not be reachable directly

**This is the mistake that makes Cloudflare decorative.** If the origin server
has a public IP, an attacker who finds it (Shodan, Censys, certificate
transparency logs, a stale DNS record, an email header) connects straight to it
and every edge protection is bypassed — WAF, rate limiting, Access, all of it.

Two ways to close it. Prefer the first.

**Cloudflare Tunnel (recommended).** The origin makes an *outbound* connection
to Cloudflare and has **no inbound ports open at all** — nothing to find and
nothing to connect to. It also works from a home network or a laptop with no
static IP, which is what makes it the right fit for this project.

```bash
cloudflared tunnel login
cloudflared tunnel create sentinelcti
cloudflared tunnel route dns sentinelcti cti.example.com
cloudflared tunnel run --url http://localhost:8080 sentinelcti
```

A `cloudflared` service is included (commented) in `docker-compose.yml`.

**Firewall allowlist (if you must expose a host).** Permit inbound 80/443 from
Cloudflare's ranges only, and drop everything else:

```bash
for cidr in $(curl -s https://www.cloudflare.com/ips-v4); do
  ufw allow from "$cidr" to any port 443 proto tcp
done
ufw default deny incoming && ufw enable
```

Then enable **Authenticated Origin Pulls** (SSL/TLS → Origin Server) so the
origin only accepts TLS connections presenting a Cloudflare client certificate.
An allowlist alone still trusts anyone who can route from a Cloudflare IP.

### 12.3 DNS and edge configuration

| Setting | Value | Why |
|---|---|---|
| DNS record | `A`/`CNAME`, **proxied** (orange cloud) | Grey cloud = DNS only = origin IP published to the world |
| SSL/TLS mode | **Full (strict)** | *Flexible* leaves Cloudflare→origin unencrypted; *Full* accepts any certificate including an attacker's |
| Always Use HTTPS | On | |
| Min TLS version | 1.2 | |
| WAF Managed Rules | On | |
| Bot Fight Mode | On | |

### 12.4 Rules worth adding

This application has characteristics a generic ruleset will not know about.

**Rate limit uploads separately.** File analysis is the most expensive endpoint
and the natural target:

```
Expression : http.request.uri.path eq "/api/analyze/file"
Rate       : 10 requests per minute per IP
Action     : Block for 1 minute
```

**Do not let Cloudflare cache the API.** Analysis results are per-submission and
stale data would be actively misleading:

```
Expression : starts_with(http.request.uri.path, "/api/")
Setting    : Bypass cache
```

**Restrict the interactive docs.** `/docs` and `/redoc` are useful in
development and unnecessary exposure in production — either block them or put
them behind Access.

### 12.5 Cloudflare Access is how this deployment gets authentication

The application has **no authentication** (see [Limitations](#15-limitations)),
so anything reachable is readable and submittable by anyone. Cloudflare Access
puts an identity gate in front of the origin — Google, GitHub, or one-time email
PIN — without a line of application code, and is free for small teams.

Zero Trust → Access → Applications → Add a self-hosted application over your
hostname, with a policy allowing only your own email address.

This is the single highest-value item in this section. Rate limiting and a WAF
protect an open door; Access closes it.

### 12.6 What Cloudflare does not do

- **It does not make the analyzer safe.** Uploads are still hostile input; the
  protections in [section 2](#2-safety-model) are what handle that.
- **It does not protect Supabase.** The database is a separate hosted endpoint
  reached directly. Restrict network access in the Supabase dashboard.
- **It does not replace the application's own rate limiting.** Edge limits can
  be bypassed by anything that reaches the origin, which is why both exist.
- **It terminates TLS at the edge**, so Cloudflare can see request contents.
  That is a real consideration for a platform handling potentially sensitive
  artefacts, and an argument for keeping this deployment private.

### 12.7 Deploying to Vercel with Supabase and Cloudflare DNS

The deployed shape: **everything on Vercel, data in Supabase, DNS at
Cloudflare.** One deployment, three services.

```mermaid
flowchart LR
    U["Browser"] --> CF["Cloudflare DNS<br/>cti.example.com"]
    CF --> V["Vercel"]
    subgraph V["Vercel project"]
        S["Static React bundle"]
        F["/api/* -> Python function<br/>(the FastAPI app)"]
    end
    F --> DB[("Supabase<br/>PostgreSQL")]
```

**Supabase hosts the database, not the API.** It runs PostgreSQL (plus auth,
storage and Deno edge functions), but it cannot run a Python process — so the
FastAPI application runs as a Vercel serverless function alongside the
frontend. Same origin, which means no CORS grant is needed at all.

#### What is already wired up

| File | Purpose |
|---|---|
| `api/index.py` | Vercel entrypoint. Imports the *existing* app rather than defining a second one, so there is no parallel routing table to keep in sync. |
| `vercel.json` | Builds the frontend, routes `/api/*` and `/docs` to the function, SPA fallback for client-side routes, caching and security headers. |
| `requirements.txt` (root) | Defers to `backend/requirements.txt` — one dependency list, not two that drift. |

#### Deploying

Import the repository in Vercel with **Root Directory = repository root** (not
`frontend/` — the function lives at the root). Then set:

```
DATABASE_URL              postgresql+psycopg://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:6543/postgres
DATABASE_DISABLE_POOLING  true
AUTO_CREATE_TABLES        false
UPLOAD_DIR                /tmp/quarantine
ENVIRONMENT               production
DEBUG                     false
ACCESS_TOKEN              <generate one>
ACCESS_PROTECTED_METHODS  DELETE
```

Create the schema once from your machine before the first deploy:

```bash
cd backend && python -m scripts.check_db --create
```

`AUTO_CREATE_TABLES=false` then stops every cold start paying a
schema-reflection round-trip to Singapore for tables that already exist.

#### What serverless changes, honestly

Three guarantees depend on a long-running process:

| Property | On Vercel | Mitigation |
|---|---|---|
| **In-process rate limiting** | Stops binding — each invocation has its own memory, so the window resets constantly | Cloudflare rate limiting on the hostname ([12.4](#124-rules-worth-adding)). The in-process limiter still bounds a warm instance and costs nothing, so leave it on. |
| **Quarantine disk budget** | Becomes per-invocation | Harmless: uploads are deleted immediately after analysis, so nothing accumulates. `UPLOAD_DIR` must be `/tmp` — the only writable path. |
| **Analysis time budget** | A Hobby function caps at 10 s, the same as the analyzer's own budget | `maxDuration: 30` in `vercel.json` restores the intended truncated-but-labelled report. |

Startup tolerates a read-only filesystem: it logs a warning and continues, so
the endpoints that never touch the disk keep working rather than the whole API
failing to boot.

If you would rather keep all three guarantees intact, run the API on a
long-running container instead (Render, Railway, Fly.io — all have free tiers),
set `VITE_API_BASE_URL` in Vercel to that host, add the Vercel origin to
`CORS_ORIGINS`, and widen `connect-src` in the `vercel.json` CSP to include it.

#### Cloudflare DNS

| Record | Points at | Proxy |
|---|---|---|
| `cti` (or `@`) | `cname.vercel-dns.com` | **DNS only (grey cloud)** |

**Grey cloud, deliberately.** Vercel issues and renews its own TLS certificate
and runs its own CDN. Orange-clouding it puts two CDNs and two certificate
authorities in the same path, which commonly produces redirect loops and
stale-cache surprises. Add the domain under **Vercel → Project → Settings →
Domains** and it verifies against the CNAME.

The trade-off: with DNS-only, Cloudflare's WAF and rate limiting do not apply,
because traffic never traverses their proxy. If you want those — and with the
in-process limiter degraded on serverless, there is a real argument for it —
either orange-cloud the record and accept the CDN-on-CDN caveats, or split the
API onto its own proxied `api.` hostname.

## 13. Running the tests

```bash
cd backend && python -m pytest
```

```
459 passed
```

Coverage by area:

| Suite | What it asserts |
|---|---|
| `test_workspace_isolation.py` | One workspace never sees another's listing, report, dashboard counts or activity series, by reference or by numeric id; nothing at all is shared, so a new visitor's history and dashboard are empty; purge deletes only the caller's rows and genuinely removes them rather than hiding them; the retention sweep expires old rows and a zero setting disables it |
| `test_hostile_uploads.py` | 16 adversarial payloads complete in bounded time; extraction scales linearly rather than quadratically; truncation is reported not hidden; control characters, ANSI escapes, bidi overrides and NUL bytes never reach output; indicators are defanged; sample bytes are removed even when analysis is cut short; the API still serves other requests afterwards |
| `test_postgres_compat.py` | Every query compiles against the real PostgreSQL dialect; JSON becomes JSONB; `date_trunc` is used on Postgres and `date()` on SQLite; Supabase pooler detection, prepared-statement disabling and TLS enforcement; the connection password is never printed or exposed by the API |
| `test_url_analyzer.py` | Valid/invalid URLs, scheme rejection, HTTPS, IP hosts, punycode, brand impersonation, encoding tricks, payload extensions, multi-label suffixes |
| `test_hash_analyzer.py` | MD5/SHA-1/SHA-256 identification, invalid input, normalisation, collision-resistance annotation, **verification that the hard-coded EICAR digests are correct** |
| `test_risk_engine.py` | Band boundaries (inclusive, contiguous, 0–100), accumulation, capping, corroboration, score floors, breakdown/points consistency |
| `test_file_analyzer.py` | Hash correctness vs `hashlib`, multi-chunk streaming, magic bytes, type mismatch, string extraction, entropy, filename sanitisation (traversal, control chars, reserved names), quarantine containment, oversized-upload abort leaving nothing on disk |
| `test_ip_domain_analyzers.py` | IPv4/IPv6 validation, scope classification, documentation ranges, DGA entropy, punycode |
| `test_api.py` | Success paths, validation errors, 404/413/422, pagination, filtering, sorting, deletion, dashboard aggregation, security headers, and that responses never contain a stack trace |

Frontend checks:

```bash
cd frontend && npm run lint && npm run build
```

## 14. API documentation

Interactive Swagger UI at **`/docs`**, ReDoc at **`/redoc`**, schema at **`/openapi.json`**.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Liveness plus a real database round-trip and provider roster |
| `GET` | `/api/config` | Platform capabilities (no secrets) |
| `GET` | `/api/stats/dashboard` | Live aggregates and activity series |
| `POST` | `/api/analyze/url` | Analyse a URL |
| `POST` | `/api/analyze/domain` | Analyse a domain |
| `POST` | `/api/analyze/ip` | Analyse an IP address |
| `POST` | `/api/analyze/hash` | Analyse a file hash |
| `POST` | `/api/analyze/file` | Analyse an uploaded file (static only) |
| `GET` | `/api/analyses` | Paginated history with search, filter, sort |
| `GET` | `/api/analyses/{id}` | Full report by numeric id **or** `SC-` reference |
| `DELETE` | `/api/analyses/{id}` | Delete a stored analysis |
| `POST` | `/api/analyses/purge` | Delete every analysis in the caller's workspace |

```bash
curl -X POST http://localhost:8000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://paypal.secure.login.account-verify.xyz/webscr/confirm.php"}'
```

### Adding a threat-intelligence provider

```python
class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"
    display_name = "VirusTotal"

    @property
    def is_configured(self) -> bool:
        return bool(settings.virustotal_api_key)

    async def lookup_hash(self, hash_value: str) -> ProviderLookup:
        ...
```

Register the class in `providers/registry.py` and add its name to `ENABLED_PROVIDERS`. Nothing else changes: `safe_lookup` already guarantees a slow or failing provider degrades the analysis to `partial` rather than failing it.

## 15. Limitations

Stated plainly, because knowing what a tool cannot do is part of using it safely.

- **The risk score is not calibrated.** It is a weighted heuristic sum, not a probability. Treat it as triage prioritisation.
- **Static analysis only.** Packed, encrypted or heavily obfuscated samples will reveal little. Archive contents are never inspected — extraction is unsafe and out of scope.
- **No sandbox.** There is no behavioural analysis, because there is no detonation. That requires isolated infrastructure well beyond this project.
- **The offline provider dataset is tiny.** `UNKNOWN` is the common answer, and absence of a record is explicitly not evidence of safety.
- **The public-suffix list is curated, not complete.** A ~70-entry multi-label set covers the overwhelming majority of real submissions; exotic suffixes may split incorrectly.
- **Heuristics produce false positives.** A legitimate CDN hostname can look like a DGA; a legitimate short link is still a short link. This is why every finding is named and explained rather than silently folded into a number.
- **The content sweep is windowed.** Hashes cover the whole file, but pattern matching stops after 1 MB, and a sample that exhausts the time budget yields a truncated report. Both are stated in the report; neither is silent.
- **No authentication.** Deploy on a trusted network only, or put [Cloudflare Access](#125-cloudflare-access-is-how-this-deployment-gets-authentication) in front of it.
- **Rate limiting is in-process.** Correct for one worker; multiple replicas need a shared store. Behind a proxy it is only meaningful once `TRUSTED_PROXIES` is set — the Settings page reports the resolved client-IP source and warns when the configuration is half-finished, because that failure is otherwise silent.
- **Single-node, synchronous.** Analyses run inside the request, on a bounded worker pool. Fine at MVP scale, not at ingest scale.

## 16. Future research & development

### Phase 2 — Intelligence enrichment
- VirusTotal and AbuseIPDB integrations behind the existing provider interface
- WHOIS and registration-age analysis (newly registered domains are a strong signal)
- Passive DNS history and TLS certificate analysis (issuer, age, SAN sprawl)
- YARA rule support for safe static scanning
- STIX/TAXII import and export for interoperability

### Phase 3 — Analytical depth
- ML-based classification trained on a labelled corpus, which would make a *calibrated* score possible for the first time
- Threat actor clustering and campaign detection across stored analyses
- IOC relationship graphs (which hashes reference which infrastructure)
- Fuller MITRE ATT&CK mapping with tactic coverage visualisation
- Automated report generation (PDF export, executive summaries)

### Phase 4 — Platform maturity
- ~~PostgreSQL as the default backing store~~ — **done**, see [section 9](#9-using-supabase-postgresql)
- Alembic migrations in place of `create_all`
- Redis for shared rate limiting and caching
- Celery workers for asynchronous analysis of large samples
- Authentication, RBAC and multi-user organisations
- Distributed analysis workers with a sandboxed detonation tier on isolated infrastructure

---

**Defensive use only.** SentinelCTI analyses indicators; it does not attack, scan or exploit anything. Do not upload confidential data — this is a demonstration platform, not an accredited malware analysis service.

Licensed under the MIT License.
