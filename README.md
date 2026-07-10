# Recon/VAPT — Bug Bounty Automation Platform

A self-hosted platform that automates the full loop of authorized bug bounty
and VAPT engagements: passive OSINT → DNS/HTTP probing → IP enrichment →
JS-aware crawling → active vulnerability scanning → CORS/takeover/cloud-
exposure checks → optional directory/parameter fuzzing → diffing against the
previous scan → alerting only on genuinely new findings. Runs one-off ("full
scan") or on a schedule ("continuous monitoring").

## What's in this version

- **Redesigned UI** — single-accent dark theme, severity conveyed by small
  dots/labels instead of blocks of color, real tabs, filterable tables,
  copy-to-clipboard, live scan-progress polling (no manual refresh needed).
- **12 passive OSINT sources**, 8 of them API-key-gated so the platform gets
  measurably more thorough as you add keys, with zero required to start.
- **Free IP enrichment** (Shodan InternetDB — no key needed) surfacing open
  ports and known CVEs on every resolved IP, not just HTTP findings.
- **Confidence labeling** on every finding — heuristic detections (CNAME-
  pattern takeover guesses, regex-only secret matches) are marked
  `unconfirmed`; signature/tool-verified ones (nuclei templates, trufflehog)
  are `confirmed`. Wildcard-DNS zones are detected and every affected
  subdomain is flagged, instead of silently presenting a false positive as
  a real host.
- **Authentication** (optional but recommended) — API-key header for the
  JSON API, signed-cookie session for the dashboard.
- **SSRF and ReDoS guards** on every place user input reaches a filesystem
  path, an outbound webhook, or a regex compiler.

## Architecture

- **Python 3.11+ / asyncio core** — every phase runs concurrently.
- **FastAPI backend** (`app/main.py`) — JSON API + server-rendered dashboard.
- **SQLAlchemy async ORM over SQLite** (swap `DATABASE_URL` for Postgres to
  scale past one machine).
- **APScheduler** for continuous monitoring.
- Wraps industry-standard tools via `app/core/tool_runner.py` and **degrades
  gracefully to native Python fallbacks** for any tool that isn't installed
  — a missing binary means less depth on that phase, never a crash.

## Quickstart

```bash
git clone <this repo>
cd bugbounty-platform
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# at minimum set RESEARCHER_NAME / RESEARCHER_CONTACT

# Optional but recommended — installs subfinder/httpx/katana/nuclei/ffuf/x8/trufflehog
./scripts/install_tools.sh

uvicorn app.main:app --reload
```

Open `http://localhost:8000`. API docs at `/docs`.

## Every tool, technique, and data source in use

**Passive OSINT (subdomain discovery, no packets to the target itself):**
| Source | Needs a key? | What it adds |
|---|---|---|
| crt.sh | no | certificate-transparency log subdomains |
| Wayback Machine (CDX API) | no | historically archived hostnames |
| RapidDNS | no | passive DNS aggregator |
| AlienVault OTX | no | passive DNS |
| subfinder (CLI) | no | 40+ aggregated passive sources in one tool |
| assetfinder (CLI) | no | additional passive aggregation |
| Shodan | `SHODAN_API_KEY` | DNS subdomain records Shodan has indexed |
| Censys | `CENSYS_API_ID` + `_SECRET` | certificate/host search |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | historical DNS + subdomains |
| VirusTotal | `VIRUSTOTAL_API_KEY` | passive DNS + subdomains |
| urlscan.io | `URLSCAN_API_KEY` (optional — works unauth'd at lower quota) | scanned pages under the domain |
| ProjectDiscovery Chaos | `CHAOS_API_KEY` | curated bug-bounty-program subdomain dataset |
| BinaryEdge | `BINARYEDGE_API_KEY` | passive DNS |
| LeakIX | `LEAKIX_API_KEY` | exposed-service search |
| github-subdomains (CLI) | `GITHUB_TOKEN` | subdomains leaked in public code |

**DNS / HTTP / crawling:**
- `dnsx` (CLI) or native `dnspython` async resolution — with **wildcard DNS
  detection**: if the zone wildcards, every affected subdomain is flagged
  `wildcard_suspect` instead of being presented as a confirmed distinct host.
- `httpx` (CLI, ProjectDiscovery) or native `aiohttp` probing with a **built-in
  tech fingerprinter** (header + body signatures for nginx/Apache/IIS/
  Cloudflare/WordPress/Drupal/React/Next.js/Laravel/Shopify/etc.) so the
  native fallback isn't blind on tech detection when httpx isn't installed.
- `katana` (CLI, JS-aware crawler) or native same-host link extraction.

**Enrichment:**
- **Shodan InternetDB** (`internetdb.shodan.io`, free, no key) — open ports,
  CPEs, and any CVEs Shodan's own scanning has already associated with each
  resolved IP. Genuinely new signal a pure HTTP pipeline misses (e.g. an
  exposed Redis or database port with no web server on it at all).

**Active vulnerability scanning:**
- `nuclei` — cve/exposures/misconfiguration/default-login/panel/backup/
  debug/redirect/sqli/ssrf/xss/lfi/rce/idor template tags.
- Native CORS misconfiguration prober (crafted Origin headers, reflected/
  wildcard ACAO + credentials combo detection).
- Subdomain takeover: native CNAME-fingerprint check (marked `unconfirmed`
  — verify before reporting) **and** nuclei's takeover templates (marked
  `confirmed`).
- Cloud bucket exposure: S3/GCS/Azure Blob brand-name permutation probing.
- `ffuf` (directories) + `x8` (hidden parameters) — **full-scan only**,
  excluded from continuous monitoring so scheduled runs stay fast and polite.
- JS secret scanning: regex patterns (AWS/GCP/Slack/Stripe keys, JWTs,
  private-key blocks — marked `unconfirmed`, regex can false-positive) plus
  `trufflehog --only-verified` (marked `confirmed` — provider-API-verified
  live credentials).

Every active item above is filtered through `ScopeFilter.in_scope()` before
a single request goes out.

## Security model

This app can trigger outbound network scans on command. If it's ever
reachable beyond `127.0.0.1`, an unauthenticated scan-trigger endpoint is a
way for a stranger to make **your** IP send active traffic at **their**
chosen target. Set `APP_PASSWORD` in `.env` before binding to anything other
than loopback — it protects both surfaces:

- **JSON API** — `X-API-Key: <APP_PASSWORD>` header on every request.
- **Dashboard** — `POST /login` sets an HMAC-signed session cookie
  (`SESSION_SECRET`, auto-generated and persisted to `.session_secret` on
  first run if you don't set one explicitly). 7-day expiry.

Leaving `APP_PASSWORD` blank is fine for strictly-local use — the app logs a
warning at startup so you don't forget it's unauthenticated.

Other hardening in this version:
- **SSRF guard** (`app/config.py::is_public_http_target`) — every
  user-supplied webhook URL is checked before the app POSTs to it. Loopback,
  private (RFC 1918), and link-local (incl. the `169.254.169.254` cloud
  metadata endpoint) targets are rejected at program-creation time, not just
  silently skipped later.
- **ReDoS guard** (`app/core/scope.py::validate_scope_regex`) — scope
  regexes are length-capped and checked against a nested-quantifier shape
  (`(a+)+`-style patterns) before being accepted, since these are user input
  that gets matched against every discovered host on every scan.
- **Path traversal guard** (`Settings.safe_workspace_slug`) — a program name
  can no longer inject `../` or an absolute path into the scan workspace
  directory.
- **Rate limiting** — a lightweight in-memory limiter caps mutating requests
  (POST/PATCH/DELETE, including login attempts) per client IP.
- **Attribution header** — `X-Bug-Bounty: researcher=...; contact=...` sent
  on every active request, per common bug-bounty program norms.

## Scan modes

| Mode | Phases | Used by |
|---|---|---|
| `full` | everything, including ffuf/x8 fuzzing | manual "Full scan" button |
| `incremental` | passive → DNS → HTTP → enrichment → crawl → JS/secrets → nuclei → CORS → takeover → cloud (no fuzzing) | continuous monitoring scheduler |

## Continuous monitoring & alerting

Enable per-program with an interval and a webhook URL. On each scheduled
run: an `incremental` scan runs, gets diffed by fingerprint (not exact text,
so template wording changes don't cause false "new" alerts) against the last
**completed** run, and only genuinely-new items that haven't been alerted
before (checked against `alert_log`) get posted. First scan for a program
never alerts — everything is a baseline.

## Project layout

```
app/
  main.py                 FastAPI app, lifespan startup, auth redirect handler, rate limiter
  config.py                Settings (.env-driven) + SSRF guard + workspace-slug sanitizer
  models.py / schemas.py   DB models (+ SEVERITY_RANK) / API schemas
  api/
    programs.py             CRUD + scope/webhook validation (API-key protected)
    scans.py                  trigger/inspect scan runs (API-key protected)
    findings.py                 filterable findings list (API-key protected)
    diffs.py                     diff any scan against its predecessor (API-key protected)
    dashboard.py                  server-rendered HTML + /login /logout (session protected)
  core/
    orchestrator.py         wires every phase together per scan
    diff_engine.py           new/removed asset + finding computation
    alerting.py               webhook notifications, dedupe, SSRF-checked before sending
    scheduler.py               APScheduler continuous monitoring
    scope.py                    scope_regex enforcement + ReDoS validation
    security.py                  API-key auth, signed session cookies, rate-limit middleware
    tool_runner.py                async subprocess wrapper, tool-availability checks
    rate_limiter.py                shared token-bucket limiter for native HTTP phases
    phases/
      passive_recon.py       12 OSINT sources (see table above)
      dns_resolve.py           dnsx/dnspython, wildcard detection
      http_probe.py             httpx/aiohttp + native tech fingerprinting
      enrichment.py              Shodan InternetDB — free IP-level enrichment
      crawl.py                    katana or native link extraction
      js_secrets.py                 regex + trufflehog-verified secret scanning
      vuln_scan.py                    nuclei — the main active VAPT signal
      fuzzing.py                       ffuf (dirs) + x8 (params) — full-scan only
      cors_check.py                     crafted-Origin CORS misconfig probing
      takeover_check.py                  dangling-CNAME + nuclei takeover templates
      cloud_check.py                      S3/GCS/Azure public bucket probing
  templates/, static/       dashboard UI (style.css, app.js — tabs/polling/copy/toasts)
scripts/install_tools.sh    installs the Go-based external tools
tests/                       scope, diff-engine, and security/SSRF/ReDoS tests
```

## Extending it

- New active phase → `app/core/phases/your_phase.py` returning
  `{"finding_type", "severity", "target", "name", "detail", "confidence"}`
  dicts (`confidence` defaults to `"confirmed"` if omitted — only set it to
  `"unconfirmed"` for heuristic/pattern-based detections), call it from
  `orchestrator.run_scan()`, filter inputs through `scope.filter()` first.
- New passive OSINT source → add an async function to `passive_recon.py`,
  gate it behind a `settings.your_api_key` check, add it to the `tasks` dict
  in `passive_recon.run()`.
- Upgrading from a pre-existing `bugbounty.db`: new columns are added
  automatically on startup via a lightweight SQLite migration in
  `database.py` (Postgres users: manage schema changes yourself, Alembic
  recommended once the schema needs anything non-additive).
