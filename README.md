# Recon/VAPT — Bug Bounty Automation Platform

A self-hosted platform that automates the full loop of authorized bug bounty
and VAPT engagements: passive OSINT → DNS/HTTP probing → JS-aware crawling →
active vulnerability scanning → CORS/takeover/cloud-exposure checks → optional
directory/parameter fuzzing → diffing against the previous scan → alerting
only on genuinely new findings. Runs one-off ("full scan") or on a schedule
("continuous monitoring").

Built as a proper platform, not a single script:

- **Python 3.11+ / asyncio core** — every phase runs concurrently, not
  sequentially like a bash pipeline.
- **FastAPI backend** (`app/main.py`) — JSON API + server-rendered dashboard.
- **SQLAlchemy async ORM over SQLite** (swap the `DATABASE_URL` for Postgres
  to scale past one machine).
- **APScheduler** for continuous monitoring.
- Wraps industry-standard tools (subfinder, dnsx, httpx, katana, nuclei, ffuf,
  x8, trufflehog) via `app/core/tool_runner.py`, and **degrades gracefully to
  native Python fallbacks** for any tool that isn't installed — the platform
  never crashes because a binary is missing, it just does less on that phase.

## Why this is architected the way it is

The original `bugbounty_recon.sh` you had is a solid *linear* pipeline: one
tool after another, writing text files. That's fine for a single manual run.
It falls over the moment you want any of:

- **State** — "what did we find last time, and what's new since then?"
- **Concurrency** — bash can background jobs, but coordinating 10 tools with
  timeouts, partial failures, and structured merging gets unmanageable fast.
- **A UI** — someone other than you (or you, three weeks from now) needs to
  see results without SSHing in and grepping log files.
- **Scheduling** — a cron job calling a bash script has no idea what's
  "new" versus "we already told you about this."

Those four things are exactly what a database + async orchestrator + web
layer buy you, which is why this is a platform instead of a bigger script.

## Quickstart

```bash
git clone <this repo>
cd bugbounty-platform
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env — at minimum set RESEARCHER_NAME / RESEARCHER_CONTACT,
# these get sent as an X-Bug-Bounty attribution header on every active request

# Optional but recommended — installs subfinder/httpx/katana/nuclei/ffuf/x8/trufflehog
./scripts/install_tools.sh

uvicorn app.main:app --reload
```

Open `http://localhost:8000` — create a program (target scope), hit **Full
scan**, watch it populate. API docs live at `/docs` (FastAPI auto-generated).

## Scope enforcement — read this before pointing it at anything

Every program you create has a `scope_regex` (and optional
`out_of_scope_regex`). Every *active* phase — nuclei, ffuf/x8 fuzzing, CORS
probing, subdomain-takeover HTTP checks, cloud bucket probing — filters its
target list through `app/core/scope.py::ScopeFilter` before sending a single
request. Passive phases (crt.sh, Wayback, etc.) query third parties about
your domain, not the domain itself, so they're not scope-gated the same way.

`ENFORCE_SCOPE=true` in `.env` is the master switch. Leave it on. It exists
so a typo in your target list can't turn into an unauthorized scan.

Also set `RESEARCHER_NAME` / `RESEARCHER_CONTACT` — most programs want an
identifiable header on traffic from automated tooling so their blue team can
tell it's you and not an actual attacker. It's sent on every active request.

## Scan modes

| Mode          | Phases                                                                 | Used by                          |
|---------------|-------------------------------------------------------------------------|-----------------------------------|
| `full`        | everything, including ffuf/x8 directory & parameter fuzzing            | manual "Full scan" button         |
| `incremental` | passive → DNS → HTTP → crawl → JS/secrets → nuclei → CORS → takeover → cloud (no fuzzing) | continuous monitoring scheduler   |

Fuzzing is deliberately excluded from scheduled/incremental runs — it's the
noisiest, most request-heavy phase, and continuous monitoring should stay
fast and polite, not hammer every in-scope host every few hours.

## Continuous monitoring & alerting

Enable it per-program (dashboard or `PATCH /api/programs/{id}/monitoring`)
with an interval and a webhook URL (Slack/Discord-compatible incoming
webhook). On each scheduled run:

1. Orchestrator runs an `incremental` scan.
2. `diff_engine.compute_diff()` compares against the last **completed** run
   for that program — new subdomains, new endpoints, new findings (matched
   by a stable fingerprint, not exact text, so wording changes in a nuclei
   template don't cause false "new" alerts).
3. `alerting.send_new_finding_alerts()` posts only what's both new *and*
   never alerted before (checked against `alert_log`), so a program re-scanned
   every 6 hours doesn't re-notify you about the same open finding forever.

First scan for a program never fires an alert — everything is a baseline.

## Project layout

```
app/
  main.py                 FastAPI app, lifespan startup (DB init + scheduler)
  config.py                Settings (.env-driven)
  models.py / schemas.py   DB models / API schemas
  api/
    programs.py            CRUD + scope for programs
    scans.py                trigger/inspect scan runs (JSON API)
    findings.py              filterable findings list
    diffs.py                  diff any scan against its predecessor
    dashboard.py                server-rendered HTML (Jinja2)
  core/
    orchestrator.py         wires every phase together per scan
    diff_engine.py           new/removed asset + finding computation
    alerting.py               webhook notifications, dedupe via alert_log
    scheduler.py               APScheduler continuous monitoring
    scope.py                   scope_regex / out_of_scope_regex enforcement
    tool_runner.py              async subprocess wrapper, tool-availability checks
    rate_limiter.py              shared token-bucket limiter for native HTTP phases
    phases/
      passive_recon.py       crt.sh, Wayback, RapidDNS, OTX, subfinder, assetfinder, github-subdomains
      dns_resolve.py          dnsx or native dnspython, wildcard detection
      http_probe.py            httpx CLI or native aiohttp probing
      crawl.py                  katana or native link extraction
      js_secrets.py              fetch JS, regex secret scan + trufflehog
      vuln_scan.py                nuclei — the main active VAPT signal
      fuzzing.py                   ffuf (dirs) + x8 (params) — full-scan only
      cors_check.py                 crafted-Origin CORS misconfig probing
      takeover_check.py             dangling-CNAME + nuclei takeover templates
      cloud_check.py                 S3/GCS/Azure public bucket probing
  templates/, static/       dashboard UI
scripts/install_tools.sh    installs the Go-based external tools
tests/                       scope + diff-engine unit/integration tests
```

## What "modern and high-performing" means concretely here

- Every phase within a scan runs via `asyncio`, and independent sub-tasks
  within a phase (e.g. all 7 passive OSINT sources) run **concurrently**, not
  one after another — this alone is usually a 5-8x wall-clock improvement
  over the equivalent bash pipeline for the passive phase.
- `RateLimiter` and each CLI tool's own `-rate-limit` flag keep aggregate
  request rate polite regardless of concurrency — fast doesn't mean noisy.
- Findings are deduplicated by a content fingerprint, not raw text, so
  re-scans don't produce ballooning duplicate rows over time.
- SQLite is the default for zero-setup local use; the DB layer is async
  SQLAlchemy against a URL, so moving to Postgres for a team deployment is a
  one-line `.env` change, not a rewrite.

## Extending it

- New active phase → add `app/core/phases/your_phase.py` returning a list of
  `{"finding_type", "severity", "target", "name", "detail"}` dicts, call it
  from `orchestrator.run_scan()`, filter its inputs through `scope.filter()`
  first if it sends any request.
- New passive OSINT source → add an async function to `passive_recon.py` and
  add it to the `tasks` dict in `passive_recon.run()`.
- Swap the dashboard for a full SPA later if needed — the JSON API
  (`/api/...`) is already fully decoupled from the Jinja2 dashboard routes.
