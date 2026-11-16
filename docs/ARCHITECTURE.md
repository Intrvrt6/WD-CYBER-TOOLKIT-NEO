# Architecture

## 1. Shape of the system

```
                     ┌──────────────────────────────────────────────┐
  browser (any OS,   │  frontend/  index.html + assets/*.js (no build)│
  Android, desktop)  │  gate → dashboard → modules → assess → report │
                     └───────────────────┬──────────────────────────┘
                                         │  fetch + Bearer token
                     ┌───────────────────▼──────────────────────────┐
                     │  FastAPI  backend/main.py                     │
                     │  ┌── api/auth.py        two-stage auth        │
                     │  ├── api/core_api.py    scope/jobs/findings   │
                     │  └── api/reports_api.py reports + evidence    │
                     └───────────────────┬──────────────────────────┘
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
  authentication.py               orchestrator.py                   audit.py
  authorization.py                (preflight → job → risk)          (hash chain)
  emergency_stop.py                      │
                                         ▼
                              engines/  (one package per module)
                              ┌──────────────────────────────────┐
                              │ base.py: Context, Result,        │
                              │ registry, artifact hashing       │
                              └──────────────┬───────────────────┘
                                             ▼
                                   runner.py  (managed subprocesses,
                                   killable process groups)
                                             ▼
                           nmap tshark tcpdump arping dig yara nuclei ...
                           pymodbus  asyncua  python-can  scapy  psutil
```

## 2. Data model (SQLite by default)

| Table | Purpose |
|---|---|
| `users` | operator identity, role, Argon2id password+pin hashes, lockout state |
| `shortcuts` | stage-1 WD shortcut codes (hash only) |
| `sessions` | server-side sessions; `token_hash` (SHA-256), stage, expiry, revocation |
| `scope_entries` | registered targets and their classified type |
| `authorizations` | one per approved test: targets, scope snapshot, TTL, revoked flag |
| `assessments` | template run: mode, intensity, params, status, risk, summary |
| `findings` | per-check result: severity, CVSS, CWE, evidence (JSON), evidence source |
| `artifacts` | evidence files with size + SHA-256 |
| `jobs` | background execution state, progress 0-100, structured log |
| `audit_events` | append-only hash chain (`seq`, `prev_hash`, `hash`) |
| `state_kv` | durable JSON state (emergency stop, bootstrap marker, rate limiter) |

Point `WD_DATABASE_URL` at PostgreSQL (e.g. `postgresql+psycopg://user:pass@host/db`) to move off
SQLite; the schema and stores are dialect-agnostic. Run `database/schema.sql` for a reference DDL.

## 3. Request flow: one assessment

1. **Stage 1** — `POST /api/auth/stage1 {username, password, shortcut}` → verifies both the operator
   password *and* an active WD shortcut; issues an opaque session token (stored hashed).
2. **Stage 2** — `POST /api/auth/stage2 {pin}` → raises the session to stage 2.
3. **Scope** — `POST /api/scope {target}` → type auto-classified and registered.
4. **Authorization** — `POST /api/authorizations {targets, ttl}` → requires stage 2, validates targets
   against the scope registry, snapshots the match, stores an expiring token.
5. **Assessment** — `POST /api/assessments {template, targets, mode, intensity, params}` → merges
   template defaults, runs **preflight** (targets present, engine loaded, mode valid, template's
   preflight acknowledgements) and stores the assessment.
6. **Execution** — `POST /api/assessments/{id}/run {authz_id, confirm:true}` → verifies the
   authorization (exists, confirmed, unexpired, not revoked, targets ⊆ authz targets, targets still
   in scope), enqueues a `Job`, and starts a worker thread.
7. **Engine** — `orchestrator._run_job` builds a `Context` (targets, params, evidence dir, log/progress
   callbacks) and calls `engine.run(ctx)`. Each `Result` carries `check_id`, `status`, `severity`,
   `source`, `evidence[]`.
8. **Persistence** — findings and artifacts are written; risk score and summary computed; the audit
   chain records `assessment.completed` with counts.
9. **Reporting** — `GET /api/assessments/{id}/report?fmt=pdf&lang=id` renders 12 sections, listing
   executed checks and explicitly marking checks that did not run.

## 4. Engine contract

```python
class SomeEngine:
    module = "some_module"
    title = "Module X - ..."
    description = "one line"
    checks = [("XX-01", "check title", True), ...]   # (id, title, active)
    def run(self, ctx: Context) -> list[Result]: ...
```

Rules every engine follows:

- **Never fabricate.** A missing binary, interface or endpoint produces
  `base.unavailable(check_id, title, reason)`.
- **Stamp the provenance.** `Result.source` ∈ `live | lab | local | unavailable`.
- **Bound everything.** Every subprocess has a timeout; the emergency stop can kill any engine
  mid-flight because all commands run through `runner.executor`.
- **Persist evidence.** Raw command output, capture files and protocol transcripts go through
  `ctx.save_text(...)` / `artifact(...)` with a SHA-256.
- **Fail soft.** A per-check exception becomes an `error` Result; it never aborts the whole run.

Registration is tolerant (`engines/__init__.py`): if an engine cannot import (missing optional
library), the platform still starts and reports that module as unavailable with the exact error.

## 5. Emergency stop semantics

`POST /api/emergency-stop` (any authenticated operator, stage 1 is enough to *halt*):

1. Sets `state_kv.emergency_stop = {active:true, generation:N+1}`.
2. Calls `runner.executor.request_stop()` → SIGTERM to every tracked process group and a latch that
   makes new `run()` calls fail immediately.
3. Marks queued/running jobs `aborted` and created/running assessments `aborted`.
4. Revokes all authorizations and all sessions.
5. Writes `emergency_stop.activated` to the audit chain.

Recovery requires a fresh stage-1 + stage-2 login and `POST /api/emergency-stop/clear`
(stage 2 only), which resets the executor latch and marks the stop cleared in the audit chain.
The stop is server state — a client that still shows a green dashboard cannot execute.

## 6. Audit integrity

Each event is chained:

```
hash_n = sha256( hash_{n-1} || canonical_json({seq, ts, actor, action, target, detail}) )
```

`ts` is normalised to a UTC `%Y-%m-%dT%H:%M:%S.%f` string before hashing so the digest survives
SQLite dropping timezone info. `/api/audit/verify` recomputes the whole chain; mutating or deleting
any row reports `valid:false` with the first broken `seq`.

## 7. Extension points

- **New module:** create `engines/<name>/engine.py`, add the class to `MODULE_CLASSES` in
  `engines/__init__.py`, add `templates/<name>_pentest.yaml`. No other file changes required.
- **New template:** drop a YAML file in `templates/`; it appears in the UI and API automatically.
- **PostgreSQL:** set `WD_DATABASE_URL`; no code change.
- **Auth backend:** swap `authentication.py`; the API only depends on `session_from_token`.
