# Changelog

All notable changes to WD CYBER TOOLKIT NEO. Versions follow the application's own
`APP_VERSION` in `backend/config.py`.

## 1.2.1 — 2026-11-16

Second security release, from the same adversarial review's remaining findings. All six were live
at `1.2.0`; each is covered by `tests/test_review_second_pass.py` and re-proved live
(`live-proof-6/LIVE-PROOF-6.md`, 38/38).

### Fixed

- **Scope matching was a bare string prefix (scope escape).** A grant of `https://example.com`
  covered `https://example.com@evil.tld/` (`example.com` as *userinfo*), `https://example.com.attacker.tld/`
  and `https://example.com.evil.tld:8443/p`, and a registered `/24` covered a requested `/8`. A
  harness proved the outbound consequence: the platform fetched an attacker host and stored its
  marker in its own evidence directory while the audit log recorded only the in-scope name. Matching
  is now origin + path for URLs, subdomain-only for domains, and subnet containment for IP ranges.
- **Audit tail truncation verified as valid.** Deleting the newest events left a shorter but
  self-consistent chain, so the natural cover-up went undetected. The expected tail (`seq`, `head`)
  is now persisted in `state_kv` outside `audit_events`, written in the same transaction as each
  append, and compared by `/api/audit/verify` (`"tail truncated: ..."`, plus `anchored: false` for
  pre-anchor chains).
- **`viewer` could authorize, create and execute.** Every execute route used the stage-2 dependency
  without an RBAC check, so a "read-only" role could spend authorizations and launch scans.
  `require_stage2_role(...)` now guards authorize/create/run; the viewer keeps read-only access and
  halt stays open by design.
- **Emergency stop did not block assessment creation.** `require_clear` was missing on
  `POST /api/assessments`, so work could be queued behind an active halt and would fire on clear.
- **Credential rotation left other sessions valid.** Changing the password or PIN now revokes every
  other session of that operator and keeps the caller's, so a stolen token does not outlive the
  recovery action.
- **`kv()` trusted any value starting with `<` as markup.** Console key/value panels interpolated
  such values into `innerHTML` unescaped; escaping is now unconditional with an explicit
  `{html: true}` opt-in for real markup.

### Changed

- `APP_VERSION` is `1.2.1`; `docs/SECURITY.md` documents semantic scope matching, the audit anchor
  and its limits, the viewer role's actual capability, and session revocation on credential change.
- Test suite is 151 tests.

## 1.2.0 — 2026-11-16

Security release. Every item below was found by an independent adversarial review of the
running service, reproduced against it, then fixed and re-proved end to end
(`live-proof-6/LIVE-PROOF-6.md`, 31/31). Regression tests live in
`tests/test_access_control_regressions.py` and `tests/test_static_serving.py`.

### Fixed

- **Unauthenticated arbitrary file read through the SPA catch-all.** The console route served
  `frontend/<path>` whenever the result was a file, and the path was attacker-controlled. `GET
  /../database/bootstrap_credentials.txt` returned the operator password, stage-2 PIN and WD
  shortcut in cleartext; `GET /../../../../../etc/passwd` read outside the app entirely. The path
  is now resolved and must stay inside `frontend/`, and only known asset extensions are served.
- **Second factor was self-serviceable.** `POST /api/auth/pin` accepted a stage-1-only session plus
  the stage-1 password, so anyone holding the password could choose a new PIN and then immediately
  satisfy stage 2. PIN rotation now requires an already-stage-2 session.
- **PIN guessing was unbounded.** Wrong PINs returned `401` forever with no throttle, no ceiling and
  no lockout, so a 6-8 digit PIN was trivially iterable on one session. A wrong PIN now counts
  toward the account lockout and 5 wrong PINs on a session revoke it (`423
  PIN_ATTEMPTS_EXCEEDED`).
- **One identity could lock out every operator.** The login rate limit was a single global counter
  keyed `login_attempts`, so ten failed logins from any source returned `429` for all subsequent
  logins install-wide. Limits are now per key: per claimed username at the configured budget and
  per client address at ten times that.
- **Any operator could spend another operator's authorization.** `assert_valid` never compared the
  authorization's owner with the caller, so a test ran on somebody else's approval and the audit
  trail attributed it to whoever held the id. Now `403 AUTHZ_FOREIGN`.
- **Integration execution bypassed the access model.** `POST /api/integrations/katana/crawl`,
  `/nuclei/sqli` and `/ksubdomain/enum` ran real tools against a caller-supplied target with only a
  stage-1 session, no scope check and no emergency-stop check. They now require stage 2 on a
  rotated password, a target inside the registered scope, and a clear stop.
- **Concurrent audit appends could duplicate a sequence number.** Read-tail/insert was unguarded, so
  two requests could both claim `seq N` and make a healthy chain look tampered with. Appends are
  serialised and `seq` carries a unique index on new databases.
- **Assessment ownership was not checked on run.** A non-admin operator could run another
  operator's assessment; now `403 ASSESSMENT_FOREIGN`.

### Changed

- `APP_VERSION` is `1.2.0`.
- `docs/SECURITY.md` documents the per-key throttle, the PIN ceiling, authorization ownership,
  integration gating, static-file containment and the retrospective nature of audit verification.
- The console's Account view explains that PIN rotation needs a stage-2 session instead of failing
  with an opaque error.

## 1.1.0

- Artax AI analyst, upstream integrations (ARTEX, ScopeSentry, ksubdomain, katana, oscuridad nuclei
  templates), ten engines, 12-section EN/ID reports, tamper-evident audit chain, global emergency
  stop, two-stage access control with Argon2id, bootstrap password rotation gate.
