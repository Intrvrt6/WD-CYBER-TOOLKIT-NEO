# Changelog

All notable changes to WD CYBER TOOLKIT NEO. Versions follow the application's own
`APP_VERSION` in `backend/config.py`.

## 1.4.1 — 2026-11-16

Patch release fixing one defect in the 1.4.0 discovery endpoint: it advertised the wrong port.

### Fixed

- **`GET /api/network` always reported port 8000**, whatever port the console was actually served
  on. The payload read only `WD_PORT`, which is exported by `run.sh` and `termux.sh` but is absent
  from the environment `uvicorn --port <n>` is commonly started with. A console on `:9187` therefore
  told clients `on_device_url: http://127.0.0.1:8000`, and the APK's DETECT would dial a port with
  nothing behind it — the same class of bug this release was meant to remove (the client had been
  guessing `10.0.2.2`). Observed before the fix on a live instance on `:9455`: `"port": 8000`,
  `"on_device_url": "http://127.0.0.1:8000"`.

  The advertised port is now resolved by `platform_utils.serving_port()` in trust order: the `Host`
  header's explicit port (what the client really dialled, and correct behind a reverse proxy) →
  the socket port the request arrived on → `WD_PORT` → the documented default. `GET /api/network`
  passes the live request's port and headers, so the advertised URL is the one that answers. Only
  the *port* is taken from `Host`; the advertised host stays loopback/LAN, so a spoofed `Host` can
  at most misstate the port of this same console in an advisory, unauthenticated payload.

- **The test that covered this did not assert the port.** It checked only that `on_device_url`
  started with `http://127.0.0.1:`, which is why it passed on `:9187` while the payload said 8000.
  Six tests now assert the completed URL, including IPv6 authorities, bare hostnames and the
  `user:pass@host` case; all six fail against the 1.4.0 code.

### Tests

- Full suite: **233 passed** — 227 at 1.4.0 plus the six new port tests.
- `python3 tests/audit_all_engines.py` — **0 / 10 engines with problems**.
- `python3 scripts/termux_proof.py` — **30 passed, 0 failed**.
- `android/run_harness.sh` — **30 / 30 checks**.

### Known limits

- The port now reported is correct for a direct connection and for a proxy that forwards the client's
  `Host`. A proxy that rewrites `Host` to the upstream address without setting `X-Forwarded-Host`
  will still cause the socket port to be reported; that is the safe direction (a real port) rather
  than an invented one.

## 1.4.0 — 2026-11-16

Android access release. The platform now runs *on the phone* under Termux, and the APK knows how to
reach it without the operator typing an address. Every number below was read back from a command
that was actually executed on this host, not estimated.

### Added

- **`backend/platform_utils.py`** — one platform abstraction for interface enumeration with an
  explicit fallback chain: `ip -br addr` → `ip addr show` → `ifconfig -a` → `psutil` →
  `ioctl(SIOCGIFCONF/SIOCGIFADDR)`. The last link is a raw syscall, so an Android phone with no
  `iproute2` installed can still report its own addresses. Every caller gets real data or an empty
  result *with a reason*; nothing is fabricated.
- **`GET /api/network`** — a deliberately **unauthenticated** discovery endpoint. A client has to
  learn the console URL before it can hold a token, so this returns addressing facts only
  (`platform`, `port`, `bind_host`, `urls`, `on_device_url`, `lan_url`, `primary_lan_ip`,
  `interface_source`, `has_iproute2`, `can_utils`, `instance`, `version`) — no scope, no findings, no
  secrets. `on_device_url` is always loopback-first, because an APK sitting next to a Termux console
  must dial `127.0.0.1`, not the phone's LAN address.
- **`scripts/termux.sh`** — one-command Termux installer (`pkg` instead of `apt`, `clang` for the C
  extensions, no venv, `requirements-core.txt`, and a `termux-wake-lock` so the server survives
  screen-off). Supports `--install`, `--run`, `--check` and `--help`; `--check` changes nothing.
- **`requirements-core.txt`** — the Android/Termux-safe subset. It is a strict subset of
  `requirements.txt` (a test asserts this) and deliberately omits `scapy`, `python-can`,
  `pymodbus`, `asyncua`, `yara-python` and `psutil`, which either fail to build on aarch64 Android or
  are pointless on a phone. The affected modules then report `unavailable` with the reason instead
  of pretending to run.
- **`docs/TERMUX.md`** — install, the four real Android differences, root/`tsu` for live capture, how
  to point the APK at a console, first login, recommended phone setup, troubleshooting.
- **`scripts/termux_proof.py`** — proves the stack under a simulated Termux (hides `ip`/`ss`/
  `ifconfig` from `PATH`, sets the Android markers) and then drives the real API end to end.
- **`tests/test_termux_android.py`** — 30 tests covering detection, the fallback chain, LAN-URL
  shape, the requirement split, shell-script syntax, and the APK default/detect regressions.

### Changed

- **`backend/capabilities.py`** now delegates interface and CAN detection to `platform_utils`, and
  `/api/capabilities` gained `platform`, `is_termux`, `is_android`, `interface_source`,
  `primary_lan_ip`, `lan_urls` and `platform_notes`. The UI no longer shows zero interfaces on a
  phone with no explanation.
- **`scripts/install.sh`** detects Termux and `exec`s `scripts/termux.sh` instead of printing advice
  it never followed.
- **`scripts/run.sh`** prints the addresses a client can actually use (`this device` and `LAN`), via
  the same `platform_utils.lan_urls()` helper `/api/network` uses, so the two cannot drift apart.
- **The APK default server is now `http://127.0.0.1:8000`.** It used to be `10.0.2.2:8000`, which is
  the *emulator's* alias for the host machine and is dead on real hardware — the app opened offline
  on every phone. `10.0.2.2` is kept only as an emulator-only shortcut, and an install upgraded from
  an older build has the dead value healed once on first launch.
- **New DETECT button** on the login screen: tries the on-device loopback, the emulator alias when
  actually emulated, then asks any console it reaches `GET /api/network` for the addresses it
  advertises, and saves the first one whose `/api/health` answers. If nothing answers it says so and
  names the port it tried.
- **`MainActivity.async()` discarded its `Job<T>` return value**, so any value-returning callback got
  `null`. Added `asyncValue()` for the value path; `async()` is now documented as side-effect-only.

### Fixed

- **`run.sh` lost its executable bit** in the working tree (`100755` → `100644`); restored.
- **The core harness only passed on a database that had already been rotated.** It rotated the
  bootstrap password to `Harness-Rotated-Pass-2026` and then logged in again with the *old* value,
  so the wrong-PIN check failed with HTTP 401 on a fresh database. It now tracks the current
  password. Verified on a brand-new database: **30/30**.

### Tests

- Full suite: **227 passed** (`python3 -m pytest -q`) — 197 at 1.3.0 plus the 30 new Termux tests.
- `python3 tests/audit_all_engines.py` — **0 / 10 engines with problems**.
- `python3 scripts/termux_proof.py` — **30 passed, 0 failed**.
- `android/run_harness.sh` — **30 / 30 checks**, on a fresh database and again on a re-run. The new
  check is `network discovery answers unauthenticated`, which is what DETECT depends on; the other 29
  are unchanged.

### Known limits

- No Android device or emulator exists in the build environment (no KVM), so Termux is proven by
  simulating its environment. Real-hardware behaviour — `pkg` resolution, a phone's actual interface
  names, wake-lock under OEM battery savers — is implemented but unconfirmed on a device.
- The `MainActivity` UI itself (the DETECT button wiring) is compiled into the signed APK and its
  bytecode is inspected, but the button has not been *pressed* on hardware. The client call it makes
  is covered by the harness.

## 1.3.0 — 2026-11-16

Engine-layer correctness release plus the native Android client. Every item below was reproduced on
this host before the fix and is locked by a named test afterwards.

### Added

- **Native Android client (`android/`)** — a dependency-free app for the whole API: two-stage
  unlock, dashboard, assess, scope, findings, all six report formats, Artax and audit-chain
  verification. No Gradle, no Jetpack, no network at build time; `build_apk.sh` drives the SDK
  build tools directly and produces a signed, zipaligned `dist/wd-neo.apk`.
- **`android/prepare_sdk.sh`** — fetches build-tools, the platform jar and a released R8, so the
  APK can be rebuilt on a clean host.
- **`android/run_harness.sh`** — compiles the *same* `Json`/`HttpClient`/`WdApi` sources that are
  packaged into the APK and drives the real HTTP API (29 checks), which tests the client contract
  without an emulator.
- **`docs/AUDIT_v1.3.0.md`** — the audit record for the engine-layer work in this release.

### Fixed

- **An executed check was reported as "not executed" (`automotive_can`).** `CAN-05` (anomaly
  detection) ran and produced five failing findings, but section 4 of the report printed
  `- [ ] CAN-05 - Not executed` and `8 of 9 declared check(s) executed; 1 could not run` — beside
  its own findings. The parent/suffix rule was `check_id.rstrip("0123456789") == declared_id`, which
  can never match an alphabetic suffix, so a check that emitted only derived ids (`CAN-05a`..`CAN-05e`)
  was declared missing. Coverage under-reported exactly where the platform promises never to
  misreport; `summary.coverage.missing` carried the same error.
- **Coverage accounting is now one shared rule (`backend/coverage.py`).** The orchestrator roll-up,
  the `unavailable_checks` mapping and the report renderer all resolve a produced id to its declared
  parent through the same helper, so they cannot disagree. A derived id must start with a letter and
  be at most three characters, which keeps `CAN-10` from being read as a variant of `CAN-1`.
- **`database/schema.sql`** gains the `findings.status` column the ORM already wrote, so a database
  provisioned from the reference DDL no longer fails with "no such column".
- **The APK build was broken on this toolchain.** The `d8` inside `build-tools;android-14` is an
  R8 8.2.2-dev snapshot that dies with `NullPointerException: Cannot invoke "String.length()"` on
  *any* anonymous inner class — reproduced with a two-line stand-in class, so it was the tool and
  not the app. `build_apk.sh` now uses a released R8 from Google's Maven repository when present.

### Tests

- `tests/test_coverage_accounting.py` — 11 tests: the derived-id rule (`CAN-05a`, `CAN-06b`,
  `NET-02b`), the `CAN-1`/`CAN-10` counter-example, the orchestrator roll-up, and an end-to-end
  report assertion that an executed check never renders as unreached.

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
- Test suite: 186 collected tests (168 test functions, parametrised) at 1.2.1; 197 at 1.3.0.

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
