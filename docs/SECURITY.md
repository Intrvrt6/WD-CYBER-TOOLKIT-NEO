# Security Model

## 1. Two-stage access control

| Stage | Proof required | Grants |
|---|---|---|
| 1 | WD shortcut code **and** operator password | a session that can browse scope, templates, modules, capabilities, audit |
| 2 | separate PIN | authorizations, assessment creation, execution, report save, stop clear |

Design intent:

- The **WD shortcut** is an additional operator control (something you carry), not a replacement
  for the password (something you know). Both are verified on every stage-1 attempt, and a stolen
  password alone yields no session.
- **Stage 2 is enforced on the server** via a FastAPI dependency (`require_stage2`). Hiding buttons
  in the UI is cosmetic; the API returns `403 STAGE2_REQUIRED` regardless of client.
- A **session token** is an opaque 32-byte URL-safe random string. Only its SHA-256 fingerprint is
  stored (`sessions.token_hash`), so a database read does not yield usable tokens.

## 2. Cryptography

| Purpose | Algorithm | Parameters |
|---|---|---|
| passwords, PINs, shortcut codes | Argon2id (`argon2-cffi`) | t=3, m=64 MiB, p=2, hash_len=32, salt 16 |
| session tokens | `secrets.token_urlsafe(32)` | 256-bit entropy |
| token storage | SHA-256 fingerprint | never the cleartext token |
| audit chain | SHA-256 over `prev_hash ‖ canonical_json` | tamper-evident |
| evidence integrity | SHA-256 per artifact | stored in `artifacts.sha256` |
| comparisons | `hmac.compare_digest` where applicable | constant time |

No plaintext password, PIN or shortcut is ever stored. `security.hash_secret` rejects empty input;
`verify_secret` returns `False` for malformed hashes instead of raising.

## 3. Password and PIN policy

- Password: minimum 12 characters, at least three of {lowercase, uppercase, digit, symbol}.
- PIN: minimum 6 digits.
- Bootstrap passwords are generated with `secrets` (not `random`) and are ~97 bits of entropy
  (`XXXXX-XXXXX-XXXXX-XXXXX!7`); PINs are 8 digits; shortcuts are `WD-` + 13 alphanumerics (~67 bits).
- `must_change_password` is set when the password was auto-generated, so a fresh install forces a
  first-login rotation (disable with `WD_FORCE_PASSWORD_CHANGE=0`).

## 4. Brute-force resistance

- **Account lockout**: 5 consecutive failures (configurable) lock the account for 15 minutes;
  the lockout is recorded in the audit chain.
- **Rate limiting**: a sliding window of 10 attempts per 60 s per client IP, returning `429`.
- Both counters are server-side and survive client restarts.
- Authentication failures are audited with the reason (`bad_credentials` / `bad_shortcut`).

Note: lockout applies to the operator account; rate limiting is global per window in this release
(see `backend/authentication.py::_throttle`) rather than per username.

## 5. Scope and authorization discipline

Three independent gates must pass before any active test runs:

1. **Scope registry** — the target (or a covering CIDR/domain/URL prefix) is registered.
2. **Authorization token** — exists, `confirmed`, unexpired, not revoked, and its `targets` list is a
   superset of the requested targets (`AUTHZ_TARGET_MISMATCH` otherwise).
3. **Emergency-stop gate** — the stop must be clear.

The authorization also snapshots the scope match at issue time, so the audit trail records exactly
what was considered in scope when approval was given.

## 6. Session lifecycle

- Created on stage 1, TTL `WD_SESSION_TTL_MINUTES` (default 480).
- Raised to stage 2 in place; the token does not change (so the client keeps one credential).
- Revoked by: explicit logout, emergency stop, or expiry.
- Resolution checks `revoked` and normalises naive SQLite datetimes to UTC before comparing.

## 7. Role-based access control

| Role | Capability |
|---|---|
| `admin` | everything, plus operator creation and shortcut issuance |
| `operator` | scope management, authorizations, assessments, reports |
| `viewer` | read-only browsing (no scope writes, no execution) |

RBAC is enforced through the `require_role(...)` dependency; there is no client-side authorization.

## 8. Emergency stop as a safety control

- Anyone authenticated (even stage 1, even a viewer) can **halt** — stopping must never be blocked
  by an approval workflow.
- Halting is server-authoritative: jobs and assessments are marked `aborted`, every tracked
  subprocess group receives SIGTERM, the executor latches closed, and **all authorizations and all
  sessions are revoked**.
- Resuming requires a fresh stage-1 + stage-2 login and an explicit `clear` (stage 2 only).
- Both transitions are recorded in the audit chain with counts and the acting operator.

## 9. Audit integrity

```
hash_n = sha256( hash_{n-1} || canonical_json({seq, ts, actor, action, target, detail}) )
```

- `ts` is normalised to `%Y-%m-%dT%H:%M:%S.%f` UTC **before** hashing, so the digest is stable even
  though SQLite does not persist timezone offsets.
- `seq` must be contiguous; a gap means rows were deleted.
- `verify_chain()` recomputes from genesis and reports the first broken `seq` and the reason.
- Exports: JSON (full detail) and CSV (flat, for SIEM ingestion).

Because the chain is computed over every field of every event, altering an actor, action, target,
timestamp or detail value invalidates that event and every later one.

## 10. Operational hardening checklist

- [ ] Delete `database/bootstrap_credentials.txt` after storing the values.
- [ ] Rotate password + PIN after first login.
- [ ] Serve behind TLS (reverse proxy) — the app itself speaks plain HTTP.
- [ ] Restrict `WD_HOST` to a management interface where possible; do not expose the API publicly.
- [ ] Keep `evidence/` and `database/` on a backed-up volume; both are inside the audit perimeter.
- [ ] Export the audit JSON to immutable storage after each engagement.
- [ ] Review `/api/capabilities` before an engagement and record missing tools as coverage limits.

## 11. Known security limitations (honest list)

- **CORS is permissive** (`allow_origins=["*"]`) so the SPA can be served from any host in a lab.
  Tighten it for internet-facing deployments.
- **Tokens travel in the `Authorization` header only** — no cookies, so CSRF is not applicable, but
  the client must hold the token (it uses `localStorage`).
- **One shared rate-limit window** rather than a per-username bucket (see above).
- **No MFA/TOTP** beyond the two-stage shared-secret model.
- **Subprocess execution is by design** — the platform is a pentest driver; run it on a host you
  control, not on a shared multi-tenant box without OS-level isolation.
- Engines execute read-only operations by default; any write/transmit path requires an explicit
  parameter (`allow_plc_write`, `allow_active`, `execute_arp_spoof`, `replay_allowed`).
