# API Reference

Base URL `http://<host>:8000`. All protected endpoints require
`authorization: Bearer <session-token>`. Errors return
`{"detail": {"code": "...", "message": "..."}}` (or a plain string for FastAPI validation).

Interactive schema: `/api/docs` · OpenAPI: `/api/openapi.json`

## Public

| Method | Path | Returns |
|---|---|---|
| GET | `/api/health` | status, version, engine registry status, emergency-stop state |
| GET | `/api/capabilities` | detected CLI tools + Python modules, host, interfaces, CAN, USB, raw-socket |
| GET | `/api/version` | instance/version/python |

## Authentication

### POST `/api/auth/stage1`
```json
{"username":"WD-OPERATOR-01","password":"...","shortcut":"WD-..."}
```
`200` → `{token, stage:1, user, expires_at, next}` · `401 INVALID_CREDENTIALS` · `423 LOCKED` · `429 RATE_LIMITED`

### POST `/api/auth/stage2`  *(Bearer stage-1 token)*
```json
{"pin":"42424242"}
```
`200` → `{stage:2, user, emergency_stop}` · `401 INVALID_PIN`

| Method | Path | Notes |
|---|---|---|
| GET | `/api/auth/me` | user, stage, session expiry, emergency-stop state |
| POST | `/api/auth/logout` | revokes the current session |
| POST | `/api/auth/password` | `{old_password,new_password}` — 12+ chars, 3+ classes |
| POST | `/api/auth/pin` | `{password,new_pin}` — 6+ digits |
| GET | `/api/auth/operators` | admin only |
| POST | `/api/auth/operators` | admin only — `{username,password,pin,role}` |
| POST | `/api/auth/shortcuts?label=` | admin only — issues a new WD shortcut, returned once |
| POST | `/api/auth/unlock` | stage 2 — clears an active emergency stop |

## Scope

| Method | Path | Notes |
|---|---|---|
| GET | `/api/scope` | list registered targets |
| POST | `/api/scope` | `{target,target_type?,description?}` — type auto-classified |
| DELETE | `/api/scope/{id}` | deactivate |
| POST | `/api/scope/validate` | `{targets:[...]}` → per-target `in_scope`, `matched_scope` |

## Templates & modules

| Method | Path | Notes |
|---|---|---|
| GET | `/api/templates` | 10 templates with checklist, preflight, safety, params |
| GET | `/api/templates/{id}` | full YAML-derived template |
| GET | `/api/modules` | engine catalog + registration status |

## Authorizations

### POST `/api/authorizations` *(stage 2)*
```json
{"targets":["testssl.sh"],"ttl_minutes":30,"intended_test":"authorized network pentest"}
```
`200` → `{id, targets, expires_at, confirmed, scope_snapshot}`
`403` `OUT_OF_SCOPE` / `STAGE2_REQUIRED` · `423 EMERGENCY_STOP`

`GET /api/authorizations` — recent authorizations with revoked/expiry state.

## Assessments

### POST `/api/assessments` *(stage 2)*
```json
{"template":"network_pentest","targets":["testssl.sh"],"mode":"live","intensity":"light","params":{}}
```
`200` → assessment plus `preflight: {ok, checks[]}`.

### POST `/api/assessments/{id}/run` *(stage 2)*
```json
{"authz_id":"<uuid>","confirm":true}
```
`200` → `{job_id, assessment_id, status}` · `403` authz errors · `409 already running` · `423` stop active

| Method | Path | Notes |
|---|---|---|
| GET | `/api/assessments` | recent assessments (limit) |
| GET | `/api/assessments/{id}` | assessment + findings + artifacts |
| GET | `/api/assessments/{id}/findings` | findings only, severity-ordered |
| GET | `/api/jobs/{job_id}` | status, progress 0–100, structured log, error |
| GET | `/api/stats` | dashboard aggregates |

## Reports

| Method | Path | Notes |
|---|---|---|
| GET | `/api/assessments/{id}/report?fmt=pdf\|html\|md&lang=en\|id&download=` | renders the 12-section report |
| POST | `/api/assessments/{id}/report/save?fmt=&lang=` | writes under `reports/`, returns path+size |
| GET | `/api/evidence/{assessment_id}/{artifact_id}` | download an evidence file |
| GET | `/api/evidence/samples` | bundled sample/fixture files |

## Audit

| Method | Path | Notes |
|---|---|---|
| GET | `/api/audit?limit=&action=` | recent events (newest first) |
| GET | `/api/audit/verify` | `{valid, events, head, broken_at?, reason?}` |
| GET | `/api/audit/export?fmt=json\|csv` | downloadable export |

## Emergency stop

| Method | Path | Notes |
|---|---|---|
| GET | `/api/emergency-stop` | `{active, generation, activated_at, ...}` |
| POST | `/api/emergency-stop` | `{reason}` — stage 1 is sufficient to halt |
| POST | `/api/emergency-stop/clear` | **stage 2 only** — clears the stop |

## Status codes

| Code | Meaning |
|---|---|
| 200 | success |
| 400 | invalid input |
| 401 | missing/invalid session or credentials |
| 403 | stage 2 required, out of scope, authorization invalid/expired/revoked |
| 404 | unknown assessment/template/job/artifact |
| 409 | assessment already running, duplicate operator |
| 423 | emergency stop active, or account locked |
| 429 | rate limited |
