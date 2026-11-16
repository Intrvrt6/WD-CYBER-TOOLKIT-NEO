# Audit & Remediation Record — v1.3.0

Professional correctness audit of WD CYBER TOOLKIT NEO. Every finding below was
**reproduced**, fixed, and then locked with an automated test so it cannot
return. Nothing here is speculative: each item names the observable defect, the
mechanism, and the proof.

Method: execute every engine for real, assert the platform-wide result contract,
drive the full HTTP workflow against a live server, and inspect the rendered
report — rather than trusting unit tests alone.

---

## Defects found and fixed

### 1. Engine results carried no evidence trail (2 engines)

| | |
|---|---|
| Checks | `MITM-06`, `SOC-03b` |
| Defect | Results were emitted with `evidence=[]`, so a report showed a conclusion with no supporting artefact |
| Cause | The "skipped" branch of `MITM-06` and the authorization-notice branch of `SOC-03b` set `data=` but never `evidence=` |
| Fix | Both now attach a structured evidence record stating the decision and its reason |
| Test | `test_engine_contract_regressions.py::test_mitm_skipped_check_still_carries_evidence`, `::test_social_campaign_authorization_notice_has_evidence` |

### 2. `physical_security` contradicted itself (status vs source)

| | |
|---|---|
| Checks | `PHY-01..04`, `PHY-06` |
| Defect | Emitted `status="info"` with `source="unavailable"` — read as "observed, informational" while the source simultaneously claimed no evidence existed |
| Cause | A domain with zero observed controls was classified as informational instead of unavailable |
| Fix | Status is now `unavailable` whenever no control was observed, so status and source agree |
| Test | `::test_physical_unobserved_domain_is_status_unavailable_not_info` (plus the platform-wide agreement test) |

### 3. Duplicate check ids (`CAN-05`, `CAN-06`)

| | |
|---|---|
| Defect | `CAN-05` emitted up to five findings under one id; `CAN-06` emitted a summary row *and* a failing finding under one id |
| Impact | Report tables showed identical check ids, and any per-id lookup (severity map, Artax context) silently kept only one of them |
| Fix | Per-anomaly-class suffixes `CAN-05a..CAN-05e`; the failing replay finding is `CAN-06b` |
| Test | `test_engine_audit.py::test_findings_have_unique_ids_per_engine` (strict: **no** id may repeat) |

### 4. The engine verdict was never stored (`findings.status`)

| | |
|---|---|
| Defect | The `Finding` table had no `status` column. `findings_for()` **guessed**: `"fail" if severity != "info" else "info"` |
| Impact | An `unavailable` check was returned to clients as `info`, and the assessment summary reported `by_status={'info': 8}` while two of those checks could not run at all. It also made `pass` indistinguishable from `info` |
| Fix | `status` is a persisted column, written from the engine's `Result.status` and read back verbatim. The inference survives only as a fallback for pre-existing rows |
| Migration | `database._reconcile_columns()` adds missing columns at boot (idempotent, additive only). Verified against a database materialised from the *old* schema |
| Test | `test_report_integrity.py::test_findings_for_returns_stored_status`, `::test_finding_status_is_persisted_not_derived` |

### 5. The report claimed unavailable checks had run

| | |
|---|---|
| Defect | Section 4 (Methodology) rendered every declared check as `[x] executed`. `NET-08` (IDS, Suricata/Zeek absent) appeared to have run successfully |
| Impact | The report **overstated coverage** — the one thing the platform promises never to do |
| Fix | Three explicit states: `[x]` executed, `[!]` not executed **with the engine's stated reason**, `[ ]` not reached; plus a summary line ("7 of 8 declared check(s) executed; 1 could not run") |
| Test | `::test_markdown_marks_unavailable_as_not_executed`, `::test_markdown_reports_coverage_summary`, and the Indonesian variant |

### 6. Silent failure path in the job runner

| | |
|---|---|
| Defect | If recording a *failed* job itself raised (DB locked, schema drift), the exception was swallowed with `except Exception: pass`, leaving the job in `running` with no trace anywhere |
| Fix | The path now logs the exception with the job and assessment ids so the state is diagnosable |
| Test | covered by the boot/API suite (the handler is import- and run-exercised) |

### 7. `schema.sql` was out of sync with the models

| | |
|---|---|
| Defect | The reference DDL lacked `findings.status`, so anyone provisioning from it would hit "no such column" |
| Fix | Column added; verified by materialising the DDL and comparing `PRAGMA table_info` against the declared column set |

### 8. An executed check was reported as "not executed" (found in 1.3.0)

| | |
|---|---|
| Check | `CAN-05` (anomaly detection), `automotive_can` |
| Defect | The check **ran** and produced five failing findings (`CAN-05a`..`CAN-05e` with counter, period, DLC, payload and late-id anomalies), yet report section 4 printed `- [ ] CAN-05 - Not executed` and `8 of 9 declared check(s) executed; 1 could not run` — directly above those same findings. `summary.coverage.missing` carried the identical error, so the API and the report agreed on a falsehood. |
| Cause | `_declared_reported()` decided parentage with `check_id.rstrip("0123456789") == declared_id`. Stripping trailing *digits* can never remove an alphabetic suffix: `"CAN-05a".rstrip("0123456789")` is `"CAN-05a"`, so a check that emitted only derived ids was declared missing. `NET-02b`/`NET-05c` were unaffected only because those engines also emit the base id. |
| Impact | Coverage was **understated**, the mirror image of the overstatement fixed in defect 5. Both break the same platform promise — the checklist and the findings table disagree — and an operator could conclude anomaly detection had not run when it had raised five findings. |
| Fix | One shared rule, `backend/coverage.py`: a produced id belongs to a declared id when it matches exactly, or is followed by an optional `-` and at most three alphanumerics **starting with a letter**. The orchestrator roll-up, the `unavailable_checks` mapping and the report renderer all call it, so they cannot diverge. The leading-letter requirement keeps `CAN-10` from being read as a variant of `CAN-1`. |
| Verified | Before: `coverage={"declared": 9, "reported": 8, "missing": ["CAN-05"], "percent": 88.9}` and `- [ ] CAN-05`. After: `{"declared": 9, "reported": 9, "missing": [], "percent": 100.0}` and `- [x] CAN-05`, with the five findings unchanged. A real `network_pentest` run still renders `NET-03`/`NET-08` as `[!]` with their reasons, so honest degradation is intact. |
| Test | `tests/test_coverage_accounting.py` (11 tests), including the `CAN-1`/`CAN-10` counter-example and an end-to-end report assertion. |

### 9. The APK build could not complete on this toolchain (found in 1.3.0)

| | |
|---|---|
| Defect | `android/build_apk.sh` failed at step 4/7 with `NullPointerException: Cannot invoke "String.length()" because "<parameter1>" is null`, so no APK had ever been produced. |
| Cause | The `d8` shipped in `build-tools;android-14` is an **R8 8.2.2-dev snapshot** that crashes on any anonymous inner class. Reproduced with a two-line stand-in class containing one anonymous `AdapterView.OnItemSelectedListener`, so the fault was the tool, not the app. Independent of `--min-api`, `--no-desugaring`, `-source/-target 8` and every `-g` debug-info setting. |
| Fix | `build_apk.sh` uses a **released R8** (`com.android.tools.r8.D8` from Google's Maven repository) when one is present and falls back to build-tools' `d8` otherwise. `android/prepare_sdk.sh` fetches build-tools, the platform jar and that R8, so the build is reproducible on a clean host. |
| Verified | `BUILD OK` — `dist/wd-neo.apk`, 58 719 bytes, verified with APK Signature Scheme v2 and v3, `zipalign -c` clean, `aapt2 dump badging` reports `sh.testssl.wdneo` 1.0.0 (minSdk 24, targetSdk 34) and a launchable `MainActivity`. The rebuild is byte-size stable, and its SHA-256 is published beside the artefact. |
| Test | `android/run_harness.sh` drives the packaged `Json`/`HttpClient`/`WdApi` classes against the live API: **29/29 checks pass** (two-stage unlock, wrong-shortcut and wrong-PIN rejection, 10 templates, 10 engines, scope accept/reject, authorization, assessment + job, PDF, localised MD, audit chain, logout revocation). |

---

## Regression tests added

| File | Tests | Purpose |
|---|---|---|
| `tests/test_boot.py` | 8 | Import/mount the real app; every `backend.*` module imports; every engine module imports; all routers present in OpenAPI; index and static assets served; no debug routes |
| `tests/test_engine_audit.py` | 9 | Execute **all ten engines** and assert the contract: valid tokens, status/source agreement, unavailable states a reason, evidence present, no silent check gaps, unique ids |
| `tests/test_engine_contract_regressions.py` | 9 | One test per fixed defect |
| `tests/test_report_integrity.py` | 9 | Persisted status, three-state checklist (EN + ID), PDF/HTML render, all twelve sections in both languages |
| `tests/test_coverage_accounting.py` | 11 | Derived-id `→` declared-id coverage: `CAN-05a..e` counts `CAN-05` executed, `CAN-1`/`CAN-10` do not alias, the roll-up and the report both use the one shared rule |

`tests/audit_all_engines.py` remains as the developer CLI for a human-readable
per-engine dump; the pytest module is what CI enforces.

---

## Verification evidence

```
engines registered : 10 / 10          check ids declared : 78 (all unique)
engine import errors: 0
full test suite    : 197 passed
E2E over real HTTP : 10 / 10 templates PASS
report sections    : 12 / 12 in English and Indonesian
```

Each template was driven through the complete authorized workflow against a live
server (stage-1 → stage-2 → scope → authorization → assessment → job → findings
→ PDF → audit chain), not invoked directly:

| Template | Target | Mode |
|---|---|---|
| network_pentest | testssl.sh | live |
| mitm_pentest | https://testssl.sh | live |
| webapp_pentest | http://127.0.0.1:8099 | live |
| scada_pentest | modbus://127.0.0.1:5020 | lab |
| can_pentest | can:wdcan0 | lab |
| ioc_pentest | example.com | live |
| mobile_pentest | 127.0.0.1 | live |
| social_pentest | example.com | live |
| physical_pentest | site-a | live |
| hardware_pentest | 127.0.0.1 | live |

`scripts/e2e_proof.py` reproduces all of this and additionally asserts the
persisted status/source contract on the stored rows returned by the API.

---

## Honest limitations (unchanged, and reported by the platform itself)

- **Suricata / Zeek** are not bundled; `NET-08` reports `unavailable` with that exact reason (now visible as `[!]` in the report).
- **MalwareBazaar** enrichment needs `params.mb_api`; without it the sources that answered are named individually.
- **CAN** lab uses python-can's userspace `virtual` bus because this kernel has no `vcan` module; live mode needs a real SocketCAN interface and says so when absent.
- **USB** enumeration reports exactly what the kernel exposes (`/dev/bus/usb` is absent in containers).
- **Physical** controls that were not observed are reported as *not observed*, and the risk score stays explicitly incomplete.
