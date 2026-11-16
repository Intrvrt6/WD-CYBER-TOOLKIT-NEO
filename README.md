# WD CYBER TOOLKIT NEO

**Professional Advanced Edition** — a working, modular cybersecurity engineering platform for
network, MITM, OT/ICS, automotive CAN, threat-intelligence, mobile, social-engineering,
physical and hardware assessments. Python/FastAPI backend, dependency-free dark web UI,
SQLite by default (PostgreSQL-ready), real tool execution, tamper-evident audit trail,
**Artax AI** analysis, and professional PDF/HTML/Markdown reporting in English and Bahasa Indonesia.
It integrates with ARTEX, ScopeSentry, ksubdomain, katana and the oscuridad nuclei templates.

> Every result is labelled with **how** it was obtained — `live` (real interface/target),
> `lab` (bundled simulator), `local` (this-host facts) or `unavailable` (could not run, reason
> recorded). Nothing is fabricated and no missing dependency is silently treated as a pass.

---

## 1. What is implemented

### Modules (engines)

| Module | Engine | Checks | Real work performed |
|---|---|---|---|
| **A — Network** | `engines/network` | NET-01…08 | nmap host discovery + service scan, DNS record harvest (dig), TLS handshake/chain/cipher assessment, live packet capture (tcpdump) + protocol hierarchy (tshark), ARP/neighbour integrity, segmentation review, IDS log correlation |
| **B — MITM** | `engines/mitm` | MITM-01…07 | Certificate trust validation, TLS protocol/downgrade matrix, ARP cache-vs-reply integrity (arping), DNS answer consistency across resolvers, gateway/route sanity, opt-in ARP frame injection (scapy), mitmproxy readiness |
| **C — SCADA/ICS** | `engines/scada_ics` | ICS-01…10 | Ten-stage industrial template: discovery, protocol identification (Modbus/OPC UA/DNP3/EtherNet-IP), service inventory, authentication assessment, segmentation, configuration, vulnerability correlation, risk classification, evidence, safe-stop proof. Bundled pymodbus + asyncua simulators |
| **D — Automotive/CAN** | `engines/automotive_can` | CAN-01…09 | CAN ID inventory, message classification, timing/jitter analysis, anomaly detection, replay risk + performed replay, UDS diagnostics over ISO-TP, diagnostic security assessment, chart data. Bundled multi-ECU simulator |
| **E — IOC/Botnet** | `engines/threat_intelligence` | IOC-01…09 | IOC ingestion/classification, correlation (DNS/hash/internal CIDR), enrichment, C2 heuristics, static malware analysis, live process triage (psutil), pcap anomaly analysis, real YARA runs, Sigma-subset hunting |
| **F — Mobile/Zero-click** | `engines/mobile_security` | MOB-01…08 | APK/IPA static analysis (binary AXML parser, manifest facts), platform patch level, permission audit, attack-surface inventory, dependency checks, exposure classes, secure-config audit, prioritisation |
| **G — Social Eng.** | `engines/social_engineering` | SOC-01…06 | Live SPF/DMARC/DKIM selector verification, email security scoring, authorized phishing + landing templates, awareness metrics schema, typosquat resolution |
| **H — Physical** | `engines/physical_security` | PHY-01…06 | Checklist engine scoring real observations; unobserved items explicitly reported as *not observed*; incident documentation artifacts |
| **I — Hardware** | `engines/hardware_security` | HW-01…07 | USB/PCI/peripheral inventory from `/sys`, firmware facts, device inventory, hardware anomaly heuristics, authorized-device diff, tamper checklist |
| **J — Web App** | `engines/webapp` | WEB-01…08 | HTTP fingerprint & security headers, TLS posture, path discovery, cookie flags, CORS policy, information disclosure, reflection surface, bounded Nuclei baseline |

### Engine delivery status

All ten engines are implemented, registered and execution-verified on this host. `GET /api/modules`
returns `registered` (10) and `failed` (`{}`), and every finding is stamped with the source that
produced it (`live`, `lab`, `local`, `unavailable`).

| Module | Checks | Verified by |
|---|---|---|
| A Network | NET-01…08 | nmap, TLS handshake, tcpdump capture, tshark decode |
| B MITM | MITM-01…07 | cert chain, TLS matrix, arping, mitmproxy detection |
| C SCADA/ICS | ICS-01…10 | real Modbus 0x03 response bytes, asyncua endpoints, read-only proof |
| D Automotive/CAN | CAN-01…09 | 703 captured frames, 5 anomaly classes, 5 UDS exchanges over hand-built ISO-TP |
| E IOC/Botnet | IOC-01…09 | YARA CLI + python matches, Sigma over 300+ live events, ipinfo |
| F Mobile | MOB-01…08 | binary AXML parse of a real APK |
| G Social Eng. | SOC-01…06 | live SPF/DMARC/DKIM lookups |
| H Physical | PHY-01…06 | checklist scored from supplied observations |
| I Hardware | HW-01…07 | /sys inventory, firmware hash comparison |
| J Web App | WEB-01…08 | ffuf paths, nuclei findings, reflection probe |

Adding another module is a single file — `engines/<module>/engine.py` exposing the declared class —
plus a template; no other change is required.

### Platform core

- **Two-stage WD access control** — Stage 1: WD shortcut code + operator password.
  Stage 2: separate PIN (rotating the PIN itself needs an already-stage-2 session, so the
  second factor is not self-serviceable; 5 wrong PINs revoke the session; every active
  integration call is scope- and stop-gated too).
  A generated bootstrap password must be rotated before authorizing or executing (428 until then).
  Only stage-2 sessions may authorize or execute tests.
- **Argon2id** for passwords, PINs and shortcut codes; session tokens stored as SHA-256 fingerprints.
- **Scope registry** with automatic target classification (IP / CIDR / domain / URL / CAN / ICS endpoint),
  wildcard subdomain coverage, and per-assessment authorization tokens with TTL and target binding.
- **Preflight → confirm → execute** pipeline with background jobs, progress and live logs.
- **Global emergency stop** — aborts jobs, kills managed process groups, revokes assessments,
  authorizations *and* all sessions; execution stays blocked until a fresh stage-1+2 unlock.
- **Tamper-evident audit log** — append-only SHA-256 hash chain (`prev_hash` + canonical event),
  verified via `/api/audit/verify`, exportable as JSON/CSV.
- **Risk scoring** across findings and **12-section professional reports** (EN/ID × PDF/HTML/MD).
- **Capability detection** — every module reports which CLI tools and Python packages actually exist.

---

## 2. Quick start

```bash
cd WD-CYBER-TOOLKIT-NEO
./scripts/install.sh        # venv + pip deps + capability report
./android/                  native client: build_apk.sh, prepare_sdk.sh, src/, harness/
./scripts/run.sh            # http://0.0.0.0:8000  (API docs at /api/docs)
```

On first boot the platform generates a strong operator password, stage-2 PIN and WD shortcut,
prints them once to the console and writes them to `database/bootstrap_credentials.txt` (mode `0600`).

To provision explicitly instead, set environment variables **before** first boot:

```bash
export WD_ADMIN_USER=WD-OPERATOR-01
export WD_ADMIN_PASSWORD='Your-Strong-Password-1'
export WD_ADMIN_PIN=424242
export WD_SHORTCUT=WD-XXXXXXXXXXXXX
./scripts/run.sh
```

Run the test suite (233 collected tests: hashing, auth, lockout, per-identity rate limiting, stage-2 PIN
ceiling, scope, authorization ownership, static-file containment, audit chain + concurrency,
emergency stop, engine contract, full API flow):

```bash
./scripts/test.sh
```

### Android / Termux

The platform runs **on the phone itself** — full backend, all engines, web UI:

```bash
pkg install -y git
cd ~ && git clone https://github.com/Intrvrt6/WD-CYBER-TOOLKIT-NEO.git
cd WD-CYBER-TOOLKIT-NEO
bash scripts/termux.sh          # installs packages + deps, inits DB, starts server
```

It prints the addresses that actually work:

```
 this device : http://127.0.0.1:8000   <-- open in the phone's browser
 LAN        : http://192.168.1.42:8000  <-- other devices on the same Wi-Fi
```

`scripts/termux.sh` handles what the generic installer cannot: `pkg` instead of
`apt`, `clang` for native extensions, no venv, a **core-only** requirement set
(`requirements-core.txt`), and a `termux-wake-lock` so the server survives
screen-off.

Android has no `iproute2`, so interface detection falls back
`ip -br addr → ip addr show → ifconfig -a → psutil → ioctl(SIOCGIFADDR)` and reports
which path it used — the UI no longer shows zero interfaces on a phone.

Live packet capture needs root (`pkg install tsu`, then run under `sudo tsu`);
`lab` mode and all socket-based modules work unprivileged.

**The APK connects to that console** with no configuration: it defaults to
`http://127.0.0.1:8000` and its **DETECT** button discovers the right address via
`GET /api/network`. Full guide: [`docs/TERMUX.md`](docs/TERMUX.md).

```bash
bash scripts/termux.sh --check    # diagnose the environment
python3 scripts/termux_proof.py   # 30 end-to-end checks under a simulated Termux
```

### Native Android client (`android/`)

A dependency-free native Android app for the same API: two-stage unlock, dashboard, assess,
scope, findings, six-format reports, Artax and audit-chain verification. No Gradle, no Jetpack,
no network access at build time — the SDK build tools are invoked directly.

```bash
./android/prepare_sdk.sh      # once: fetches build-tools, android.jar and R8
./android/build_apk.sh        # -> android/dist/wd-neo.apk (signed, zipaligned)
./android/run_harness.sh http://127.0.0.1:8000   # 30 core-client checks over real HTTP
```

The harness compiles the *same* `Json`/`HttpClient`/`WdApi` sources that are packaged into the
APK and drives the real API, so the client contract is tested without an emulator.

### Windows

Run under **WSL2** (recommended, full tool support) with the same Linux steps above.

---

## 3. Artax AI (built-in analyst)

Artax answers questions about an assessment using **only evidence the platform recorded**, and it
tells you which mode produced the answer:

| mode | when | what answers |
|---|---|---|
| `endpoint` | `WD_ARTAX_BASE_URL` set | a real model over any OpenAI-compatible `/chat/completions` endpoint |
| `local` | no endpoint configured | a deterministic evidence-only analyst (ordering, coverage gaps, remediation) |
| `disabled` | `WD_ARTAX_ENABLED=0` | nothing; the API says so |

Every response carries `parser` (`endpoint` or `local-rules`), so a deterministic answer is never
mislabelled as model output. Artax is advisory: it cannot execute, change scope, or authorize.

```bash
# which mode is live
curl -s $API/api/artax/status -H "authorization: Bearer $TOKEN"

# ask about one assessment (answers in the language you use)
curl -s -X POST $API/api/artax/ask -H "authorization: Bearer $TOKEN"   -H 'content-type: application/json'   -d '{"question":"Apa prioritas perbaikan dan apa yang belum teruji?","assessment_id":"<id>"}' | jq -r .answer

# presets: executive_summary | remediation_plan | coverage_review | attack_paths | report_review
curl -s -X POST "$API/api/artax/preset/remediation_plan?assessment_id=<id>"   -H "authorization: Bearer $TOKEN" | jq -r .answer
```

To use a real model:

```bash
WD_ARTAX_BASE_URL=https://api.openai.com/v1
WD_ARTAX_API_KEY=sk-...
WD_ARTAX_MODEL=gpt-4o-mini      # or any chat-completions model
```

## 4. Upstream integrations

Seven upstream projects are wired in, each pinned to a commit. See
[`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) for the full table, licensing posture and config.

| Upstream | Kind | Verified behaviour |
|---|---|---|
| **ARTEX** (BaaRai) | REST service | status/stats/tasks proxied; reports "not configured" when unset |
| **ScopeSentry** | REST service | health + asset page |
| **ScopeSentry-Scan** | node binary | detected by path; presence reported honestly |
| **ScopeSentry-doc-src** | docs site | linked/probeable; no runtime API |
| **ksubdomain** | CLI binary | auto-detected on PATH |
| **katana** | CLI binary | **real crawl** — returns parsed endpoints |
| **nuclei-template** (oscuridad) | vendored | **real SQLi detection** — 2 high-severity matches on a lab target |

The **Integrations** tab shows live availability for each; nothing is faked.

Two upstream defects handled: the three oscuridad templates all declared `id: oscuridad-sql`
(nuclei then reports `no templates provided for scan`), and fuzzing templates need `-dast`
or they silently send no requests. Both are fixed by the adapter and documented.

## 5. First assessment (API or UI)

UI: open the app → Stage 1 (username, password, shortcut) → Stage 2 (PIN) → **Scope** → add a target →
**New Assessment** → pick template → validate → **Authorize & execute**.

Equivalent API sequence:

```bash
API=http://127.0.0.1:8000

# Stage 1 — WD shortcut + credentials
TOKEN=$(curl -s -X POST $API/api/auth/stage1 -H 'content-type: application/json' \
  -d '{"username":"WD-OPERATOR-01","password":"...","shortcut":"WD-..."}' | jq -r .token)

# Stage 2 — PIN
curl -s -X POST $API/api/auth/stage2 -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"pin":"12345678"}'

# Register scope (auto-classified)
curl -s -X POST $API/api/scope -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"target":"testssl.sh"}'

# Authorize this specific test
AUTHZ=$(curl -s -X POST $API/api/authorizations -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"targets":["testssl.sh"],"ttl_minutes":30,"intended_test":"network pentest"}' | jq -r .id)

# Create + run
ASID=$(curl -s -X POST $API/api/assessments -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"template":"network_pentest","targets":["testssl.sh"],"mode":"live","intensity":"light"}' | jq -r .id)
JOB=$(curl -s -X POST $API/api/assessments/$ASID/run -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d "{\"authz_id\":\"$AUTHZ\",\"confirm\":true}" | jq -r .job_id)

curl -s $API/api/jobs/$JOB -H "authorization: Bearer $TOKEN" | jq '.status,.progress'
curl -s $API/api/assessments/$ASID/findings -H "authorization: Bearer $TOKEN" | jq
curl -s "$API/api/assessments/$ASID/report?fmt=pdf&lang=id" -H "authorization: Bearer $TOKEN" -o report.pdf
```

---

## 6. LIVE vs LAB execution

Some modules need hardware this host may not have. Each assessment declares its mode and every
finding is stamped with the evidence source.

| Mode | Meaning |
|---|---|
| `live` | Talks to a real target/interface supplied in scope. If the capability is missing the check returns `unavailable` **with the reason** — never a fabricated pass. |
| `lab` | Starts a bundled, in-repo simulator/bench and reports against it as `lab`. |

Lab benches included:

- **ICS:** real `pymodbus` Modbus-TCP server and real `asyncua` OPC UA server started by the engine
  (deterministic simulated PLC data, read-only by default).
- **CAN:** real multi-ECU simulator over `python-can` (periodic frames, counters/checksums, a
  replay-friendly static ID, and a UDS/ISO-TP responder). Uses the `virtual` bus because this
  kernel has no `vcan` module.
- **Capture analysis** can also consume your own `pcap_path` instead of capturing.

---

## 7. Safety model

- ICS is **read-only by default**. A PLC write happens only with `params.allow_plc_write=true`
  and is followed by a documented read-back and restore of the original value.
- CAN replay/transmit is opt-in (`params.replay_allowed`); the template documents that
  road-going vehicles must not be used for writes.
- Active MITM interception (ARP injection) requires `params.allow_active=true` and records the exact
  frame plus the rollback action.
- Nuclei is bounded; Katana is never run with JavaScript link parsing in constrained sandboxes.

---

## 8. Project layout

```
WD-CYBER-TOOLKIT-NEO/
├── frontend/                 index.html, assets/{app.css,api.js,ui.js,app.js}
├── backend/
│   ├── main.py               FastAPI app, lifespan, bootstrap, SPA mount
│   ├── config.py             env/.env configuration
│   ├── database.py           SQLAlchemy models + session factory
│   ├── security.py           Argon2id hashing, token fingerprints, policy
│   ├── authentication.py     two-stage auth, lockout, session lifecycle
│   ├── authorization.py      scope registry, target validation, authz tokens
│   ├── emergency_stop.py     global stop / unlock state machine
│   ├── audit.py              hash-chained audit log + exports
│   ├── runner.py             managed subprocess execution (killable)
│   ├── capabilities.py       runtime dependency detection
│   ├── templates_registry.py YAML assessment templates
│   ├── orchestrator.py       preflight → jobs → findings → risk
│   ├── deps.py               FastAPI auth dependencies (stage/RBAC)
│   ├── api/{auth,core_api,reports_api}.py
│   └── reports/generator.py  12-section MD/HTML/PDF reports (EN/ID)
├── engines/                  base.py + one package per module
├── templates/                *.yaml assessment templates (10)
├── database/                 SQLite DB + one-time bootstrap credentials
├── evidence/                 per-assessment evidence artifacts
├── reports/                  generated reports + run logs
├── tests/                    pytest suite (233 tests)
├── scripts/                  install.sh, run.sh, test.sh
├── docs/                     ARCHITECTURE.md, OPERATOR_MANUAL.md, API.md, SECURITY.md
├── requirements.txt
└── README.md
```

---

## 9. Honest limitations

- **Suricata/Zeek** are not bundled; the IDS integration parses an `eve.json` you supply and
  reports `unavailable` when neither binary exists.
- **VirusTotal/MalwareBazaar** enrichment requires an API key (`params.mb_api`); without it the
  enrichment check reports which sources did not answer.
- **AMTI / hardware** checks depend on `/sys` exposure; the platform reports what the kernel
  actually exposes (e.g. `/dev/bus/usb` absent in containers) rather than inventing devices.
- **Physical** assessments are checklist-driven: anything not observed is reported as *not observed*,
  and the risk score stays explicitly incomplete until an operator fills observations.
- Reports state which checks executed and which did not; a missing check is never rendered as a pass.
  A check that emits only derived ids (e.g. `CAN-05a..CAN-05e`) still counts its declared parent
  (`CAN-05`) as executed, and vice versa — the checklist and the findings table always agree.

---

## 10. Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, data model, request flow
- [`docs/OPERATOR_MANUAL.md`](docs/OPERATOR_MANUAL.md) — day-to-day workflow, safety, reporting
- [`docs/API.md`](docs/API.md) — endpoint reference with examples
- [`docs/SECURITY.md`](docs/SECURITY.md) — access model, cryptography, audit integrity
- [`docs/TERMUX.md`](docs/TERMUX.md) — run on Android, connect the APK, troubleshoot
