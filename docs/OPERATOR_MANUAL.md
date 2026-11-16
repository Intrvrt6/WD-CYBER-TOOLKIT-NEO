# Operator Manual

Day-to-day use of WD CYBER TOOLKIT NEO: from login to a signed-off PDF report.

## 1. Access: the two stages

**Stage 1 — WD shortcut + credentials.** You need three things, all issued once at bootstrap:
operator username, operator password, and a WD shortcut code (`WD-` + 13 alphanumerics).
The shortcut is an additional operator control, not a replacement for a password — a stolen
password alone is not enough to start a session.

**Stage 2 — PIN.** A separate PIN raises the session to "authorized operator". Until stage 2 is
complete the platform accepts read-only browsing but refuses to create authorizations, create
assessments or execute anything. This is enforced server-side (`STAGE2_REQUIRED`), not in the UI.

Good practice:

- Store the bootstrap file's contents in your password manager, then delete
  `database/bootstrap_credentials.txt`.
- Rotate the password and PIN from the API after first login:
  `POST /api/auth/password` and `POST /api/auth/pin`.
- Issue/rotate stage-1 shortcuts as an admin with `POST /api/auth/shortcuts` (the code is returned
  once; only its Argon2id hash is kept).
- Five failed logins lock the account for 15 minutes (configurable via `WD_MAX_LOGIN_FAILURES`,
  `WD_LOCKOUT_MINUTES`). Repeated attempts are rate limited.

## 2. Registering scope

Every target must be in the scope registry before it can be tested. The **Scope** view (or
`POST /api/scope`) accepts:

| You enter | Classified as | Covers |
|---|---|---|
| `10.0.0.5` | `ip` | that address |
| `10.0.0.0/24` | `cidr` | every address in the range |
| `example.com` | `domain` | the apex **and all subdomains** (`app.example.com`, `https://api.example.com/v1`) |
| `https://app.example.com/api` | `url` | URLs with that prefix |
| `can:vcan0` | `can` | that CAN interface |
| `modbus://10.0.0.5:502` | `ics_endpoint` | that ICS endpoint |

Scope is a safety control: an out-of-scope target is rejected with `OUT_OF_SCOPE` (HTTP 403)
before any traffic is sent. Use **VALIDATE** in the assessment view to dry-run the check.

## 3. Running an assessment

1. **New Assessment** → choose a template. The panel shows the module, accepted scope types,
   number of checks, applicable standards and safety flags.
2. Enter targets (comma or newline separated).
3. Choose **mode**:
   - `live` — test the real target/interface.
   - `lab` — use the bundled simulator (ICS, CAN) where no hardware is available.
4. Choose **intensity** (`light` / `normal` / `deep`) — this changes scanner breadth, e.g. nmap
   top-100 vs top-1000 vs all ports.
5. Add **extra params** as JSON when a template needs them. Common ones:

   | Param | Used by | Meaning |
   |---|---|---|
   | `interface` | network | capture interface (default: route to 8.8.8.8) |
   | `capture_seconds` | network | capture window |
   | `pcap_path` | network, threat_intelligence | analyse an existing capture instead of capturing |
   | `ids_log` | network | Suricata `eve.json` to correlate |
   | `allow_active` | mitm | permits ARP frame injection |
   | `execute_arp_spoof` | mitm | actually transmits the gratuitous ARP |
   | `allow_plc_write` | scada_ics | permits a single documented register write (default read-only) |
   | `unit_id` | scada_ics | Modbus unit id |
   | `replay_allowed` | automotive_can | permits the lab replay test |
   | `iocs` / `ioc_file` | threat_intelligence | indicators to investigate |
   | `sample_path` | threat_intelligence | file for static malware analysis |
   | `apk_path` / `ipa_path` | mobile_security | app artifact to inspect |
   | `observations` | physical_security | checklist answers (`{control_id: {answer, note}}`) |
   | `authorized_inventory` | hardware_security | allow-list for device diffing |

6. Set the **authorization TTL** and an **intended test** note. The note is stored on the
   authorization and in the audit chain — it is your statement of what was approved.
7. **VALIDATE** runs preflight and prints the scope match table.
8. **AUTHORIZE & EXECUTE** creates the authorization and the assessment, then starts the job.
   The live panel shows progress and the structured log as checks run.

Concurrency note: one assessment runs one job at a time; starting a second run for the same
assessment returns `409 already running`.

## 4. Reading results

Each finding shows:

- **severity** pill (critical/high/medium/low/info) and **evidence source** pill
  (`live`, `lab`, `local`, `unavailable`).
- The check id, the affected asset, CVSS score + vector and CWE where applicable.
- A description stating the observation, and the remediation.
- The **evidence block**: the exact command and its output, so you can reproduce it.

An `unavailable` source means the check could not run and the reason is printed (missing binary,
no interface, no artifact). Treat it as a coverage gap, not a pass.

## 5. Reports

**Reports** view → pick assessment, format (PDF/HTML/Markdown) and language (EN/ID):

- **GENERATE** opens the document in a new tab.
- **SAVE TO DISK** writes it under `reports/`.

The twelve sections are: Executive Summary, Scope, Rules of Engagement, Methodology and Execution
(with a checklist showing which checks ran), Tools and Versions (detected at report time),
Findings, CVSS Scores, Evidence (with SHA-256 per artifact), Business Impact, Remediation,
Retesting Results, Conclusion.

## 6. Emergency stop

Press **EMERGENCY STOP** in the top bar (any authenticated operator — stage 1 is sufficient to halt):

- Running jobs and assessments are aborted.
- Every managed subprocess (nmap, tshark, nuclei, simulators) is killed.
- All authorizations are revoked and **all sessions are invalidated**.
- New execution is refused until you log in again (stage 1 + stage 2) and press clear.

The stop is server state: closing the browser does not clear it.

## 7. Audit and forensics

**Audit** view lists the hash-chained events. **VERIFY CHAIN** recomputes every hash and reports
`valid` plus the head hash; a single modified or deleted row makes it fail at a precise `seq`.
Export with the **JSON** / **CSV** buttons for evidence packages.

Recorded for every operation: operator identity, authentication events, authorizations with scope
snapshot, target identifiers, assessment start/end, executed commands (with return code and
stdout), tool versions, findings, evidence references, errors and emergency-stop events.

## 8. Per-module notes

- **Network** — set `interface` explicitly on hosts with several NICs. `deep` intensity scans all
  65,535 TCP ports; budget time accordingly.
- **MITM** — passive by default. `allow_active` + `execute_arp_spoof` transmits frames; a captive
  rollback note is recorded (re-ARP the true gateway MAC).
- **SCADA/ICS** — read-only unless `allow_plc_write`. In `lab` mode the engine starts its own
  Modbus/OPC UA servers on localhost; nothing external is touched.
- **CAN** — `live` needs a real SocketCAN interface (`can0`); without one the checks report
  `unavailable` with that reason. `lab` uses the in-process virtual bus and a simulated multi-ECU
  vehicle, including UDS diagnostics and an injected-fault anomaly.
- **IOC** — supply `iocs` or `ioc_file`; without enrichment credentials the report states exactly
  which sources answered and which did not.
- **Mobile** — without `apk_path`/`ipa_path` the engine reports what it can prove on this host and
  marks the rest unavailable; it never invents manifest facts.
- **Physical** — fill `observations` to get a real risk score; unobserved controls stay "not observed".
- **Hardware** — containers often lack `/dev/bus/usb`; the engine reports exactly that.

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `STAGE2_REQUIRED` | complete `POST /api/auth/stage2` with the PIN |
| `OUT_OF_SCOPE` | add the target to the scope registry first |
| `AUTHZ_TARGET_MISMATCH` | the authorization covers different targets; authorise these ones |
| `EMERGENCY_STOP` (423) | stop is active: re-login and `POST /api/emergency-stop/clear` |
| `LIVE` checks say `unavailable` | the binary/interface really is missing — see **Capabilities** |
| Report generation fails | check the assessment exists and has findings; see server log |
| Engine module reported unavailable at boot | an optional import failed; the log names the exact error |
