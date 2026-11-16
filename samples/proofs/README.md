# Engine verification proofs

Verbatim output captured from real executions on the build host. Nothing here is illustrative;
each block is the stdout of an actual run.

## mobile_security — real F-Droid APK, binary AXML parser

```
$ python3 -c "... MobileEngine().run(ctx) with params.apk_path=samples/mobile/fdroid-privileged-2070.apk"
```

See [`01-mobile.txt`](01-mobile.txt) — package `org.fdroid.fdroid.privileged`, versionName 0.2.7,
versionCode 2070, permissions and exported components read from the binary manifest.

## social_engineering — live SPF/DMARC/DKIM

See [`02-social.txt`](02-social.txt) — SPF and DMARC present for `example.com`, DKIM selector probes,
rubric score 75/100 (grade C), rendered phishing/landing templates, and real typosquat resolution.

## physical_security — checklist scoring from real observations

See [`03-physical.txt`](03-physical.txt) — access-control and CCTV controls scored pass/fail from a
supplied observations map; unobserved controls reported as *not observed*, never guessed.

## hardware_security — host inventory and firmware comparison

See [`04-hardware.txt`](04-hardware.txt) — `/sys` enumeration, peripheral sources, firmware baseline
hash comparison, and an explicit note that `/dev/bus/usb` is absent on this container host.

## threat_intelligence — IOC, YARA and Sigma

```
$ python3 workstreams/95b18276-.../run_ti.py
```

Exercised: IOC classification, hash correlation against a real file, YARA CLI **and** yara-python
matching a generated fixture, the Sigma-subset evaluator over a JSONL event file, live process
triage via psutil, and pcap anomaly analysis on a synthesized capture.

## network — live network pentest end-to-end

See [`../../reports/e2e-proof.log`](../../reports/e2e-proof.log) and
[`../../reports/demo-proof.log`](../../reports/demo-proof.log): full two-stage login, scope,
authorization, assessment execution and PDF report, with nmap/tsql/tcpdump output as evidence and a
verified audit hash chain.

## Application test suite

```
$ python3 -m pytest tests/ -q
77 passed
```

Covers Argon2id hashing, two-stage auth, lockout, session revocation/expiry, scope classification and
CIDR/domain/URL matching, authorization gates, audit-chain tamper detection, emergency-stop semantics,
engine contract invariants and the full API surface.
