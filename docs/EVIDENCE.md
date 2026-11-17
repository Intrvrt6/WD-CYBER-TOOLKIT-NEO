# Evidence Integrity

How WD CYBER TOOLKIT NEO proves that a finding's evidence is what was actually
observed, and that it has not changed since.

## 1. The guarantee

Every assessment produces two independent records:

| Record | Where | Purpose |
|---|---|---|
| **Artifact bytes** | `evidence/<assessment_id>/…` | the raw material (nmap XML, pcap, protocol transcripts, YARA output, generated JSONL) |
| **Artifact rows** | `artifacts` table | name, path, kind, exact size, **SHA-256** |

The SHA-256 is computed from the bytes on disk at the moment the artifact is
recorded, so an auditor can re-hash the file later and detect any change.

```bash
python3 scripts/verify_evidence.py     # re-hashes every recorded artifact
```

```
verdict
  [ ok ] every recorded artifact exists on disk  (30/30)
  [ ok ] every artifact has a 64-hex sha256      (30/30)
  [ ok ] recorded sha256 equals recomputed hash  (30/30)
  [ ok ] recorded size equals real size          (30/30)
```

## 2. Two write paths, both registered

An artifact enters the trail through either route, and the orchestrator merges
them so neither can be forgotten:

```python
# (a) the Context registers what it writes  — preferred
ctx.save_text("nmap_stdout.txt", res.stdout)      # registered automatically
ctx.save_bytes("capture.pcap", blob, kind="pcap") # binary, registered
ctx.register("/path/already/written.json")         # adopt an existing file

# (b) a Result can carry artifacts directly
ctx.add(Result("NET-02", ..., evidence=[artifact(xml_path, "nmap_scan.xml", "xml")]))
```

Registration lives in `Context.save_text()`, not in each engine, because relying
on callers was the original bug: engines called `save_text()` for its side effect
and dropped the return value, so files landed on disk while **zero** artifact rows
were written and no hash was ever logged.

## 3. Directories are first-class

A rule directory (`yara_rules/`) is valid evidence. Its digest is computed over a
**sorted manifest** of `(relative path, file digest)` pairs, which is
reproducible and changes if any contained file changes:

```
sha256( for each file sorted by path: relpath \0 sha256(bytes) \n )
```

Its recorded size is the sum of the contained file sizes. Treating a directory as
a plain file used to raise `IsADirectoryError`, which failed the entire IOC
assessment.

## 4. The filesystem is the ground truth for size

If an engine reports a wrong size (historically `size: 0` for a directory), the
orchestrator overwrites it with `os.path.getsize()` / the summed directory size.
A recorded artifact can never disagree with the bytes actually stored.

A missing hash is likewise **recomputed** rather than stored empty, so no row can
claim an integrity value nobody calculated.

## 5. Verifying an engagement

```bash
# 1. re-hash everything the database claims
python3 scripts/verify_evidence.py

# 2. run one assessment end-to-end and verify its artifacts over HTTP
python3 scripts/evidence_proof.py

# 3. check the audit chain itself
curl -s http://127.0.0.1:8000/api/audit/verify -H "authorization: Bearer $TOKEN"
```

`verify_evidence.py` covers every assessment in the database. It reports
`MISSING` for a file that has vanished, `MISMATCH` for altered bytes, and a size
disagreement separately — each is a distinct failure mode.

## 6. What is covered

Verified across **7 templates / 30 artifacts**: network (2), SCADA/ICS (3), IOC (9,
including a rule directory), hardware (1), physical (3), social (5), webapp (7) —
every hash and size matched the bytes on disk.

`tests/test_evidence_integrity.py` holds 15 regression tests covering
registration, directory digests, manifest determinism, size reconciliation, hash
recomputation, deduplication by path, and the `IsADirectoryError` regression.

## 7. Honest limitations

- This is **integrity, not authenticity**: a tamper-evident hash chain detects
  modification, but anyone with write access to both the database *and* the
  evidence tree could rewrite both consistently. Keep the audit JSON export on
  separate storage for a stronger guarantee.
- Hashes are recorded at write time. An artifact modified *after* the assessment
  completes is detected by `verify_evidence.py` on the next run, not automatically.
- Evidence is stored on the local filesystem; there is no remote object-store
  replication in this release.
