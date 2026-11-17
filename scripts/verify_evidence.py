#!/usr/bin/env python3
"""Verify the evidence-artifact contract end to end.

Claim under test: "Evidence artifacts saved to evidence_dir, SHA-256 logged."

That claim has three separately falsifiable parts:
  1. a file really exists under the assessment's evidence_dir
  2. the database records that artifact with a sha256
  3. the recorded sha256 equals the hash computed from the bytes on disk
     (and the recorded size equals the real size)

Any mismatch is reported as a failure. Nothing is assumed.
"""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend import config, database  # noqa: E402

PASS = FAIL = 0


def check(ok: bool, label: str, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [ ok ] {label}" + (f"  ({detail})" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {label}" + (f"  ({detail})" if detail else ""))


def disk_hash(path: Path) -> tuple[str, int]:
    """Reproduce engines.base.sha256_file exactly.

    A directory is hashed over a sorted (relative path, file digest) manifest,
    so a rule directory gets a real, reproducible integrity value rather than
    raising IsADirectoryError.
    """
    if path.is_dir():
        h = hashlib.sha256()
        total = 0
        for root, dirs, files in os.walk(path):
            dirs.sort()
            for name in sorted(files):
                full = Path(root) / name
                rel = str(full.relative_to(path)).replace(os.sep, "/")
                sub_digest, sub_size = disk_hash(full)
                h.update(rel.encode("utf-8"))
                h.update(b"\x00")
                h.update(sub_digest.encode("ascii"))
                h.update(b"\n")
                total += sub_size
        return h.hexdigest(), total
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


database.init_db()
db = database.SessionLocal()

try:
    from sqlalchemy import select
    from backend.database import Artifact

    rows = list(db.execute(select(Artifact).order_by(Artifact.created_at)).scalars())
    print(f"artifacts recorded in database: {len(rows)}")
    check(len(rows) > 0, "database holds at least one artifact row")
    print()

    if not rows:
        print("no artifacts to verify - run an assessment first")
        sys.exit(1)

    print(f"{'assessment':<10} {'file':<34} {'size':>9}  {'sha256 (recorded = recomputed)'}")
    print("-" * 100)

    with_sha = 0
    files_present = 0
    hash_matches = 0
    size_matches = 0

    seen = set()
    for a in rows:
        p = Path(a.path)
        if p.is_absolute():
            full = p
        else:
            # paths are stored relative to the repo root
            full = ROOT / p
        present = full.is_file() or full.is_dir()
        if present:
            files_present += 1
        recorded_sha = (a.sha256 or "").strip()
        if len(recorded_sha) == 64:
            with_sha += 1

        if present:
            real_sha, real_size = disk_hash(full)
            ok_hash = recorded_sha == real_sha
            ok_size = int(a.size or 0) == real_size
            hash_matches += 1 if ok_hash else 0
            size_matches += 1 if ok_size else 0
            mark = "MATCH" if ok_hash else "MISMATCH"
            print(f"{a.assessment_id[:8]:<10} {a.name[:33]:<34} {real_size:>9}  {mark}  {real_sha[:16]}...")
            if not ok_hash:
                print(f"           recorded: {recorded_sha}")
                print(f"           recomputed: {real_sha}")
            if not ok_size:
                print(f"           recorded size {a.size} != real size {real_size}")
        else:
            print(f"{a.assessment_id[:8]:<10} {a.name[:33]:<34} {'MISSING':>9}  file not found: {full}")
        seen.add(a.assessment_id)

    print()
    print("verdict")
    check(files_present == len(rows), "every recorded artifact exists on disk",
          f"{files_present}/{len(rows)}")
    check(with_sha == len(rows), "every artifact has a 64-hex sha256",
          f"{with_sha}/{len(rows)}")
    check(hash_matches == files_present, "recorded sha256 equals recomputed hash",
          f"{hash_matches}/{files_present}")
    check(size_matches == files_present, "recorded size equals real size",
          f"{size_matches}/{files_present}")

    print()
    print(f"assessments covered: {len(seen)}")
    print(f"evidence root: {config.EVIDENCE_DIR}")

finally:
    db.close()

print()
print("=" * 60)
print(f"RESULT: {PASS} passed, {FAIL} failed")
print("=" * 60)
sys.exit(1 if FAIL else 0)
