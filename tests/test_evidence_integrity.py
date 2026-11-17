"""Evidence-artifact integrity contract.

Locks in three real bugs that made the audit trail lie:

 1. Context.save_text() wrote a file but never registered it, and engines
    discarded its return value -> files on disk, ZERO Artifact rows, so no
    SHA-256 was ever logged.
 2. An engine attached the nmap XML to Result.data instead of Result.evidence,
    so it never reached the evidence trail.
 3. A directory artifact (yara_rules) raised IsADirectoryError, failing the
    whole IOC assessment.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from engines.base import Context, Result, artifact, sha256_file


@pytest.fixture()
def ctx(tmp_path: Path) -> Context:
    return Context(assessment_id="ev-1", module="network", mode="live",
                   intensity="light", targets=["127.0.0.1"], params={},
                   evidence_dir=str(tmp_path / "evidence"))


# ------------------------------------------------------- registration ------
def test_save_text_registers_the_artifact(ctx):
    """The caller may ignore the return value; the artifact must still exist."""
    ctx.save_text("probe.txt", "hello evidence")
    assert len(ctx.artifacts) == 1
    meta = ctx.artifacts[0]
    assert meta["name"] == "probe.txt"
    assert Path(meta["path"]).is_file()
    assert len(meta["sha256"]) == 64


def test_save_text_sha256_matches_the_written_bytes(ctx):
    ctx.save_text("hash.txt", "abc")
    real = hashlib.sha256(b"abc").hexdigest()
    assert ctx.artifacts[0]["sha256"] == real
    assert ctx.artifacts[0]["size"] == 3


def test_save_text_is_idempotent_for_the_same_path(ctx):
    ctx.save_text("same.txt", "v1")
    ctx.save_text("same.txt", "v2")
    assert len(ctx.artifacts) == 1, "re-writing one path must not duplicate the record"


def test_save_bytes_registers_binary_evidence(ctx):
    ctx.save_bytes("blob.bin", b"\x00\x01\x02", kind="pcap")
    meta = ctx.artifacts[0]
    assert meta["kind"] == "pcap"
    assert meta["size"] == 3
    assert meta["sha256"] == hashlib.sha256(b"\x00\x01\x02").hexdigest()


def test_register_records_an_existing_file(ctx, tmp_path: Path):
    p = tmp_path / "existing.txt"
    p.write_text("already here")
    ctx.register(str(p), "existing.txt", "text/plain")
    assert len(ctx.artifacts) == 1
    assert ctx.artifacts[0]["sha256"] == sha256_file(str(p))


# ---------------------------------------------------------- directories ----
def test_sha256_file_supports_a_directory(tmp_path: Path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "a.yar").write_text("rule a {}")
    (d / "b.yar").write_text("rule b {}")
    digest = sha256_file(str(d))
    assert len(digest) == 64
    # deterministic
    assert digest == sha256_file(str(d))


def test_directory_digest_changes_when_contents_change(tmp_path: Path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "a.yar").write_text("rule a {}")
    first = sha256_file(str(d))
    (d / "b.yar").write_text("rule b {}")
    assert sha256_file(str(d)) != first


def test_artifact_of_a_directory_does_not_raise(tmp_path: Path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "a.yar").write_text("rule a {}")
    meta = artifact(str(d), "rules", "directory")
    assert meta["size"] == len("rule a {}")
    assert len(meta["sha256"]) == 64


def test_artifact_of_a_missing_path_is_empty_not_an_error(tmp_path: Path):
    meta = artifact(str(tmp_path / "absent"), "absent", "file")
    assert meta["size"] == 0 and meta["sha256"] == ""


# ------------------------------------------------------- orchestrator ------
def test_collect_artifacts_includes_context_registry(ctx):
    from backend.orchestrator import _collect_artifacts

    ctx.save_text("one.txt", "a")
    ctx.save_text("two.txt", "bb")
    rows = _collect_artifacts([], ctx.evidence_dir, "ev-1", ctx)
    names = {r["name"] for r in rows}
    assert names == {"one.txt", "two.txt"}
    for r in rows:
        assert len(r["sha256"]) == 64
        assert r["size"] == os.path.getsize(r["path"])


def test_collect_artifacts_includes_result_evidence_paths(ctx, tmp_path: Path):
    from backend.orchestrator import _collect_artifacts

    p = tmp_path / "from-result.txt"
    p.write_text("x")
    res = Result("T-01", "t", "info", evidence=[{"path": str(p), "name": "from-result.txt"}])
    rows = _collect_artifacts([res], ctx.evidence_dir, "ev-1", ctx)
    assert [r["name"] for r in rows] == ["from-result.txt"]
    assert len(rows[0]["sha256"]) == 64


def test_collect_artifacts_recomputes_a_missing_hash(ctx):
    """A row must never carry an uncalculated integrity value."""
    from backend.orchestrator import _collect_artifacts

    ctx.save_text("nohash.txt", "data")
    ctx.artifacts[0]["sha256"] = ""  # simulate a caller that forgot
    rows = _collect_artifacts([], ctx.evidence_dir, "ev-1", ctx)
    assert rows[0]["sha256"] == hashlib.sha256(b"data").hexdigest()


def test_collect_artifacts_uses_filesystem_size_over_a_stale_claim(ctx):
    """An engine reporting size=0 must not disagree with the bytes on disk."""
    from backend.orchestrator import _collect_artifacts

    ctx.save_text("sized.txt", "1234567890")
    ctx.artifacts[0]["size"] = 0
    rows = _collect_artifacts([], ctx.evidence_dir, "ev-1", ctx)
    assert rows[0]["size"] == 10


def test_collect_artifacts_deduplicates_by_path(ctx):
    from backend.orchestrator import _collect_artifacts

    meta = ctx.save_text("dup.txt", "z")
    res = Result("T-02", "t", "info", evidence=[meta])
    rows = _collect_artifacts([res], ctx.evidence_dir, "ev-1", ctx)
    assert len(rows) == 1


# --------------------------------------------------- engine-level proof ----
def test_ioc_engine_records_a_directory_artifact():
    """Regression: this used to raise IsADirectoryError and fail the assessment."""
    from engines.base import get_engine

    ctx = Context(assessment_id="ioc-dir", module="threat_intelligence", mode="live",
                  intensity="light", targets=["example.com"],
                  params={"iocs": ["example.com"]},
                  evidence_dir="/tmp/wd_ev_ioc_dir")
    results = get_engine("threat_intelligence").run(ctx)
    assert results, "engine returned nothing"
    # whatever it registered must be digestible, directories included
    for meta in ctx.artifacts:
        assert len(meta["sha256"]) == 64, meta.get("name")
        assert meta["size"] > 0, f"{meta.get('name')} reported size 0"
