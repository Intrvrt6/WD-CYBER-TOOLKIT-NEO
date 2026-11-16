"""Engine framework contract + per-engine smoke tests (no fabricated results)."""
import pytest

from engines import base
from engines.base import Context, Result, artifact, cidr_hosts, unavailable


def test_result_records_evidence_source():
    r = Result(check_id="X-01", title="t", status="info", source="lab")
    assert r.to_dict()["source"] == "lab"


def test_unavailable_helper_is_explicit():
    r = unavailable("X-02", "title", "tool missing")
    assert r.status == "unavailable" and r.source == "unavailable"
    assert "tool missing" in r.description


def test_cidr_hosts_is_bounded():
    hosts = cidr_hosts("10.0.0.0/24", limit=10)
    assert len(hosts) == 10
    assert cidr_hosts("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert cidr_hosts("not-a-cidr") == []


def test_context_add_and_save_text(tmp_path):
    ctx = Context(assessment_id="a", module="network", mode="lab", intensity="light",
                  targets=[], params={}, evidence_dir=str(tmp_path))
    ctx.add(Result("X-01", "t", "info"))
    assert len(ctx.findings) == 1
    meta = ctx.save_text("x.txt", "hello")
    assert meta["size"] == 5 and len(meta["sha256"]) == 64
    assert (tmp_path / "x.txt").read_text() == "hello"


def test_artifact_hash_matches_known_value(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"abc")
    meta = artifact(str(p), "f.bin")
    assert meta["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_registry_lists_engines():
    import engines  # noqa: F401
    mods = base.modules()
    assert "network" in mods and "mitm" in mods
    catalog = base.module_catalog()
    assert all("checks" in m and m["checks"] for m in catalog)


def test_get_engine_unknown_raises():
    with pytest.raises(KeyError):
        base.get_engine("does_not_exist")


# ---------------------------------------------------------------- engines ---
def test_network_engine_classify_helpers():
    from engines.network.engine import (base_target, is_ip, is_network, parse_host_port,
                                        parse_nmap_xml)
    assert base_target("https://a.example.com/x") == "a.example.com"
    assert parse_host_port("https://a.example.com") == ("a.example.com", 443)
    assert parse_host_port("a.example.com:8443") == ("a.example.com", 8443)
    assert is_ip("10.0.0.1") and not is_ip("example.com")
    assert is_network("10.0.0.0/24") and not is_network("10.0.0.1")
    assert parse_nmap_xml("/nonexistent.xml") == []


def test_ssh_nmap_xml_parser(tmp_path):
    from engines.network.engine import parse_nmap_xml
    p = tmp_path / "scan.xml"
    p.write_text('<nmaprun><host><address addr="10.0.0.5"/>'
                 '<ports><port portid="22" protocol="tcp"><state state="open"/>'
                 '<service name="ssh" product="OpenSSH" version="8.9"/>'
                 '</port><port portid="80" protocol="tcp"><state state="closed"/></port>'
                 '</ports></host></nmaprun>')
    rows = parse_nmap_xml(str(p))
    assert len(rows) == 1
    assert rows[0]["port"] == 22 and rows[0]["service"] == "ssh"
    assert rows[0]["product"] == "OpenSSH"


def test_all_registered_engines_declare_unique_check_ids():
    import engines  # noqa: F401
    for name in base.modules():
        eng = base.get_engine(name)
        ids = [c[0] for c in eng.checks]
        assert ids, f"{name} declares no checks"
        assert len(ids) == len(set(ids)), f"{name} has duplicate check ids"
        assert eng.title and eng.description, name
        assert hasattr(eng, "run") and callable(eng.run), name


def test_network_engine_produces_labelled_results():
    """Local-only checks: exercise the engine without touching the network."""
    from engines.network.engine import NetworkEngine
    ctx = Context(assessment_id="t", module="network", mode="lab", intensity="light",
                  targets=["127.0.0.1"], params={}, evidence_dir="/tmp/wd_test_ev")
    res = NetworkEngine().run(ctx)
    assert res, "engine returned no results"
    for r in res:
        assert r.source in ("live", "lab", "local", "unavailable"), r.source
        assert r.status in ("pass", "fail", "info", "unavailable", "error")
