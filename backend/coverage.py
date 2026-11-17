"""Coverage bookkeeping for declared engine checks.

Every engine declares a checklist (`engine.checks`: id -> title). A check may emit
more than one result, and those extra results carry a derived id so report tables
stay unique (CAN-05 -> CAN-05a..CAN-05e, CAN-06 -> CAN-06b, NET-02b).

Coverage must therefore be measured against the DECLARED ids, treating a derived
id as belonging to its declared parent. Two failure modes matter, and they pull in
opposite directions:

* too strict (exact match only): an executed check is reported as "not executed",
  so the report *understates* coverage and contradicts its own findings table;
* too loose (bare prefix match): `NET-1` would be satisfied by `NET-10`, and a
  module could appear to cover more checks than it declared.

`parent_of` resolves a produced id to the declared id it belongs to using the
strictest rule that still accepts real derived ids: an exact match, or the
declared id followed by one short alphanumeric suffix (`b`, `-b`, `05a`-style
index). Anything longer is treated as a different check.
"""
from __future__ import annotations


# A derived id is `<declared>` + optional `-` + a short suffix that STARTS WITH A
# LETTER (CAN-05a, CAN-06b, NET-02b, NET-05c). Requiring a leading letter is what
# keeps `CAN-10` from being read as a variant of `CAN-1`: a purely numeric tail is
# a different check number, not a sub-finding.
_MAX_SUFFIX = 3


def _suffix_ok(suffix: str) -> bool:
    if not suffix or len(suffix) > _MAX_SUFFIX:
        return False
    if not (suffix.isascii() and suffix.isalnum()):
        return False
    return suffix[0].isalpha()


def belongs(produced_id: str, declared_id: str) -> bool:
    """True when `produced_id` is the declared check or a derived id of it."""
    produced_id = str(produced_id or "")
    if produced_id == declared_id:
        return True
    if not produced_id.startswith(declared_id):
        return False
    rest = produced_id[len(declared_id):]
    if rest.startswith("-"):
        rest = rest[1:]
    return _suffix_ok(rest)


def declared_reported(declared: list[str], produced_ids: list[str]) -> list[str]:
    """Which declared checks produced at least one result (in declared order)."""
    produced = [str(p) for p in produced_ids]
    return [cid for cid in declared if any(belongs(p, cid) for p in produced)]


def declared_missing(declared: list[str], produced_ids: list[str]) -> list[str]:
    reported = set(declared_reported(declared, produced_ids))
    return [cid for cid in declared if cid not in reported]


def strip_suffix(produced_id: str, declared: list[str]) -> str:
    """Map a produced id back to its declared parent, or return it unchanged."""
    for cid in declared:
        if belongs(produced_id, cid):
            return cid
    return str(produced_id)
