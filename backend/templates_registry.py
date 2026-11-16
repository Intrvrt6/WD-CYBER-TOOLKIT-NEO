"""Assessment template registry loaded from templates/*.yaml."""
from __future__ import annotations

import glob
import os
from functools import lru_cache
from typing import Any

import yaml

from backend import config


@lru_cache(maxsize=1)
def load_all() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(glob.glob(os.path.join(str(config.TEMPLATES_DIR), "*.yaml"))):
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not data.get("id"):
            data["id"] = os.path.basename(path).removesuffix(".yaml")
        data["_path"] = path
        data.setdefault("module", data["id"].replace("_pentest", ""))
        data.setdefault("checklist", [])
        data.setdefault("preflight", [])
        data.setdefault("params", {})
        out[data["id"]] = data
    return out


def get(template_id: str) -> dict[str, Any]:
    all_t = load_all()
    if template_id not in all_t:
        raise KeyError(f"unknown template '{template_id}'; available: {', '.join(sorted(all_t))}")
    return all_t[template_id]


def catalog() -> list[dict[str, Any]]:
    out = []
    for tid, t in sorted(load_all().items()):
        out.append({
            "id": tid, "name": t.get("name"), "module": t.get("module"),
            "description": t.get("description", "").strip(),
            "mode_default": t.get("mode_default", "live"),
            "intensity_options": t.get("intensity_options", ["normal"]),
            "scope_types": (t.get("scope") or {}).get("target_types", []),
            "requires_authorization": (t.get("scope") or {}).get("require_authorization", True),
            "checklist": t.get("checklist", []),
            "preflight": t.get("preflight", []),
            "params": t.get("params", {}),
            "standards": t.get("standards", []),
            "safety": t.get("safety", {}),
        })
    return out
