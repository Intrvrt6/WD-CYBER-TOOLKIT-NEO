"""Engine auto-registration.

Each module package exposes an engine class in <module>/engine.py. Registration
is tolerant: if one engine fails to import (missing optional dependency), the
platform still starts and reports that module as unavailable with the reason.
"""
from __future__ import annotations

import importlib
import traceback

from engines import base

MODULE_CLASSES = {
    "network": ("engines.network.engine", "NetworkEngine"),
    "mitm": ("engines.mitm.engine", "MITMEngine"),
    "scada_ics": ("engines.scada_ics.engine", "SCADAEngine"),
    "automotive_can": ("engines.automotive_can.engine", "CANEngine"),
    "threat_intelligence": ("engines.threat_intelligence.engine", "ThreatIntelEngine"),
    "webapp": ("engines.webapp.engine", "WebAppEngine"),
    "mobile_security": ("engines.mobile_security.engine", "MobileEngine"),
    "social_engineering": ("engines.social_engineering.engine", "SocialEngine"),
    "physical_security": ("engines.physical_security.engine", "PhysicalEngine"),
    "hardware_security": ("engines.hardware_security.engine", "HardwareEngine"),
}

LOAD_ERRORS: dict[str, str] = {}


def _register_all() -> None:
    for module, (path, cls_name) in MODULE_CLASSES.items():
        if module in base._REGISTRY:
            continue
        try:
            mod = importlib.import_module(path)
            cls = getattr(mod, cls_name)
            if not getattr(cls, "module", None):
                cls.module = module
            base.register(cls)
        except Exception as exc:
            LOAD_ERRORS[module] = f"{type(exc).__name__}: {exc}"


_register_all()


def status() -> dict:
    return {
        "registered": base.modules(),
        "failed": LOAD_ERRORS,
        "expected": sorted(MODULE_CLASSES),
    }
