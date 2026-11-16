"""Third-party upstream integrations (ARTEX, ScopeSentry, katana).

Each module exposes a small, honest adapter: it talks to the upstream exactly as
that project documents, reports which mode it is in, and returns `available:
false` + a reason instead of pretending a service answered.
"""
from backend.integrations.registry import INTEGRATIONS, catalog, status

__all__ = ["INTEGRATIONS", "catalog", "status"]
