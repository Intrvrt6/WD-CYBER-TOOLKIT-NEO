"""katana adapter - real crawling via the katana CLI.

We drive the binary rather than importing the Go package: that is how the
upstream documents usage, and it keeps this repo free of a Go build step.
Ubuntu/CI note: katana's `-jsl` (JS link parsing) needs a headless browser and
is memory hungry, so we never enable it implicitly.
"""
from __future__ import annotations

import json
import os
import shutil
from typing import Any

from backend import runner


def binary() -> str | None:
    return os.environ.get("WD_KATANA_BIN") or shutil.which("katana")


def version() -> str | None:
    b = binary()
    if not b:
        return None
    res = runner.run([b, "-version"], timeout=15)
    for line in (res.stdout or "").splitlines():
        line = line.strip()
        if line and "_" not in line and "\\" not in line:
            return line[:160]
    return "unknown"


def crawl(url: str, depth: int = 2, duration_s: int = 45, concurrency: int = 5,
          js_crawl: bool = False, headless: bool = False,
          extra_args: list[str] | None = None) -> dict[str, Any]:
    """Crawl one authorized URL. Returns parsed endpoints + the raw evidence."""
    b = binary()
    if not b:
        return {"available": False, "reason": "katana not installed (set WD_KATANA_BIN)",
                "url": url, "endpoints": []}
    argv = [b, "-u", url, "-d", str(max(1, min(depth, 5))),
            "-ct", f"{max(5, min(duration_s, 300))}s",
            "-c", str(max(1, min(concurrency, 10))),
            "-silent", "-nc", "-jsonl"]
    if js_crawl:
        if headless:
            argv += ["-jsl", "-headless"]
        else:
            argv += ["-jsl"]
    if extra_args:
        argv += [a for a in extra_args if isinstance(a, str)]
    res = runner.run(argv, timeout=max(20, min(duration_s, 300)) + 45)

    endpoints: list[dict[str, Any]] = []
    for line in (res.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            if line.startswith("http"):
                endpoints.append({"url": line, "source": None, "method": "GET"})
            continue
        req = ev.get("request") or {}
        endpoints.append({
            "url": ev.get("request", {}).get("endpoint") or ev.get("url") or req.get("endpoint"),
            "method": req.get("method") or "GET",
            "source": ev.get("source"),
            "tag": ev.get("tag"),
            "status": (ev.get("response") or {}).get("status_code"),
        })
    seen, unique = set(), []
    for e in endpoints:
        key = (e.get("url"), e.get("method"))
        if e.get("url") and key not in seen:
            seen.add(key)
            unique.append(e)
    return {
        "available": True, "binary": b, "version": version(), "url": url,
        "endpoints": unique, "count": len(unique),
        "returncode": res.returncode, "timed_out": res.timed_out,
        "stderr_tail": (res.stderr or "")[-800:],
        "evidence": res.as_evidence(),
    }
