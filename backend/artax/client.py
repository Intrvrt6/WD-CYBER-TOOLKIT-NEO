"""Artax AI client.

Works against any OpenAI-compatible /chat/completions endpoint. Three operating
modes, and the UI always shows which one is live:

  * ``endpoint``  - a real model endpoint is configured (WD_ARTAX_BASE_URL).
  * ``local``     - no endpoint configured: a deterministic, evidence-only local
                    analyst produces the analysis. It is NOT presented as model
                    output; every reply is labelled parser='local-rules'.
  * unavailable   - disabled by configuration.

This honesty matters: the platform never implies an LLM answered when none did.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

import httpx

from backend import config


class ArtaxError(Exception):
    def __init__(self, message: str, code: str = "ARTAX_ERROR", status: int = 502):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


class ArtaxClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 model: str | None = None, timeout: int | None = None) -> None:
        self.base_url = (base_url if base_url is not None else config.ARTAX_BASE_URL).rstrip("/")
        self.api_key = api_key if api_key is not None else config.ARTAX_API_KEY
        self.model = model or config.ARTAX_MODEL
        self.timeout = timeout or config.ARTAX_TIMEOUT

    # ------------------------------------------------------------------ ---
    @property
    def mode(self) -> str:
        if not config.ARTAX_ENABLED:
            return "disabled"
        return "endpoint" if self.base_url else "local"

    def status(self) -> dict[str, Any]:
        return {
            "enabled": config.ARTAX_ENABLED,
            "mode": self.mode,
            "model": self.model,
            "endpoint_configured": bool(self.base_url),
            "endpoint": self.base_url or None,
            "api_key_present": bool(self.api_key),
            "note": ("model endpoint configured" if self.base_url
                     else "no endpoint configured: deterministic evidence-only analyst"),
        }

    # ------------------------------------------------------------- endpoint --
    def _post_chat(self, messages: list[dict[str, str]], temperature: float = 0.2,
                   max_tokens: int = 1400) -> tuple[str, dict[str, Any]]:
        url = f"{self.base_url}/chat/completions"
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        body = {"model": self.model, "messages": messages, "temperature": temperature,
                "max_tokens": max_tokens, "stream": False}
        try:
            with httpx.Client(timeout=self.timeout) as c:
                r = c.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            raise ArtaxError(f"Artax endpoint unreachable: {exc}", "ENDPOINT_UNREACHABLE") from exc
        if r.status_code == 401:
            raise ArtaxError("Artax endpoint rejected the API key", "UNAUTHORIZED", 401)
        if r.status_code >= 400:
            raise ArtaxError(f"Artax endpoint error {r.status_code}: {r.text[:300]}", "ENDPOINT_ERROR")
        try:
            data = r.json()
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as exc:
            raise ArtaxError("Artax endpoint returned an unexpected payload", "BAD_PAYLOAD") from exc
        usage = data.get("usage") or {}
        return content.strip(), {"model": data.get("model"), "usage": usage}

    # ---------------------------------------------------------------- ask ---
    def ask(self, question: str, context: str = "", history: Iterable[dict] | None = None) -> dict[str, Any]:
        """Ask Artax a question grounded in `context`."""
        q = (question or "").strip()
        if not q:
            raise ArtaxError("Question must not be empty", "EMPTY_QUESTION", 400)
        if self.mode == "disabled":
            raise ArtaxError("Artax AI is disabled (WD_ARTAX_ENABLED=0)", "DISABLED", 503)

        messages: list[dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]
        for turn in (history or []):
            role = turn.get("role")
            content = (turn.get("content") or "")[:8000]
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})
        if context:
            messages.append({"role": "user", "content": f"EVIDENCE CONTEXT\n{context}\n\nEND CONTEXT"})
            messages.append({"role": "assistant",
                             "content": "Context acknowledged. I will reason only from this evidence."})
        messages.append({"role": "user", "content": q})

        if self.mode == "endpoint":
            answer, meta = self._post_chat(messages)
            return {"answer": answer, "parser": "endpoint", "model": meta.get("model") or self.model,
                    "usage": meta.get("usage") or {}}

        return {"answer": local_analysis(q, context), "parser": "local-rules",
                "model": "deterministic-evidence-analyst", "usage": {}}

    # -------------------------------------------------------------- stream --
    def stream(self, question: str, context: str = "") -> Iterable[str]:
        """Yield answer chunks. Endpoint mode uses SSE; local mode yields once."""
        if self.mode != "endpoint":
            yield local_analysis(question, context)
            return
        url = f"{self.base_url}/chat/completions"
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        body = {"model": self.model, "stream": True, "temperature": 0.2,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": f"EVIDENCE CONTEXT\n{context}\n\nEND CONTEXT"},
                             {"role": "user", "content": question}]}
        try:
            with httpx.Client(timeout=self.timeout) as c:
                with c.stream("POST", url, headers=headers, json=body) as r:
                    r.raise_for_status()
                    for line in r.iter_lines():
                        if not line or not line.startswith("data:"):
                            continue
                        payload = line[5:].strip()
                        if payload == "[DONE]":
                            return
                        try:
                            delta = json.loads(payload)["choices"][0]["delta"].get("content")
                        except (KeyError, IndexError, ValueError):
                            continue
                        if delta:
                            yield delta
        except httpx.HTTPError as exc:
            raise ArtaxError(f"Artax stream failed: {exc}", "STREAM_FAILED") from exc


# ---------------------------------------------------------------------------
# Deterministic local analyst
# ---------------------------------------------------------------------------
_SEV_RANK = ["critical", "high", "medium", "low", "info"]


def _parse_context(context: str) -> dict[str, Any]:
    """Extract the structured facts we emitted in build_assessment_context()."""
    out: dict[str, Any] = {"findings": [], "meta": {}, "missing": [], "raw": context}
    section = None
    for line in (context or "").splitlines():
        if line.startswith("==="):
            section = line.strip("= ")
            continue
        # Order matters: the "CHECKS THAT DID NOT REPORT: ..." line also contains a
        # colon, so it must be matched BEFORE the generic key/value branch.
        if line.startswith("CHECKS THAT DID NOT REPORT"):
            out["missing"] = [x.strip() for x in line.split(":", 1)[-1].split(",") if x.strip()]
        elif section == "ASSESSMENT" and ":" in line:
            k, v = line.split(":", 1)
            out["meta"][k.strip()] = v.strip()
        elif section == "FINDINGS (severity ordered)" and line.startswith("["):
            out["findings"].append(line)
    return out


def local_analysis(question: str, context: str) -> str:
    """A real, useful, non-hallucinating analysis from the evidence block.

    This is the fallback when no model endpoint is configured. It performs
    actual ordering/aggregation over the evidence - it does not pretend to be
    an LLM, and the API labels it parser='local-rules'.
    """
    parsed = _parse_context(context)
    meta = parsed["meta"]
    findings = parsed["findings"]
    q = (question or "").lower()

    if not context.strip().startswith("=== PLATFORM") and not findings and not meta:
        return ("No evidence context was supplied, so there is nothing to analyse. "
                "Select an assessment first (Reports / Findings view), or ask about "
                "platform capability. I only reason from evidence this platform produced.")

    lines: list[str] = []

    # ── platform-level question ────────────────────────────────────────────
    if context.strip().startswith("=== PLATFORM"):
        lines.append("**Platform state**")
        for line in context.splitlines():
            if line.startswith(("instance:", "engines registered:", "engines unavailable:",
                                "cli tools missing:", "emergency_stop:")):
                lines.append(f"- {line}")
        if "module" in q or "capab" in q or "bisa" in q:
            modline = next((l for l in context.splitlines() if l.startswith("modules:")), "")
            if modline:
                lines.append("")
                lines.append("**Modules available**")
                for part in modline.replace("modules: ", "").split(";"):
                    if part.strip():
                        lines.append(f"- {part.strip()}")
        missing_line = next((l for l in context.splitlines() if l.startswith("cli tools missing:")), "")
        if missing_line and "missing" not in missing_line.split(":", 1)[1].strip()[:4]:
            lines.append("")
            lines.append("**Coverage note:** some tools are missing, so checks that need them "
                         "will report `unavailable` rather than a pass.")
        return "\n".join(lines)

    # ── assessment-level question ─────────────────────────────────────────
    def sev_of(f: str) -> str:
        parts = [p.strip() for p in f.split("|")]
        return parts[1] if len(parts) > 1 else "info"

    counted: dict[str, int] = {}
    for f in findings:
        counted[sev_of(f)] = counted.get(sev_of(f), 0) + 1
    ordered = sorted(counted.items(), key=lambda kv: _SEV_RANK.index(kv[0]) if kv[0] in _SEV_RANK else 99)
    reported_issues = [f for f in findings if sev_of(f) in ("critical", "high", "medium", "low")]

    mode = meta.get("mode", "?")
    risk = meta.get("risk_score", "?")
    status = meta.get("status", "?")

    lines.append("**Assessment summary**")
    intensity = meta.get("intensity", "?")
    lines.append(f"- template `{meta.get('template','?')}` (module {meta.get('module','?')}) "
                 f"on {meta.get('targets','?')}")
    lines.append(f"- mode **{mode}**, intensity {intensity}, status {status}, "
                 f"risk score {risk}")
    lines.append("- severity mix: " + (", ".join(f"{k}={v}" for k, v in ordered) or "no findings"))
    src = meta.get("by_source", "")
    if src:
        lines.append(f"- evidence sources: {src}")
        if "'lab'" in src or '"lab"' in src:
            lines.append("  - `lab` entries come from a **bundled simulator**, not production hardware.")

    # Priority ordering — the actual analytical value
    if reported_issues:
        lines.append("")
        lines.append("**Prioritised issues (highest severity first)**")
        for f in reported_issues[:8]:
            lines.append(f"- {f}")
        if len(reported_issues) > 8:
            lines.append(f"- ... and {len(reported_issues) - 8} more")
    else:
        lines.append("")
        lines.append("**No failing condition was recorded.**"
                     if findings else "**No findings were recorded for this assessment.**")
        if not findings:
            lines.append("  This usually means the run produced only informational results, "
                         "or the assessment did not complete.")

    # Coverage gap — the thing reports most often hide
    if parsed["missing"]:
        lines.append("")
        lines.append("**Coverage gaps (checks that did not report)**")
        for cid in parsed["missing"]:
            lines.append(f"- `{cid}` — treat as NOT TESTED, not as a pass")
    unavail = meta.get("unavailable_checks")
    if unavail and unavail not in ("0", "None", ""):
        lines.append("")
        lines.append(f"**{unavail} check(s) reported `unavailable`** — the reason is in each finding; "
                     "those capabilities are missing on the assessed host, so absence of a finding "
                     "is not evidence of absence of the issue.")

    # Question-aware next steps
    lines.append("")
    lines.append("**Suggested next actions**")
    # Intent detection: Indonesian "perbaikan"/"perbaiki" share the stem "perbaik",
    # so match stems rather than whole words.
    if any(k in q for k in ("remediat", "fix", "perbaik", "saran", "rekomendasi",
                            "mitigasi", "rekomend", "priorit")):
        rems = [l.strip()[len("remediation:"):].strip() for l in context.splitlines()
                if l.strip().startswith("remediation:")]
        if rems:
            for r in rems[:6]:
                lines.append(f"- {r}")
        else:
            lines.append("- No remediation text was recorded; re-run with a template that supplies it.")
    elif any(k in q for k in ("coverage", "cakupan", "missing", "tidak",
                                  "not run", "did not run", "unavailable", "gap", "celah")):
        lines.append("- Close the coverage gaps above by installing the missing capability and re-running "
                     "the same template in the same scope.")
    else:
        lines.append("- Re-run at higher intensity if the severity mix looks thin.")
        lines.append("- Attach the generated PDF report as the evidence package.")
    lines.append("")
    lines.append("_Deterministic analysis from recorded evidence (no model endpoint "
                 "configured; set WD_ARTAX_BASE_URL to enable model-backed reasoning)._".strip())
    return "\n".join(lines)


from backend.artax.prompts import SYSTEM_PROMPT  # noqa: E402  (avoid circular import at module load)

_client: ArtaxClient | None = None


def get_client() -> ArtaxClient:
    global _client
    if _client is None:
        _client = ArtaxClient()
    return _client


def reset_client() -> None:
    global _client
    _client = None
