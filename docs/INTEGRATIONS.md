# Upstream Integrations

WD CYBER TOOLKIT NEO integrates with five upstream projects. Each is pinned to an exact
commit so behaviour is reproducible, and each adapter reports **`available: true/false` with
a concrete reason** — a missing service is never presented as a passing check.

| id | Upstream | License | Revision | Kind |
|---|---|---|---|---|
| `artex` | [BaaRai/ARTEX](https://github.com/BaaRai/ARTEX) | AGPL-3.0 | `d005bfe5ba11` | REST service (Go + PostgreSQL) |
| `scopesentry` | [Autumn-27/ScopeSentry](https://github.com/Autumn-27/ScopeSentry) | see upstream | `d770b7a137ec` | REST service (FastAPI + Vue) |
| `scopesentry_scan` | [Autumn-27/ScopeSentry-Scan](https://github.com/Autumn-27/ScopeSentry-Scan) | see upstream | `cf9a46e176f0` | Node binary (Go) |
| `scopesentry_docs` | [Autumn-27/ScopeSentry-doc-src](https://github.com/Autumn-27/ScopeSentry-doc-src) | see upstream | `6c9552decaf0` | Documentation site |
| `ksubdomain` | [Autumn-27/ksubdomain](https://github.com/Autumn-27/ksubdomain) | MIT | `9790e99b17e7` | CLI binary (Go) |
| `katana` | [Autumn-27/katana](https://github.com/Autumn-27/katana) | MIT | `05e5ecf57e57` | CLI binary (Go) |
| `nuclei_templates` | [Autumn-27/nuclei-template](https://github.com/Autumn-27/nuclei-template) | MIT | `d05da2145064` | Vendored templates (in-repo) |

> Pinning to a commit is a deliberate reproducibility choice: it is not a claim that the
> pinned revision is the current upstream HEAD.

## Licensing posture

- **AGPL-3.0 (ARTEX):** treated as a *separate process*. WD NEO talks to it over HTTP and does
  not vendor or link its code, which keeps this repository's own licensing simple. If you
  redistribute a combined work, review AGPL-3.0 obligations.
- **MIT (katana, ksubdomain, nuclei-template):** the nuclei templates are vendored directly
  under `templates/nuclei/oscuridad/`, WITH the upstream `LICENSE` file preserved.
  `katana` and `ksubdomain` are invoked as installed binaries, not vendored.
- **ScopeSentry family:** license terms are defined by its own repository; the docs source is
  only linked/probed, never copied.

## Configuration

All integrations are optional. Set what you have:

```bash
# ARTEX service (leave unset to disable)
WD_ARTAX_URL=http://127.0.0.1:8787
WD_ARTAX_TOKEN=<artex api token>

# ScopeSentry server
WD_SCOPESENTRY_URL=http://127.0.0.1:8082
WD_SCOPESENTRY_TOKEN=<scopesentry token>

# ScopeSentry scan node binary
WD_SCOPESENTRY_SCAN_BIN=/usr/local/bin/ScopeSentry-Scan

# CLI binaries (auto-detected on PATH when unset)
WD_KATANA_BIN=/usr/local/bin/katana
WD_KSUBDOMAIN_BIN=/usr/local/bin/ksubdomain
```

Check what is live at any time:

```bash
curl -s $API/api/integrations/status -H "authorization: Bearer $TOKEN" | jq
```

or open the **Integrations** tab in the UI.

## What each integration actually does

### katana — real crawling (verified)

```bash
curl -s -X POST $API/api/integrations/katana/crawl \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"url":"https://target.example","depth":2,"duration_s":30}' | jq '.count'
```

Returns parsed endpoints (`method`, `url`, `source`, `status`). `-jsonl` is used for
machine-readable output. **`-jsl` is never enabled implicitly** — JS link parsing needs a
headless browser and is memory-hungry; pass `js_crawl: true` (optionally `headless: true`)
to opt in.

### nuclei templates — real SQLi detection (verified)

The oscuridad set is vendored at `templates/nuclei/oscuridad/`. Two upstream defects are
handled by the adapter:

1. **All three files declared `id: oscuridad-sql`.** nuclei refuses a multi-template scan with
   duplicate IDs and then reports the unhelpful `no templates provided for scan`. They are
   re-id'd to `oscuridad-sql00/01/02`.
2. **Fuzzing templates require `-dast`.** Without it nuclei loads them but issues no requests —
   a silent false negative. The adapter always sets `-dast`.

Verified against a lab endpoint that delays on a bare quote: two templates matched with
payloads `'+or+sleep(7)--+#` and `+XOR(if(now()=sysdate(),sleep(1),0))XOR%23`.

### ARTEX — autonomous pentest engine

`GET /api/integrations/artex/overview` proxies its `/api/auth/status`, `/api/stats` and
`/api/tasks`. When `WD_ARTAX_URL` is unset the response says so
(`"reason": "not configured (set WD_ARTAX_URL)"`) instead of returning empty data that could
be mistaken for a real result.

### ScopeSentry — asset management

`GET /api/integrations/scopesentry/overview` returns its health probe plus an asset page.
The scan-node integration detects the binary and reports its version; driving nodes directly
is the ScopeSentry server's job, not this platform's.

## Attribution

Upstream projects are the work of their authors. WD CYBER TOOLKIT NEO's adapters are thin
clients; all detection logic, crawling and template content belong to the upstream projects.
Nothing here claims official affiliation with or endorsement by those authors.
