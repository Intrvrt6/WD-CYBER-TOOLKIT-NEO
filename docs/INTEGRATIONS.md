# Upstream Integrations

WD CYBER TOOLKIT NEO talks to seven upstream projects. Each is pinned to a commit
(see [`../NOTICE.md`](../NOTICE.md)) and each is **optional**: if it is missing the
platform reports `available:false` with a concrete reason instead of faking a result.

```
GET  /api/integrations              catalog: repo, licence, pinned commit, env vars
GET  /api/integrations/status       live probe of all seven
GET  /api/integrations/artex/overview
GET  /api/integrations/scopesentry/overview
GET  /api/integrations/nuclei/templates
POST /api/integrations/katana/crawl       {url, depth, duration_s, js_crawl}
POST /api/integrations/nuclei/sqli        {url, use_workflow, timeout_s}
POST /api/integrations/ksubdomain/enum    {domain, dict_path, duration_s}
```

## Configuration

| Variable | Used by | Meaning |
|---|---|---|
| `WD_ARTAX_URL` | ARTEX | Base URL of a running ARTEX instance, e.g. `http://127.0.0.1:8787` |
| `WD_ARTAX_TOKEN` | ARTEX | Bearer token, if ARTEX requires one |
| `WD_SCOPESENTRY_URL` | ScopeSentry | Base URL of the ScopeSentry server |
| `WD_SCOPESENTRY_TOKEN` | ScopeSentry | Bearer token for its API |
| `WD_SCOPESENTRY_SCAN_BIN` | ScopeSentry-Scan | Path to the scan-node binary |
| `WD_SCOPESENTRY_DOCS_URL` | ScopeSentry-doc-src | Hosted docs site to link/probe |
| `WD_KSUBDOMAIN_BIN` | ksubdomain | Path to `ksubdomain` |
| `WD_KATANA_BIN` | katana | Path to `katana` |
| `WD_NUCLEI_BIN` | nuclei | Path to `nuclei` |
| `WD_NUCLEI_TEMPLATE_DIR` | nuclei-template | Override the vendored template directory |

Binaries are also discovered on `PATH`, so usually you only set the URL variables.

## ARTEX

A separate Go + PostgreSQL service. WD NEO never vendors it (AGPL-3.0 stays at arm's
length). Bring it up from its own checkout:

```bash
git clone https://github.com/BaaRai/ARTEX && cd ARTEX
cp .env.example .env         # set POSTGRES_PASSWORD
docker compose up -d --build
# then, for WD NEO:
export WD_ARTAX_URL=http://127.0.0.1:8787
```

ARTEX's own onboarding lives at `/setup` (one-time setup token printed in its logs).

## ScopeSentry family

ScopeSentry is the asset-discovery server (FastAPI + Vue); ScopeSentry-Scan is a Go
node agent that executes its tasks; ScopeSentry-doc-src is the documentation site.
WD NEO consumes the server's REST API and reports node/binary presence — it does not
pretend to drive nodes.

```bash
export WD_SCOPESENTRY_URL=http://127.0.0.1:8082
export WD_SCOPESENTRY_TOKEN=...            # if your instance requires auth
export WD_SCOPESENTRY_SCAN_BIN=/opt/scopesentry-scan/ScopeSentry-Scan
```

## katana (crawler)

```bash
katana -version                # verified here: installed on PATH
export WD_KATANA_BIN=/usr/local/bin/katana   # optional
```

`POST /api/integrations/katana/crawl` returns parsed endpoints (method, URL, source,
status) plus the raw command evidence. `-jsl` (JS link parsing) is **opt-in only**:
it needs a headless browser and is memory hungry, so it is never enabled implicitly.

Verified: crawling the local WD NEO UI returned 6 real endpoints.

## nuclei-template (oscuridad SQLi set) — vendored

These four files are MIT-licensed, so they ship inside this repository at
`templates/nuclei/` and run offline. Two gotchas were found and are handled:

1. **Duplicate template id.** All three templates declare `id: oscuridad-sql`. Passing
them as three `-t` flags makes nuclei fail with *"no templates provided for scan"*.
   Pass the **directory** or the **workflow** instead.
2. **They are DAST templates.** They use `fuzzing:`, which nuclei disables by default.
   Without `-dast`, nuclei loads zero templates and sends no requests — which looks
   exactly like a clean (false-negative) result. The adapter always sets `-dast`.

```bash
curl -X POST $API/api/integrations/nuclei/sqli \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"url":"https://target.example/product?id=1"}'
```

Verified detection (not just a clean exit) against the deliberately vulnerable
fixture in `tests/sqli_target.py`:

```
DETECTED: high | oscuridad-sql00 | Blind SQL Injection time based detection of sql backend
          | http://127.0.0.1:8095/?id=1'
```

## ksubdomain

Stateless subdomain brute force. Needs `CAP_NET_RAW`; without it the adapter says so
rather than returning "no subdomains found".

```bash
curl -X POST $API/api/integrations/ksubdomain/enum \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"domain":"example.com","duration_s":60}'
```

A default wordlist lives at `samples/subdomains.txt` (6 entries, deliberately small);
pass `dict_path` to use your own.

## Why the platform stays honest

Every integration response carries either real data or an explicit reason:

```json
{"available": false, "reason": "not configured (set WD_ARTAX_URL)"}
{"available": false, "reason": "not found (set WD_KSUBDOMAIN_BIN or install ksubdomain)"}
{"available": true,  "version": "KSubdomain version 1.9.5"}
```

That way an unconfigured upstream shows up as a coverage gap in reports, never as a
silent pass.
