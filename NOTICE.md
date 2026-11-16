# Third-party notices and upstream provenance

WD CYBER TOOLKIT NEO integrates the following upstream projects. Each entry pins the
exact commit that was inspected/built during development.

| Project | Upstream | License | Pinned commit | How it is used |
|---|---|---|---|---|
| ARTEX | https://github.com/BaaRai/ARTEX | AGPL-3.0 | `d005bfe5ba117830fb81c6ad4c103dbeeee31ba8` | External autonomous pentest service; consumed over REST (`WD_ARTAX_URL`). **Not vendored** to keep AGPL at arm's length. |
| ScopeSentry | https://github.com/Autumn-27/ScopeSentry | see upstream | `d770b7a137ec2de15816fea4bd561f49cf486db2` | Asset-discovery server; consumed over REST (`WD_SCOPESENTRY_URL`). Not vendored. |
| ScopeSentry-Scan | https://github.com/Autumn-27/ScopeSentry-Scan | see upstream | `cf9a46e176f0bcba6c7000bcad8b0b72b872dc63` | Scan node binary; detected by path (`WD_SCOPESENTRY_SCAN_BIN`). Not vendored. |
| ScopeSentry-doc-src | https://github.com/Autumn-27/ScopeSentry-doc-src | see upstream | `6c9552decaf0c5c279c1ae0cf1da03c957a67428` | Documentation reference linked from the UI. Not vendored. |
| ksubdomain | https://github.com/Autumn-27/ksubdomain | see upstream (module `github.com/boy-hack/ksubdomain`) | `9790e99b17e7af33bd49adcf1bcaf8e7960d144d` | Subdomain brute-force CLI (`WD_KSUBDOMAIN_BIN`). Not vendored. |
| katana | https://github.com/Autumn-27/katana | MIT (ProjectDiscovery) | `05e5ecf57e57f44345d7a4a9945abf20113f43e1` | Crawler CLI (`WD_KATANA_BIN`). Not vendored. |
| nuclei-template | https://github.com/Autumn-27/nuclei-template | **MIT** (c) 2023 Cookie | `d05da21450648a444498f7cd7233f9da0b0bf08e` | SQLi templates **vendored** in `templates/nuclei/oscuridad/` (MIT permits redistribution; LICENSE kept alongside). |

## Operational facts verified during integration

- The oscuridad SQLi templates all share the template id `oscuridad-sql`, so they must be
  run as a **directory** (or via the workflow), never as three `-t` flags.
- They use `fuzzing:` (DAST), which nuclei disables by default — **`-dast` is required**.
  Verified: with `-dast`, nuclei detects a real SQLi (high, `oscuridad-sql00`) against a
  deliberately vulnerable local target.
- ARTEX requires Go 1.26.10 per its `go.mod`; it builds here via `GOTOOLCHAIN=auto`
  (verified: 43 MB binary produced).

## Licensing caution

ARTEX and ScopeSentry are consumed as separate processes, not copied into this tree.
If you later vendor ARTEX source, AGPL-3.0 obligations attach to the combined work.
