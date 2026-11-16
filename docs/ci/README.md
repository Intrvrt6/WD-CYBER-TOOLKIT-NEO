# CI workflow (GitHub Actions)

This file is the real test pipeline for WD CYBER TOOLKIT NEO. It lives here rather than in
`.github/workflows/` because the Neo GitHub App installation used to publish this repository
lacks the App permission **Workflows**, which GitHub requires for any write inside
`.github/workflows/`. The repository ships a placeholder `blank.yml` there that was created with
the repository itself.

## Enable it

Copy this file into place and commit (from a client whose token has `workflows` permission, or
after granting the App **Workflows: write**):

```bash
cp docs/ci/github-actions-ci.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "ci: enable the real test pipeline"
git push
```

## What it runs

* Matrix on **Python 3.11 and 3.12**
* Installs the system tooling the engines drive (`nmap`, `tcpdump`, `dig`, `whois`, `yara`,
  `can-utils`, `jq`, `openssl`)
* Byte-compiles `backend/`, `engines/`, `tests/`
* **Registry gate** — asserts exactly 10 engines register, `LOAD_ERRORS` is empty, every engine
  declares checks, and no engine has duplicate check ids
* **Full pytest suite** (101 tests)
* **API smoke** — health and capabilities return 200, `/api/scope` returns 401 without a token,
  the OpenAPI document publishes report and emergency-stop paths

The same gates can be reproduced locally without GitHub:

```bash
python -m compileall -q backend engines tests
python -m pytest tests/ -q
```
