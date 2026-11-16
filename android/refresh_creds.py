#!/usr/bin/env python3
"""Find a working operator password and write /tmp/creds.json for the harness.

The bootstrap password is rotated on first login, and the JVM harness rotates it to
HARNESS_PASSWORD. Guessing against the login endpoint costs a failed attempt on
every miss, and MAX_LOGIN_FAILURES locks the account, so the candidate order is
chosen to hit on the FIRST try once the harness has run:

  1. the password already stored in the output file (a previous run's success)
  2. HARNESS_PASSWORD   - what the harness rotates to
  3. the bootstrap value - only correct on a brand-new database

Usage: refresh_creds.py <base-url> <bootstrap-file> <out-json>
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

HARNESS_PASSWORD = "Harness-Rotated-Pass-2026"


def stage1_ok(base: str, user: str, password: str, shortcut: str) -> tuple[bool, int]:
    body = json.dumps({"username": user, "password": password,
                       "shortcut": shortcut}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/api/auth/stage1", data=body,
                                 headers={"content-type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15)
        return True, 200
    except urllib.error.HTTPError as exc:
        return False, exc.code
    except Exception:
        return False, 0


def main() -> int:
    base, credfile, out = sys.argv[1:4]

    bootstrap: dict[str, str] = {}
    with open(credfile, encoding="utf-8") as fh:
        for line in fh:
            if ":" in line:
                key, _, value = line.partition(":")
                bootstrap[key.strip()] = value.strip()

    user = bootstrap["Operator username"]
    shortcut = bootstrap["Stage-1 WD shortcut"]
    pin = bootstrap["Stage-2 PIN"]

    candidates: list[str] = []
    if os.path.exists(out):
        try:
            with open(out, encoding="utf-8") as fh:
                previous = json.load(fh).get("pass")
            if previous:
                candidates.append(previous)
        except Exception:
            pass
    for extra in (HARNESS_PASSWORD, bootstrap["Operator password"]):
        if extra not in candidates:
            candidates.append(extra)

    for password in candidates:
        ok, code = stage1_ok(base, user, password, shortcut)
        if ok:
            with open(out, "w", encoding="utf-8") as fh:
                json.dump({"user": user, "pass": password, "pin": pin,
                           "shortcut": shortcut}, fh)
            label = "stored" if password == candidates[0] and os.path.exists(out) else "rotated"
            if password == bootstrap["Operator password"]:
                label = "bootstrap"
            print(f"creds refreshed (password form: {label})")
            return 0
        if code == 423:
            print("account locked: wait for the lockout window or reset the database")
            return 1

    print("could not find a working password")
    return 1


if __name__ == "__main__":
    sys.exit(main())
