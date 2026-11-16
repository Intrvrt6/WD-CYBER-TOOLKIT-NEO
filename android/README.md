# Android client — WD NEO APK

Native Android client for WD CYBER TOOLKIT NEO. It is a real, signed, installable
APK built directly with the Android SDK build tools (no Gradle, no network at build
time) and it drives the same authenticated REST API as the web UI.

```
android/dist/wd-neo.apk          58,719 bytes   signed (v2 + v3), minSdk 24, targetSdk 34
package                          sh.testssl.wdneo
version                          1.0.0 (versionCode 1)
```

---

## Install

```bash
adb install -r android/dist/wd-neo.apk
```

On the device, open **WD NEO**, then enter the backend base URL (for example
`http://192.168.1.10:8000`), the operator username/password, the stage-1 WD
shortcut and the stage-2 PIN. The app normalises the URL (adds a scheme, trims a
trailing slash) and stores only what it needs to resume the session.

---

## Build from source

Preflight requires a JDK, `keytool`, `zip`, and an Android SDK with build-tools +
a platform `android.jar`. Point the script at them if they are not in the default
locations:

```bash
cd android
export ANDROID_BUILD_TOOLS=/path/to/build-tools/34.0.0
export ANDROID_PLATFORM=/path/to/platforms/android-34
./build_apk.sh --clean      # -> dist/wd-neo.apk
```

Default paths used by this repo's build host:
`/workspace/android-sdk/bt/android-14` and
`/workspace/android-sdk/plat/android-34-ext12`.

The script runs seven stages and fails loudly rather than emitting a broken APK:
compile resources (`aapt2`) → link resources + manifest → `javac` → dex (`d8`) →
package → `zipalign` → sign (`apksigner`) → verify.

---

## Two d8/R8 bugs you will hit (and their fixes)

The bundled `d8` is R8 **8.2.2**, which has two reproducible defects on this
toolchain. Both are worked around in source, with the reason recorded next to the
code.

### 1. It crashes on Java 17 class files

```
java.lang.NullPointerException: Cannot invoke "String.length()" because "<parameter1>" is null
Compilation failed with an internal error.
```

**Fix:** compile to Java 11 bytecode (`javac -source 11 -target 11`).

### 2. It crashes on **non-static** inner classes that implement a generic Android interface

This is the subtle one. A six-line reproducer is enough:

```java
public class C {
    public final class L implements android.widget.AdapterView.OnItemSelectedListener {
        public void onItemSelected(android.widget.AdapterView<?> p, android.view.View v, int pos, long id) { }
        public void onNothingSelected(android.widget.AdapterView<?> p) { }
    }
}
```

`C.class` and the top-level equivalent both dex fine; `C$L.class` (a *non-static*
inner class) makes d8 throw the same internal NPE. **Fix:** declare such
listeners `static` and pass the activity in explicitly — see
`MainActivity.TemplateSelectListener`.

Both bugs were found by isolating classes one at a time, not by guessing.

---

## Verify the artifact

```bash
apksigner verify --verbose --print-certs android/dist/wd-neo.apk
zipalign -c -v 4 android/dist/wd-neo.apk
aapt2 dump badging android/dist/wd-neo.apk | head -6
```

Expected: `Verifies`, v2 **and** v3 schemes true, `Verification successful`,
package `sh.testssl.wdneo`, `sdkVersion:'24'`, `targetSdkVersion:'34'`.

---

## Test the client logic (no emulator needed)

`run_harness.sh` compiles the **exact** `Json`, `HttpClient` and `WdApi` classes
that are packaged into the APK and runs them against a live backend. This is the
emulator substitute: if the harness passes, the client's networking, JSON parsing
and API contract are correct.

```bash
# 1. start the backend
./scripts/run.sh &

# 2. give the harness credentials
python3 - <<'PY'
import json
c = {}
for line in open("database/bootstrap_credentials.txt"):
    if ":" in line:
        k, _, v = line.partition(":"); c[k.strip()] = v.strip()
json.dump({"user": c["Operator username"], "pass": c["Operator password"],
           "pin": c["Stage-2 PIN"], "shortcut": c["Stage-1 WD shortcut"]},
          open("/tmp/creds.json", "w"))
PY

# 3. run it
cd android && ./run_harness.sh http://127.0.0.1:8000
```

Last recorded run — **29 passed, 0 failed**:

```
ok   url: normalizeBase adds scheme and trims slash
ok   health responds ok
ok   unauthenticated request is rejected with 401
ok   stage 1 returns a token
ok   stage 1 rejects a bad shortcut
ok   stage 2 raises the session to stage 2
ok   stage 2 rejects a wrong PIN
ok   templates list ten entries
ok   modules lists ten engines
ok   stats responds
ok   emergency stop state responds and is clear
ok   artax status responds
ok   add scope entry (idempotent)
ok   validate scope accepts an in-scope host
ok   validate scope rejects an out-of-scope host
ok   create authorization
ok   authorization is refused for an out-of-scope target
ok   create assessment with a passing preflight
ok   run the assessment
ok   job reaches a terminal state
ok   findings come back with a persisted status
ok   report downloads as a real PDF
ok   markdown report is localised (EN and ID)
ok   audit chain verifies
ok   logout revokes the session
PASSED: 29   FAILED: 0
```

---

## What the client does

* Two-stage login exactly like the web UI: stage 1 (shortcut + password) and
  stage 2 (PIN), then everything else is authorised by the returned token.
* Scope registration and validation, with the out-of-scope rejection surfaced to
  the operator.
* Create an assessment from a template, run it, poll the job to a terminal state.
* List findings with their **persisted** status and evidence source, so an
  `unavailable` check is never shown as a pass.
* Download the PDF report and the localised Markdown report.
* Verify the audit hash chain and log out (server-side revocation).

## Limitations

* The client talks to a backend you run; it is not a standalone scanner. The
  engines execute on the server host, where the security tooling lives.
* Only the Java 11 language level is used so the Android build tools can dex it.
* `dist/*.idsig` (v4 signature side files) and `build/` are not committed; both
  are regenerated by `build_apk.sh`.
