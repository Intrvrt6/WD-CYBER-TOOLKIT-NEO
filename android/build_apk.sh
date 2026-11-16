#!/usr/bin/env bash
# Build a signed, installable WD NEO APK with the Android SDK build tools
# directly (no Gradle, no network at build time).
#
#   ./build_apk.sh            # full build -> dist/wd-neo.apk
#   ./build_apk.sh --clean    # wipe build/ and dist/ first
#
# Produces a release-signed APK and prints the verification report.
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

BT="${ANDROID_BUILD_TOOLS:-/workspace/android-sdk/bt/android-14}"
PLATFORM="${ANDROID_PLATFORM:-/workspace/android-sdk/plat/android-34-ext12}"
ANDROID_JAR="$PLATFORM/android.jar"

# The d8 shipped inside build-tools/android-14 is an R8 8.2.2-dev snapshot that
# dies with a NullPointerException on ANY anonymous inner class:
#   Error in ...MainActivity$1.class: Cannot invoke "String.length()" because ... is null
# (reproduced on a two-line stand-in class, so it is the tool, not our code).
# A released R8 from Google's Maven repository is used instead when available.
R8_JAR="${R8_JAR:-${ANDROID_SDK_ROOT:-/workspace/android-sdk}/r8-9.5.32.jar}"
[ -f "$R8_JAR" ] || R8_JAR="/workspace/dl/r8-9.5.32.jar"

MIN_SDK=24
TARGET_SDK=34

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- preflight --
log "preflight"
for tool in "$BT/aapt2" "$BT/d8" "$BT/zipalign" "$BT/apksigner"; do
  [ -x "$tool" ] || fail "missing build tool: $tool"
done
[ -f "$ANDROID_JAR" ] || fail "missing android.jar: $ANDROID_JAR"
command -v javac >/dev/null || fail "javac not found (install a JDK)"
command -v keytool >/dev/null || fail "keytool not found"
command -v zip >/dev/null || fail "zip not found"
echo "build-tools : $($BT/aapt2 version 2>&1 | head -1)"
echo "platform    : $ANDROID_JAR"
echo "javac       : $(javac -version 2>&1)"

if [ "${1:-}" = "--clean" ]; then
  log "clean"
  rm -rf build dist
fi

rm -rf build dist
mkdir -p build/gen build/classes build/dex dist

# -------------------------------------------------------------- 1. resources --
log "1/7 compile resources"
if [ -d res ] && [ -n "$(find res -type f -print -quit)" ]; then
  "$BT/aapt2" compile --dir res -o build/res.zip
  RES_ARGS=(build/res.zip)
  echo "compiled $(find res -type f | wc -l) resource file(s)"
else
  RES_ARGS=()
  echo "no resources (manifest-only build)"
fi

# ------------------------------------------------------------------ 2. link --
log "2/7 link resources + manifest"
"$BT/aapt2" link \
  -o build/base.apk \
  -I "$ANDROID_JAR" \
  --manifest AndroidManifest.xml \
  --java build/gen \
  --min-sdk-version "$MIN_SDK" \
  --target-sdk-version "$TARGET_SDK" \
  --version-code "${VERSION_CODE:-1}" \
  --version-name "${VERSION_NAME:-1.0.0}" \
  "${RES_ARGS[@]}"
[ -s build/base.apk ] || fail "aapt2 produced no APK"

# ---------------------------------------------------------------- 3. javac ---
log "3/7 compile java"
mapfile -t SOURCES < <(find src build/gen -name '*.java' -print)
[ "${#SOURCES[@]}" -gt 0 ] || fail "no java sources found"
# Compile to Java 11 bytecode (major 55). The bundled d8 (R8 8.2.2) crashes
# with an internal NullPointerException on Java 17 class files (major 61,
# NestHost/NestMembers attributes). Java 11 is well within d8's supported range
# and Android's desugaring handles the rest.
javac -source 11 -target 11 -Xlint:-options -encoding UTF-8 \
  -cp "$ANDROID_JAR" \
  -d build/classes \
  "${SOURCES[@]}"
CLASS_COUNT=$(find build/classes -name '*.class' | wc -l)
[ "$CLASS_COUNT" -gt 0 ] || fail "javac produced no classes"
echo "$CLASS_COUNT class file(s) from ${#SOURCES[@]} source file(s)"

# ------------------------------------------------------------------- 4. d8 ---
log "4/7 dex (d8)"
mapfile -t CLASSES < <(find build/classes -name '*.class' -print)
if [ -f "$R8_JAR" ]; then
  echo "dexer       : bundled R8 ($R8_JAR)"
  java -cp "$R8_JAR" com.android.tools.r8.D8 \
    --min-api "$MIN_SDK" --lib "$ANDROID_JAR" --output build/dex "${CLASSES[@]}"
else
  echo "dexer       : $BT/d8 (build-tools)"
  "$BT/d8" --min-api "$MIN_SDK" --lib "$ANDROID_JAR" --output build/dex "${CLASSES[@]}"
fi
[ -s build/dex/classes.dex ] || fail "d8 produced no classes.dex"
echo "classes.dex: $(stat -c%s build/dex/classes.dex) bytes"

# -------------------------------------------------------------- 5. package ---
log "5/7 package"
cp build/base.apk build/unsigned.apk
# store the dex uncompressed-agnostic: plain deflate is fine for API 24+
(cd build/dex && zip -q -X "$HERE/build/unsigned.apk" classes.dex)
unzip -l build/unsigned.apk | tail -6

# --------------------------------------------------------------- 6. align ----
log "6/7 zipalign"
"$BT/zipalign" -f -p 4 build/unsigned.apk build/aligned.apk
"$BT/zipalign" -c -p 4 build/aligned.apk
echo "alignment verified"

# ----------------------------------------------------------------- 7. sign ---
log "7/7 sign"
# The signing key decides the app IDENTITY: a different key means Android
# refuses the update (INSTALL_FAILED_UPDATE_INCOMPATIBLE). So the default
# keystore is committed, and callers can override it with WD_KEYSTORE /
# WD_STOREPASS / WD_KEYPASS to sign with their own.
KEYSTORE="${WD_KEYSTORE:-keystore/wd-neo.jks}"
STOREPASS="${WD_STOREPASS:-wdneo-release}"
KEYPASS="${WD_KEYPASS:-$STOREPASS}"
KEYALIAS="${WD_KEYALIAS:-wdneo}"
if [ ! -f "$KEYSTORE" ]; then
  mkdir -p "$(dirname "$KEYSTORE")"
  keytool -genkeypair -keystore "$KEYSTORE" -alias "$KEYALIAS" \
    -keyalg RSA -keysize 2048 -validity 10950 \
    -storepass "$STOREPASS" -keypass "$KEYPASS" \
    -dname 'CN=WD Cyber Toolkit NEO, OU=Security Engineering, O=WD, L=Jakarta, C=ID'
  echo "generated release keystore $KEYSTORE"
fi
echo "keystore    : $KEYSTORE (alias $KEYALIAS)"
"$BT/apksigner" sign \
  --ks "$KEYSTORE" \
  --ks-key-alias "$KEYALIAS" \
  --ks-pass pass:"$STOREPASS" \
  --key-pass pass:"$KEYPASS" \
  --min-sdk-version "$MIN_SDK" \
  --out dist/wd-neo.apk \
  build/aligned.apk

log "verify"
"$BT/apksigner" verify --verbose --print-certs dist/wd-neo.apk | sed -n '1,14p'

SIZE=$(stat -c%s dist/wd-neo.apk)
SHA=$(sha256sum dist/wd-neo.apk | awk '{print $1}')
cat > dist/wd-neo.apk.sha256 <<EOF
$SHA  wd-neo.apk
EOF

printf '\n\033[1;32mBUILD OK\033[0m\n'
echo "apk    : dist/wd-neo.apk"
echo "size   : $SIZE bytes"
echo "sha256 : $SHA"
