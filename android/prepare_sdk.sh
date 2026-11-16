#!/usr/bin/env bash
# Fetch the Android SDK build tools, platform jar and a working R8 into
# ${ANDROID_SDK_ROOT:-/workspace/android-sdk}. Idempotent; only used when the
# host has no SDK preinstalled.
#
# Why R8 and not build-tools' d8: the d8 inside build-tools;android-14 is an
# R8 8.2.2-dev snapshot that crashes with a NullPointerException on any
# anonymous inner class (MainActivity$1.class, and a two-line stand-in class),
# so the released D8 from Google's Maven repository is used instead.
set -Eeuo pipefail

SDK="${ANDROID_SDK_ROOT:-/workspace/android-sdk}"
BT_VER="${ANDROID_BUILD_TOOLS_VER:-14.0.0}"
PLATFORM="${ANDROID_PLATFORM_VER:-34-ext12}"
R8_VER="${R8_VERSION:-9.5.32}"

DL="$SDK/.download"
BT="$SDK/bt/android-14"
PLAT="$SDK/plat/android-$PLATFORM"
R8_JAR="$SDK/r8-$R8_VER.jar"

mkdir -p "$DL" "$BT" "$PLAT"

fetch() { # url dest
  local url="$1" dest="$2"
  if [ -s "$dest" ]; then echo "cached  $dest"; return; fi
  echo "fetch   $url"
  curl -fsSL --retry 3 --connect-timeout 20 -o "$dest.part" "$url"
  mv "$dest.part" "$dest"
}

# ---------------------------------------------------------- build tools ------
if [ ! -x "$BT/aapt2" ]; then
  fetch "https://dl.google.com/android/repository/build-tools_r${BT_VER}-linux.zip" "$DL/build-tools.zip"
  echo "unzip   build-tools"
  rm -rf "$DL/bt" && mkdir -p "$DL/bt"
  unzip -q "$DL/build-tools.zip" -d "$DL/bt"
  # the archive may nest one level (android-14/ or android-14.0.0/)
  src="$(find "$DL/bt" -maxdepth 2 -name aapt2 -printf '%h\n' | head -1)"
  [ -n "$src" ] || { echo "aapt2 not found in the build-tools archive" >&2; exit 1; }
  cp -a "$src"/. "$BT"/
fi

# -------------------------------------------------------------- platform -----
if [ ! -f "$PLAT/android.jar" ]; then
  fetch "https://dl.google.com/android/repository/platform-${PLATFORM}_r01.zip" "$DL/platform.zip"
  echo "unzip   platform"
  rm -rf "$DL/plat" && mkdir -p "$DL/plat"
  unzip -q "$DL/platform.zip" -d "$DL/plat"
  src="$(find "$DL/plat" -maxdepth 3 -name android.jar -printf '%h\n' | head -1)"
  [ -n "$src" ] || { echo "android.jar not found in the platform archive" >&2; exit 1; }
  cp -a "$src"/. "$PLAT"/
fi

# -------------------------------------------------------------------- r8 -----
if [ ! -s "$R8_JAR" ]; then
  fetch "https://dl.google.com/dl/android/maven2/com/android/tools/r8/${R8_VER}/r8-${R8_VER}.jar" "$R8_JAR"
fi

# ---------------------------------------------------------------- verify -----
for f in "$BT/aapt2" "$BT/zipalign" "$BT/apksigner" "$PLAT/android.jar" "$R8_JAR"; do
  [ -e "$f" ] || { echo "missing: $f" >&2; exit 1; }
  echo "ok      $f"
done
java -cp "$R8_JAR" com.android.tools.r8.D8 --version

cat <<EOF

Android build inputs ready.
  ANDROID_BUILD_TOOLS=$BT
  ANDROID_PLATFORM=$PLAT
  R8_JAR=$R8_JAR

Build the APK with:  ./android/build_apk.sh
EOF
