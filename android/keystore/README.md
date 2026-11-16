# Release signing key

`wd-neo.jks` is the **committed** release signing key for the Android client.

```
alias        wdneo
storepass    wdneo-release
keypass      wdneo-release
DN           CN=WD Cyber Toolkit NEO, OU=Security Engineering, O=WD, L=Jakarta, C=ID
cert SHA-256  73119799ee36960bfbf1f5af64a574a90d0fcfdd3441acd492a9f5e62bb8936b
```

## Why it is committed (and why that is correct)

Android identifies an app by its signing certificate. If the key changes, an
update is rejected:

```
adb install -r wd-neo.apk
Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: ... signatures do not match]
```

Because `build_apk.sh` generated a **new random key whenever `keystore/` was
missing**, and `keystore/` was gitignored, every fresh clone produced a different
certificate. That was measured, not assumed — two builds from an identical tree
gave two different certificate digests:

```
build 1  cert SHA-256 = 4ed1063ddd67cdb9a8ac53688646a9f32b2a6c885cefe13383eeed3cc8f541ca
build 2  cert SHA-256 = 73119799ee36960bfbf1f5af64a574a90d0fcfdd3441acd492a9f5e62bb8936b
```

With the key committed, consecutive builds now share one identity:

```
build 1  cert SHA-256 = 73119799ee36960bfbf1f5af64a574a90d0fcfdd3441acd492a9f5e62bb8936b
build 2  cert SHA-256 = 73119799ee36960bfbf1f5af64a574a90d0fcfdd3441acd492a9f5e62bb8936b
```

## Treating it as a secret

This is a **release keystore with a documented passphrase**, so it is not
confidential. It is still the app identity: anyone with it can sign an update your
install will accept. For a public distribution, generate your own key and keep it
out of the repository:

```bash
keytool -genkeypair -keystore android/keystore/wd-neo.jks -alias wdneo \
  -keyalg RSA -keysize 2048 -validity 10950 \
  -storepass "$STORE_PASS" -keypass "$KEY_PASS" \
  -dname 'CN=Your Org, O=Your Org, C=ID'
```

then point the build at it with `WD_KEYSTORE` / `WD_STOREPASS` / `WD_KEYPASS`
(see `build_apk.sh`).
