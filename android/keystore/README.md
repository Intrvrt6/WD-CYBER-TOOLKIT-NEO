# Android release signing key — operator-managed

**No private signing key belongs in this repository.** The previously committed
`wd-neo.jks` and its documented passphrase are considered compromised and have
been removed from the current source tree. Removing the file in a new commit does
not erase it from earlier Git history or existing clones.

## Required incident actions

1. Generate a new release keystore under the publisher's control and store an
   encrypted backup offline or in an approved secret manager.
2. Do not reuse the old committed certificate or passphrase.
3. Purge the old keystore blob from repository history using a coordinated
   history rewrite, then force-update the affected branches and ask collaborators
   to re-clone. This is not performed automatically by this source change because
   rewriting shared Git history is disruptive.
4. If the old-signed APK has already been distributed, plan a migration: Android
   will reject an APK signed with the new certificate as an in-place update.
   Users may need to uninstall the old build and install the new one, unless an
   applicable managed app-signing/rotation mechanism is already configured.
5. Treat any APK built with the old key as untrusted for future release signing.

## Create a private signing key

Run from the repository root (or use the build script's automatic local key
creation) and never commit the resulting file:

```bash
mkdir -p android/keystore
keytool -genkeypair \
  -keystore android/keystore/wd-neo.jks \
  -alias wdneo -keyalg RSA -keysize 3072 -validity 10950 \
  -dname 'CN=WD Cyber Toolkit NEO, OU=Security Engineering, O=WD, L=Jakarta, C=ID'
chmod 600 android/keystore/wd-neo.jks
```

Supply passwords through a secret manager or protected environment variables:

```bash
cd android
export WD_KEYSTORE=keystore/wd-neo.jks
export WD_KEYALIAS=wdneo
export WD_STOREPASS='(retrieve from your secret manager)'
export WD_KEYPASS='(retrieve from your secret manager)'
./build_apk.sh --clean
```

The build script refuses to sign if `WD_STOREPASS` or `WD_KEYPASS` is missing.
It creates a local key only when the configured keystore path does not exist.
The keystore file is ignored by Git. Keep a secure offline backup; losing the
private key prevents signing compatible updates.
