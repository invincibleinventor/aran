#!/bin/sh
# Builds one app folder (manifest + res + src/*.kt) into a signed APK without Gradle.
set -e
APP="$(cd "$1" && pwd)"; NAME="$(basename "$APP")"
SDK="$HOME/Library/Android/sdk"; BT="$SDK/build-tools/36.0.0"; JAR="$SDK/platforms/android-35/android.jar"
STUDIO="/Applications/Android Studio.app/Contents"
export JAVA_HOME="$STUDIO/jbr/Contents/Home"
KOTLINC="$STUDIO/plugins/Kotlin/kotlinc/bin/kotlinc"; STDLIB="$STUDIO/plugins/Kotlin/kotlinc/lib/kotlin-stdlib.jar"
OUT="$APP/build"; rm -rf "$OUT"; mkdir -p "$OUT/dex"
LINK_RES=""
if [ -d "$APP/res" ]; then "$BT/aapt2" compile --dir "$APP/res" -o "$OUT/res.zip"; LINK_RES="$OUT/res.zip"; fi
"$BT/aapt2" link -I "$JAR" --manifest "$APP/AndroidManifest.xml" --min-sdk-version 29 --target-sdk-version 35 \
  -o "$OUT/unsigned.apk" $LINK_RES
bash "$KOTLINC" "$APP"/src/*.kt -classpath "$JAR" -d "$OUT/classes.jar" -jvm-target 11 -no-reflect -nowarn 2>&1 | grep -v "^warning" || true
"$BT/d8" --release --min-api 29 --lib "$JAR" --output "$OUT/dex" "$OUT/classes.jar" "$STDLIB"
(cd "$OUT/dex" && zip -q -j "$OUT/unsigned.apk" classes*.dex)
"$BT/zipalign" -f 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
KS="$HOME/.android/debug.keystore"
[ -f "$KS" ] || "$JAVA_HOME/bin/keytool" -genkeypair -keystore "$KS" -storepass android -alias androiddebugkey -keypass android -keyalg RSA -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --out "$APP/../$NAME.apk" "$OUT/aligned.apk"
echo "built android/$NAME.apk"
