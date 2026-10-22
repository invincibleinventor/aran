#!/bin/sh
# One-shot demo: verify phone, plant the benign mock apps the way an abuser would,
# then launch Aran Desk. Nothing here aborts the demo — each step reports and moves on.
ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
ok(){ printf '  \033[32mok\033[0m  %s\n' "$1"; }
no(){ printf '  \033[31m!!\033[0m  %s\n' "$1"; }

echo "== phone =="
LINE=$("$ADB" devices -l | sed -n '2p')
case "$LINE" in
  *" device "*) ok "connected: $(echo "$LINE" | grep -o 'model:[^ ]*')" ;;
  *unauthorized*) no "phone shows 'unauthorized' — tap Allow on the USB debugging prompt, re-run"; exit 1 ;;
  *) no "no phone. Check cable + USB debugging, then re-run"; exit 1 ;;
esac

echo "== install (grant all permissions) =="
for apk in systemsync batterysaver vault; do
  if "$ADB" install -r -g "$ROOT/android/$apk.apk" >/dev/null 2>&1; then ok "$apk"
  else no "$apk failed — ColorOS: Developer options > enable 'Disable permission monitoring' + 'Install via USB', re-run"; fi
done

echo "== grant the spying access =="
SVC=com.aran.systemsync/com.aran.systemsync.ScreenService
CUR=$("$ADB" shell settings get secure enabled_accessibility_services | tr -d '\r')
case "$CUR" in
  *"$SVC"*) : ;;
  null|"") "$ADB" shell settings put secure enabled_accessibility_services "$SVC" ;;
  *) "$ADB" shell settings put secure enabled_accessibility_services "$CUR:$SVC" ;;
esac
"$ADB" shell settings put secure accessibility_enabled 1 >/dev/null 2>&1 && ok "accessibility" || no "accessibility — turn on System Sync in Settings > Accessibility"
"$ADB" shell cmd notification allow_listener com.aran.systemsync/com.aran.systemsync.NotifService >/dev/null 2>&1 && ok "notification listener" || no "notification listener — enable System Sync by hand"
"$ADB" shell dpm set-active-admin --user 0 com.aran.batterysaver/.Admin >/dev/null 2>&1 && ok "device admin" || no "device admin — open Battery Saver Plus, tap Activate"
# ColorOS blocks adb from disabling another app's component, so the app hides its own icon via this intent.
"$ADB" shell am start -n com.aran.systemsync/.SetupActivity --ez autohide true >/dev/null 2>&1 && sleep 2
LAUNCH=$("$ADB" shell cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER 2>/dev/null | grep -c systemsync)
[ "$LAUNCH" = "0" ] && ok "icon hidden" || no "icon — open System Sync, tap '3. Hide icon'"

echo "== plant evidence =="
"$ADB" push "$ROOT/android/demo-evidence/." /sdcard/Download/ >/dev/null 2>&1 && ok "evidence in Downloads" || no "evidence push failed"
"$ADB" shell 'rm -f /sdcard/Download/aran-vault-pack-*.json' >/dev/null 2>&1

echo "== launch Aran Desk =="
cd "$ROOT/aran-desk"
(sleep 1.5 && open "http://localhost:8000") &
exec uv run -q python main.py
