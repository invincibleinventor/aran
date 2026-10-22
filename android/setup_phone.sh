#!/bin/sh
# DEMO PHONE SETUP ONLY. Installs the benign mock apps + Vault and grants their access the way an abuser would.
# This is not part of Aran Desk (the Desk is read-only and its tests forbid these commands).
set -e
cd "$(dirname "$0")"
ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
$ADB wait-for-device
for apk in systemsync batterysaver vault; do $ADB install -r -g "$apk.apk"; done

SVC=com.aran.systemsync/com.aran.systemsync.ScreenService
CUR=$($ADB shell settings get secure enabled_accessibility_services | tr -d '\r')
case "$CUR" in *"$SVC"*) ;; null|"") $ADB shell settings put secure enabled_accessibility_services "$SVC" ;; *) $ADB shell settings put secure enabled_accessibility_services "$CUR:$SVC" ;; esac
$ADB shell settings put secure accessibility_enabled 1
$ADB shell cmd notification allow_listener com.aran.systemsync/com.aran.systemsync.NotifService
$ADB shell dpm set-active-admin --user 0 com.aran.batterysaver/.Admin || echo "!! Open Battery Saver Plus on the phone and tap Activate"
$ADB shell pm disable com.aran.systemsync/com.aran.systemsync.Launcher 2>/dev/null \
  || echo "!! Open System Sync Service on the phone and tap '3. Hide icon'"

$ADB push demo-evidence/. /sdcard/Download/ >/dev/null
$ADB shell 'rm -f /sdcard/Download/aran-vault-pack-*.json'
echo
echo "Done. Check with: $ADB shell settings get secure enabled_accessibility_services"
