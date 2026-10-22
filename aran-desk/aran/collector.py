"""Pulls phone state over adb. Every command is checked against a read-only allowlist."""
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

ADB = shutil.which("adb") or os.path.expanduser("~/Library/Android/sdk/platform-tools/adb")
AAPT2 = next((p for p in sorted(
    __import__("glob").glob(os.path.expanduser("~/Library/Android/sdk/build-tools/*/aapt2")), reverse=True)), None)

READ_ONLY_PREFIXES = (
    ("devices",), ("get-state",), ("pull",),
    ("shell", "getprop"), ("shell", "pm", "list"), ("shell", "pm", "path"),
    ("shell", "dumpsys"), ("shell", "settings", "get"),
    ("shell", "cmd", "package", "query-activities"), ("shell", "ls"),
)

PLAY_STORES = {"com.android.vending", "com.google.android.feedback",
               "com.sec.android.app.samsungapps", "com.xiaomi.mipicks",
               "com.heytap.market", "com.oppo.market", "com.bbk.appstore"}

SENSITIVE = {"android.permission.READ_SMS", "android.permission.ACCESS_FINE_LOCATION",
             "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS",
             "android.permission.READ_CALL_LOG", "android.permission.CAMERA",
             "android.permission.ACCESS_BACKGROUND_LOCATION"}


# The Vault must never show up in a report she might share, or it would reveal itself.
HIDDEN_FROM_REPORT = {"com.aran.vault"}


class ReadOnlyViolation(RuntimeError):
    pass


def adb(*args, timeout=30):
    if not any(args[:len(p)] == p for p in READ_ONLY_PREFIXES):
        raise ReadOnlyViolation(f"blocked non-read-only adb command: {args}")
    result = subprocess.run([ADB, *args], capture_output=True, text=True, timeout=timeout)
    return result.stdout


def device_info():
    try:
        devices = [l for l in adb("devices", timeout=5).splitlines()[1:] if l.strip().endswith("device")]
    except Exception:
        return None
    if not devices:
        return None
    serial = devices[0].split()[0]
    prop = lambda key: adb("shell", "getprop", key).strip()
    return {
        "model": f'{prop("ro.product.manufacturer").title()} {prop("ro.product.model")}'.strip(),
        "android": prop("ro.build.version.release"),
        "sdk": prop("ro.build.version.sdk"),
        "serial_sha256": hashlib.sha256(serial.encode()).hexdigest(),
    }


def _third_party_packages():
    apps = {}
    for line in adb("shell", "pm", "list", "packages", "-3", "-i").splitlines():
        if not line.startswith("package:"):
            continue
        pkg = line[len("package:"):].split()[0]
        installer = line.split("installer=")[1].strip() if "installer=" in line else "null"
        if pkg in HIDDEN_FROM_REPORT:
            continue
        apps[pkg] = None if installer in ("null", "") else installer
    return apps


def _component_packages(raw):
    return {c.split("/")[0] for c in raw.strip().split(":") if "/" in c}


def parse_dumpsys_packages(text):
    """Split `dumpsys package packages` into per-package facts."""
    facts = {}
    current = None
    section = None
    for line in text.splitlines():
        header = re.match(r"^  Package \[([^\]]+)\]", line)
        if header:
            current = facts.setdefault(header.group(1), {"requested": [], "granted": []})
            section = None
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("requested permissions:"):
            section = "requested"
            continue
        if stripped.endswith("permissions:"):
            section = "granted"
            continue
        for key in ("versionName", "firstInstallTime", "lastUpdateTime"):
            if stripped.startswith(key + "="):
                current[key] = stripped.split("=", 1)[1]
                section = None
        if section == "requested" and re.match(r"^[\w.]+(: restricted=\w+)?$", stripped):
            current["requested"].append(stripped.split(":")[0])
        elif section == "granted" and "granted=true" in stripped:
            current["granted"].append(stripped.split(":")[0])
    return facts


def _label(pkg, with_apk):
    if pkg in KNOWN_LABELS:
        return KNOWN_LABELS[pkg]
    if with_apk and AAPT2:
        path = adb("shell", "pm", "path", pkg).strip().splitlines()
        base = next((p[len("package:"):] for p in path if p.endswith("base.apk")), None)
        if base:
            with tempfile.TemporaryDirectory() as tmp:
                local = os.path.join(tmp, "base.apk")
                adb("pull", base, local, timeout=60)
                badging = subprocess.run([AAPT2, "dump", "badging", local],
                                         capture_output=True, text=True).stdout
                found = re.search(r"application-label:'([^']+)'", badging)
                if found:
                    return found.group(1)
    parts = [p for p in pkg.split(".") if p not in ("com", "org", "net", "in", "android", "app", "mobile", "apps")]
    return (parts[-1] if parts else pkg).replace("_", " ").title()


def collect(progress=lambda step, detail="": None):
    """Returns {device, collected_at, apps:[facts]}. Calls progress() between stages."""
    device = device_info()
    if not device:
        raise RuntimeError("No phone connected. Check the cable and USB debugging.")
    progress("connect", f'{device["model"]} · Android {device["android"]}')

    packages = _third_party_packages()
    progress("apps", f"{len(packages)} user-installed apps")

    dumped = parse_dumpsys_packages(adb("shell", "dumpsys", "package", "packages", timeout=90))
    progress("perms", "permissions, install dates and sources read")

    launcher = adb("shell", "cmd", "package", "query-activities", "--brief",
                   "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER")
    launchable = {l.strip().split("/")[0] for l in launcher.splitlines() if "/" in l}
    progress("icons", f"{sum(1 for p in packages if p not in launchable)} apps without an app-drawer icon")

    accessibility = _component_packages(adb("shell", "settings", "get", "secure", "enabled_accessibility_services"))
    listeners = _component_packages(adb("shell", "settings", "get", "secure", "enabled_notification_listeners"))
    dp = adb("shell", "dumpsys", "device_policy")
    # AOSP prints ComponentInfo{pkg/...}; OEM builds (ColorOS) list "pkg/.Admin:" under Enabled Device Admins.
    admins = set(re.findall(r"ComponentInfo\{([^/]+)/", dp)) | set(re.findall(r"^\s+([\w.]+)/[\w.$]+:\s*$", dp, re.M))
    idle = adb("shell", "dumpsys", "deviceidle", "whitelist")
    battery = {l.split(",")[1] for l in idle.splitlines() if l.startswith("user,") and l.count(",") >= 2}
    progress("special", f"{len(accessibility)} accessibility · {len(listeners)} notification readers · {len(admins)} device admins")

    apps = []
    for pkg, installer in packages.items():
        facts = dumped.get(pkg) or parse_dumpsys_packages(adb("shell", "dumpsys", "package", pkg)).get(pkg) \
            or {"requested": [], "granted": []}
        apps.append({
            "package": pkg,
            "installer": installer,
            "version": facts.get("versionName"),
            "first_install": facts.get("firstInstallTime"),
            "last_update": facts.get("lastUpdateTime"),
            "requested": sorted(set(facts["requested"])),
            "granted": sorted(set(facts["granted"])),
            "has_launcher": pkg in launchable,
            "accessibility": pkg in accessibility,
            "notif_listener": pkg in listeners,
            "device_admin": pkg in admins,
            "battery_exempt": pkg in battery,
        })
    return {"device": device, "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "apps": apps}


def resolve_labels(apps, flagged):
    for app in apps:
        app["label"] = _label(app["package"], with_apk=app["package"] in flagged)


KNOWN_LABELS = {
    "com.aran.systemsync": "System Sync Service", "com.aran.batterysaver": "Battery Saver Plus",
    "com.aran.vault": "Calculator", "com.whatsapp": "WhatsApp", "com.whatsapp.w4b": "WhatsApp Business",
    "com.instagram.android": "Instagram", "com.facebook.katana": "Facebook", "com.facebook.orca": "Messenger",
    "org.telegram.messenger": "Telegram", "com.snapchat.android": "Snapchat", "com.truecaller": "Truecaller",
    "com.phonepe.app": "PhonePe", "net.one97.paytm": "Paytm", "com.google.android.apps.nbu.paisa.user": "Google Pay",
    "in.swiggy.android": "Swiggy", "com.application.zomato": "Zomato", "in.amazon.mShop.android.shopping": "Amazon",
    "com.flipkart.android": "Flipkart", "com.spotify.music": "Spotify", "com.netflix.mediaclient": "Netflix",
    "in.startv.hotstar": "JioHotstar", "com.x8bit.bitwarden": "Bitwarden", "com.lastpass.lpandroid": "LastPass",
    "com.google.android.apps.authenticator2": "Google Authenticator", "com.linkedin.android": "LinkedIn",
    "com.twitter.android": "X", "com.discord": "Discord", "us.zoom.videomeetings": "Zoom",
    "com.microsoft.teams": "Microsoft Teams", "com.google.android.apps.classroom": "Google Classroom",
    "com.duolingo": "Duolingo", "com.openai.chatgpt": "ChatGPT", "com.anthropic.claude": "Claude",
    "com.sbi.lotusintouch": "YONO SBI", "com.csam.icici.bank.imobile": "iMobile Pay", "com.olacabs.customer": "Ola",
    "com.ubercab": "Uber", "com.rapido.passenger": "Rapido", "com.jio.myjio": "MyJio", "com.myairtelapp": "Airtel Thanks",
    "com.google.android.apps.maps": "Google Maps", "com.android.chrome": "Chrome", "com.google.android.youtube": "YouTube",
    "com.google.android.gm": "Gmail", "com.google.android.apps.photos": "Google Photos", "com.reddit.frontpage": "Reddit",
    "com.pinterest": "Pinterest", "com.mxtech.videoplayer.ad": "MX Player", "com.lenskart.app": "Lenskart",
    "com.digilocker.android": "DigiLocker", "in.gov.uidai.mAadhaarPlus": "mAadhaar",
}
