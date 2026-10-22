"""Turns observed signals into a risk score. A transparent weighted sum; matches slide 7."""
from . import matcher
from .collector import PLAY_STORES, SENSITIVE

WEIGHTS = {
    "watchware_list": 0.40,
    "hides_icon": 0.30,
    "reads_notifs": 0.20,
    "accessibility": 0.20,
    "device_admin": 0.20,
    "sideloaded": 0.15,
    "sensitive_bundle": 0.10,
    "battery_exempt": 0.05,
    "boot": 0.05,
}
ALLOWLIST_BONUS = -0.40
HIGH, REVIEW = 0.70, 0.35

REASONS = {
    "known": ("Matches a known stalkerware app: {name}", "அறியப்பட்ட உளவு செயலியுடன் பொருந்துகிறது: {name}"),
    "watchware_list": ("On the stalkerware watch list", "கண்காணிப்பு செயலிகள் பட்டியலில் உள்ளது"),
    "hides_icon": ("Hides its icon from your app list", "இதன் ஐகான் மறைக்கப்பட்டுள்ளது"),
    "reads_notifs": ("Can read all your notifications", "உங்கள் அறிவிப்புகளை இது படிக்கும்"),
    "accessibility": ("Can see what is on your screen (accessibility service)", "உங்கள் திரையில் உள்ளதை இது பார்க்க முடியும்"),
    "device_admin": ("Has device-admin rights, so it is hard to remove", "சாதன நிர்வாக உரிமை உள்ளது, அகற்றுவது கடினம்"),
    "sideloaded": ("Installed from outside the Play Store", "Play Store-க்கு வெளியே நிறுவப்பட்டது"),
    "sensitive_bundle": ("Asks for messages, location, microphone and contacts together", "செய்திகள், இருப்பிடம், மைக், தொடர்புகள் அனைத்தையும் கேட்கிறது"),
    "battery_exempt": ("Allowed to run in the background without limits", "பின்னணியில் தடையின்றி இயங்க அனுமதி உள்ளது"),
    "boot": ("Starts by itself when the phone turns on", "போன் ஆன் ஆனதும் தானாகவே இயங்குகிறது"),
    "allowlisted": ("Known, trusted app from the Play Store", "Play Store-இல் இருந்து வந்த நம்பகமான செயலி"),
}


def signals_for(app):
    perms = set(app["requested"])
    return {
        "watchware_list": matcher.on_watchware(app["package"]),
        "hides_icon": not app["has_launcher"],
        "reads_notifs": app["notif_listener"],
        "accessibility": app["accessibility"],
        "device_admin": app["device_admin"],
        "sideloaded": app.get("installer") not in PLAY_STORES,
        "sensitive_bundle": len(perms & SENSITIVE) >= 4,
        "battery_exempt": app["battery_exempt"],
        "boot": "android.permission.RECEIVE_BOOT_COMPLETED" in perms,
    }


def band(score):
    return "HIGH" if score >= HIGH else "REVIEW" if score >= REVIEW else "NORMAL"


def score_app(app):
    signals = signals_for(app)
    known = matcher.known_stalkerware(app["package"])
    if known:
        en, ta = REASONS["known"]
        return {"score": 1.0, "band": "HIGH", "known": known, "signals": [k for k, v in signals.items() if v],
                "reasons": [{"key": "known", "weight": None, "en": en.format(name=known), "ta": ta.format(name=known)}]}
    reasons = [{"key": k, "weight": WEIGHTS[k], "en": REASONS[k][0], "ta": REASONS[k][1]}
               for k, present in signals.items() if present]
    total = sum(r["weight"] for r in reasons)
    if matcher.allowlisted(app):
        total += ALLOWLIST_BONUS
        reasons.append({"key": "allowlisted", "weight": ALLOWLIST_BONUS, "en": REASONS["allowlisted"][0], "ta": REASONS["allowlisted"][1]})
    total = round(max(0.0, min(1.0, total)), 2)
    return {"score": total, "band": band(total), "known": None,
            "signals": [k for k, v in signals.items() if v], "reasons": reasons}


def analyse(scan):
    order = {"HIGH": 0, "REVIEW": 1, "NORMAL": 2}
    findings = [{**app, **score_app(app)} for app in scan["apps"]]
    findings.sort(key=lambda f: (order[f["band"]], -f["score"], f.get("label", f["package"]).lower()))
    return findings
