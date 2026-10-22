import json
import os
import queue
import secrets
import threading
import time
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from aran import abuse, collector, complaint, matcher, report, sealer, scorer, vault_chain

ROOT = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(ROOT, "cases")
FIXTURES = os.path.join(ROOT, "fixtures")
VAULT_PACK_PREFIX = "aran-vault-pack"

app = FastAPI(title="Aran Desk")
app.mount("/cases", StaticFiles(directory=CASES), name="cases")
STATE = {"scan": None, "findings": None, "replay": False, "abuse": None}
CHAT_HINTS = ("chat with", "whatsapp chat")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def _case_dir(case_id):
    path = os.path.join(CASES, os.path.basename(case_id))
    if not os.path.isdir(path):
        raise HTTPException(404, "unknown case")
    return path


VAULT_APK = os.path.normpath(os.path.join(ROOT, "..", "android", "vault.apk"))
VAULT_PKG = "com.aran.vault"


@app.get("/")
def index():
    return FileResponse(os.path.join(ROOT, "static", "index.html"))


@app.get("/install")
def install_page():
    return FileResponse(os.path.join(ROOT, "static", "install.html"))


def _adb_write(*args, timeout=120):
    """TESTING ONLY. Deliberately bypasses collector's read-only guard to set up a test phone.
    Never used by the scan flow — the victim-facing path stays strictly read-only."""
    import subprocess
    r = subprocess.run([collector.ADB, *args], capture_output=True, text=True, timeout=timeout)
    return (r.returncode == 0, (r.stdout + r.stderr).strip())


@app.post("/api/install-vault")
def install_vault():
    if collector.device_info() is None:
        raise HTTPException(404, "No phone connected. USB cable + USB debugging on, then tap Allow.")
    if not os.path.exists(VAULT_APK):
        raise HTTPException(500, f"vault.apk not found at {VAULT_APK}. Build it with android/build.sh vault.")
    steps = []
    ok, out = _adb_write("install", "-r", VAULT_APK, timeout=180)
    steps.append({"name": "Install Aran Vault APK", "ok": ok, "detail": out or "Success"})
    # Best-effort ColorOS/Android setup so the notification listener runs in the background.
    grants = [
        ("Grant notification access", ("shell", "cmd", "notification", "allow_listener",
                                       f"{VAULT_PKG}/{VAULT_PKG}.AbuseWatch")),
        ("Exempt from battery optimisation", ("shell", "dumpsys", "deviceidle", "whitelist", f"+{VAULT_PKG}")),
        ("Allow background run", ("shell", "appops", "set", VAULT_PKG, "RUN_ANY_IN_BACKGROUND", "allow")),
    ]
    for label, cmd in grants:
        if not ok:
            break
        g_ok, g_out = _adb_write(*cmd)
        steps.append({"name": label, "ok": g_ok, "detail": g_out or "done"})
    return {"ok": ok, "apk": os.path.basename(VAULT_APK), "steps": steps}


@app.get("/api/device")
def device():
    return {"device": collector.device_info(), "indicators": len(matcher.STALKERWARE),
            "watchware": len(matcher.WATCHWARE), "desk_key": sealer.public_hex()[:16]}


def _live_scan(emit):
    scan = collector.collect(progress=lambda step, detail="": emit(step, detail))
    preliminary = {a["package"] for a in scan["apps"]
                   if scorer.score_app({**a, "label": a["package"]})["band"] != "NORMAL"}
    collector.resolve_labels(scan["apps"], preliminary)
    os.makedirs(FIXTURES, exist_ok=True)
    _write_json(os.path.join(FIXTURES, "latest_live.json"), scan)
    return scan


def _replay_scan(emit):
    path = os.path.join(FIXTURES, "latest_live.json")
    if not os.path.exists(path):
        path = os.path.join(FIXTURES, "scan.json")
    scan = json.load(open(path, encoding="utf-8"))
    apps = scan["apps"]
    hidden = sum(1 for a in apps if not a["has_launcher"])
    for step, detail in [("connect", f'{scan["device"]["model"]} · Android {scan["device"]["android"]}'),
                         ("apps", f"{len(apps)} user-installed apps"),
                         ("perms", "permissions, install dates and sources read"),
                         ("icons", f"{hidden} apps without an app-drawer icon"),
                         ("special", f'{sum(a["accessibility"] for a in apps)} accessibility · {sum(a["notif_listener"] for a in apps)} notification readers · {sum(a["device_admin"] for a in apps)} device admins')]:
        time.sleep(0.55)
        emit(step, detail)
    return scan


@app.post("/api/scan")
def scan(replay: bool = False):
    events = queue.Queue()

    def emit(step, detail=""):
        events.put({"step": step, "detail": detail})

    def run():
        try:
            data = _replay_scan(emit) if replay else _live_scan(emit)
            findings = scorer.analyse(data)
            time.sleep(0.4 if replay else 0)
            emit("match", f"checked against {len(matcher.STALKERWARE)} known stalkerware and {len(matcher.WATCHWARE)} watchware packages (Echap)")
            STATE.update(scan=data, findings=findings, replay=replay, abuse=None)
            events.put({"result": {"device": data["device"], "collected_at": data["collected_at"],
                                   "replay": replay, "findings": findings}})
        except Exception as error:
            events.put({"error": str(error)})
        events.put(None)

    threading.Thread(target=run, daemon=True).start()

    def stream():
        while (event := events.get()) is not None:
            yield json.dumps(event, ensure_ascii=False) + "\n"

    return StreamingResponse(stream(), media_type="application/x-ndjson")


class SealRequest(BaseModel):
    safety_plan: bool = True
    volunteer: str = "Help-desk volunteer"


@app.post("/api/messages")
def messages(replay: bool = False):
    chats = []
    if replay:
        raw = open(os.path.join(FIXTURES, "chat_R.txt"), encoding="utf-8").read()
        chats.append(abuse.analyse_chat("WhatsApp Chat with R.txt", raw))
    else:
        listing = collector.adb("shell", "ls", "/sdcard/Download/").splitlines()
        names = [n.strip() for n in listing if n.strip().lower().endswith(".txt")
                 and any(h in n.lower() for h in CHAT_HINTS)]
        if not names:
            raise HTTPException(404, "No chat export found in Downloads. On her phone: WhatsApp chat → Export chat (without media).")
        tmp = os.path.join(FIXTURES, "_chat_pull.txt")
        for name in names:
            collector.adb("pull", f"/sdcard/Download/{name}", tmp)
            chats.append(abuse.analyse_chat(name, open(tmp, encoding="utf-8").read()))
        if os.path.exists(tmp):
            os.remove(tmp)
    band = "HIGH" if any(c["band"] == "HIGH" for c in chats) else \
           ("REVIEW" if any(c["band"] == "REVIEW" for c in chats) else "NORMAL")
    method = "on-device patterns + Desk ML model, English + Tamil" if abuse.mlclassifier.available() \
        else "on-device patterns, English + Tamil"
    result = {"analysed_at": _now(), "replay": replay, "method": method,
              "categories": sorted({x for c in chats for x in c["categories"]}),
              "flagged_total": sum(len(c["flagged"]) for c in chats), "band": band, "chats": chats}
    STATE["abuse"] = result
    return result


@app.post("/api/seal")
def seal(body: SealRequest):
    if not STATE["findings"]:
        raise HTTPException(400, "scan first")
    created = _now()
    case_id = f"ARAN-{created[:10].replace('-', '')}-{secrets.token_hex(2).upper()}"
    os.makedirs(os.path.join(CASES, case_id))
    pack = {
        "format": "aran-evidence/1",
        "case_id": case_id,
        "created_at": created,
        "desk": {"software": "Aran Desk 0.1", "volunteer": body.volunteer},
        "device": STATE["scan"]["device"],
        "consent": {"given": True, "safety_plan_discussed": body.safety_plan, "recorded_at": created},
        "scan": {"collected_at": STATE["scan"]["collected_at"], "method": "adb, read-only",
                 "apps_checked": len(STATE["findings"]), "replay": STATE["replay"],
                 "indicators": f"Echap stalkerware-indicators, {len(matcher.STALKERWARE)} packages"},
        "actions": {"removed": [], "note": "Nothing was removed from this device"},
        "items": STATE["findings"],
    }
    if STATE["abuse"]:
        pack["messages"] = STATE["abuse"]
    sealer.seal(pack)
    folder = os.path.join(CASES, case_id)
    _write_json(os.path.join(folder, "evidence.json"), pack)
    pdf = report.render_pdf(report.report_body(pack), os.path.join(folder, "report.pdf"))
    signed = sealer.sign_file(pdf)
    return {"case_id": case_id, "sha256": pack["seal"]["sha256"], "ed25519": pack["seal"]["ed25519"],
            "public_key": pack["seal"]["desk_public_key"], "items": len(pack["items"]),
            "report": f"/cases/{case_id}/{os.path.basename(pdf)}", "report_sha256": signed["sha256"],
            "path": os.path.relpath(os.path.join(folder, "evidence.json"), ROOT)}


@app.post("/api/verify/{case_id}")
def verify(case_id: str):
    folder = _case_dir(case_id)
    try:
        pack = json.load(open(os.path.join(folder, "evidence.json"), encoding="utf-8"))
    except json.JSONDecodeError as error:
        return {"evidence": {"ok": False, "message": f"evidence.json is no longer valid JSON ({error.msg})"}}
    result = {"evidence": sealer.verify(pack)}
    if os.path.exists(os.path.join(folder, "report.pdf.sig.json")):
        result["report"] = sealer.verify_file(os.path.join(folder, "report.pdf"))
    vault_path = os.path.join(folder, "vault_pack.json")
    if os.path.exists(vault_path):
        result["vault"] = vault_chain.verify_chain(json.load(open(vault_path, encoding="utf-8")))
    return result


@app.post("/api/vault/{case_id}")
def vault(case_id: str, replay: bool = False):
    folder = _case_dir(case_id)
    target = os.path.join(folder, "vault_pack.json")
    source = "replay"
    if replay:
        _write_json(target, json.load(open(os.path.join(FIXTURES, "vault_pack.json"), encoding="utf-8")))
    else:
        listing = collector.adb("shell", "ls", "/sdcard/Download/").split()
        packs = sorted(f for f in listing if f.startswith(VAULT_PACK_PREFIX) and f.endswith(".json"))
        if not packs:
            raise HTTPException(404, "No Vault export found in Downloads. On her phone: Vault → Export pack.")
        source = f"/sdcard/Download/{packs[-1]}"
        collector.adb("pull", source, target)
    pack = json.load(open(target, encoding="utf-8"))
    result, signature = vault_chain.countersign(pack)
    if signature:
        _write_json(os.path.join(folder, "vault_countersign.json"), signature)
    return {"result": result, "countersignature": signature, "pack": pack, "source": source,
            "path": os.path.relpath(target, ROOT)}


class ComplaintRequest(BaseModel):
    name: str = ""
    contact: str = ""


@app.post("/api/complaint/{case_id}")
def make_complaint(case_id: str, body: ComplaintRequest):
    folder = _case_dir(case_id)
    pack = json.load(open(os.path.join(folder, "evidence.json"), encoding="utf-8"))
    vault_pack = None
    if os.path.exists(os.path.join(folder, "vault_countersign.json")):
        vault_pack = json.load(open(os.path.join(folder, "vault_pack.json"), encoding="utf-8"))
    text = complaint.draft(pack, body.name, body.contact, vault_pack, pack.get("messages"))
    with open(os.path.join(folder, "complaint.txt"), "w", encoding="utf-8") as f:
        f.write(text)
    pdf = report.render_pdf(report.complaint_body(text), os.path.join(folder, "complaint.pdf"))
    sections = complaint.sections_for([f for f in pack["items"] if f["band"] != "NORMAL"], pack.get("messages"))
    return {"text": text, "pdf": f"/cases/{case_id}/{os.path.basename(pdf)}",
            "sections": [{"statute": s, "why": w} for s, w in sections]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
