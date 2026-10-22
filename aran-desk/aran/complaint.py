"""Complaint draft. Statutes come only from this fixed, reviewed list. No network, no LLM."""
SECTION_RULES = [
    (lambda f: f["band"] == "HIGH",
     "BNS 2023 s.78(1)(ii): stalking, including monitoring a woman's use of the internet or electronic communication",
     "A concealed app was monitoring the phone"),
    (lambda f: "reads_notifs" in f["signals"] or "android.permission.READ_SMS" in f.get("requested", []),
     "IT Act 2000 s.66E: violation of privacy",
     "The app could read private messages and notifications"),
    (lambda f: "sideloaded" in f["signals"] and f["band"] != "NORMAL",
     "IT Act 2000 s.43 read with s.66: unauthorised access to a computer resource",
     "Installed from outside the Play Store without the owner's informed consent"),
]
# Statutes raised by the content of messages, independent of any app on the phone.
MESSAGE_RULES = {
    "threat": ("BNS 2023 s.351: criminal intimidation",
               "Messages threatened harm if she spoke out"),
    "surveillance": ("BNS 2023 s.78(1)(ii): stalking, including monitoring a woman's communication",
                     "Messages show her movements and messages were being watched"),
}
ALWAYS = ("BSA 2023 s.63(4): electronic record with a certificate stating its hash value",
          "Each exhibit carries its SHA-256 hash and the Desk's Ed25519 signature")


def sections_for(findings, abuse=None):
    out = []
    for finding in findings:
        for predicate, statute, why in SECTION_RULES:
            if predicate(finding) and all(statute != s for s, _ in out):
                out.append((statute, why))
    for category in (abuse or {}).get("categories", []):
        rule = MESSAGE_RULES.get(category)
        if rule and all(rule[0] != s for s, _ in out):
            out.append(rule)
    return out + [ALWAYS]


def draft(case, name="", contact="", vault=None, abuse=None):
    flagged = [f for f in case["items"] if f["band"] != "NORMAL"]
    findings = "\n".join(
        f'  {i}. {f["label"]} ({f["package"]}): {f["band"]} {f["score"]:.2f}\n'
        + "\n".join(f'     - {r["en"]}' for r in f["reasons"] if r["key"] != "allowlisted")
        for i, f in enumerate(flagged, 1)) or "  No suspicious apps were found."
    sections = "\n".join(f"  - {s}\n    ({why})" for s, why in sections_for(flagged, abuse))
    msg_block = ""
    msgs = [m for c in (abuse or {}).get("chats", []) for m in c["flagged"]]
    if msgs:
        lines = "\n".join(f'  - {m["time"]} — "{m["text"]}"\n'
                          f'    ({", ".join(sorted({c["en"].split(" — ")[0] for c in m["categories"]}))})'
                          for m in msgs)
        msg_block = f"\n\nThreatening or monitoring messages (on-device analysis)\n{lines}"
    seal = case["seal"]
    exhibits = [f'  Exhibit A: Aran Desk scan report (report.pdf)\n    Evidence SHA-256: {seal["sha256"]}\n    Desk signature (Ed25519): {seal["ed25519"][:64]}…']
    if vault:
        exhibits.append(f'  Exhibit B: Aran Vault evidence chain, {len(vault["items"])} items, countersigned by the Desk\n'
                        f'    Chain head SHA-256: {vault["head"]}')
        exhibits += [f'    B{e["index"] + 1}. {e["type"].replace("_", " ")} "{e["name"]}" SHA-256 {e["content_sha256"]}' for e in vault["items"]]
    device = case["device"]
    return f"""To: National Cyber Crime Reporting Portal (cybercrime.gov.in)
Category: Women/Children Related Crime > Cyber Stalking / Bullying

Complainant: {name or "[her name]"}        Contact: {contact or "[phone or email]"}
Date of scan: {case["created_at"][:10]}        Case reference: {case["case_id"]}

What happened
  My phone ({device["model"]}, Android {device["android"]}) was checked at a help desk
  with my consent, using a read-only USB scan. It found app(s) that can monitor me:

{findings}

Legal provisions (for review with a legal-aid volunteer)
{sections}{msg_block}

Evidence manifest
{chr(10).join(exhibits)}

Declaration
  The device was scanned with my consent. Nothing was removed from it.
  I have read this draft and I am submitting this complaint myself.

---
Draft prepared by Aran Desk for her review. Not legal advice. Not court-admissible on its own.
"""
