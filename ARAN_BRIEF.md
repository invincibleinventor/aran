# Aran Desk — Team Brief

*One page to get anyone, with zero background, fully up to speed.*

---

## The one-sentence version

**Aran Desk helps a domestic-abuse victim find out if her phone is secretly spying on her, catch abusive messages in English and Tamil, and turn it all into tamper-proof evidence she can take to the police — without a laptop, an account, or the internet.**

"Aran" (அரண்) means *fortress / shield* in Tamil.

---

## The problem we're solving

Abusers increasingly use phones as weapons. Two patterns:

1. **Stalkerware** — hidden apps the abuser installs on the victim's phone to secretly read her messages, track her location, and listen to calls. They hide their own icon, so she can't see them. This is a real, common form of domestic abuse.
2. **Abusive & threatening messages** — surveillance ("I know where you were"), control ("come home now"), isolation ("why are you talking to him"), slurs, and threats — often in **Tanglish** (Tamil written in English letters), which normal filters don't understand.

Victims usually have no safe, simple way to **prove** any of this. Screenshots can be faked; a phone can be wiped. Courts need trustworthy evidence.

---

## What we built (three parts)

### 1. The Desk — a read-only phone scanner
A small web app that runs **on a helper's laptop** (a counsellor / help-desk volunteer). The victim's phone is plugged in by USB. The Desk:
- Lists installed apps and their permissions, **reading only — it never installs, removes, or changes anything** on her phone.
- Flags suspicious apps: known stalkerware, apps that hide their icon, read notifications, use accessibility services, or were installed from outside the Play Store.
- **Every flag comes with a plain-language reason in Tamil + English** — nothing is a black box.

### 2. The Vault — a disguised app on the phone
An Android app that looks like an ordinary **Calculator**. Type a PIN to reveal the real vault. It:
- Stores evidence (screenshots, chat exports) **encrypted with a hardware key** (AES-256). Nothing leaves the phone unless she chooses to export.
- Quietly **watches incoming notifications** and auto-captures abusive messages the moment they arrive — so the evidence exists even if the sender deletes the message later.

### 3. The abuse-message detector (two layers)
This reads chat exports and flags abuse:
- **Layer 1 — transparent rules:** a curated keyword + grammar system for English and Tamil (script + Tanglish). Fast, offline, and every hit names the exact phrase that fired, so it holds up in court.
- **Layer 2 — a trained AI model:** a machine-learning classifier that catches *veiled* abuse the keywords miss — threats with no bad word, like *"don't make me come find you"* (flagged 94% abusive). It's the "proper AI" layer, and it only ever **adds** warnings on top of the rules; if it ever fails to load, the rules still work. Nothing breaks.

---

## How the evidence becomes trustworthy

When she's ready, the Desk **seals** the report: it hashes every finding (SHA-256) and signs it with the Desk's key (Ed25519), and links each item to the one before it in a **chain**. If anyone later changes a single character, the chain breaks and verification fails. This is the same idea that makes a blockchain tamper-evident. She can then generate a **pre-filled police complaint** citing the relevant legal sections.

---

## Why it's credible (what makes this not a toy)

- **Read-only & consent-first** — the victim agrees on screen before anything runs; the scanner physically refuses any command that would change her phone.
- **Fully offline, no accounts** — runs on `localhost`, makes no network calls. Her data never goes to a server.
- **Bilingual** — built for Tamil speakers, including Tanglish, which mainstream tools ignore.
- **Explainable + AI** — rules give court-ready reasons; the ML model adds reach. Best of both.

> Honest caveat for Q&A: the AI model is trained on a **curated/synthetic corpus**, so don't quote a "100% accuracy" number — demonstrate it live on the veiled-threat example instead.

---

## The demo flow (what the video shows)

1. **Consent** screen → 2. **Connect** the phone by USB → 3. **Scan** (read-only) → 4. **Explain**: flagged apps *and* flagged messages, each with Tamil+English reasons and the AI badge → 5. **Seal** the evidence → 6. **She decides**: save to Vault, draft a police complaint, or plan removal.

---

## How to run it (for teammates)

**The Desk (laptop):**
```bash
cd aran-desk
python3 -m uvicorn main:app --port 8000
# open http://127.0.0.1:8000
```

**Install the Vault app on a test phone:**
- Easiest: open **http://127.0.0.1:8000/install**, plug in the phone (USB debugging on), click **Install Aran Vault**.
- Or by command line:
  ```bash
  ~/Library/Android/sdk/platform-tools/adb install -r android/vault.apk
  ```
- After install: open the Calculator disguise, enter the PIN to reveal the vault, and enable **Notification access** for Aran Vault in Settings if it wasn't granted automatically.

> ⚠️ The install page **writes to the phone** — use a test device you own, never the victim-facing read-only flow.

---

## Glossary

| Term | Plain meaning |
|---|---|
| **Stalkerware** | Hidden spying app an abuser secretly installs |
| **Tanglish** | Tamil written in English letters (e.g. "phone check panren") |
| **adb** | The standard tool to talk to an Android phone over USB |
| **Read-only** | Can look but never change/install/delete |
| **Hash / SHA-256** | A fingerprint of data; changes if the data changes — used to detect tampering |
| **Hash chain** | Items linked by fingerprints so no item can be altered unnoticed |
| **APK** | An Android app installer file |
