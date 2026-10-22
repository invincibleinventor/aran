# Aran: demo runbook

```
aran-desk/   Python Desk (FastAPI + one offline HTML page). ./run.sh → http://localhost:8000
android/     systemsync.apk (mock spy, HIGH 0.85) · batterysaver.apk (REVIEW 0.40) · vault.apk (Calculator)
             build.sh <app> rebuilds without Gradle · setup_phone.sh installs + grants on the demo phone
```

## One-time setup (≈5 min)
1. Phone: Settings → About → tap Build number 7× → Developer options → **USB debugging ON**. Plug in, tap **Allow**.
2. `android/setup_phone.sh`: installs the 3 APKs, turns on the mock's accessibility + notification access,
   makes Battery Saver a device admin, hides the mock's icon, puts demo screenshot + chat export in Downloads.
   If it prints `!!`, do that step on the phone.
3. `cd aran-desk && ./run.sh`, then run one **live** scan. This saves `fixtures/latest_live.json`, and
   "Replay saved scan" will reuse it if adb flakes.
4. `export PATH="$PWD/aran-desk/bin:$PATH"` so `aran verify …` works in the terminal.

Secret sum: **1947 + 58 =** opens the real vault. Decoy: **1111 + 1 =** opens an empty vault.

## Video shot list (≈3.5 min). Record the Mac screen; mirror the phone with `brew install scrcpy && scrcpy`
| # | Shot | What to say |
|---|------|-------------|
| 1 | Tick consent boxes → Continue | "Nothing runs until she agrees." |
| 2 | Phone appears → **Scan phone**. Progress streams | "Read-only. Nothing installed on her phone." |
| 3 | System Sync Service **HIGH 0.85**. Score bar + 4 reasons, toggle **தமிழ்** | "Every flag has a reason she can read." |
| 4 | Battery Saver **REVIEW**. Expand "apps look normal" (WhatsApp OK) | "Allowlist only counts Play Store installs." |
| 5 | **Seal report** → open PDF | "SHA-256 + Ed25519. Nothing was removed." |
| 6 | **Money shot.** Split screen: terminal + browser. `aran verify cases/<id>/evidence.json` → OK. Open evidence.json in VS Code, change System Sync's `"score": 0.85` → `0.15`, save. Browser turns **red by itself** (live seal watch), then `aran verify` → FAIL item 1 | "One byte changed, and we can show where." |
| 7 | Phone (scrcpy): Calculator, do 12×3. Then `1947+58=` → Vault. Add screenshot + chat export, chain counter goes up. Export pack | "To him it is a calculator." |
| 8 | `1111+1=` → empty vault | "Decoy code for when she's forced to open it." |
| 9 | Desk: **Import Vault export** → chain blocks + countersign | "The Desk anchors when the evidence existed." |
| 10 | Draft complaint → statutes + hashes → Copy | "Aran drafts it. She files it herself." |
| 11 | Terminal: `uv run pytest -q` (14 passed) and show `test_desk_never_calls_uninstall_disable_or_force_stop` | "The build fails if the Desk ever calls uninstall." |

Fallbacks: adb drops → **Replay saved scan** / **Use saved export** (same UI). `aran tamper <evidence.json>` flips item 1 for you.

## Honest limits (say them if asked)
- Mock apps are benign stand-ins with **no INTERNET permission**. They request access and do nothing.
- Cert-hash matching is not built; matching uses Echap package names (615) + behaviour signals.
- The chat-abuse classifier (slide 7) is not in this build.
- Vault export goes to Downloads as a hashes-only JSON. She should delete it after the hand-off.
