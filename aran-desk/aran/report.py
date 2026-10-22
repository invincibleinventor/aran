"""Renders the sealed report and complaint as PDFs through headless Chrome (handles Tamil shaping)."""
import html
import os
import shutil
import subprocess
import tempfile

CHROME = next((p for p in ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                           shutil.which("chromium") or "", shutil.which("google-chrome") or ""] if p and os.path.exists(p)), None)

CSS = """
@page { size: A4; margin: 16mm 14mm; }
body { font-family: -apple-system, 'Helvetica Neue', 'Tamil Sangam MN', sans-serif; color: #1c1f4a; font-size: 10.5pt; }
h1 { font-size: 22pt; margin: 0; letter-spacing: -0.5px; } h1 span { color: #d9442b; font-weight: 600; margin-left: 8px; }
h2 { font-size: 12pt; margin: 18px 0 6px; border-bottom: 2px solid #1c1f4a; padding-bottom: 3px; }
.meta { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-top: 10px; }
.meta div { background: #f1f2f8; padding: 6px 8px; border-radius: 4px; font-size: 9pt; } .meta b { display: block; font-size: 7.5pt; color: #5b5f86; text-transform: uppercase; letter-spacing: .5px; }
.banner { margin-top: 10px; padding: 8px 10px; background: #e3f2ee; color: #0f6b5c; font-weight: 600; border-radius: 4px; }
.app { border: 1px solid #d9dbe8; border-left: 5px solid #ccc; border-radius: 4px; padding: 8px 10px; margin: 8px 0; page-break-inside: avoid; }
.app.HIGH { border-left-color: #d9442b; } .app.REVIEW { border-left-color: #b8760a; }
.app .top { display: flex; justify-content: space-between; } .app .pkg { color: #5b5f86; font-size: 8.5pt; }
.chip { color: #fff; font-weight: 700; font-size: 9pt; padding: 3px 8px; border-radius: 3px; } .chip.HIGH { background: #d9442b; } .chip.REVIEW { background: #b8760a; } .chip.NORMAL { background: #137a6b; }
.reason { margin: 4px 0 0 0; font-size: 9.5pt; } .reason .ta { color: #5b5f86; } .reason .w { float: right; color: #5b5f86; }
table { width: 100%; border-collapse: collapse; font-size: 8.5pt; } td, th { text-align: left; padding: 3px 4px; border-bottom: 1px solid #e6e7f0; }
.hash { font-family: Menlo, monospace; font-size: 7.5pt; word-break: break-all; background: #f1f2f8; padding: 6px 8px; border-radius: 4px; }
.foot { margin-top: 16px; font-size: 8pt; color: #5b5f86; } pre { white-space: pre-wrap; font-family: Menlo, monospace; font-size: 8.5pt; line-height: 1.45; }
"""


def render_pdf(body, path):
    page = f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{body}</body></html>"
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as f:
        f.write(page)
    if not CHROME:
        shutil.copy(f.name, path.replace(".pdf", ".html"))
        return path.replace(".pdf", ".html")
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    f"--print-to-pdf={path}", f"file://{f.name}"], capture_output=True, timeout=60)
    os.unlink(f.name)
    return path


def _reason(r):
    weight = "" if r["weight"] is None else f'{r["weight"]:+.2f}'
    return f"<div class='reason'><span class='w'>{weight}</span>{html.escape(r['en'])}<br><span class='ta'>{html.escape(r['ta'])}</span></div>"


def report_body(case):
    e = html.escape
    d, seal = case["device"], case["seal"]
    flagged = [f for f in case["items"] if f["band"] != "NORMAL"]
    normal = [f for f in case["items"] if f["band"] == "NORMAL"]
    cards = "".join(
        f"""<div class="app {f['band']}"><div class="top"><div><b>{e(f['label'])}</b><div class="pkg">{e(f['package'])} · v{e(str(f.get('version') or '?'))} · installed {e(str(f.get('first_install') or '?'))} · source: {e(f.get('installer') or 'sideloaded (not a store)')}</div></div>
        <div><span class="chip {f['band']}">{f['band']} {f['score']:.2f}</span></div></div>
        {''.join(_reason(r) for r in f['reasons'])}
        </div>""" for f in flagged) or "<p>No suspicious apps were found.</p>"
    rows = "".join(f"<tr><td>{e(f['label'])}</td><td>{e(f['package'])}</td><td>{e(f.get('installer') or 'sideloaded')}</td><td>{f['score']:.2f}</td></tr>" for f in normal)
    vault = case.get("vault")
    vault_html = ""
    if vault:
        vrows = "".join(f"<tr><td>{x['index'] + 1}</td><td>{e(x['type'])}</td><td>{e(x['name'])}</td><td class='hash' style='background:none;padding:3px 4px'>{x['content_sha256']}</td></tr>" for x in vault["items"])
        vault_html = f"""<h2>Aran Vault evidence chain (countersigned)</h2><table><tr><th>#</th><th>Type</th><th>Name</th><th>Content SHA-256</th></tr>{vrows}</table>
        <div class="hash" style="margin-top:6px">Chain head: {vault['head']}<br>Desk countersignature (Ed25519): {vault['countersignature']['ed25519']}<br>Signed at: {vault['countersignature']['signed_at']}</div>"""
    return f"""
<h1>Aran Desk · Scan report<span>அரண்</span></h1>
<div class="meta"><div><b>Case</b>{e(case['case_id'])}</div><div><b>Sealed (UTC)</b>{e(case['created_at'])}</div>
<div><b>Device</b>{e(d['model'])} · Android {e(d['android'])}</div><div><b>Apps checked</b>{len(case['items'])}</div></div>
<div class="banner">✓ Read-only scan with her consent. Nothing was removed from this device. · எதுவும் அகற்றப்படவில்லை.</div>
<h2>Apps that need attention ({len(flagged)})</h2>{cards}
<h2>Other apps checked ({len(normal)})</h2><table><tr><th>App</th><th>Package</th><th>Source</th><th>Score</th></tr>{rows}</table>
{vault_html}
<h2>Evidence integrity</h2>
<div class="hash">Evidence SHA-256 (head): {seal['sha256']}<br>Desk signature (Ed25519): {seal['ed25519']}<br>Desk public key: {seal['desk_public_key']}<br>Device serial (SHA-256): {d['serial_sha256']}</div>
<p class="foot">Score = sum of named signals (hidden icon +0.30, notification access +0.20, accessibility +0.20, device admin +0.20, outside Play Store +0.15, sensitive bundle +0.10, battery exemption +0.05, boot +0.05; known-good allowlist −0.40). 0.70+ High, 0.35–0.70 Review. Known stalkerware from Echap stalkerware-indicators (CC BY 4.0).
Verify at any time: <code>aran verify evidence.json</code>. This report supports, but is not by itself, a BSA s.63 certificate.</p>"""


def complaint_body(text):
    return f"<h1>Complaint draft<span>புகார் வரைவு</span></h1><div class='banner' style='background:#fdf1e3;color:#8a5a08'>Draft for her review. She edits and files it herself on cybercrime.gov.in. Not legal advice.</div><pre>{html.escape(text)}</pre>"
