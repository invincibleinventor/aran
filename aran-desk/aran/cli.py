"""aran verify <evidence.json | vault_pack.json | report.pdf>  ·  aran tamper <evidence.json>"""
import json
import sys

from . import sealer, vault_chain

GREEN, RED, DIM, BOLD, RESET = "\033[1;32m", "\033[1;31m", "\033[2m", "\033[1m", "\033[0m"


def _print(result, detail=""):
    if result["ok"]:
        print(f"\n  {GREEN}✔ OK{RESET}  {result['message']}")
    else:
        print(f"\n  {RED}✘ FAIL{RESET}  {result['message']}")
    if detail:
        print(f"  {DIM}{detail}{RESET}")
    print()
    return 0 if result["ok"] else 1


def verify(path):
    print(f"{BOLD}Aran Desk · verify{RESET}  {DIM}{path}{RESET}")
    if path.endswith(".pdf"):
        return _print(sealer.verify_file(path))
    try:
        pack = json.load(open(path, encoding="utf-8"))
    except json.JSONDecodeError as error:
        return _print({"ok": False, "message": f"not valid JSON any more ({error.msg})"})
    if pack.get("source") == "aran-vault":
        print(f"  {DIM}walking {len(pack['items'])} hash-chain links from GENESIS…{RESET}")
        return _print(vault_chain.verify_chain(pack))
    seal = pack.get("seal", {})
    print(f"  {DIM}recomputing SHA-256 of {len(pack['items'])} items · checking Ed25519 signature{RESET}")
    result = sealer.verify(pack)
    detail = f"sealed head  {seal.get('sha256', '')}" if result["ok"] else ""
    if "expected" in result:
        detail = f"sealed  {result['expected']}\n  now     {result['actual']}"
    return _print(result, detail)


def tamper(path):
    pack = json.load(open(path, encoding="utf-8"))
    item = pack["items"][0]
    item["score"] = 0.15
    item["band"] = "NORMAL"
    json.dump(pack, open(path, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"changed item 1 ({item.get('label')}) score to 0.15 / NORMAL")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("verify", "tamper"):
        print(__doc__)
        return 2
    return verify(sys.argv[2]) if sys.argv[1] == "verify" else tamper(sys.argv[2])


if __name__ == "__main__":
    sys.exit(main())
