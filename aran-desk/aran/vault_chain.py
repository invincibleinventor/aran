"""Verifies an Aran Vault export pack (hash chain), then the Desk countersigns its head."""
import hashlib
from datetime import datetime, timezone
from .sealer import desk_key, public_hex


def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def entry_body(entry, prev):
    return f'{entry["index"]}|{entry["type"]}|{entry["name"]}|{entry["added_at"]}|{entry["content_sha256"]}|{entry["cipher_sha256"]}|{prev}'


def verify_chain(pack):
    prev = "GENESIS"
    for entry in pack["items"]:
        if entry["prev"] != prev:
            return {"ok": False, "where": entry["index"], "message": f'Chain broken at item {entry["index"] + 1}: link to the previous item does not match'}
        if _h(entry_body(entry, prev)) != entry["hash"]:
            return {"ok": False, "where": entry["index"], "message": f'Chain broken at item {entry["index"] + 1} ({entry["name"]}): it was changed after import'}
        prev = entry["hash"]
    if prev != pack["head"]:
        return {"ok": False, "where": "head", "message": "Chain head does not match the last item"}
    return {"ok": True, "message": f'Chain intact: {len(pack["items"])} items, head {prev[:12]}…', "head": prev}


def countersign(pack):
    result = verify_chain(pack)
    if not result["ok"]:
        return result, None
    signed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload = f'aran-vault-head|{pack["head"]}|{signed_at}'
    return result, {"head": pack["head"], "signed_at": signed_at,
                    "ed25519": desk_key().sign(payload.encode()).hex(), "desk_public_key": public_hex()}
