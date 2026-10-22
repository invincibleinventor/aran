"""Seals an evidence pack with SHA-256 + Ed25519, and re-verifies it."""
import hashlib
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "keys", "desk_ed25519.pem")


def desk_key():
    if not os.path.exists(KEY_PATH):
        key = Ed25519PrivateKey.generate()
        with open(KEY_PATH, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        os.chmod(KEY_PATH, 0o600)
    with open(KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), None)


def public_hex(key=None):
    return (key or desk_key()).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sha256(obj):
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


def _header(pack):
    return {k: v for k, v in pack.items() if k not in ("items", "seal")}


def _head(header_hash, item_hashes):
    return hashlib.sha256((header_hash + "".join(item_hashes)).encode()).hexdigest()


def seal(pack):
    key = desk_key()
    header_hash = sha256(_header(pack))
    item_hashes = [sha256(item) for item in pack["items"]]
    head = _head(header_hash, item_hashes)
    pack["seal"] = {
        "algorithm": "SHA-256 per item, head = SHA-256(header || items); Ed25519 over head",
        "header_sha256": header_hash,
        "item_sha256": item_hashes,
        "sha256": head,
        "ed25519": key.sign(head.encode()).hex(),
        "desk_public_key": public_hex(key),
    }
    return pack


def verify(pack):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    seal_block = pack.get("seal") or {}
    if sha256(_header(pack)) != seal_block.get("header_sha256"):
        return {"ok": False, "where": "header", "message": "Case details were changed after sealing"}
    stored = seal_block.get("item_sha256", [])
    if len(stored) != len(pack["items"]):
        return {"ok": False, "where": "items", "message": f"Items were added or removed ({len(stored)} sealed, {len(pack['items'])} now)"}
    for index, item in enumerate(pack["items"]):
        if sha256(item) != stored[index]:
            return {"ok": False, "where": index, "label": item.get("label") or item.get("package"),
                    "message": f"Item {index + 1} ({item.get('label') or item.get('package')}) was changed after sealing",
                    "expected": stored[index], "actual": sha256(item)}
    head = _head(seal_block["header_sha256"], stored)
    if head != seal_block.get("sha256"):
        return {"ok": False, "where": "head", "message": "Seal hash does not match the items"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(seal_block["desk_public_key"])).verify(
            bytes.fromhex(seal_block["ed25519"]), head.encode())
    except Exception:
        return {"ok": False, "where": "signature", "message": "Desk signature does not match. The seal was forged or recomputed"}
    if seal_block["desk_public_key"] != public_hex():
        return {"ok": False, "where": "key", "message": "Signed by a different Desk key than this one"}
    return {"ok": True, "message": f"Sealed evidence is intact: {len(stored)} items, signature valid", "sha256": head}


def sign_file(path):
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    record = {"file": os.path.basename(path), "sha256": digest,
              "ed25519": desk_key().sign(digest.encode()).hex(), "desk_public_key": public_hex()}
    with open(path + ".sig.json", "w") as f:
        json.dump(record, f, indent=2)
    return record


def verify_file(path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    record = json.load(open(path + ".sig.json"))
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    if digest != record["sha256"]:
        return {"ok": False, "message": f"{record['file']} was changed after it was signed"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(record["desk_public_key"])).verify(
            bytes.fromhex(record["ed25519"]), digest.encode())
    except Exception:
        return {"ok": False, "message": "Signature does not match"}
    return {"ok": True, "message": f"{record['file']} is intact, signature valid", "sha256": digest}
