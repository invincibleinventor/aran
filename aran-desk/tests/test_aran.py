import ast
import copy
import json
import os
import re

import pytest

from aran import collector, scorer, sealer, vault_chain

ROOT = os.path.join(os.path.dirname(__file__), "..")
SCAN = json.load(open(os.path.join(ROOT, "fixtures", "scan.json")))
FORBIDDEN = {"uninstall", "install", "install-multiple", "force-stop", "clear", "disable", "disable-user",
             "kill", "push", "rm", "reboot", "remount", "root", "sideload", "uninstall-system-updates"}


def _adb_calls():
    for folder in ("aran", "."):
        for name in os.listdir(os.path.join(ROOT, folder)):
            if name.endswith(".py"):
                tree = ast.parse(open(os.path.join(ROOT, folder, name)).read())
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "adb":
                        yield name, tuple(a.value for a in node.args if isinstance(a, ast.Constant))


def test_desk_never_calls_uninstall_disable_or_force_stop():
    calls = list(_adb_calls())
    assert len(calls) >= 10
    for name, args in calls:
        assert not FORBIDDEN & set(args), f"{name}: destructive adb call {args}"
        assert any(args[:len(p)] == p for p in collector.READ_ONLY_PREFIXES), f"{name}: adb call outside read-only list {args}"


@pytest.mark.parametrize("args", [("uninstall", "com.x"), ("shell", "pm", "uninstall", "com.x"),
                                  ("shell", "am", "force-stop", "com.x"), ("install", "x.apk"),
                                  ("shell", "pm", "disable-user", "com.x"), ("shell", "rm", "-rf", "/sdcard")])
def test_adb_wrapper_blocks_writes(args):
    with pytest.raises(collector.ReadOnlyViolation):
        collector.adb(*args)


def test_mock_spy_app_scores_high_085_like_slide_7():
    finding = scorer.analyse(SCAN)[0]
    assert finding["package"] == "com.aran.systemsync"
    assert (finding["band"], finding["score"]) == ("HIGH", 0.85)
    assert all(r["ta"] for r in finding["reasons"])


def test_allowlist_requires_store_install():
    whatsapp = next(a for a in SCAN["apps"] if a["package"] == "com.whatsapp")
    assert scorer.score_app(whatsapp)["band"] == "NORMAL"
    fake = {**whatsapp, "installer": None, "has_launcher": False, "notif_listener": True}
    assert scorer.score_app(fake)["band"] != "NORMAL"


def test_known_stalkerware_goes_straight_to_high():
    pkg = next(iter(__import__("aran.matcher").matcher.STALKERWARE))
    app = {**SCAN["apps"][-1], "package": pkg}
    assert scorer.score_app(app)["score"] == 1.0


def _pack():
    return sealer.seal({"case_id": "T", "device": SCAN["device"], "items": copy.deepcopy(scorer.analyse(SCAN))})


def test_seal_verifies_and_one_byte_change_fails():
    pack = _pack()
    assert sealer.verify(pack)["ok"]
    pack["items"][0]["score"] = 0.15
    result = sealer.verify(pack)
    assert not result["ok"] and result["where"] == 0


def test_recomputed_hashes_still_fail_on_signature():
    pack = _pack()
    pack["items"][0]["band"] = "NORMAL"
    pack["seal"]["item_sha256"][0] = sealer.sha256(pack["items"][0])
    pack["seal"]["sha256"] = sealer._head(pack["seal"]["header_sha256"], pack["seal"]["item_sha256"])
    assert sealer.verify(pack)["where"] == "signature"


def test_vault_chain_detects_edit():
    pack = json.load(open(os.path.join(ROOT, "fixtures", "vault_pack.json")))
    assert vault_chain.verify_chain(pack)["ok"]
    pack["items"][1]["content_sha256"] = "0" * 64
    assert vault_chain.verify_chain(pack)["where"] == 1


def test_dumpsys_parser():
    text = """Packages:
  Package [com.aran.systemsync] (abc):
    versionName=2.4.1
    firstInstallTime=2026-10-09 23:41:17
    requested permissions:
      android.permission.READ_SMS
      android.permission.RECEIVE_BOOT_COMPLETED
    install permissions:
      android.permission.RECEIVE_BOOT_COMPLETED: granted=true
    User 0: ceDataInode=1 installed=true
      runtime permissions:
        android.permission.READ_SMS: granted=false, flags=[ ]
"""
    facts = collector.parse_dumpsys_packages(text)["com.aran.systemsync"]
    assert facts["versionName"] == "2.4.1"
    assert facts["requested"] == ["android.permission.READ_SMS", "android.permission.RECEIVE_BOOT_COMPLETED"]
    assert facts["granted"] == ["android.permission.RECEIVE_BOOT_COMPLETED"]
