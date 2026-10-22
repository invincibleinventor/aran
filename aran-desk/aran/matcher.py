"""Echap stalkerware-indicators (CC BY 4.0) + the known-good allowlist."""
import os
import yaml

DATA = os.path.join(os.path.dirname(__file__), "..", "data")


def _load(name):
    index = {}
    with open(os.path.join(DATA, name)) as f:
        for entry in yaml.safe_load(f):
            for pkg in entry.get("packages") or []:
                index[pkg] = entry["name"]
    return index


STALKERWARE = _load("ioc.yaml")
WATCHWARE = _load("watchware.yaml")
with open(os.path.join(DATA, "allowlist.txt")) as f:
    ALLOWLIST = {l.split("#")[0].strip() for l in f if l.split("#")[0].strip()}


def known_stalkerware(pkg):
    return STALKERWARE.get(pkg)


def on_watchware(pkg):
    return pkg in WATCHWARE


def allowlisted(app):
    # A sideloaded APK can reuse a trusted package name, so the discount needs a store install.
    from .collector import PLAY_STORES
    return app["package"] in ALLOWLIST and app.get("installer") in PLAY_STORES
