#!/usr/bin/env python3
"""Frisk Intel Manifest Manager

Manages {INTEL_DIR}/manifest.json — tracks source sync status.
"""

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'common'))
from config import INTEL_DIR

MANIFEST_PATH = os.path.join(INTEL_DIR, "manifest.json")

def load_manifest():
    """Load manifest, create empty if missing."""
    if os.path.exists(MANIFEST_PATH):
        with open(MANIFEST_PATH, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                pass
    return {
        "version": "2.0",
        "sources": [],
        "updated_at": None
    }

def save_manifest(manifest):
    """Atomic write manifest."""
    manifest["updated_at"] = datetime.now(timezone.utc).isoformat()
    tmp = MANIFEST_PATH + ".new"
    with open(tmp, 'w') as f:
        json.dump(manifest, f, indent=2, sort_keys=False)
    os.rename(tmp, MANIFEST_PATH)

def update_source(name, url="", record_count=0, status="success", error_msg=""):
    """Update or add a source entry in the manifest."""
    manifest = load_manifest()
    found = False
    for src in manifest["sources"]:
        if src["name"] == name:
            src["url"] = url
            src["last_sync"] = datetime.now(timezone.utc).isoformat()
            src["record_count"] = record_count
            src["status"] = status
            if error_msg:
                src["error"] = error_msg
            elif "error" in src:
                del src["error"]
            found = True
            break
    if not found:
        entry = {
            "name": name,
            "url": url,
            "last_sync": datetime.now(timezone.utc).isoformat(),
            "record_count": record_count,
            "status": status
        }
        if error_msg:
            entry["error"] = error_msg
        manifest["sources"].append(entry)
    save_manifest(manifest)

def get_source(name):
    """Get a source entry by name."""
    manifest = load_manifest()
    for src in manifest["sources"]:
        if src["name"] == name:
            return src
    return None

def get_status():
    """Return manifest summary for status display."""
    return load_manifest()

def main():
    if len(sys.argv) < 2:
        print("Usage: manifest.py <update|status> [args...]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "update":
        if len(sys.argv) < 4:
            print("Usage: manifest.py update <name> <record_count> [status] [error_msg]")
            sys.exit(1)
        name = sys.argv[2]
        count = int(sys.argv[3])
        status = sys.argv[4] if len(sys.argv) > 4 else "success"
        error = sys.argv[5] if len(sys.argv) > 5 else ""
        update_source(name, record_count=count, status=status, error_msg=error)
    elif cmd == "status":
        manifest = get_status()
        print(json.dumps(manifest, indent=2))
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()