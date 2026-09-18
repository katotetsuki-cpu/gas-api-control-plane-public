#!/usr/bin/env python3
import hashlib
import json
import sys
from pathlib import Path

def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def main() -> int:
    if len(sys.argv) != 2:
        print("USAGE_ERROR", file=sys.stderr)
        return 2
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    files = payload.get("files") or []
    entries = []
    total_bytes = 0
    manifest_present = False
    for item in files:
        name = str(item.get("name", ""))
        file_type = str(item.get("type", ""))
        source = str(item.get("source", ""))
        if name == "appsscript" and file_type == "JSON":
            manifest_present = True
        raw = source.encode("utf-8")
        total_bytes += len(raw)
        entries.append({
            "name_sha256": sha256_text(name),
            "type": file_type,
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "source_bytes": len(raw),
        })
    entries.sort(key=lambda e: (e["name_sha256"], e["type"]))
    aggregate = hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    receipt = {
        "state": "PASS_READONLY_GETCONTENT" if manifest_present else "FAIL_MANIFEST_MISSING",
        "script_id_sha256": sha256_text(str(payload.get("scriptId", ""))),
        "file_count": len(files),
        "manifest_present": manifest_present,
        "total_source_bytes": total_bytes,
        "files": entries,
        "aggregate_fingerprint": aggregate,
        "source_exposed": False,
        "mutation_count": 0,
    }
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if manifest_present else 1

if __name__ == "__main__":
    raise SystemExit(main())
