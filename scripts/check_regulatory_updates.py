#!/usr/bin/env python3
"""Standalone script to check for regulatory updates.

Designed to run from GitHub Actions on a schedule. Exits with:
  0 — all frameworks current, no changes detected
  1 — changes detected or staleness warning (action needed)
  2 — script error

Output is JSON written to stdout for GitHub Actions to parse.
"""

import json
import sys
from pathlib import Path

# Add src to path so we can import the package directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aws_india_compliance.domains import check_staleness, load_manifest
from aws_india_compliance.knowledge import monitor_source_changes


def main() -> int:
    try:
        manifest = load_manifest()
        frameworks = manifest.get("frameworks", {})

        # Staleness check
        staleness = check_staleness()

        # Content hash + circular detection
        source_changes = monitor_source_changes()

        action_needed = False
        findings: list[str] = []

        for fw_key, fw_data in frameworks.items():
            name = fw_data.get("name", fw_key)

            # Check staleness
            if fw_key in staleness.get("stale_frameworks", []):
                findings.append(f"STALE: {name} — last verified {fw_data.get('last_verified', 'unknown')}")
                action_needed = True

            # Check content changes
            sc = source_changes.get(fw_key, {})
            if sc.get("hash_changed"):
                findings.append(f"CONTENT_CHANGED: {name} — source page hash differs from baseline")
                action_needed = True

            # Check new circulars
            new_circulars = sc.get("new_circulars", [])
            if new_circulars:
                findings.append(f"NEW_CIRCULARS: {name} — {len(new_circulars)} new circular(s) detected")
                action_needed = True

        result = {
            "action_needed": action_needed,
            "manifest_version": manifest.get("manifest_version", "unknown"),
            "last_updated": manifest.get("last_updated", "unknown"),
            "findings": findings,
            "staleness": staleness,
        }

        print(json.dumps(result, indent=2))

        if action_needed:
            return 1
        return 0

    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
