"""Compile all framework YAML files into a single control_mappings.json.

This script reads every YAML file in src/aws_india_compliance/frameworks/
(excluding files starting with underscore) and generates the unified
control_mappings.json file that the existing codebase uses at runtime.

Usage:
    python scripts/build_manifest.py

The output is written to src/aws_india_compliance/control_mappings.json.
Run this after editing any framework YAML to keep the JSON in sync.
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

import yaml

# Paths relative to repository root
REPO_ROOT = Path(__file__).resolve().parent.parent
FRAMEWORKS_DIR = REPO_ROOT / "src" / "aws_india_compliance" / "frameworks"
OUTPUT_FILE = REPO_ROOT / "src" / "aws_india_compliance" / "control_mappings.json"


def load_frameworks() -> dict[str, dict]:
    """Load all framework YAML files and return them keyed by id."""
    frameworks: dict[str, dict] = {}

    if not FRAMEWORKS_DIR.is_dir():
        print(f"Error: frameworks directory not found at {FRAMEWORKS_DIR}", file=sys.stderr)
        sys.exit(1)

    for filepath in sorted(FRAMEWORKS_DIR.glob("*.yaml")):
        if filepath.name.startswith("_"):
            continue

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except (yaml.YAMLError, OSError) as e:
            print(f"Error reading {filepath.name}: {e}", file=sys.stderr)
            sys.exit(1)

        if not isinstance(data, dict) or "id" not in data:
            print(f"Error: {filepath.name} is missing required 'id' field.", file=sys.stderr)
            sys.exit(1)

        frameworks[data["id"]] = data
        print(f"  Loaded: {data['id']} ({len(data.get('domains', {}))} domains)")

    return frameworks


def build_manifest(frameworks: dict[str, dict]) -> dict:
    """Build the control_mappings.json structure from loaded frameworks."""
    manifest: dict = {
        "manifest_version": "2.0.0",
        "last_updated": date.today().isoformat(),
        "generated_by": "scripts/build_manifest.py",
        "note": "This file is auto-generated from frameworks/*.yaml. Do not edit directly.",
        "frameworks": {},
        "regulatory_sources": {},
        "update_history": [],
    }

    for fw_id, fw_data in frameworks.items():
        # Build the framework entry in the expected JSON format
        fw_entry: dict = {
            "name": fw_data.get("name", ""),
            "version": fw_data.get("version", ""),
            "source_url": fw_data.get("source_url", ""),
            "last_verified": fw_data.get("last_verified", ""),
            "domains": {},
        }

        # Convert domains from integer keys back to string keys (JSON requires string keys)
        for dom_key, dom_data in fw_data.get("domains", {}).items():
            dom_str = str(dom_key)
            domain_entry: dict = {
                "name": dom_data.get("name", ""),
                "section": dom_data.get("section", ""),
                "type": dom_data.get("type", "technical"),
                "aws_controls": dom_data.get("aws_controls", []),
                "config_rules": dom_data.get("config_rules", []),
                "guardrails": dom_data.get("guardrails", []),
            }
            # Include optional fields if present
            if dom_data.get("nist_csf"):
                domain_entry["nist_csf"] = dom_data["nist_csf"]
            if dom_data.get("notes"):
                # Collapse multiline notes to a single line for JSON
                notes = dom_data["notes"].strip().replace("\n", " ")
                domain_entry["rules_2025_notes"] = notes

            fw_entry["domains"][dom_str] = domain_entry

        manifest["frameworks"][fw_id] = fw_entry

        # Build regulatory_sources from search_sources and circular_sources
        sources_list: list[dict] = []
        for url in fw_data.get("search_sources", []):
            sources_list.append({"url": url, "type": "regulatory_text"})
        for url in fw_data.get("circular_sources", []):
            sources_list.append({"url": url, "type": "circulars"})
        if sources_list:
            manifest["regulatory_sources"][fw_id] = sources_list

    return manifest


def main() -> None:
    """Main entry point: load YAMLs, build manifest, write JSON."""
    print(f"Building control_mappings.json from {FRAMEWORKS_DIR}/")
    print()

    frameworks = load_frameworks()

    if not frameworks:
        print("Error: no framework YAML files found.", file=sys.stderr)
        sys.exit(1)

    manifest = build_manifest(frameworks)

    # Write output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print()
    print(f"Generated: {OUTPUT_FILE}")
    print(f"  Frameworks: {len(manifest['frameworks'])}")
    total_domains = sum(
        len(fw.get("domains", {})) for fw in manifest["frameworks"].values()
    )
    print(f"  Total domains: {total_domains}")
    print(f"  Manifest version: {manifest['manifest_version']}")


if __name__ == "__main__":
    main()
