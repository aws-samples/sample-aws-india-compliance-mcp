"""CLI-only maintainer tools — not exposed via MCP.

These tools are for package maintainers to update control mappings
when new regulatory circulars are published. End users don't need these.

Usage:
    aws-india-compliance-admin check      # Check for regulatory updates
    aws-india-compliance-admin propose     # Propose mapping update (interactive)
    aws-india-compliance-admin apply       # Apply proposed changes
"""

from __future__ import annotations

import json
import sys
from datetime import date

from .domains import check_staleness, load_manifest, save_manifest
from .knowledge import monitor_source_changes


def cmd_check() -> int:
    """Check regulatory update staleness. Exit 0 = current, 1 = action needed."""
    manifest = load_manifest()
    frameworks = manifest.get("frameworks", {})
    staleness = check_staleness()
    source_changes = monitor_source_changes()

    action_needed = False
    findings: list[str] = []

    for fw_key, fw_data in frameworks.items():
        name = fw_data.get("name", fw_key)

        if fw_key in staleness.get("stale_frameworks", []):
            findings.append(f"STALE: {name} — last verified {fw_data.get('last_verified', 'unknown')}")
            action_needed = True

        sc = source_changes.get(fw_key, {})
        if sc.get("hash_changed"):
            findings.append(f"CONTENT_CHANGED: {name}")
            action_needed = True

        new_circulars = sc.get("new_circulars", [])
        if new_circulars:
            findings.append(f"NEW_CIRCULARS: {name} — {len(new_circulars)} detected")
            action_needed = True

    result = {
        "action_needed": action_needed,
        "manifest_version": manifest.get("manifest_version", "unknown"),
        "last_updated": manifest.get("last_updated", "unknown"),
        "findings": findings,
    }

    print(json.dumps(result, indent=2))
    return 1 if action_needed else 0


def cmd_propose(framework: str, regulatory_text: str, source_url: str = "", circular_date: str = "") -> str:
    """Analyze regulatory text and return current mappings + analysis prompt."""
    manifest = load_manifest()
    fw_data = manifest.get("frameworks", {}).get(framework.lower())
    if not fw_data:
        return json.dumps({"error": f"Unknown framework: {framework}. Use: dpdp, rbi, sebi"})

    current_domains = fw_data.get("domains", {})

    print(f"Framework: {fw_data['name']}")
    print(f"Current domains: {len(current_domains)}")
    print(f"Regulatory text length: {len(regulatory_text)} chars")
    print(f"\nCurrent mappings:\n{json.dumps(current_domains, indent=2)[:2000]}...")
    print(f"\nPaste this into your LLM client with the regulatory text to get proposed changes.")

    return json.dumps({
        "framework": framework,
        "current_mappings": current_domains,
        "source_url": source_url,
        "circular_date": circular_date,
    }, indent=2)


def cmd_apply(framework: str, proposed_changes_json: str, source_url: str = "", circular_date: str = "") -> int:
    """Apply proposed mapping changes to control_mappings.json."""
    try:
        proposed = json.loads(proposed_changes_json)
    except (json.JSONDecodeError, TypeError) as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        return 2

    manifest = load_manifest()
    fw_key = framework.lower()
    fw_data = manifest.get("frameworks", {}).get(fw_key)
    if not fw_data:
        print(f"Error: Unknown framework: {framework}", file=sys.stderr)
        return 2

    impact_level = proposed.get("impact_level", "none")
    if impact_level == "none":
        print("No changes needed.")
        return 0

    changes = proposed.get("proposed_changes", [])
    new_domains = proposed.get("new_domains", [])
    domains = fw_data["domains"]
    applied: list[str] = []

    for change in changes:
        dom_num = change.get("domain", "")
        if dom_num not in domains:
            print(f"Warning: domain {dom_num} not found, skipping")
            continue

        field = change.get("field", "")
        action = change.get("action", "")
        current = domains[dom_num].get(field, [])

        if action == "add" and isinstance(current, list):
            if change["value"] not in current:
                current.append(change["value"])
                domains[dom_num][field] = current
                applied.append(f"Added '{change['value']}' to domain {dom_num}.{field}")
        elif action == "remove" and isinstance(current, list):
            target = change.get("old_value", change.get("value", ""))
            if target in current:
                current.remove(target)
                domains[dom_num][field] = current
                applied.append(f"Removed '{target}' from domain {dom_num}.{field}")
        elif action == "replace":
            old = domains[dom_num].get(field)
            domains[dom_num][field] = change["value"]
            applied.append(f"Replaced domain {dom_num}.{field}: '{old}' → '{change['value']}'")

    for nd in new_domains:
        if not nd.get("name"):
            continue
        next_num = str(max(int(k) for k in domains.keys()) + 1)
        domains[next_num] = {
            "name": nd["name"],
            "section": nd.get("section", ""),
            "type": nd.get("type", "technical"),
            "aws_controls": nd.get("aws_controls", []),
            "config_rules": nd.get("config_rules", []),
            "guardrails": nd.get("guardrails", []),
        }
        applied.append(f"Added new domain {next_num}: {nd['name']}")

    # Update metadata
    today = date.today().isoformat()
    fw_data["last_verified"] = today
    if circular_date:
        fw_data["version"] = f"{fw_data.get('version', '')} + update {circular_date}"
    manifest["last_updated"] = today

    if "update_history" not in manifest:
        manifest["update_history"] = []
    manifest["update_history"].append({
        "date": today,
        "framework": fw_key,
        "source_url": source_url,
        "circular_date": circular_date,
        "changes_applied": len(applied),
        "summary": proposed.get("analysis_summary", ""),
    })

    save_manifest(manifest)

    print(f"Applied {len(applied)} changes to {fw_key} mappings.")
    for a in applied:
        print(f"  • {a}")
    print(f"last_verified updated to {today}")
    return 0


def main() -> None:
    """CLI entry point for maintainer tools."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "check":
        sys.exit(cmd_check())
    elif cmd == "propose":
        if len(sys.argv) < 4:
            print("Usage: aws-india-compliance-admin propose <framework> <text-file>")
            sys.exit(2)
        framework = sys.argv[2]
        text_file = sys.argv[3]
        with open(text_file, "r") as f:
            text = f.read()
        source_url = sys.argv[4] if len(sys.argv) > 4 else ""
        circular_date = sys.argv[5] if len(sys.argv) > 5 else ""
        cmd_propose(framework, text, source_url, circular_date)
    elif cmd == "apply":
        if len(sys.argv) < 4:
            print("Usage: aws-india-compliance-admin apply <framework> <changes-json-file>")
            sys.exit(2)
        framework = sys.argv[2]
        changes_file = sys.argv[3]
        with open(changes_file, "r") as f:
            changes_json = f.read()
        source_url = sys.argv[4] if len(sys.argv) > 4 else ""
        circular_date = sys.argv[5] if len(sys.argv) > 5 else ""
        sys.exit(cmd_apply(framework, changes_json, source_url, circular_date))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
