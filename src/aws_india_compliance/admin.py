"""CLI-only maintainer tools, not exposed via MCP.

These tools are for package maintainers to update control mappings
when new regulatory circulars are published. End users do not need these.

Usage:
    aws-india-compliance-admin check      # Check for regulatory updates
    aws-india-compliance-admin propose    # Propose mapping update (interactive)
    aws-india-compliance-admin apply      # Apply proposed changes to framework YAML
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from . import framework_registry
from .domains import check_staleness
from .knowledge import monitor_source_changes

_FRAMEWORKS_DIR = Path(__file__).parent / "frameworks"


def _load_framework_yaml(framework: str) -> tuple[dict[str, Any], Path]:
    """Load a framework YAML file by id. Returns (data, filepath)."""
    filepath = _FRAMEWORKS_DIR / f"{framework}.yaml"
    if not filepath.exists():
        print(f"Error: framework file not found: {filepath}", file=sys.stderr)
        sys.exit(2)
    with open(filepath, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data, filepath


def _save_framework_yaml(data: dict[str, Any], filepath: Path) -> None:
    """Write a framework dict back to its YAML file."""
    with open(filepath, "w", encoding="utf-8") as fh:
        yaml.dump(data, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)


def cmd_check() -> int:
    """Check regulatory update staleness. Exit 0 = current, 1 = action needed."""
    staleness = check_staleness()
    source_changes = monitor_source_changes()

    action_needed = False
    findings: list[str] = []

    all_frameworks = framework_registry.get_all()
    for fw_key, fw_data in all_frameworks.items():
        name = fw_data.get("name", fw_key)

        if fw_key in staleness.get("stale_frameworks", []):
            findings.append(f"STALE: {name} (last verified {fw_data.get('last_verified', 'unknown')})")
            action_needed = True

        sc = source_changes.get(fw_key, {})
        if sc.get("hash_changed"):
            findings.append(f"CONTENT_CHANGED: {name}")
            action_needed = True

        new_circulars = sc.get("new_circulars", [])
        if new_circulars:
            findings.append(f"NEW_CIRCULARS: {name} ({len(new_circulars)} detected)")
            action_needed = True

    result = {
        "action_needed": action_needed,
        "registered_frameworks": framework_registry.get_ids(),
        "findings": findings,
    }

    print(json.dumps(result, indent=2))
    return 1 if action_needed else 0


def cmd_propose(framework: str, regulatory_text: str, source_url: str = "", circular_date: str = "") -> str:
    """Analyze regulatory text and return current mappings for LLM analysis."""
    fw_data = framework_registry.get(framework.lower())
    if not fw_data:
        valid = ", ".join(framework_registry.get_ids())
        print(f"Error: Unknown framework '{framework}'. Valid: {valid}", file=sys.stderr)
        sys.exit(2)

    current_domains = fw_data.get("domains", {})

    # Convert domain data to a simplified form for LLM consumption
    domains_summary: dict[str, Any] = {}
    for dom_num, dom_data in current_domains.items():
        domains_summary[str(dom_num)] = {
            "name": dom_data.get("name", ""),
            "section": dom_data.get("section", ""),
            "type": dom_data.get("type", ""),
            "aws_controls": dom_data.get("aws_controls", []),
            "config_rules": dom_data.get("config_rules", []),
            "guardrails": dom_data.get("guardrails", []),
        }

    print(f"Framework: {fw_data['name']}")
    print(f"Current domains: {len(current_domains)}")
    print(f"Regulatory text length: {len(regulatory_text)} chars")
    print(f"\nCurrent mappings:\n{json.dumps(domains_summary, indent=2)[:2000]}...")
    print(f"\nPaste this into your LLM client with the regulatory text to get proposed changes.")

    return json.dumps({
        "framework": framework,
        "current_mappings": domains_summary,
        "source_url": source_url,
        "circular_date": circular_date,
    }, indent=2)


def cmd_apply(framework: str, proposed_changes_json: str, source_url: str = "", circular_date: str = "") -> int:
    """Apply proposed mapping changes to the framework YAML file."""
    try:
        proposed = json.loads(proposed_changes_json)
    except (json.JSONDecodeError, TypeError) as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        return 2

    fw_key = framework.lower()
    fw_data, filepath = _load_framework_yaml(fw_key)

    impact_level = proposed.get("impact_level", "none")
    if impact_level == "none":
        print("No changes needed.")
        return 0

    changes = proposed.get("proposed_changes", [])
    new_domains = proposed.get("new_domains", [])
    domains = fw_data.get("domains", {})
    applied: list[str] = []

    for change in changes:
        dom_num = change.get("domain", "")
        # Domain keys in YAML are integers
        dom_key = int(dom_num) if isinstance(dom_num, str) and dom_num.isdigit() else dom_num
        if dom_key not in domains:
            print(f"Warning: domain {dom_key} not found, skipping")
            continue

        field = change.get("field", "")
        action = change.get("action", "")
        current = domains[dom_key].get(field, [])

        if action == "add" and isinstance(current, list):
            if change["value"] not in current:
                current.append(change["value"])
                domains[dom_key][field] = current
                applied.append(f"Added '{change['value']}' to domain {dom_key}.{field}")
        elif action == "remove" and isinstance(current, list):
            target = change.get("old_value", change.get("value", ""))
            if target in current:
                current.remove(target)
                domains[dom_key][field] = current
                applied.append(f"Removed '{target}' from domain {dom_key}.{field}")
        elif action == "replace":
            old = domains[dom_key].get(field)
            domains[dom_key][field] = change["value"]
            applied.append(f"Replaced domain {dom_key}.{field}: '{old}' -> '{change['value']}'")

    for nd in new_domains:
        if not nd.get("name"):
            continue
        next_num = max(domains.keys()) + 1 if domains else 1
        domains[next_num] = {
            "name": nd["name"],
            "section": nd.get("section", ""),
            "type": nd.get("type", "technical"),
            "aws_controls": nd.get("aws_controls", []),
            "config_rules": nd.get("config_rules", []),
            "guardrails": nd.get("guardrails", []),
        }
        applied.append(f"Added new domain {next_num}: {nd['name']}")

    # Update metadata in the YAML
    today = date.today().isoformat()
    fw_data["last_verified"] = today
    if circular_date:
        fw_data["version"] = f"{fw_data.get('version', '')} + update {circular_date}"

    # Save back to YAML
    _save_framework_yaml(fw_data, filepath)

    # Reload the registry so changes take effect immediately
    framework_registry.reload()

    print(f"Applied {len(applied)} changes to {filepath.name}")
    for a in applied:
        print(f"  - {a}")
    print(f"last_verified updated to {today}")
    print()
    print("Next steps:")
    print("  1. Run: python scripts/build_manifest.py  (regenerate control_mappings.json)")
    print("  2. Run: python scripts/scaffold_framework.py --validate-all")
    print("  3. Run: PYTHONPATH=src python -m pytest tests/ -v")
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
        with open(text_file, "r", encoding="utf-8") as f:
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
        with open(changes_file, "r", encoding="utf-8") as f:
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
