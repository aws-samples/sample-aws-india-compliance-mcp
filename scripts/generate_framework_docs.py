"""Generate framework documentation from YAML definitions.

Reads all framework YAML files and produces:
- docs/frameworks/index.md (summary table of all frameworks)
- docs/frameworks/<id>.md (per-framework detail page)

Usage:
    python scripts/generate_framework_docs.py
"""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FRAMEWORKS_DIR = REPO_ROOT / "src" / "aws_india_compliance" / "frameworks"
DOCS_DIR = REPO_ROOT / "docs" / "frameworks"


def load_frameworks() -> list[dict]:
    """Load all framework YAMLs sorted by id."""
    frameworks: list[dict] = []
    for filepath in sorted(FRAMEWORKS_DIR.glob("*.yaml")):
        if filepath.name.startswith("_"):
            continue
        with open(filepath, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict) and "id" in data:
            frameworks.append(data)
    return frameworks


def generate_index(frameworks: list[dict]) -> str:
    """Generate the frameworks index page with summary table."""
    lines: list[str] = []
    lines.append("# Supported Compliance Frameworks")
    lines.append("")
    lines.append(f"This project currently supports **{len(frameworks)} regulatory frameworks**.")
    lines.append("Each framework is defined in a single YAML file and auto-discovered at runtime.")
    lines.append("")
    lines.append("## Framework Summary")
    lines.append("")
    lines.append("| Framework | Domains | Checks | Type | Last Verified | Source |")
    lines.append("|-----------|---------|--------|------|---------------|--------|")

    for fw in frameworks:
        fw_id = fw["id"]
        name = fw["name"]
        domains = fw.get("domains", {})
        checks = fw.get("checks", [])
        num_domains = len(domains)
        num_checks = len(checks) if checks else 0
        last_verified = fw.get("last_verified", "unknown")
        source_url = fw.get("source_url", "")
        activation = fw.get("activation", "opt_in")
        activation_label = "Always" if activation == "always" else "Opt-in"

        source_link = f"[Link]({source_url})" if source_url else "N/A"
        detail_link = f"[{name}]({fw_id}.md)"

        lines.append(
            f"| {detail_link} | {num_domains} | {num_checks} | "
            f"{activation_label} | {last_verified} | {source_link} |"
        )

    lines.append("")
    lines.append("## Framework Types")
    lines.append("")
    lines.append("- **Always**: Assessed on every scan automatically (DPDP, CERT-In)")
    lines.append("- **Opt-in**: Assessed only when the user passes the activation flag (RBI, SEBI)")
    lines.append("")
    lines.append("## Adding a New Framework")
    lines.append("")
    lines.append("See [CONTRIBUTING_FRAMEWORKS.md](https://github.com/aws-samples/sample-aws-india-compliance-mcp/blob/main/CONTRIBUTING_FRAMEWORKS.md) for the full guide.")
    lines.append("")
    lines.append("Quick start:")
    lines.append("```bash")
    lines.append('python scripts/scaffold_framework.py --new --id myframework --name "My Framework" --source-url "https://example.com"')
    lines.append("```")
    lines.append("")
    lines.append(f"*Auto-generated on {date.today().isoformat()} from framework YAML definitions.*")
    lines.append("")
    return "\n".join(lines)


def generate_framework_page(fw: dict) -> str:
    """Generate a detail page for a single framework."""
    lines: list[str] = []
    fw_id = fw["id"]
    name = fw["name"]
    version = fw.get("version", "")
    source_url = fw.get("source_url", "")
    last_verified = fw.get("last_verified", "")
    activation = fw.get("activation", "opt_in")
    activation_param = fw.get("activation_param", "")
    penalty_default = fw.get("penalty_default", "")
    domains = fw.get("domains", {})
    checks = fw.get("checks", [])
    search_sources = fw.get("search_sources", [])
    circular_sources = fw.get("circular_sources", [])
    keywords = fw.get("keywords", [])

    lines.append(f"# {name}")
    lines.append("")

    # Metadata table
    lines.append("| Property | Value |")
    lines.append("|----------|-------|")
    lines.append(f"| **ID** | `{fw_id}` |")
    lines.append(f"| **Version** | {version} |")
    lines.append(f"| **Source** | [{source_url}]({source_url}) |")
    lines.append(f"| **Last Verified** | {last_verified} |")
    lines.append(f"| **Activation** | {activation} |")
    if activation_param:
        lines.append(f"| **Activation Param** | `{activation_param}` |")
    lines.append(f"| **Domains** | {len(domains)} |")
    lines.append(f"| **Declarative Checks** | {len(checks) if checks else 0} |")
    if penalty_default:
        lines.append(f"| **Default Penalty** | {penalty_default} |")
    lines.append("")

    # Domains
    lines.append("## Control Domains")
    lines.append("")
    lines.append("| # | Domain | Section | Type |")
    lines.append("|---|--------|---------|------|")
    for dom_num in sorted(domains.keys(), key=lambda x: int(x) if str(x).isdigit() else 0):
        dom = domains[dom_num]
        dom_name = dom.get("name", "")
        section = dom.get("section", "")
        dom_type = dom.get("type", "")
        lines.append(f"| {dom_num} | {dom_name} | {section} | {dom_type} |")
    lines.append("")

    # AWS controls per domain
    lines.append("## AWS Controls by Domain")
    lines.append("")
    for dom_num in sorted(domains.keys(), key=lambda x: int(x) if str(x).isdigit() else 0):
        dom = domains[dom_num]
        aws_controls = dom.get("aws_controls", [])
        config_rules = dom.get("config_rules", [])
        guardrails = dom.get("guardrails", [])
        if not aws_controls and not config_rules and not guardrails:
            continue
        lines.append(f"### Domain {dom_num}: {dom.get('name', '')}")
        lines.append("")
        if aws_controls:
            lines.append("**AWS Services:**")
            for ctrl in aws_controls:
                lines.append(f"- {ctrl}")
            lines.append("")
        if config_rules:
            lines.append("**Config Rules:**")
            for rule in config_rules:
                lines.append(f"- `{rule}`")
            lines.append("")
        if guardrails:
            lines.append("**Control Tower Guardrails:**")
            for gr in guardrails:
                lines.append(f"- `{gr}`")
            lines.append("")

    # Checks summary
    if checks:
        resource_checks = [c for c in checks if "match" in c]
        arch_checks = [c for c in checks if "match_any" in c]
        lines.append("## Assessment Checks")
        lines.append("")
        lines.append(f"This framework has **{len(checks)} declarative checks** ")
        lines.append(f"({len(resource_checks)} resource-level, {len(arch_checks)} architecture-level).")
        lines.append("")
        lines.append("| Type | Match | Domain | Risk | Gap |")
        lines.append("|------|-------|--------|------|-----|")
        for check in checks:
            if "match" in check:
                match_val = check["match"]
                check_type = "Resource"
            else:
                match_val = check.get("match_any", "")
                check_type = "Architecture"
            domain = check.get("domain", "")
            risk = check.get("risk", "")
            gap = check.get("gap", "")[:60]
            lines.append(f"| {check_type} | `{match_val}` | {domain} | {risk} | {gap} |")
        lines.append("")

    # Monitoring
    if search_sources or circular_sources or keywords:
        lines.append("## Regulatory Monitoring")
        lines.append("")
        if search_sources:
            lines.append("**Search Sources:**")
            for url in search_sources:
                lines.append(f"- {url}")
            lines.append("")
        if circular_sources:
            lines.append("**Circular Sources:**")
            for url in circular_sources:
                lines.append(f"- {url}")
            lines.append("")
        if keywords:
            lines.append("**Monitoring Keywords:**")
            lines.append(f"`{', '.join(keywords)}`")
            lines.append("")

    # Notes from domains
    domain_notes = []
    for dom_num in sorted(domains.keys(), key=lambda x: int(x) if str(x).isdigit() else 0):
        dom = domains[dom_num]
        notes = dom.get("notes", "")
        if notes:
            domain_notes.append((dom_num, dom.get("name", ""), notes.strip()))

    if domain_notes:
        lines.append("## Implementation Notes")
        lines.append("")
        for dom_num, dom_name, notes in domain_notes:
            lines.append(f"**Domain {dom_num} ({dom_name}):** {notes}")
            lines.append("")

    lines.append(f"*Auto-generated on {date.today().isoformat()} from `frameworks/{fw_id}.yaml`.*")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    """Main entry point."""
    print(f"Generating framework documentation from {FRAMEWORKS_DIR}/")
    print()

    frameworks = load_frameworks()
    if not frameworks:
        print("Error: no framework YAML files found.", file=sys.stderr)
        sys.exit(1)

    # Create output directory
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    # Generate index
    index_content = generate_index(frameworks)
    index_path = DOCS_DIR / "index.md"
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(index_content)
    print(f"  Generated: {index_path}")

    # Generate per-framework pages
    for fw in frameworks:
        page_content = generate_framework_page(fw)
        page_path = DOCS_DIR / f"{fw['id']}.md"
        with open(page_path, "w", encoding="utf-8") as f:
            f.write(page_content)
        print(f"  Generated: {page_path} ({len(fw.get('domains', {}))} domains)")

    # Update mkdocs.yml nav to include all frameworks
    update_mkdocs_nav(frameworks)

    print()
    print(f"Done. {len(frameworks)} framework pages generated in {DOCS_DIR}/")


def update_mkdocs_nav(frameworks: list[dict]) -> None:
    """Update the Frameworks nav section in mkdocs.yml to include all frameworks."""
    mkdocs_path = REPO_ROOT / "mkdocs.yml"
    if not mkdocs_path.exists():
        return

    content = mkdocs_path.read_text(encoding="utf-8")

    # Build the new frameworks nav entries
    nav_lines: list[str] = []
    nav_lines.append("  - Frameworks:")
    nav_lines.append("    - Overview: frameworks/index.md")
    for fw in frameworks:
        fw_id = fw["id"]
        name = fw["name"]
        # Use framework id as a clean short label
        label_map = {
            "dpdp": "DPDP Act 2023",
            "rbi": "RBI Master Direction",
            "sebi": "SEBI CSCRF",
            "certin": "CERT-In Directions",
            "irdai": "IRDAI ICS Guidelines",
        }
        label = label_map.get(fw_id, name[:50])
        nav_lines.append(f"    - {label}: frameworks/{fw_id}.md")

    new_nav = "\n".join(nav_lines) + "\n"

    # Find and replace the Frameworks section in nav
    import re
    # Match from "  - Frameworks:" through all lines starting with "    - "
    pattern = r"(  - Frameworks:\n(?:    - [^\n]+\n)+)"
    if re.search(pattern, content):
        updated = re.sub(pattern, new_nav, content)
        if updated != content:
            mkdocs_path.write_text(updated, encoding="utf-8")
            print(f"  Updated: mkdocs.yml nav ({len(frameworks)} framework entries)")

if __name__ == "__main__":
    main()
