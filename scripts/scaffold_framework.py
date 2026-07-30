"""Scaffold and validate compliance framework YAML files.

This script helps contributors create new framework definitions or
validate existing ones against the expected schema.

Usage:
    # Generate a new framework skeleton
    python scripts/scaffold_framework.py --new --id gdpr --name "EU GDPR" \
        --source-url "https://gdpr-info.eu"

    # Validate an existing framework file
    python scripts/scaffold_framework.py --validate frameworks/gdpr.yaml

    # Validate all framework files in the directory
    python scripts/scaffold_framework.py --validate-all
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FRAMEWORKS_DIR = REPO_ROOT / "src" / "aws_india_compliance" / "frameworks"

# Validation patterns
ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,30}$")
CONFIG_RULE_PATTERN = re.compile(r"^[a-z0-9-]+$")
GUARDRAIL_PATTERN = re.compile(r"^AWS-GR_[A-Z0-9_]+$")
VALID_DOMAIN_TYPES = {"organizational", "technical"}
VALID_ACTIVATIONS = {"always", "opt_in"}
VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
REQUIRED_TOP_LEVEL = {"id", "name", "version", "source_url"}
REQUIRED_DOMAIN_FIELDS = {"name", "section", "type"}


def generate_skeleton(fw_id: str, name: str, source_url: str) -> str:
    """Generate a framework YAML skeleton with placeholder content."""

    skeleton = f"""# {name}
# Source: {source_url}
# Created: {date.today().isoformat()}
#
# Instructions:
# 1. Fill in the domains section with control domains from the regulation
# 2. For each domain, specify whether it is organizational or technical
# 3. For technical domains, add relevant AWS Config rules and guardrails
# 4. Run: python scripts/scaffold_framework.py --validate frameworks/{fw_id}.yaml

id: {fw_id}
name: "{name}"
version: ""  # Fill in: regulation version or circular date
source_url: "{source_url}"
last_verified: "{date.today().isoformat()}"

source_domains:
  - ""  # Fill in: domain name from the source_url (e.g. "gdpr-info.eu")

activation: opt_in
activation_param: "is_{fw_id}_regulated"

search_sources:
  - "{source_url}"

circular_sources: []
  # Fill in: URLs of pages that list new circulars or amendments
  # Example: "https://regulator-site.gov/circulars"

keywords:
  # Fill in: keywords to detect relevant new circulars on listing pages
  - ""

penalty_default: ""  # Fill in: default penalty text shown on gaps

penalty_overrides: {{}}
  # Fill in per-domain overrides if penalties differ by domain
  # Example:
  #   3: "Up to EUR 10M or 2% of turnover"

config_rule_params: {{}}
  # Fill in: framework-specific AWS Config rule parameter overrides
  # Example:
  #   CW_LOGGROUP_RETENTION_PERIOD_CHECK:
  #     MinRetentionTime: "365"

# Control Domains
# Add one entry per control domain identified in the regulation.
# For each domain, classify as "organizational" (requires human processes,
# cannot be checked via infrastructure) or "technical" (can be validated
# by checking AWS resource configurations).

domains:
  1:
    name: ""  # Fill in: domain name from the regulation
    section: ""  # Fill in: article or section reference
    type: technical  # or "organizational"
    aws_controls: []
      # Fill in: AWS services that address this domain
      # Example: ["KMS encryption", "S3 Block Public Access"]
    config_rules: []
      # Fill in: AWS Config managed rule names (only for technical domains)
      # Example: ["encrypted-volumes", "rds-storage-encrypted"]
      # Full list: https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html
    guardrails: []
      # Fill in: Control Tower guardrail identifiers
      # Example: ["AWS-GR_ENCRYPTED_VOLUMES"]

  # Add more domains as needed:
  # 2:
  #   name: ""
  #   section: ""
  #   type: organizational
  #   aws_controls: []
  #   config_rules: []
  #   guardrails: []
"""
    return skeleton


def validate_file(filepath: Path) -> list[str]:
    """Validate a single framework YAML file. Returns list of error strings."""
    errors: list[str] = []

    if not filepath.exists():
        return [f"File not found: {filepath}"]

    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]
    except OSError as e:
        return [f"File read error: {e}"]

    if not isinstance(data, dict):
        return ["File does not contain a YAML mapping at the top level."]

    # Required top-level fields
    for field in REQUIRED_TOP_LEVEL:
        if field not in data or not data[field]:
            errors.append(f"Missing or empty required field: '{field}'")

    # ID format
    fw_id = data.get("id", "")
    if fw_id and not ID_PATTERN.match(fw_id):
        errors.append(
            f"Invalid id '{fw_id}': must be 2-31 characters, lowercase letters, "
            f"digits, and underscores, starting with a letter."
        )

    # Check id matches filename
    expected_filename = f"{fw_id}.yaml"
    if fw_id and filepath.name != expected_filename:
        errors.append(
            f"Filename mismatch: file is '{filepath.name}' but id is '{fw_id}'. "
            f"Expected filename: '{expected_filename}'."
        )

    # Activation
    activation = data.get("activation", "opt_in")
    if activation not in VALID_ACTIVATIONS:
        errors.append(f"Invalid activation '{activation}': must be 'always' or 'opt_in'.")

    if activation == "opt_in" and not data.get("activation_param"):
        errors.append("activation is 'opt_in' but no activation_param is specified.")

    # Domains
    domains = data.get("domains", {})
    if not domains:
        errors.append("No domains defined. At least one domain is required.")
    else:
        for dom_key, dom_data in domains.items():
            prefix = f"Domain {dom_key}"

            if not isinstance(dom_data, dict):
                errors.append(f"{prefix}: must be a mapping, got {type(dom_data).__name__}.")
                continue

            for field in REQUIRED_DOMAIN_FIELDS:
                if field not in dom_data or not dom_data[field]:
                    errors.append(f"{prefix}: missing or empty required field '{field}'.")

            dom_type = dom_data.get("type", "")
            if dom_type and dom_type not in VALID_DOMAIN_TYPES:
                errors.append(
                    f"{prefix}: invalid type '{dom_type}'. "
                    f"Must be 'organizational' or 'technical'."
                )

            # Validate config rule name formats
            for rule in dom_data.get("config_rules", []):
                if rule and not CONFIG_RULE_PATTERN.match(rule):
                    errors.append(
                        f"{prefix}: invalid config_rule name '{rule}'. "
                        f"Must be lowercase letters, digits, and hyphens only."
                    )

            # Validate guardrail ID formats
            for gr in dom_data.get("guardrails", []):
                if gr and not GUARDRAIL_PATTERN.match(gr):
                    errors.append(
                        f"{prefix}: invalid guardrail ID '{gr}'. "
                        f"Must match pattern 'AWS-GR_UPPERCASE_NAME'."
                    )

    # Validate checks if present
    checks = data.get("checks", [])
    if checks and isinstance(checks, list):
        for i, check in enumerate(checks):
            check_prefix = f"Check [{i}]"
            if not isinstance(check, dict):
                errors.append(f"{check_prefix}: must be a mapping.")
                continue

            # Resource-level check
            if "match" in check:
                for field in ("property", "domain", "risk", "gap", "remediation", "reference"):
                    if field not in check:
                        errors.append(f"{check_prefix}: missing required field '{field}'.")
                if "expect" not in check and "expect_min" not in check:
                    errors.append(f"{check_prefix}: must have either 'expect' or 'expect_min'.")
                risk = check.get("risk", "")
                if risk and risk not in VALID_RISK_LEVELS:
                    errors.append(f"{check_prefix}: invalid risk '{risk}'.")

            # Architecture-level check
            elif "match_any" in check:
                for field in ("domain", "risk", "gap", "remediation", "reference"):
                    if field not in check:
                        errors.append(f"{check_prefix}: missing required field '{field}'.")
                risk = check.get("risk", "")
                if risk and risk not in VALID_RISK_LEVELS:
                    errors.append(f"{check_prefix}: invalid risk '{risk}'.")

            else:
                errors.append(
                    f"{check_prefix}: must have either 'match' (resource check) "
                    f"or 'match_any' (architecture check)."
                )

    return errors


def validate_all() -> dict[str, list[str]]:
    """Validate all framework YAML files in the frameworks directory."""
    results: dict[str, list[str]] = {}

    if not FRAMEWORKS_DIR.is_dir():
        print(f"Error: frameworks directory not found at {FRAMEWORKS_DIR}", file=sys.stderr)
        sys.exit(1)

    for filepath in sorted(FRAMEWORKS_DIR.glob("*.yaml")):
        if filepath.name.startswith("_"):
            continue
        results[filepath.name] = validate_file(filepath)

    return results


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Scaffold and validate compliance framework YAML files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--new", action="store_true",
        help="Generate a new framework skeleton YAML file."
    )
    group.add_argument(
        "--validate", type=str, metavar="FILE",
        help="Validate a single framework YAML file."
    )
    group.add_argument(
        "--validate-all", action="store_true",
        help="Validate all framework YAML files in the frameworks directory."
    )

    # Arguments for --new mode
    parser.add_argument("--id", type=str, help="Framework identifier (lowercase, e.g. 'gdpr').")
    parser.add_argument("--name", type=str, help="Full framework name.")
    parser.add_argument("--source-url", type=str, help="Primary regulatory source URL.")
    parser.add_argument(
        "--output", type=str,
        help="Output path for generated file. Default: frameworks/<id>.yaml"
    )

    args = parser.parse_args()

    if args.new:
        if not args.id or not args.name or not args.source_url:
            parser.error("--new requires --id, --name, and --source-url")

        if not ID_PATTERN.match(args.id):
            print(
                f"Error: invalid id '{args.id}'. Must be 2-31 characters, "
                f"lowercase letters, digits, and underscores, starting with a letter.",
                file=sys.stderr
            )
            sys.exit(1)

        skeleton = generate_skeleton(args.id, args.name, args.source_url)

        output_path = Path(args.output) if args.output else FRAMEWORKS_DIR / f"{args.id}.yaml"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(skeleton)

        print(f"Created framework skeleton: {output_path}")
        print()
        print("Next steps:")
        print(f"  1. Edit {output_path} and fill in the domain definitions")
        print(f"  2. Validate: python scripts/scaffold_framework.py --validate {output_path}")
        print(f"  3. Build manifest: python scripts/build_manifest.py")
        print(f"  4. Run tests: PYTHONPATH=src python3 -m pytest tests/ -v")

    elif args.validate:
        filepath = Path(args.validate)
        if not filepath.is_absolute():
            filepath = REPO_ROOT / filepath

        errors = validate_file(filepath)

        if errors:
            print(f"FAIL: {filepath.name} ({len(errors)} errors)")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print(f"PASS: {filepath.name}")

    elif args.validate_all:
        results = validate_all()
        total_errors = 0
        for filename, errors in results.items():
            if errors:
                print(f"FAIL: {filename} ({len(errors)} errors)")
                for e in errors:
                    print(f"  - {e}")
                total_errors += len(errors)
            else:
                print(f"PASS: {filename}")

        print()
        if total_errors:
            print(f"Validation failed: {total_errors} errors across {len(results)} files.")
            sys.exit(1)
        else:
            print(f"All {len(results)} framework files are valid.")


if __name__ == "__main__":
    main()
