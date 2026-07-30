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

# Known config rule to check mappings.
# Each entry maps a config rule name to the check definition it implies.
# This powers the --suggest-checks feature.
RULE_TO_CHECK: dict[str, dict] = {
    # Encryption at rest
    "encrypted-volumes": {
        "match": "EC2::Instance",
        "property": "ebs_encrypted",
        "expect": True,
        "risk": "high",
        "gap": "EBS volumes not encrypted at rest",
        "remediation": "Enable EBS encryption by default or encrypt existing volumes",
    },
    "rds-storage-encrypted": {
        "match": "RDS::DB",
        "property": "encryption",
        "expect": "encrypted",
        "risk": "high",
        "gap": "RDS instance not encrypted at rest",
        "remediation": "Enable RDS storage encryption",
    },
    "s3-bucket-server-side-encryption-enabled": {
        "match": "S3::Bucket",
        "property": "encryption",
        "expect": "encrypted",
        "risk": "high",
        "gap": "S3 bucket lacks encryption at rest",
        "remediation": "Enable SSE-KMS or SSE-S3 encryption",
    },
    "dynamodb-table-encrypted-kms": {
        "match": "DynamoDB::Table",
        "property": "encryption",
        "expect": "encrypted",
        "risk": "high",
        "gap": "DynamoDB table not encrypted with KMS",
        "remediation": "Enable KMS encryption on the table",
    },
    "elasticsearch-encrypted-at-rest": {
        "match": "Elasticsearch",
        "property": "encryption",
        "expect": "encrypted",
        "risk": "high",
        "gap": "Elasticsearch domain not encrypted at rest",
        "remediation": "Enable encryption at rest on the domain",
    },
    "sns-encrypted-kms": {
        "match": "SNS::Topic",
        "property": "encryption",
        "expect": "encrypted",
        "risk": "medium",
        "gap": "SNS topic not encrypted with KMS",
        "remediation": "Enable KMS encryption on the SNS topic",
    },
    "eks-secrets-encrypted": {
        "match": "EKS::Cluster",
        "property": "secrets_encrypted",
        "expect": True,
        "risk": "high",
        "gap": "EKS cluster secrets not encrypted",
        "remediation": "Enable KMS envelope encryption for Kubernetes secrets",
    },
    # Public access
    "s3-bucket-public-read-prohibited": {
        "match": "S3::Bucket",
        "property": "public_access_blocked",
        "expect": True,
        "risk": "high",
        "gap": "S3 bucket allows public read access",
        "remediation": "Enable S3 Block Public Access (all 4 settings)",
    },
    "s3-bucket-public-write-prohibited": {
        "match": "S3::Bucket",
        "property": "public_access_blocked",
        "expect": True,
        "risk": "critical",
        "gap": "S3 bucket allows public write access",
        "remediation": "Enable S3 Block Public Access (all 4 settings)",
    },
    "rds-instance-public-access-check": {
        "match": "RDS::DB",
        "property": "public",
        "expect": False,
        "risk": "critical",
        "gap": "RDS instance is publicly accessible",
        "remediation": "Disable public accessibility on the RDS instance",
    },
    "ec2-instance-no-public-ip": {
        "match": "EC2::Instance",
        "property": "public_ip",
        "expect": False,
        "risk": "high",
        "gap": "EC2 instance has a public IP address",
        "remediation": "Remove public IP or move to private subnet",
    },
    "lambda-function-public-access-prohibited": {
        "match": "Lambda::Function",
        "property": "public",
        "expect": False,
        "risk": "high",
        "gap": "Lambda function has public access",
        "remediation": "Remove resource-based policy that allows public invocation",
    },
    "eks-endpoint-no-public-access": {
        "match": "EKS::Cluster",
        "property": "endpoint_public",
        "expect": False,
        "risk": "high",
        "gap": "EKS cluster API endpoint is publicly accessible",
        "remediation": "Restrict API endpoint to private access",
    },
    "s3-account-level-public-access-blocks-periodic": {
        "match": "S3::Bucket",
        "property": "public_access_blocked",
        "expect": True,
        "risk": "high",
        "gap": "S3 account-level public access blocks not enabled",
        "remediation": "Enable account-level S3 Block Public Access",
    },
    # IAM and access control
    "iam-policy-no-statements-with-admin-access": {
        "match": "IAM::Role",
        "property": "has_admin_policy",
        "expect": False,
        "risk": "critical",
        "gap": "IAM role has admin-level access policy",
        "remediation": "Apply least-privilege policies, remove AdministratorAccess",
    },
    "mfa-enabled-for-iam-console-access": {
        "match": "IAM::Role",
        "property": "mfa_enabled",
        "expect": True,
        "risk": "high",
        "gap": "MFA not enabled for IAM console access",
        "remediation": "Enable MFA for all IAM users with console access",
    },
    "ec2-imdsv2-check": {
        "match": "EC2::Instance",
        "property": "imdsv2_required",
        "expect": True,
        "risk": "high",
        "gap": "EC2 instance does not enforce IMDSv2",
        "remediation": "Set HttpTokens=required in instance metadata options",
    },
    "restricted-ssh": {
        "match": "EC2::SecurityGroup",
        "property": "open_ssh",
        "expect": False,
        "risk": "high",
        "gap": "Security group allows SSH from 0.0.0.0/0",
        "remediation": "Restrict SSH access to known IP ranges",
    },
    "access-keys-rotated": {
        "match": "IAM::Role",
        "property": "access_key_age",
        "expect_min_note": "Rotate keys older than 90 days",
        "risk": "medium",
        "gap": "IAM access keys not rotated within 90 days",
        "remediation": "Rotate access keys every 90 days or use IAM roles",
    },
    # Logging and audit
    "cloudtrail-enabled": {
        "match_any": "cloudtrail",
        "risk": "critical",
        "gap": "CloudTrail is not enabled",
        "remediation": "Enable CloudTrail in all regions",
    },
    "cloud-trail-log-file-validation-enabled": {
        "match": "CloudTrail::Trail",
        "property": "log_file_validation",
        "expect": True,
        "risk": "high",
        "gap": "CloudTrail log file validation is disabled",
        "remediation": "Enable log file validation for tamper detection",
    },
    "cloud-trail-cloud-watch-logs-enabled": {
        "match": "CloudTrail::Trail",
        "property": "cloudwatch_logs",
        "expect": True,
        "risk": "high",
        "gap": "CloudTrail not integrated with CloudWatch Logs",
        "remediation": "Configure CloudTrail to deliver logs to CloudWatch Logs",
    },
    "cloud-trail-encryption-enabled": {
        "match": "CloudTrail::Trail",
        "property": "encryption",
        "expect": "encrypted",
        "risk": "high",
        "gap": "CloudTrail logs not encrypted with KMS",
        "remediation": "Enable KMS encryption for CloudTrail log files",
    },
    "s3-bucket-logging-enabled": {
        "match": "S3::Bucket",
        "property": "access_logging",
        "expect": True,
        "risk": "medium",
        "gap": "S3 bucket lacks access logging",
        "remediation": "Enable server access logging",
    },
    "vpc-flow-logs-enabled": {
        "match_any": "vpc",
        "risk": "high",
        "gap": "VPC Flow Logs not enabled",
        "remediation": "Enable VPC Flow Logs for network traffic visibility",
    },
    "cw-loggroup-retention-period-check": {
        "match": "Logs::LogGroup",
        "property": "retention_days",
        "expect_min_note": "Framework-specific minimum (180 or 365 days)",
        "risk": "medium",
        "gap": "CloudWatch log group retention below required minimum",
        "remediation": "Set retention period to meet regulatory requirements",
    },
    # Backup and recovery
    "db-instance-backup-enabled": {
        "match": "RDS::DB",
        "property": "backup_enabled",
        "expect": True,
        "risk": "medium",
        "gap": "RDS instance backups not enabled",
        "remediation": "Enable automated backups with appropriate retention",
    },
    "dynamodb-pitr-enabled": {
        "match": "DynamoDB::Table",
        "property": "pitr",
        "expect": True,
        "risk": "medium",
        "gap": "DynamoDB table lacks point-in-time recovery",
        "remediation": "Enable PITR for disaster recovery",
    },
    "s3-bucket-versioning-enabled": {
        "match": "S3::Bucket",
        "property": "versioning",
        "expect": True,
        "risk": "medium",
        "gap": "S3 bucket lacks versioning for data recovery",
        "remediation": "Enable versioning",
    },
    "rds-multi-az-support": {
        "match": "RDS::DB",
        "property": "multi_az",
        "expect": True,
        "risk": "medium",
        "gap": "RDS instance not configured for Multi-AZ",
        "remediation": "Enable Multi-AZ deployment for high availability",
    },
    # Detection and monitoring
    "guardduty-enabled-centralized": {
        "match_any": "guardduty",
        "risk": "critical",
        "gap": "GuardDuty not enabled for threat detection",
        "remediation": "Enable Amazon GuardDuty",
    },
    "securityhub-enabled": {
        "match_any": "securityhub",
        "risk": "critical",
        "gap": "Security Hub not enabled for centralized findings",
        "remediation": "Enable AWS Security Hub",
    },
    "cloudwatch-alarm-action-check": {
        "match_any": "cloudwatch",
        "risk": "medium",
        "gap": "CloudWatch alarms without configured actions",
        "remediation": "Configure alarm actions for alerting",
    },
    # Lifecycle and retention
    "s3-lifecycle-policy-check": {
        "match": "S3::Bucket",
        "property": "lifecycle_policy",
        "expect": True,
        "risk": "medium",
        "gap": "S3 bucket lacks lifecycle policy for data retention",
        "remediation": "Add lifecycle rules for data retention and cost management",
    },
    # Network security
    "shield-advanced-enabled-autorenew": {
        "match_any": "shield",
        "risk": "high",
        "gap": "Shield Advanced not enabled for DDoS protection",
        "remediation": "Enable AWS Shield Advanced",
    },
    "guardduty-malware-protection-enabled": {
        "match_any": "guardduty",
        "risk": "high",
        "gap": "GuardDuty Malware Protection not enabled",
        "remediation": "Enable GuardDuty Malware Protection",
    },
    # Key management
    "cmk-backing-key-rotation-enabled": {
        "match": "KMS::Key",
        "property": "rotation_enabled",
        "expect": True,
        "risk": "medium",
        "gap": "KMS customer-managed key automatic rotation not enabled",
        "remediation": "Enable automatic key rotation",
    },
    "secretsmanager-rotation-enabled-check": {
        "match": "SecretsManager::Secret",
        "property": "rotation_enabled",
        "expect": True,
        "risk": "medium",
        "gap": "Secrets Manager secret rotation not configured",
        "remediation": "Enable automatic rotation for secrets",
    },
    # Snapshot security
    "ebs-snapshot-public-restorable-check": {
        "match": "EC2::Instance",
        "property": "ebs_snapshot_public",
        "expect": False,
        "risk": "critical",
        "gap": "EBS snapshots are publicly restorable",
        "remediation": "Remove public permissions from EBS snapshots",
    },
    "rds-snapshots-public-prohibited": {
        "match": "RDS::DB",
        "property": "snapshot_public",
        "expect": False,
        "risk": "critical",
        "gap": "RDS snapshots are publicly accessible",
        "remediation": "Remove public permissions from RDS snapshots",
    },
    # SSL/TLS
    "s3-bucket-ssl-requests-only": {
        "match": "S3::Bucket",
        "property": "tls_enforced",
        "expect": True,
        "risk": "high",
        "gap": "S3 bucket does not enforce TLS for requests",
        "remediation": "Add bucket policy denying non-TLS requests",
    },
}


def generate_skeleton(
    fw_id: str,
    name: str,
    source_url: str,
    search_sources: list[str] | None = None,
    circular_sources: list[str] | None = None,
    keywords: list[str] | None = None,
) -> str:
    """Generate a framework YAML skeleton with placeholder content."""
    from urllib.parse import urlparse

    # Auto-derive source domain from source_url
    parsed = urlparse(source_url)
    source_domain = parsed.netloc.lstrip("www.") if parsed.netloc else ""

    # Build search_sources list
    if search_sources:
        search_lines = "\n".join(f'  - "{u}"' for u in search_sources)
    else:
        search_lines = f'  - "{source_url}"'

    # Build circular_sources list
    if circular_sources:
        circular_lines = "\n".join(f'  - "{u}"' for u in circular_sources)
    else:
        circular_lines = '  []'

    # Build keywords list
    if keywords:
        keyword_lines = "\n".join(f'  - "{k}"' for k in keywords)
    else:
        keyword_lines = '  - ""  # Fill in: keywords to detect relevant new circulars'

    skeleton = f"""# {name}
# Source: {source_url}
# Created: {date.today().isoformat()}
#
# Instructions:
# 1. Fill in the domains section with control domains from the regulation
# 2. For each domain, specify whether it is organizational or technical
# 3. For technical domains, add relevant AWS Config rules and guardrails
# 4. Run: python scripts/scaffold_framework.py --suggest-checks frameworks/{fw_id}.yaml
# 5. Run: python scripts/scaffold_framework.py --validate frameworks/{fw_id}.yaml

id: {fw_id}
name: "{name}"
version: ""  # Fill in: regulation version or circular date
source_url: "{source_url}"
last_verified: "{date.today().isoformat()}"

source_domains:
  - "{source_domain}"

activation: opt_in
activation_param: "is_{fw_id}_regulated"

search_sources:
{search_lines}

circular_sources:
{circular_lines}

keywords:
{keyword_lines}

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


def suggest_checks(filepath: Path) -> list[dict]:
    """Suggest declarative checks based on config_rules defined in a framework YAML.

    Reads the framework file, iterates each domain's config_rules, and
    generates check definitions using the RULE_TO_CHECK mapping table.
    Deduplicates checks that would produce identical match+property combinations.

    Returns a list of suggested check dicts ready to be appended to the YAML.
    """
    if not filepath.exists():
        print(f"Error: file not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (yaml.YAMLError, OSError) as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict):
        print(f"Error: {filepath.name} is not a valid YAML mapping.", file=sys.stderr)
        sys.exit(1)

    fw_id = data.get("id", filepath.stem)
    domains = data.get("domains", {})
    existing_checks = data.get("checks", [])

    # Build a set of existing checks to avoid duplicates
    existing_keys: set[str] = set()
    if existing_checks:
        for ch in existing_checks:
            if "match" in ch:
                key = f"{ch.get('match')}|{ch.get('property')}|{ch.get('domain')}"
                existing_keys.add(key)
            elif "match_any" in ch:
                key = f"arch|{ch.get('match_any')}|{ch.get('domain')}"
                existing_keys.add(key)

    suggestions: list[dict] = []
    seen_keys: set[str] = set()

    for dom_key, dom_data in domains.items():
        if not isinstance(dom_data, dict):
            continue

        dom_num = int(dom_key) if isinstance(dom_key, (int, str)) and str(dom_key).isdigit() else dom_key
        dom_name = dom_data.get("name", "")
        dom_section = dom_data.get("section", "")
        config_rules = dom_data.get("config_rules", [])

        if not config_rules:
            continue

        for rule_name in config_rules:
            template = RULE_TO_CHECK.get(rule_name)
            if not template:
                continue

            # Build the check from the template
            check: dict = {}

            if "match_any" in template:
                # Architecture-level check
                dedup_key = f"arch|{template['match_any']}|{dom_num}"
                if dedup_key in existing_keys or dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                check = {
                    "match_any": template["match_any"],
                    "domain": dom_num,
                    "risk": template["risk"],
                    "gap": template["gap"],
                    "remediation": template["remediation"],
                    "reference": dom_section,
                    "confidence": "high",
                }
            else:
                # Resource-level check
                dedup_key = f"{template['match']}|{template['property']}|{dom_num}"
                if dedup_key in existing_keys or dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                check = {
                    "match": template["match"],
                    "property": template["property"],
                    "domain": dom_num,
                    "risk": template["risk"],
                    "gap": template["gap"],
                    "remediation": template["remediation"],
                    "reference": dom_section,
                    "confidence": "high",
                }

                # Handle expect vs expect_min
                if "expect" in template:
                    check["expect"] = template["expect"]
                elif "expect_min_note" in template:
                    # This rule needs a numeric minimum that is framework-specific.
                    # Use a placeholder that the contributor should fill in.
                    check["expect_min"] = "TODO"
                    check["_note"] = template["expect_min_note"]

            suggestions.append(check)

    return suggestions


def format_checks_as_yaml(checks: list[dict]) -> str:
    """Format a list of check dicts as YAML text suitable for appending to a framework file."""
    if not checks:
        return ""

    lines: list[str] = []
    lines.append("")
    lines.append("# Suggested checks (auto-generated from config_rules)")
    lines.append("# Review each check and adjust risk, gap text, and references as needed.")
    lines.append("# Remove the _note fields before committing.")
    lines.append("")
    lines.append("checks:")

    for check in checks:
        lines.append("")
        if "match_any" in check:
            lines.append(f"  - match_any: \"{check['match_any']}\"")
            lines.append(f"    domain: {check['domain']}")
            lines.append(f"    risk: {check['risk']}")
            lines.append(f"    gap: \"{check['gap']}\"")
            lines.append(f"    remediation: \"{check['remediation']}\"")
            lines.append(f"    reference: \"{check['reference']}\"")
            lines.append(f"    confidence: {check.get('confidence', 'high')}")
        else:
            lines.append(f"  - match: \"{check['match']}\"")
            lines.append(f"    property: \"{check['property']}\"")
            if "expect" in check:
                val = check["expect"]
                if isinstance(val, bool):
                    lines.append(f"    expect: {str(val).lower()}")
                else:
                    lines.append(f"    expect: \"{val}\"")
            elif "expect_min" in check:
                lines.append(f"    expect_min: {check['expect_min']}  # {check.get('_note', '')}")
            lines.append(f"    domain: {check['domain']}")
            lines.append(f"    risk: {check['risk']}")
            lines.append(f"    gap: \"{check['gap']}\"")
            lines.append(f"    remediation: \"{check['remediation']}\"")
            lines.append(f"    reference: \"{check['reference']}\"")
            lines.append(f"    confidence: {check.get('confidence', 'high')}")

    lines.append("")
    return "\n".join(lines)


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
    group.add_argument(
        "--suggest-checks", type=str, metavar="FILE",
        help="Suggest declarative checks based on domains and config_rules in a framework YAML."
    )

    # Arguments for --new mode
    parser.add_argument("--id", type=str, help="Framework identifier (lowercase, e.g. 'gdpr').")
    parser.add_argument("--name", type=str, help="Full framework name.")
    parser.add_argument("--source-url", type=str, help="Primary regulatory source URL.")
    parser.add_argument(
        "--search-sources", type=str, default="",
        help="Comma-separated URLs for regulatory text search."
    )
    parser.add_argument(
        "--circular-sources", type=str, default="",
        help="Comma-separated URLs of circular listing pages for update detection."
    )
    parser.add_argument(
        "--keywords", type=str, default="",
        help="Comma-separated keywords for filtering relevant circulars."
    )
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

        # Parse comma-separated list params
        search_src = [s.strip() for s in args.search_sources.split(",") if s.strip()] if args.search_sources else None
        circular_src = [s.strip() for s in args.circular_sources.split(",") if s.strip()] if args.circular_sources else None
        kw_list = [k.strip() for k in args.keywords.split(",") if k.strip()] if args.keywords else None

        skeleton = generate_skeleton(
            args.id, args.name, args.source_url,
            search_sources=search_src,
            circular_sources=circular_src,
            keywords=kw_list,
        )

        output_path = Path(args.output) if args.output else FRAMEWORKS_DIR / f"{args.id}.yaml"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(skeleton)

        print(f"Created framework skeleton: {output_path}")
        print()
        print("Next steps:")
        print(f"  1. Edit {output_path} and fill in the domain definitions")
        print(f"  2. Suggest checks: python scripts/scaffold_framework.py --suggest-checks {output_path}")
        print(f"  3. Validate: python scripts/scaffold_framework.py --validate {output_path}")
        print(f"  4. Build manifest: python scripts/build_manifest.py")
        print(f"  5. Run tests: PYTHONPATH=src python3 -m pytest tests/ -v")

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

    elif args.suggest_checks:
        filepath = Path(args.suggest_checks)
        if not filepath.is_absolute():
            filepath = REPO_ROOT / filepath

        suggestions = suggest_checks(filepath)

        if not suggestions:
            print(f"No suggestions generated for {filepath.name}.")
            print("Possible reasons:")
            print("  - No config_rules defined in any domain")
            print("  - All config_rules already have corresponding checks")
            print("  - Config rules not recognized in the mapping table")
            sys.exit(0)

        print(f"Generated {len(suggestions)} suggested checks for {filepath.name}:")
        print()

        # Show summary
        resource_checks = [c for c in suggestions if "match" in c]
        arch_checks = [c for c in suggestions if "match_any" in c]
        todo_checks = [c for c in suggestions if c.get("expect_min") == "TODO"]

        print(f"  Resource-level checks: {len(resource_checks)}")
        print(f"  Architecture-level checks: {len(arch_checks)}")
        if todo_checks:
            print(f"  Checks needing manual values (marked TODO): {len(todo_checks)}")
        print()

        # Output the YAML
        yaml_output = format_checks_as_yaml(suggestions)
        print(yaml_output)

        print()
        print("To apply these suggestions:")
        print(f"  1. Review the output above")
        print(f"  2. Copy the checks: section into {filepath.name}")
        print(f"     (or append if checks: already exists)")
        print(f"  3. Replace any TODO values with actual numbers")
        print(f"  4. Adjust gap text and references to match your regulation")
        print(f"  5. Run: python scripts/scaffold_framework.py --validate {filepath}")


if __name__ == "__main__":
    main()
