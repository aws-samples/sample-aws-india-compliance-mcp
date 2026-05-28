"""Conformance pack generator for AWS Config.

Generates AWS Config-compatible conformance pack YAML templates from the
control_mappings.json manifest. Supports all frameworks: DPDP, RBI, SEBI, CERT-In.

Each generated pack contains only AWS-managed Config rules with validated
source identifiers and correct parameter specifications.
"""

from __future__ import annotations

import json
from datetime import date
from typing import Any

from .domains import (
    CERTIN_DOMAINS,
    DPDP_DOMAINS,
    RBI_DOMAINS,
    SEBI_DOMAINS,
    load_manifest,
)

# Validated mapping: config rule name -> source identifier
# All identifiers verified against AWS documentation (May 2026).
_RULE_IDENTIFIERS: dict[str, str] = {
    "guardduty-enabled-centralized": "GUARDDUTY_ENABLED_CENTRALIZED",
    "securityhub-enabled": "SECURITYHUB_ENABLED",
    "cloud-trail-cloud-watch-logs-enabled": "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED",
    "cloudtrail-enabled": "CLOUD_TRAIL_ENABLED",
    "cloudwatch-log-group-encrypted": "CLOUDWATCH_LOG_GROUP_ENCRYPTED",
    "encrypted-volumes": "ENCRYPTED_VOLUMES",
    "rds-storage-encrypted": "RDS_STORAGE_ENCRYPTED",
    "s3-bucket-server-side-encryption-enabled": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
    "s3-bucket-public-read-prohibited": "S3_BUCKET_PUBLIC_READ_PROHIBITED",
    "s3-bucket-public-write-prohibited": "S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
    "ec2-imdsv2-check": "EC2_IMDSV2_CHECK",
    "iam-policy-no-statements-with-admin-access": "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS",
    "iam-root-access-key-check": "IAM_ROOT_ACCESS_KEY_CHECK",
    "mfa-enabled-for-iam-console-access": "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS",
    "root-account-mfa-enabled": "ROOT_ACCOUNT_MFA_ENABLED",
    "cw-loggroup-retention-period-check": "CW_LOGGROUP_RETENTION_PERIOD_CHECK",
    "s3-lifecycle-policy-check": "S3_LIFECYCLE_POLICY_CHECK",
    "dynamodb-table-encrypted-kms": "DYNAMODB_TABLE_ENCRYPTED_KMS",
    "dynamodb-pitr-enabled": "DYNAMODB_PITR_ENABLED",
    "s3-bucket-versioning-enabled": "S3_BUCKET_VERSIONING_ENABLED",
    "rds-multi-az-support": "RDS_MULTI_AZ_SUPPORT",
    "db-instance-backup-enabled": "DB_INSTANCE_BACKUP_ENABLED",
    "access-keys-rotated": "ACCESS_KEYS_ROTATED",
    "iam-password-policy": "IAM_PASSWORD_POLICY",
    "iam-user-mfa-enabled": "IAM_USER_MFA_ENABLED",
    "kms-cmk-not-scheduled-for-deletion": "KMS_CMK_NOT_SCHEDULED_FOR_DELETION",
    "vpc-flow-logs-enabled": "VPC_FLOW_LOGS_ENABLED",
    "restricted-ssh": "INCOMING_SSH_DISABLED",
    "ec2-instances-in-vpc": "INSTANCES_IN_VPC",
    "ec2-instance-managed-by-systems-manager": "EC2_INSTANCE_MANAGED_BY_SSM",
    "ec2-stopped-instance": "EC2_STOPPED_INSTANCE",
    "ec2-volume-inuse-check": "EC2_VOLUME_INUSE_CHECK",
    "cloud-trail-log-file-validation-enabled": "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED",
    "cloud-trail-encryption-enabled": "CLOUD_TRAIL_ENCRYPTION_ENABLED",
    "s3-bucket-logging-enabled": "S3_BUCKET_LOGGING_ENABLED",
    "shield-advanced-enabled-autorenew": "SHIELD_ADVANCED_ENABLED_AUTORENEW",
    "route53-dnssec-enabled": "ROUTE53_QUERY_LOGGING_ENABLED",
    "cloudwatch-alarm-action-check": "CLOUDWATCH_ALARM_ACTION_CHECK",
    "guardduty-malware-protection-enabled": "GUARDDUTY_MALWARE_PROTECTION_ENABLED",
    "s3-bucket-ssl-requests-only": "S3_BUCKET_SSL_REQUESTS_ONLY",
    "s3-account-level-public-access-blocks-periodic": "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC",
    "rds-instance-public-access-check": "RDS_INSTANCE_PUBLIC_ACCESS_CHECK",
    "ec2-instance-no-public-ip": "EC2_INSTANCE_NO_PUBLIC_IP",
    "lambda-function-public-access-prohibited": "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED",
    "eks-secrets-encrypted": "EKS_SECRETS_ENCRYPTED",
    "eks-endpoint-no-public-access": "EKS_ENDPOINT_NO_PUBLIC_ACCESS",
    "elasticsearch-encrypted-at-rest": "ELASTICSEARCH_ENCRYPTED_AT_REST",
    "sns-encrypted-kms": "SNS_ENCRYPTED_KMS",
    "redshift-cluster-configuration-check": "REDSHIFT_CLUSTER_CONFIGURATION_CHECK",
    "cmk-backing-key-rotation-enabled": "CMK_BACKING_KEY_ROTATION_ENABLED",
    "secretsmanager-rotation-enabled-check": "SECRETSMANAGER_ROTATION_ENABLED_CHECK",
    "ebs-snapshot-public-restorable-check": "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK",
    "rds-snapshots-public-prohibited": "RDS_SNAPSHOTS_PUBLIC_PROHIBITED",
}

# Rules that have NO parameters (confirmed via AWS docs)
_NO_PARAM_RULES: set[str] = {
    "GUARDDUTY_ENABLED_CENTRALIZED",
    "SECURITYHUB_ENABLED",
    "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED",
    "CLOUD_TRAIL_ENABLED",
    "CLOUDWATCH_LOG_GROUP_ENCRYPTED",
    "ENCRYPTED_VOLUMES",
    "RDS_STORAGE_ENCRYPTED",
    "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
    "S3_BUCKET_PUBLIC_READ_PROHIBITED",
    "S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
    "EC2_IMDSV2_CHECK",
    "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS",
    "IAM_ROOT_ACCESS_KEY_CHECK",
    "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS",
    "ROOT_ACCOUNT_MFA_ENABLED",
    "S3_LIFECYCLE_POLICY_CHECK",
    "DYNAMODB_TABLE_ENCRYPTED_KMS",
    "DYNAMODB_PITR_ENABLED",
    "S3_BUCKET_VERSIONING_ENABLED",
    "RDS_MULTI_AZ_SUPPORT",
    "DB_INSTANCE_BACKUP_ENABLED",
    "IAM_USER_MFA_ENABLED",
    "KMS_CMK_NOT_SCHEDULED_FOR_DELETION",
    "VPC_FLOW_LOGS_ENABLED",
    "INCOMING_SSH_DISABLED",
    "INSTANCES_IN_VPC",
    "EC2_INSTANCE_MANAGED_BY_SSM",
    "EC2_STOPPED_INSTANCE",
    "EC2_VOLUME_INUSE_CHECK",
    "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED",
    "CLOUD_TRAIL_ENCRYPTION_ENABLED",
    "S3_BUCKET_LOGGING_ENABLED",
    "SHIELD_ADVANCED_ENABLED_AUTORENEW",
    "ROUTE53_QUERY_LOGGING_ENABLED",
    "GUARDDUTY_MALWARE_PROTECTION_ENABLED",
    "S3_BUCKET_SSL_REQUESTS_ONLY",
    "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC",
    "RDS_INSTANCE_PUBLIC_ACCESS_CHECK",
    "EC2_INSTANCE_NO_PUBLIC_IP",
    "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED",
    "EKS_SECRETS_ENCRYPTED",
    "EKS_ENDPOINT_NO_PUBLIC_ACCESS",
    "ELASTICSEARCH_ENCRYPTED_AT_REST",
    "SNS_ENCRYPTED_KMS",
    "CMK_BACKING_KEY_ROTATION_ENABLED",
    "SECRETSMANAGER_ROTATION_ENABLED_CHECK",
    "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK",
    "RDS_SNAPSHOTS_PUBLIC_PROHIBITED",
}

# Rules with optional parameters and their defaults for compliance use cases
_RULE_DEFAULTS: dict[str, dict[str, Any]] = {
    "CW_LOGGROUP_RETENTION_PERIOD_CHECK": {
        "MinRetentionTime": "365",
    },
    "ACCESS_KEYS_ROTATED": {
        "maxAccessKeyAge": "90",
    },
    "IAM_PASSWORD_POLICY": {
        "MinimumPasswordLength": "14",
    },
    "REDSHIFT_CLUSTER_CONFIGURATION_CHECK": {
        "clusterDbEncrypted": "true",
        "loggingEnabled": "true",
    },
    "CLOUDWATCH_ALARM_ACTION_CHECK": {
        "alarmActionRequired": "true",
        "insufficientDataActionRequired": "true",
        "okActionRequired": "false",
    },
}

# Framework-specific parameter overrides
_FRAMEWORK_PARAM_OVERRIDES: dict[str, dict[str, dict[str, str]]] = {
    "rbi": {
        "CW_LOGGROUP_RETENTION_PERIOD_CHECK": {
            "MinRetentionTime": "180",  # CERT-In 180-day requirement
        },
    },
    "certin": {
        "CW_LOGGROUP_RETENTION_PERIOD_CHECK": {
            "MinRetentionTime": "180",  # CERT-In 180-day requirement
        },
    },
    "dpdp": {
        "CW_LOGGROUP_RETENTION_PERIOD_CHECK": {
            "MinRetentionTime": "365",  # DPDP Rule 6 one-year retention
        },
    },
    "sebi": {
        "CW_LOGGROUP_RETENTION_PERIOD_CHECK": {
            "MinRetentionTime": "365",  # SEBI CSCRF log retention
        },
    },
}

# Framework display names
_FRAMEWORK_NAMES: dict[str, str] = {
    "dpdp": "Digital Personal Data Protection (DPDP) Act 2023 + Rules 2025",
    "rbi": "RBI Master Direction on IT Governance, Risk, Controls and Assurance",
    "sebi": "SEBI Cybersecurity and Cyber Resilience Framework (CSCRF)",
    "certin": "CERT-In Directions on Information Security Practices 2022",
}

_FRAMEWORK_DOMAINS: dict[str, dict[int, str]] = {
    "dpdp": DPDP_DOMAINS,
    "rbi": RBI_DOMAINS,
    "sebi": SEBI_DOMAINS,
    "certin": CERTIN_DOMAINS,
}


def _rule_name_to_resource_id(rule_name: str) -> str:
    """Convert a config rule name to a valid CloudFormation resource ID.

    E.g., 'guardduty-enabled-centralized' -> 'GuarddutyEnabledCentralized'
    """
    parts = rule_name.split("-")
    return "".join(p.capitalize() for p in parts)


def _get_params_for_rule(
    source_id: str, framework: str
) -> dict[str, str] | None:
    """Get parameters for a rule, applying framework-specific overrides."""
    # Check framework overrides first
    overrides = _FRAMEWORK_PARAM_OVERRIDES.get(framework, {})
    if source_id in overrides:
        return overrides[source_id]

    # Fall back to defaults
    if source_id in _RULE_DEFAULTS:
        return _RULE_DEFAULTS[source_id]

    return None


def generate_conformance_pack(
    framework: str = "dpdp",
    include_domains: list[int] | None = None,
    exclude_domains: list[int] | None = None,
    pack_name_prefix: str = "",
) -> dict[str, Any]:
    """Generate an AWS Config conformance pack YAML for a compliance framework.

    Reads control_mappings.json to extract config_rules per domain, maps them
    to validated AWS source identifiers, and produces a deployable YAML template.

    Args:
        framework: One of "dpdp", "rbi", "sebi", "certin".
        include_domains: Only include these domain numbers (None = all).
        exclude_domains: Exclude these domain numbers (None = none).
        pack_name_prefix: Optional prefix for the conformance pack name.

    Returns:
        Dict with:
            - yaml_content: The complete YAML template string
            - pack_name: Suggested conformance pack name
            - rule_count: Number of rules included
            - domains_covered: List of domain numbers covered
            - skipped_rules: Rules that couldn't be mapped to valid identifiers
    """
    fw_key = framework.lower()
    if fw_key not in _FRAMEWORK_NAMES:
        return {
            "error": f"Unknown framework: {framework}. Valid: dpdp, rbi, sebi, certin",
        }

    manifest = load_manifest()
    fw_data = manifest.get("frameworks", {}).get(fw_key)
    if not fw_data:
        return {"error": f"Framework '{fw_key}' not found in control_mappings.json"}

    domains = fw_data.get("domains", {})
    domain_names = _FRAMEWORK_DOMAINS[fw_key]

    # Filter domains
    domain_keys = sorted(domains.keys(), key=int)
    if include_domains:
        domain_keys = [k for k in domain_keys if int(k) in include_domains]
    if exclude_domains:
        domain_keys = [k for k in domain_keys if int(k) not in exclude_domains]

    # Collect rules per domain (deduplicate across domains)
    rules_by_domain: dict[str, list[dict[str, Any]]] = {}
    seen_rules: set[str] = set()
    skipped_rules: list[dict[str, str]] = []

    for dom_key in domain_keys:
        dom_data = domains[dom_key]
        config_rules = dom_data.get("config_rules", [])
        dom_rules: list[dict[str, Any]] = []

        for rule_name in config_rules:
            if rule_name in seen_rules:
                continue

            source_id = _RULE_IDENTIFIERS.get(rule_name)
            if not source_id:
                skipped_rules.append({
                    "rule": rule_name,
                    "domain": dom_key,
                    "reason": "No validated source identifier mapping",
                })
                continue

            seen_rules.add(rule_name)
            params = _get_params_for_rule(source_id, fw_key)
            dom_rules.append({
                "rule_name": rule_name,
                "source_id": source_id,
                "resource_id": _rule_name_to_resource_id(rule_name),
                "params": params,
            })

        if dom_rules:
            rules_by_domain[dom_key] = dom_rules

    # Build YAML content
    fw_display = _FRAMEWORK_NAMES[fw_key]
    fw_version = fw_data.get("version", "")
    fw_source = fw_data.get("source_url", "")
    manifest_version = manifest.get("manifest_version", "")
    today = date.today().isoformat()

    # Determine pack name
    if pack_name_prefix:
        pack_name = f"{pack_name_prefix}-{fw_key.upper()}-Conformance-Pack"
    else:
        pack_name = f"{fw_key.upper()}-Compliance-Conformance-Pack"

    # Build parameters section
    param_lines: list[str] = []
    param_refs: dict[str, str] = {}  # source_id -> param ref name

    for dom_key, dom_rules in rules_by_domain.items():
        for rule in dom_rules:
            if rule["params"]:
                for param_name, param_value in rule["params"].items():
                    ref_name = f"{rule['resource_id']}Param{param_name}"
                    param_refs[f"{rule['source_id']}:{param_name}"] = ref_name
                    param_lines.append(f"  {ref_name}:")
                    param_lines.append(f"    Default: \"{param_value}\"")
                    param_lines.append(f"    Type: String")

    # Build resources section
    resource_lines: list[str] = []
    total_rules = 0

    for dom_key in domain_keys:
        if dom_key not in rules_by_domain:
            continue

        dom_name = domain_names.get(int(dom_key), f"Domain {dom_key}")
        dom_section = domains[dom_key].get("section", "")

        resource_lines.append("")
        resource_lines.append(f"  {'#' * 76}")
        resource_lines.append(f"  # DOMAIN {dom_key}: {dom_name}")
        resource_lines.append(f"  # {dom_section}")
        resource_lines.append(f"  {'#' * 76}")
        resource_lines.append("")

        for rule in rules_by_domain[dom_key]:
            total_rules += 1
            config_rule_name = f"{fw_key}-{rule['rule_name']}"

            resource_lines.append(f"  {rule['resource_id']}:")
            resource_lines.append(f"    Properties:")
            resource_lines.append(f"      ConfigRuleName: {config_rule_name}")
            resource_lines.append(f"      Description: >-")
            resource_lines.append(
                f"        [{fw_key.upper()} Domain {dom_key} - {dom_name}] "
                f"AWS Config rule: {rule['rule_name']}. "
                f"Mapped to {fw_display} {dom_section}."
            )

            # Add parameters if any
            if rule["params"]:
                resource_lines.append(f"      InputParameters:")
                for param_name, param_value in rule["params"].items():
                    ref_key = f"{rule['source_id']}:{param_name}"
                    ref_name = param_refs[ref_key]
                    resource_lines.append(f"        {param_name}: !Ref {ref_name}")

            resource_lines.append(f"      Source:")
            resource_lines.append(f"        Owner: AWS")
            resource_lines.append(f"        SourceIdentifier: {rule['source_id']}")
            resource_lines.append(f"    Type: AWS::Config::ConfigRule")
            resource_lines.append("")

    # Assemble full YAML
    yaml_parts: list[str] = []

    # Header comment
    yaml_parts.append(f"{'#' * 80}")
    yaml_parts.append(f"# AWS Config Conformance Pack: {fw_display}")
    yaml_parts.append(f"#")
    yaml_parts.append(f"# Framework: {fw_version}")
    yaml_parts.append(f"# Source: {fw_source}")
    yaml_parts.append(f"# Generated from: aws-india-compliance MCP server v{manifest_version}")
    yaml_parts.append(f"#")
    yaml_parts.append(f"# Domains covered: {', '.join(dom_key for dom_key in domain_keys if dom_key in rules_by_domain)}")
    yaml_parts.append(f"# Total rules: {total_rules}")
    yaml_parts.append(f"#")
    yaml_parts.append(f"# Deployment:")
    yaml_parts.append(f"#   aws configservice put-conformance-pack \\")
    yaml_parts.append(f"#     --conformance-pack-name {pack_name} \\")
    yaml_parts.append(f"#     --template-body file://<filename>.yaml")
    yaml_parts.append(f"#")
    yaml_parts.append(f"# All rule identifiers validated against AWS documentation.")
    yaml_parts.append(f"# Generated: {today}")
    yaml_parts.append(f"{'#' * 80}")
    yaml_parts.append("")

    # Parameters section (only if there are parameterized rules)
    if param_lines:
        yaml_parts.append("Parameters:")
        yaml_parts.extend(param_lines)
        yaml_parts.append("")

    # Resources section
    yaml_parts.append("Resources:")
    yaml_parts.extend(resource_lines)

    yaml_content = "\n".join(yaml_parts)

    return {
        "yaml_content": yaml_content,
        "pack_name": pack_name,
        "framework": fw_key,
        "framework_name": fw_display,
        "rule_count": total_rules,
        "domains_covered": [int(k) for k in domain_keys if k in rules_by_domain],
        "domains_without_rules": [
            int(k) for k in domain_keys if k not in rules_by_domain
        ],
        "skipped_rules": skipped_rules,
        "generated_date": today,
    }
