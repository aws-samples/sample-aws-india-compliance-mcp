"""AWS Config-based resource scanner.

Discovers resources via AWS Config Advanced Query and extracts
compliance-relevant configuration properties. Falls back to
direct API calls for account-level services (Security Hub,
GuardDuty, CloudTrail, WAF) that Config may not track.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .parsers import classify_service

_logger = logging.getLogger(__name__)

# Resource types to query from AWS Config
CONFIG_RESOURCE_TYPES: list[str] = [
    "AWS::S3::Bucket", "AWS::DynamoDB::Table", "AWS::Lambda::Function",
    "AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::EC2::Instance",
    "AWS::ECS::Cluster", "AWS::EKS::Cluster", "AWS::SQS::Queue", "AWS::SNS::Topic",
    "AWS::GuardDuty::Detector", "AWS::SecurityHub::Hub", "AWS::CloudTrail::Trail",
    "AWS::WAFv2::WebACL", "AWS::KMS::Key", "AWS::IAM::Role",
    "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::CloudFront::Distribution",
    "AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Api",
    "AWS::Redshift::Cluster", "AWS::EFS::FileSystem",
    "AWS::SageMaker::NotebookInstance", "AWS::SageMaker::Endpoint",
    "AWS::Kinesis::Stream", "AWS::Events::Rule",
    "AWS::Logs::LogGroup",
    "AWS::EC2::VPC",
    "AWS::EC2::SecurityGroup",
    "AWS::SecretsManager::Secret",
    "AWS::AccessAnalyzer::Analyzer",
    "AWS::SSM::PatchCompliance",
]


def config_to_component(resource: dict) -> dict[str, Any]:
    """Convert an AWS Config resource record to a component dict.

    Extracts compliance-relevant properties from the Config
    configuration JSON for each supported resource type.
    """
    rtype = resource.get("resourceType", "")
    name = resource.get("resourceName", "") or resource.get("resourceId", "")
    config_str = resource.get("configuration", "{}")
    try:
        config = json.loads(config_str) if isinstance(config_str, str) else config_str
        # Handle double-encoded JSON (Config sometimes returns nested strings)
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except (json.JSONDecodeError, TypeError):
                config = {}
        if not isinstance(config, dict):
            config = {}
    except (json.JSONDecodeError, TypeError):
        config = {}

    props: dict[str, Any] = {}

    if "S3::Bucket" in rtype:
        _extract_s3_props(config, props)
        _extract_s3_tls_props(config, props)
    elif "DynamoDB::Table" in rtype:
        _extract_dynamodb_props(config, props)
    elif "RDS::DB" in rtype:
        _extract_rds_props(config, props)
        _extract_rds_ssl_props(config, props)
    elif "Lambda::Function" in rtype:
        _extract_lambda_props(config, props)
    elif "EC2::Instance" in rtype:
        _extract_ec2_props(config, props)
    elif "EKS::Cluster" in rtype:
        _extract_eks_props(config, props)
    elif "ECS::Cluster" in rtype:
        _extract_ecs_props(config, props)
    elif "CloudFront::Distribution" in rtype:
        _extract_cloudfront_props(config, props)
    elif "SQS::Queue" in rtype:
        _extract_sqs_props(config, props)
    elif "SageMaker" in rtype:
        _extract_sagemaker_props(config, props)
    elif "KMS::Key" in rtype:
        _extract_kms_props(config, props)
    elif "CloudTrail::Trail" in rtype:
        _extract_cloudtrail_props(config, props)
    elif "IAM::Role" in rtype:
        _extract_iam_role_props(config, props)
    elif "Logs::LogGroup" in rtype:
        _extract_log_group_props(config, props)
    elif "EFS::FileSystem" in rtype:
        if config.get("encrypted"):
            props["encryption"] = "encrypted"
    elif "Redshift::Cluster" in rtype:
        if config.get("encrypted"):
            props["encryption"] = "encrypted"
        props["publicly_accessible"] = config.get("publiclyAccessible", False)
    elif "SNS::Topic" in rtype:
        if config.get("kmsMasterKeyId"):
            props["encryption"] = "encrypted"
    elif "EC2::VPC" in rtype and "SecurityGroup" not in rtype:
        _extract_vpc_props(config, props)
    elif "EC2::SecurityGroup" in rtype:
        _extract_security_group_props(config, props)
    elif "SecretsManager::Secret" in rtype:
        _extract_secrets_manager_props(config, props)

    # --- Tag extraction (Task 2.1) ---
    try:
        tags_raw = config.get("tags", [])
        if isinstance(tags_raw, list):
            tags = {
                t.get("key", t.get("Key", "")): t.get("value", t.get("Value", ""))
                for t in tags_raw if isinstance(t, dict)
            }
        elif isinstance(tags_raw, dict):
            tags = dict(tags_raw)
        else:
            tags = {}

        # Also check supplementaryConfiguration for tags
        supp = resource.get("supplementaryConfiguration") or {}
        if isinstance(supp, str):
            try:
                supp = json.loads(supp)
            except (json.JSONDecodeError, TypeError):
                supp = {}
        if not isinstance(supp, dict):
            supp = {}
        if isinstance(supp, dict):
            supp_tags = supp.get("Tags", supp.get("tags", []))
            if isinstance(supp_tags, list):
                for t in supp_tags:
                    if isinstance(t, dict):
                        k = t.get("key", t.get("Key", ""))
                        v = t.get("value", t.get("Value", ""))
                        if k:
                            tags.setdefault(k, v)
            elif isinstance(supp_tags, dict):
                for k, v in supp_tags.items():
                    tags.setdefault(k, v)
    except Exception:
        tags = {}

    return {
        "name": name,
        "type": rtype,
        "category": classify_service(rtype),
        "properties": props,
        "region": resource.get("awsRegion", ""),
        "account_id": resource.get("accountId", ""),
        "tags": tags,
    }


def scan_via_config(region: str, aggregator_name: str = "") -> list[dict[str, Any]]:
    """Query AWS Config for all resources and their configurations.

    Uses Config Advanced Query (select_resource_config) for single-account
    scans, or select_aggregate_resource_config with an aggregator for
    org-wide scans. Falls back to direct API calls for Security Hub,
    GuardDuty, CloudTrail, and WAF.

    Args:
        region: AWS region to scan.
        aggregator_name: Config Aggregator name for org-wide scan. Empty = single account.

    Returns:
        List of component dicts ready for assessment.

    Raises:
        RuntimeError: If Config query fails (recorder not enabled).
    """
    import boto3

    session = boto3.Session(region_name=region)
    config_client = session.client("config")

    type_list = ", ".join(f"'{t}'" for t in CONFIG_RESOURCE_TYPES)
    query = (
        f"SELECT resourceType, resourceId, resourceName, configuration, awsRegion, accountId "
        f"WHERE resourceType IN ({type_list})"
    )

    components: list[dict] = []
    try:
        if aggregator_name:
            paginator = config_client.get_paginator("select_aggregate_resource_config")
            pages = paginator.paginate(Expression=query, ConfigurationAggregatorName=aggregator_name)
        else:
            paginator = config_client.get_paginator("select_resource_config")
            pages = paginator.paginate(Expression=query)

        for page in pages:
            for result_str in page.get("Results", []):
                try:
                    components.append(config_to_component(json.loads(result_str)))
                except (json.JSONDecodeError, TypeError):
                    continue
    except Exception as e:
        raise RuntimeError(f"Config query failed: {e}. Ensure AWS Config recorder is enabled in {region}.")

    # Fallback: direct API checks for account-level services
    _fallback_security_hub(session, region, components)
    _fallback_guardduty(session, region, components)
    _fallback_cloudtrail(session, region, components)
    _fallback_waf(session, region, components)
    _fallback_backup(session, region, components)
    _fallback_inspector(session, region, components)
    _fallback_shield(session, region, components)
    _fallback_network_firewall(session, region, components)
    _fallback_access_analyzer(session, region, components)
    _fallback_macie(session, region, components)

    return components


# ---- Property extractors ----

def _extract_s3_props(config: dict, props: dict) -> None:
    sse = config.get("serverSideEncryptionConfiguration", {})
    rules = sse.get("rules", [])
    if rules:
        algo = rules[0].get("applyServerSideEncryptionByDefault", {}).get("sseAlgorithm", "")
        if algo:
            props["encryption"] = algo
        kmk = rules[0].get("applyServerSideEncryptionByDefault", {}).get("kmsMasterKeyID")
        if kmk:
            props["kms_key_id"] = kmk
    if config.get("lifecycleConfiguration", {}).get("rules"):
        props["lifecycle_policy"] = True
    pab = config.get("publicAccessBlockConfiguration", {})
    if pab and all(pab.get(k) for k in ("blockPublicAcls", "blockPublicPolicy", "restrictPublicBuckets", "ignorePublicAcls")):
        props["public_access_blocked"] = True
    if config.get("versioningConfiguration", {}).get("status") == "Enabled":
        props["versioning"] = True
    if config.get("loggingConfiguration", {}).get("destinationBucketName"):
        props["access_logging"] = True
    if config.get("objectLockConfiguration", {}).get("objectLockEnabled") == "Enabled":
        props["object_lock"] = True


def _extract_dynamodb_props(config: dict, props: dict) -> None:
    sse = config.get("ssedescription") or config.get("sSEDescription") or {}
    if sse.get("status") == "ENABLED" or sse.get("Status") == "ENABLED":
        props["encryption"] = sse.get("sSEType", sse.get("sseType", "KMS"))
    ttl = config.get("timeToLiveDescription") or {}
    if ttl.get("timeToLiveStatus") == "ENABLED":
        props["lifecycle_policy"] = True
    pitr = config.get("continuousBackupsDescription", {}).get("pointInTimeRecoveryDescription", {})
    if pitr.get("pointInTimeRecoveryStatus") == "ENABLED":
        props["pitr_enabled"] = True


def _extract_rds_props(config: dict, props: dict) -> None:
    if config.get("storageEncrypted"):
        props["encryption"] = "encrypted"
    if config.get("backupRetentionPeriod", 0) > 0:
        props["lifecycle_policy"] = True
    props["publicly_accessible"] = config.get("publiclyAccessible", False)
    props["multi_az"] = config.get("multiAZ", False)
    if config.get("enabledCloudwatchLogsExports"):
        props["audit_logging"] = True


def _extract_lambda_props(config: dict, props: dict) -> None:
    props["runtime"] = config.get("runtime", "")
    if config.get("vpcConfig", {}).get("subnetIds"):
        props["vpc_enabled"] = True
    env_vars = config.get("environment", {}).get("variables", {})
    secret_patterns = ["password", "secret", "key", "token", "api_key"]
    suspect = [k for k in env_vars if any(p in k.lower() for p in secret_patterns)]
    if suspect:
        props["suspect_env_vars"] = suspect
    if config.get("deadLetterConfig", {}).get("targetArn"):
        props["dlq_configured"] = True


def _extract_ec2_props(config: dict, props: dict) -> None:
    props["public_ip"] = bool(config.get("publicIpAddress"))
    props["imdsv2_required"] = config.get("metadataOptions", {}).get("httpTokens") == "required"
    for bdm in config.get("blockDeviceMappings", []):
        if bdm.get("ebs") and not bdm["ebs"].get("encrypted", True):
            props["unencrypted_ebs"] = True


def _extract_eks_props(config: dict, props: dict) -> None:
    if config.get("encryptionConfig"):
        props["secrets_encryption"] = True
    logging_config = config.get("logging", {}).get("clusterLogging", [])
    for lc in logging_config:
        if lc.get("enabled"):
            props["audit_logging"] = True
            break
    vpc = config.get("resourcesVpcConfig", {})
    props["public_endpoint"] = vpc.get("endpointPublicAccess", True)
    props["private_endpoint"] = vpc.get("endpointPrivateAccess", False)


def _extract_ecs_props(config: dict, props: dict) -> None:
    for s in config.get("settings", []):
        if s.get("name") == "containerInsights" and s.get("value") == "enabled":
            props["container_insights"] = True


def _extract_cloudfront_props(config: dict, props: dict) -> None:
    dist = config.get("distributionConfig", config)
    if dist.get("webACLId"):
        props["waf_attached"] = True
    if dist.get("logging", {}).get("enabled"):
        props["access_logging"] = True


def _extract_sqs_props(config: dict, props: dict) -> None:
    if config.get("kmsMasterKeyId") or config.get("sqsManagedSseEnabled"):
        props["encryption"] = "encrypted"
    if config.get("redrivePolicy"):
        props["dlq_configured"] = True


def _extract_sagemaker_props(config: dict, props: dict) -> None:
    props["direct_internet"] = config.get("directInternetAccess", "Enabled") == "Enabled"
    if config.get("kmsKeyId"):
        props["encryption"] = "encrypted"
    if config.get("subnetId"):
        props["vpc_enabled"] = True


def _extract_kms_props(config: dict, props: dict) -> None:
    props["key_manager"] = config.get("keyManager", "")
    props["key_rotation"] = config.get("keyRotationEnabled", False)


def _extract_cloudtrail_props(config: dict, props: dict) -> None:
    props["log_validation"] = config.get("logFileValidationEnabled", False)
    props["multi_region"] = config.get("isMultiRegionTrail", False)
    if config.get("kmsKeyId"):
        props["encryption"] = "encrypted"
    if config.get("cloudWatchLogsLogGroupArn"):
        props["cloudwatch_logs"] = True


def _extract_iam_role_props(config: dict, props: dict) -> None:
    policies = config.get("attachedManagedPolicies", [])
    props["attached_policies"] = [p.get("policyName", "") for p in policies]


def _extract_log_group_props(config: dict, props: dict) -> None:
    props["retention_days"] = config.get("retentionInDays", 0)


def _extract_s3_tls_props(config: dict, props: dict) -> None:
    """Extract TLS enforcement from bucket policy (aws:SecureTransport condition)."""
    bucket_policy = config.get("bucketPolicy")
    if isinstance(bucket_policy, str):
        try:
            bucket_policy = json.loads(bucket_policy)
        except (json.JSONDecodeError, TypeError):
            bucket_policy = {}
    if not isinstance(bucket_policy, dict):
        bucket_policy = {}
    policy_str = bucket_policy.get("policyText", "")
    if policy_str:
        try:
            policy = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
            if not isinstance(policy, dict):
                props["tls_enforced"] = False
                return
            for stmt in policy.get("Statement", []):
                if not isinstance(stmt, dict):
                    continue
                condition = stmt.get("Condition", {})
                if not isinstance(condition, dict):
                    continue
                bool_cond = condition.get("Bool", {})
                if not isinstance(bool_cond, dict):
                    continue
                if (
                    bool_cond.get("aws:SecureTransport") == "false"
                    and stmt.get("Effect") == "Deny"
                ):
                    props["tls_enforced"] = True
                    return
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
    props["tls_enforced"] = False


def _extract_rds_ssl_props(config: dict, props: dict) -> None:
    """Extract SSL enforcement from RDS engine type and known defaults."""
    engine = config.get("engine", "")
    # Aurora PostgreSQL and Aurora MySQL default to SSL enforcement
    props["ssl_enforced"] = engine in ("aurora-postgresql", "aurora-mysql")


def _extract_vpc_props(config: dict, props: dict) -> None:
    """Extract VPC Flow Logs status."""
    flow_logs = config.get("flowLogs", [])
    props["flow_logs_enabled"] = len(flow_logs) > 0
    if flow_logs:
        props["flow_log_destinations"] = [
            fl.get("logDestinationType", "") for fl in flow_logs
        ]


def _extract_security_group_props(config: dict, props: dict) -> None:
    """Extract ingress rules, flag 0.0.0.0/0 on SSH/RDP."""
    ingress = config.get("ipPermissions", [])
    if not isinstance(ingress, list):
        props["open_to_internet"] = []
        return
    open_ports: list[int] = []
    for rule in ingress:
        if not isinstance(rule, dict):
            continue
        from_port = rule.get("fromPort", 0) or 0
        to_port = rule.get("toPort", 0) or 0
        # Check ipv4Ranges (Config format) and ipRanges
        for range_key in ("ipv4Ranges", "ipRanges"):
            for ip_range in rule.get(range_key, []):
                if isinstance(ip_range, str):
                    cidr = ip_range
                elif isinstance(ip_range, dict):
                    cidr = ip_range.get("cidrIp", ip_range.get("cidrIpv4", ""))
                else:
                    continue
                if cidr == "0.0.0.0/0":
                    if from_port <= 22 <= to_port:
                        open_ports.append(22)
                    if from_port <= 3389 <= to_port:
                        open_ports.append(3389)
    props["open_to_internet"] = open_ports


def _extract_secrets_manager_props(config: dict, props: dict) -> None:
    """Extract rotation configuration."""
    props["rotation_enabled"] = config.get("rotationEnabled", False)


# ---- Fallback API checks ----

def _fallback_security_hub(session: Any, region: str, components: list[dict]) -> None:
    if any(c["type"] == "AWS::SecurityHub::Hub" for c in components):
        return
    try:
        sh = session.client("securityhub")
        hub = sh.describe_hub()
        components.append({
            "name": "SecurityHub", "type": "AWS::SecurityHub::Hub", "category": "security",
            "properties": {}, "region": region, "account_id": "", "tags": {},
        })
    except Exception:  # noqa: B110 — expected when service not enabled
        _logger.debug("SecurityHub not available in %s", region)


def _fallback_guardduty(session: Any, region: str, components: list[dict]) -> None:
    if any("GuardDuty" in c["type"] for c in components):
        return
    try:
        gd = session.client("guardduty")
        if gd.list_detectors().get("DetectorIds"):
            components.append({
                "name": "GuardDuty", "type": "AWS::GuardDuty::Detector", "category": "security",
                "properties": {}, "region": region, "account_id": "", "tags": {},
            })
    except Exception:  # noqa: B110 — expected when service not enabled
        _logger.debug("GuardDuty not available in %s", region)


def _fallback_cloudtrail(session: Any, region: str, components: list[dict]) -> None:
    if any("CloudTrail" in c["type"] for c in components):
        return
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        if trails:
            components.append({
                "name": trails[0].get("Name", "CloudTrail"), "type": "AWS::CloudTrail::Trail",
                "category": "security", "properties": {}, "region": region, "account_id": "", "tags": {},
            })
    except Exception:  # noqa: B110 — expected when service not enabled
        _logger.debug("CloudTrail not available in %s", region)


def _fallback_waf(session: Any, region: str, components: list[dict]) -> None:
    if any("WAF" in c["type"] for c in components):
        return
    try:
        waf = session.client("wafv2")
        if waf.list_web_acls(Scope="REGIONAL").get("WebACLs"):
            components.append({
                "name": "WAF", "type": "AWS::WAFv2::WebACL", "category": "security",
                "properties": {}, "region": region, "account_id": "", "tags": {},
            })
    except Exception:  # noqa: B110 — expected when service not enabled
        _logger.debug("WAF not available in %s", region)


def _fallback_backup(session: Any, region: str, components: list[dict]) -> None:
    """Check for AWS Backup plans via direct API."""
    try:
        backup = session.client("backup")
        plans = backup.list_backup_plans().get("BackupPlansList", [])
        if plans:
            for plan in plans[:5]:  # Cap to avoid large responses
                components.append({
                    "name": plan.get("BackupPlanName", "backup-plan"),
                    "type": "AWS::Backup::BackupPlan",
                    "category": "storage",
                    "properties": {"vault_lock": False},
                    "region": region, "account_id": "", "tags": {},
                })
        # Check vault locks
        vaults = backup.list_backup_vaults().get("BackupVaultList", [])
        for vault in vaults[:5]:
            locked = vault.get("Locked", False)
            if locked:
                for comp in components:
                    if comp["type"] == "AWS::Backup::BackupPlan":
                        comp["properties"]["vault_lock"] = True
    except Exception:  # noqa: B110 — expected when service not enabled
        _logger.debug("Backup not available in %s", region)


def _fallback_inspector(session: Any, region: str, components: list[dict]) -> None:
    """Check for Amazon Inspector enablement."""
    try:
        inspector = session.client("inspector2")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        status = inspector.batch_get_account_status(accountIds=[account_id])
        for acct in status.get("accounts", []):
            state = acct.get("state", {}).get("status", "")
            if state == "ENABLED":
                components.append({
                    "name": "Inspector", "type": "AWS::Inspector2::Detector",
                    "category": "security",
                    "properties": {"enabled": True},
                    "region": region, "account_id": acct.get("accountId", ""), "tags": {},
                })
                return
    except Exception:  # noqa: B110 — expected when service not enabled
        _logger.debug("Inspector not available in %s", region)


def _fallback_shield(session: Any, region: str, components: list[dict]) -> None:
    """Check for AWS Shield Advanced subscription."""
    try:
        shield = session.client("shield", region_name="us-east-1")  # Shield is global
        subscription = shield.describe_subscription()
        if subscription.get("Subscription"):
            components.append({
                "name": "ShieldAdvanced",
                "type": "AWS::Shield::Subscription",
                "category": "security",
                "properties": {"active": True},
                "region": "global", "account_id": "", "tags": {},
            })
    except Exception:
        _logger.debug("Shield Advanced not available")


def _fallback_network_firewall(session: Any, region: str, components: list[dict]) -> None:
    """Check for AWS Network Firewall."""
    try:
        nfw = session.client("network-firewall", region_name=region)
        firewalls = nfw.list_firewalls().get("Firewalls", [])
        for fw in firewalls[:5]:
            components.append({
                "name": fw.get("FirewallName", "network-firewall"),
                "type": "AWS::NetworkFirewall::Firewall",
                "category": "security",
                "properties": {},
                "region": region, "account_id": "", "tags": {},
            })
    except Exception:
        _logger.debug("Network Firewall not available in %s", region)


def _fallback_access_analyzer(session: Any, region: str, components: list[dict]) -> None:
    """Check for IAM Access Analyzer."""
    try:
        aa = session.client("accessanalyzer", region_name=region)
        analyzers = aa.list_analyzers(type="ACCOUNT").get("analyzers", [])
        for analyzer in analyzers[:3]:
            components.append({
                "name": analyzer.get("name", "access-analyzer"),
                "type": "AWS::AccessAnalyzer::Analyzer",
                "category": "security",
                "properties": {"status": analyzer.get("status", ""), "type": analyzer.get("type", "")},
                "region": region, "account_id": "", "tags": {},
            })
    except Exception:
        _logger.debug("Access Analyzer not available in %s", region)


def _fallback_macie(session: Any, region: str, components: list[dict]) -> None:
    """Check for Amazon Macie enablement."""
    try:
        macie = session.client("macie2", region_name=region)
        status = macie.get_macie_session()
        if status.get("status") == "ENABLED":
            components.append({
                "name": "Macie",
                "type": "AWS::Macie::Session",
                "category": "security",
                "properties": {"status": "ENABLED"},
                "region": region, "account_id": "", "tags": {},
            })
    except Exception:
        _logger.debug("Macie not available in %s", region)
