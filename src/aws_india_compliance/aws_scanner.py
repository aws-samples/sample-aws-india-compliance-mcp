"""AWS Config-based resource scanner.

Discovers resources via AWS Config Advanced Query and extracts
compliance-relevant configuration properties. Falls back to
direct API calls for account-level services (Security Hub,
GuardDuty, CloudTrail, WAF) that Config may not track.
"""

from __future__ import annotations

import json
from typing import Any

from .parsers import classify_service

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
    except (json.JSONDecodeError, TypeError):
        config = {}

    props: dict[str, Any] = {}

    if "S3::Bucket" in rtype:
        _extract_s3_props(config, props)
    elif "DynamoDB::Table" in rtype:
        _extract_dynamodb_props(config, props)
    elif "RDS::DB" in rtype:
        _extract_rds_props(config, props)
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

    return {
        "name": name,
        "type": rtype,
        "category": classify_service(rtype),
        "properties": props,
        "region": resource.get("awsRegion", ""),
        "account_id": resource.get("accountId", ""),
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


# ---- Fallback API checks ----

def _fallback_security_hub(session: Any, region: str, components: list[dict]) -> None:
    if any(c["type"] == "AWS::SecurityHub::Hub" for c in components):
        return
    try:
        sh = session.client("securityhub")
        hub = sh.describe_hub()
        components.append({
            "name": "SecurityHub", "type": "AWS::SecurityHub::Hub", "category": "security",
            "properties": {}, "region": region, "account_id": "",
        })
    except Exception:
        pass


def _fallback_guardduty(session: Any, region: str, components: list[dict]) -> None:
    if any("GuardDuty" in c["type"] for c in components):
        return
    try:
        gd = session.client("guardduty")
        if gd.list_detectors().get("DetectorIds"):
            components.append({
                "name": "GuardDuty", "type": "AWS::GuardDuty::Detector", "category": "security",
                "properties": {}, "region": region, "account_id": "",
            })
    except Exception:
        pass


def _fallback_cloudtrail(session: Any, region: str, components: list[dict]) -> None:
    if any("CloudTrail" in c["type"] for c in components):
        return
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        if trails:
            components.append({
                "name": trails[0].get("Name", "CloudTrail"), "type": "AWS::CloudTrail::Trail",
                "category": "security", "properties": {}, "region": region, "account_id": "",
            })
    except Exception:
        pass


def _fallback_waf(session: Any, region: str, components: list[dict]) -> None:
    if any("WAF" in c["type"] for c in components):
        return
    try:
        waf = session.client("wafv2")
        if waf.list_web_acls(Scope="REGIONAL").get("WebACLs"):
            components.append({
                "name": "WAF", "type": "AWS::WAFv2::WebACL", "category": "security",
                "properties": {}, "region": region, "account_id": "",
            })
    except Exception:
        pass
