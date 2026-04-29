"""Compliance assessment engine.

Evaluates infrastructure components against DPDP Act and RBI Master
Direction control domains. Checks resource-level configurations
including encryption, public access, logging, retention, and more.
"""

from __future__ import annotations

from typing import Any

from .domains import DPDP_DOMAINS, RBI_DOMAINS


def assess(components: list[dict], is_sdf: bool = False, is_rbi: bool = False) -> dict[str, Any]:
    """Run compliance assessment against DPDP and optionally RBI domains.

    Performs per-resource checks based on resource type and configuration
    properties. Returns posture scores, gap list, and component counts.

    Args:
        components: List of component dicts (from parsers or AWS scanner).
        is_sdf: Whether the organization is a Significant Data Fiduciary.
        is_rbi: Whether the organization is RBI-regulated.

    Returns:
        Dict with gaps, dpdp_posture, rbi_posture, total_components, total_gaps.
    """
    gaps: list[dict] = []
    dpdp_satisfied: set[int] = set()
    rbi_satisfied: set[int] = set()

    has_guardduty = any("guardduty" in c["type"].lower() for c in components)
    has_securityhub = any("securityhub" in c["type"].lower() or "security_hub" in c["type"].lower() for c in components)
    has_kms = any("kms" in c["type"].lower() for c in components)
    has_cloudtrail = any("cloudtrail" in c["type"].lower() for c in components)
    has_waf = any("waf" in c["type"].lower() for c in components)

    def _gap(comp_name: str, fw: str, dom: int, risk: str, desc: str, fix: str, ref: str) -> None:
        gaps.append({
            "component": comp_name, "framework": fw, "domain": dom,
            "domain_name": (DPDP_DOMAINS if fw == "dpdp" else RBI_DOMAINS).get(dom, ""),
            "risk": risk, "gap": desc, "remediation": fix, "reference": ref,
        })

    for comp in components:
        name = comp["name"]
        rtype = comp["type"]
        cat = comp.get("category", "other")
        p = comp.get("properties", {})

        _check_s3(name, rtype, p, is_rbi, has_kms, _gap, dpdp_satisfied)
        _check_dynamodb(name, rtype, p, is_rbi, _gap)
        _check_rds(name, rtype, p, is_rbi, _gap)
        _check_lambda(name, rtype, p, is_rbi, _gap)
        _check_ec2(name, rtype, p, is_rbi, _gap)
        _check_eks(name, rtype, p, is_rbi, _gap)
        _check_ecs(name, rtype, p, is_rbi, _gap)
        _check_api_gateway(name, rtype, is_rbi, has_waf, _gap)
        _check_cloudfront(name, rtype, p, is_rbi, _gap)
        _check_sqs(name, rtype, p, _gap)
        _check_sagemaker(name, rtype, p, is_rbi, _gap)
        _check_kms(name, rtype, p, is_rbi, _gap)
        _check_cloudtrail(name, rtype, p, is_rbi, _gap)
        _check_sns(name, rtype, p, _gap)

        if cat == "security":
            dpdp_satisfied.add(6)
            if is_rbi:
                rbi_satisfied.update([3, 4])

    # Architecture-level checks
    if has_guardduty:
        dpdp_satisfied.add(5)
        if is_rbi:
            rbi_satisfied.add(5)
    else:
        _gap("architecture", "dpdp", 5, "critical", "No GuardDuty for breach detection", "Enable GuardDuty", "DPDP Act Section 8(5)")

    if not has_securityhub:
        _gap("architecture", "dpdp", 5, "critical", "No Security Hub for centralized findings", "Enable Security Hub", "DPDP Act Section 8(5)")

    if has_cloudtrail:
        if is_rbi:
            rbi_satisfied.add(7)
    elif is_rbi:
        _gap("architecture", "rbi", 7, "critical", "No CloudTrail for audit logging", "Enable CloudTrail", "RBI MD Chapter VII")

    if has_waf and is_rbi:
        rbi_satisfied.add(5)
    if has_kms:
        dpdp_satisfied.add(6)
        if is_rbi:
            rbi_satisfied.add(4)

    # Domains that require organizational (non-infra) assessment
    dpdp_satisfied.update([2, 3, 4, 8, 9])
    if is_rbi:
        rbi_satisfied.update([1, 2, 6])

    if is_sdf:
        _gap("organization", "dpdp", 10, "high", "SDF must appoint DPO and conduct DPIA",
             "Appoint DPO, conduct annual DPIA", "DPDP Act Section 10(2)")

    dpdp_score = len(dpdp_satisfied) / 10 * 100
    rbi_score = len(rbi_satisfied) / 7 * 100 if is_rbi else None

    return {
        "gaps": gaps,
        "dpdp_posture": {"satisfied": len(dpdp_satisfied), "total": 10, "score": round(dpdp_score, 1)},
        "rbi_posture": {"satisfied": len(rbi_satisfied), "total": 7, "score": round(rbi_score, 1)} if is_rbi else None,
        "total_components": len(components),
        "total_gaps": len(gaps),
    }


# ---- Per-resource check functions ----

def _check_s3(name: str, rtype: str, p: dict, is_rbi: bool, has_kms: bool,
              gap: Any, dpdp_satisfied: set[int]) -> None:
    if "S3::Bucket" not in rtype:
        return
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "high", f"S3 '{name}' lacks encryption at rest", "Enable SSE-KMS encryption", "DPDP Act Section 8(4)")
    else:
        dpdp_satisfied.add(6)
    if not p.get("lifecycle_policy"):
        gap(name, "dpdp", 7, "medium", f"S3 '{name}' lacks lifecycle/retention policy", "Add lifecycle rules for data retention", "DPDP Act Section 8(6)")
    if not p.get("public_access_blocked"):
        gap(name, "dpdp", 6, "high", f"S3 '{name}' public access not fully blocked", "Enable S3 Block Public Access (all 4 settings)", "DPDP Act Section 8(4)")
        if is_rbi:
            gap(name, "rbi", 4, "high", f"S3 '{name}' public access not blocked", "Enable S3 Block Public Access", "RBI MD Chapter IV")
    if not p.get("versioning") and is_rbi:
        gap(name, "rbi", 6, "medium", f"S3 '{name}' lacks versioning for data recovery", "Enable versioning", "RBI MD Chapter VI")
    if not p.get("access_logging") and is_rbi:
        gap(name, "rbi", 7, "medium", f"S3 '{name}' lacks access logging", "Enable server access logging", "RBI MD Chapter VII")


def _check_dynamodb(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any) -> None:
    if "DynamoDB::Table" not in rtype:
        return
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "high", f"DynamoDB '{name}' lacks KMS encryption", "Enable KMS encryption", "DPDP Act Section 8(4)")
    if not p.get("lifecycle_policy"):
        gap(name, "dpdp", 7, "medium", f"DynamoDB '{name}' lacks TTL for data retention", "Enable TTL", "DPDP Act Section 8(6)")
    if not p.get("pitr_enabled") and is_rbi:
        gap(name, "rbi", 6, "medium", f"DynamoDB '{name}' lacks point-in-time recovery", "Enable PITR", "RBI MD Chapter VI")


def _check_rds(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any) -> None:
    if "RDS::DB" not in rtype:
        return
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "critical", f"RDS '{name}' storage not encrypted", "Enable RDS encryption", "DPDP Act Section 8(4)")
        if is_rbi:
            gap(name, "rbi", 4, "critical", f"RDS '{name}' not encrypted", "Enable encryption", "RBI MD Chapter IV")
    if p.get("publicly_accessible"):
        gap(name, "dpdp", 6, "critical", f"RDS '{name}' is publicly accessible", "Disable public access", "DPDP Act Section 8(4)")
        if is_rbi:
            gap(name, "rbi", 5, "critical", f"RDS '{name}' publicly accessible", "Move to private subnet", "RBI MD Chapter V")
    if not p.get("multi_az") and is_rbi:
        gap(name, "rbi", 6, "medium", f"RDS '{name}' not Multi-AZ", "Enable Multi-AZ", "RBI MD Chapter VI")
    if not p.get("audit_logging") and is_rbi:
        gap(name, "rbi", 7, "medium", f"RDS '{name}' lacks audit logging", "Enable CloudWatch log exports", "RBI MD Chapter VII")


def _check_lambda(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any) -> None:
    if "Lambda::Function" not in rtype:
        return
    if p.get("suspect_env_vars"):
        gap(name, "dpdp", 6, "high", f"Lambda '{name}' has suspect secrets in env vars: {p['suspect_env_vars']}", "Use Secrets Manager or Parameter Store", "DPDP Act Section 8(4)")
        if is_rbi:
            gap(name, "rbi", 4, "high", f"Lambda '{name}' secrets in env vars", "Use Secrets Manager", "RBI MD Chapter IV")
    if not p.get("dlq_configured") and is_rbi:
        gap(name, "rbi", 2, "low", f"Lambda '{name}' lacks dead letter queue", "Configure DLQ for error handling", "RBI MD Chapter III")


def _check_ec2(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any) -> None:
    if "EC2::Instance" not in rtype:
        return
    if p.get("public_ip"):
        gap(name, "dpdp", 6, "high", f"EC2 '{name}' has public IP", "Remove public IP, use private subnet + NAT", "DPDP Act Section 8(4)")
        if is_rbi:
            gap(name, "rbi", 5, "high", f"EC2 '{name}' has public IP", "Move to private subnet", "RBI MD Chapter V")
    if not p.get("imdsv2_required"):
        gap(name, "dpdp", 6, "medium", f"EC2 '{name}' does not require IMDSv2", "Enforce IMDSv2 (HttpTokens=required)", "DPDP Act Section 8(4)")
        if is_rbi:
            gap(name, "rbi", 5, "medium", f"EC2 '{name}' IMDSv2 not enforced", "Require IMDSv2", "RBI MD Chapter V")
    if p.get("unencrypted_ebs"):
        gap(name, "dpdp", 6, "high", f"EC2 '{name}' has unencrypted EBS volumes", "Enable EBS encryption", "DPDP Act Section 8(4)")


def _check_eks(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any) -> None:
    if "EKS::Cluster" not in rtype:
        return
    if not p.get("secrets_encryption"):
        gap(name, "dpdp", 6, "high", f"EKS '{name}' lacks secrets encryption", "Enable envelope encryption for K8s secrets", "DPDP Act Section 8(4)")
        if is_rbi:
            gap(name, "rbi", 4, "high", f"EKS '{name}' secrets not encrypted", "Enable KMS encryption for secrets", "RBI MD Chapter IV")
    if p.get("public_endpoint") and not p.get("private_endpoint"):
        gap(name, "dpdp", 6, "high", f"EKS '{name}' API server is public-only", "Enable private endpoint, restrict public access", "DPDP Act Section 8(4)")
        if is_rbi:
            gap(name, "rbi", 5, "high", f"EKS '{name}' public API endpoint", "Enable private endpoint", "RBI MD Chapter V")
    if not p.get("audit_logging"):
        gap(name, "dpdp", 5, "medium", f"EKS '{name}' lacks audit logging", "Enable control plane logging (audit, api, authenticator)", "DPDP Act Section 8(5)")
        if is_rbi:
            gap(name, "rbi", 7, "medium", f"EKS '{name}' no audit logs", "Enable cluster logging", "RBI MD Chapter VII")


def _check_ecs(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any) -> None:
    if "ECS::Cluster" not in rtype:
        return
    if not p.get("container_insights") and is_rbi:
        gap(name, "rbi", 2, "medium", f"ECS '{name}' lacks Container Insights", "Enable Container Insights for monitoring", "RBI MD Chapter III")


def _check_api_gateway(name: str, rtype: str, is_rbi: bool, has_waf: bool, gap: Any) -> None:
    if "ApiGateway" not in rtype:
        return
    if is_rbi and not has_waf:
        gap(name, "rbi", 5, "high", f"API Gateway '{name}' lacks WAF protection", "Attach WAF WebACL", "RBI MD Chapter V")


def _check_cloudfront(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any) -> None:
    if "CloudFront" not in rtype:
        return
    if not p.get("waf_attached") and is_rbi:
        gap(name, "rbi", 5, "high", f"CloudFront '{name}' lacks WAF", "Attach WAF WebACL", "RBI MD Chapter V")
    if not p.get("access_logging") and is_rbi:
        gap(name, "rbi", 7, "medium", f"CloudFront '{name}' lacks access logging", "Enable access logging", "RBI MD Chapter VII")


def _check_sqs(name: str, rtype: str, p: dict, gap: Any) -> None:
    if "SQS::Queue" not in rtype:
        return
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "medium", f"SQS '{name}' lacks encryption", "Enable SSE-KMS or SSE-SQS", "DPDP Act Section 8(4)")


def _check_sagemaker(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any) -> None:
    if "SageMaker" not in rtype:
        return
    if p.get("direct_internet"):
        gap(name, "dpdp", 6, "high", f"SageMaker '{name}' has direct internet access", "Disable direct internet, use VPC", "DPDP Act Section 8(4)")
        if is_rbi:
            gap(name, "rbi", 5, "high", f"SageMaker '{name}' direct internet", "Disable direct internet access", "RBI MD Chapter V")
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "high", f"SageMaker '{name}' lacks encryption", "Enable KMS encryption", "DPDP Act Section 8(4)")
    gap(name, "dpdp", 1, "high", f"ML component '{name}' — verify consent for training data", "Implement consent tracking for ML training data", "DPDP Act Section 6")


def _check_kms(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any) -> None:
    if "KMS::Key" not in rtype:
        return
    if p.get("key_manager") == "CUSTOMER" and not p.get("key_rotation"):
        gap(name, "dpdp", 6, "medium", f"KMS key '{name}' lacks automatic rotation", "Enable annual key rotation", "DPDP Act Section 8(4)")
        if is_rbi:
            gap(name, "rbi", 4, "medium", f"KMS key '{name}' no rotation", "Enable key rotation", "RBI MD Chapter IV")


def _check_cloudtrail(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any) -> None:
    if "CloudTrail::Trail" not in rtype:
        return
    if not p.get("log_validation"):
        gap(name, "dpdp", 5, "medium", f"CloudTrail '{name}' lacks log file validation", "Enable log file validation", "DPDP Act Section 8(5)")
        if is_rbi:
            gap(name, "rbi", 7, "medium", f"CloudTrail '{name}' no log validation", "Enable validation", "RBI MD Chapter VII")
    if not p.get("encryption") and is_rbi:
        gap(name, "rbi", 7, "medium", f"CloudTrail '{name}' logs not encrypted", "Enable KMS encryption for trail", "RBI MD Chapter VII")


def _check_sns(name: str, rtype: str, p: dict, gap: Any) -> None:
    if "SNS::Topic" not in rtype:
        return
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "low", f"SNS '{name}' lacks encryption", "Enable SSE-KMS", "DPDP Act Section 8(4)")
