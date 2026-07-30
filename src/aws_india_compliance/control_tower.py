"""Control Tower scanner and compliance assessment.

Discovers landing zone configuration, enabled controls per OU,
and maps them to DPDP/RBI control domains. Recommends missing
controls based on compliance requirements.
"""

from __future__ import annotations

import logging
from typing import Any

from .domains import CERTIN_DOMAINS, DPDP_DOMAINS, RBI_DOMAINS, SEBI_DOMAINS

_logger = logging.getLogger(__name__)

# Control Tower control → compliance domain mapping
CT_CONTROL_MAP: dict[str, dict] = {
    "AWS-GR_ENCRYPTED_VOLUMES": {"dpdp": [6], "rbi": [4], "sebi": [3], "desc": "EBS volumes must be encrypted"},
    "AWS-GR_EBS_OPTIMIZED_INSTANCE": {"dpdp": [6], "rbi": [2], "sebi": [], "desc": "EC2 instances must be EBS-optimized"},
    "AWS-GR_RDS_INSTANCE_PUBLIC_ACCESS_CHECK": {"dpdp": [6], "rbi": [4, 5], "sebi": [3], "desc": "RDS instances must not be public"},
    "AWS-GR_RDS_STORAGE_ENCRYPTED": {"dpdp": [6], "rbi": [4], "sebi": [3], "desc": "RDS storage must be encrypted"},
    "AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS": {"dpdp": [6], "rbi": [4], "sebi": [3], "desc": "Root user must not have access keys"},
    "AWS-GR_RESTRICT_ROOT_USER": {"dpdp": [6], "rbi": [4], "sebi": [3], "desc": "Root user actions restricted"},
    "AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED": {"dpdp": [6], "rbi": [4], "sebi": [3], "desc": "S3 buckets must not allow public read"},
    "AWS-GR_S3_BUCKET_PUBLIC_WRITE_PROHIBITED": {"dpdp": [6], "rbi": [4], "sebi": [3], "desc": "S3 buckets must not allow public write"},
    "AWS-GR_AUDIT_BUCKET_ENCRYPTION_ENABLED": {"dpdp": [6], "rbi": [7], "sebi": [3], "desc": "Audit bucket must be encrypted"},
    "AWS-GR_AUDIT_BUCKET_LOGGING_ENABLED": {"dpdp": [5], "rbi": [7], "sebi": [4], "certin": [1, 4], "desc": "Audit bucket logging enabled"},
    "AWS-GR_AUDIT_BUCKET_RETENTION_POLICY": {"dpdp": [7], "rbi": [7], "sebi": [6], "certin": [2], "desc": "Audit bucket has retention policy"},
    "AWS-GR_LOG_GROUP_ENCRYPTED": {"dpdp": [5, 6], "rbi": [7], "sebi": [3, 4], "certin": [2], "desc": "CloudWatch log groups encrypted"},
    "AWS-GR_CLOUDTRAIL_ENABLED": {"dpdp": [5], "rbi": [7], "sebi": [2, 4], "certin": [1, 4], "desc": "CloudTrail must be enabled"},
    "AWS-GR_CLOUDTRAIL_VALIDATION_ENABLED": {"dpdp": [5], "rbi": [7], "sebi": [2], "certin": [1], "desc": "CloudTrail log validation enabled"},
    "AWS-GR_REGION_DENY": {"dpdp": [8], "rbi": [], "sebi": [1], "desc": "Deny access to non-approved regions"},
    "AWS-GR_MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS": {"dpdp": [6], "rbi": [4], "sebi": [3], "desc": "MFA required for console access"},
    "AWS-GR_IAM_USER_MFA_ENABLED": {"dpdp": [6], "rbi": [4], "sebi": [3], "desc": "IAM users must have MFA"},
    "AWS-GR_DISALLOW_CROSS_REGION_NETWORKING": {"dpdp": [8], "rbi": [], "sebi": [1], "desc": "Restrict cross-region networking"},
    "AWS-GR_LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED": {"dpdp": [6], "rbi": [5], "sebi": [3], "desc": "Lambda must not be public"},
    "AWS-GR_EC2_INSTANCE_NO_PUBLIC_IP": {"dpdp": [6], "rbi": [5], "sebi": [3], "desc": "EC2 must not have public IP"},
    "AWS-GR_ENSURE_CLOUDTRAIL_ENABLED_ON": {"dpdp": [5], "rbi": [7], "sebi": [2, 4], "certin": [1, 4], "desc": "CloudTrail enabled in all regions"},
    "AWS-GR_S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC": {"dpdp": [6], "rbi": [4], "sebi": [3], "desc": "S3 account-level public access blocked"},
    "AWS-GR_EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK": {"dpdp": [6], "rbi": [4], "sebi": [3], "desc": "EBS snapshots not public"},
    "AWS-GR_SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS": {"dpdp": [6], "rbi": [5], "sebi": [3], "desc": "SageMaker no direct internet"},
    "AWS-GR_SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED": {"dpdp": [6], "rbi": [5], "sebi": [3], "desc": "Subnets no auto-assign public IP"},
}

# Recommended controls per compliance domain
RECOMMENDED_DPDP: dict[int, list[str]] = {
    5: ["AWS-GR_CLOUDTRAIL_ENABLED", "AWS-GR_CLOUDTRAIL_VALIDATION_ENABLED", "AWS-GR_AUDIT_BUCKET_LOGGING_ENABLED", "AWS-GR_LOG_GROUP_ENCRYPTED"],
    6: ["AWS-GR_ENCRYPTED_VOLUMES", "AWS-GR_RDS_STORAGE_ENCRYPTED", "AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED", "AWS-GR_S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
        "AWS-GR_RESTRICT_ROOT_USER", "AWS-GR_MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS", "AWS-GR_EC2_INSTANCE_NO_PUBLIC_IP", "AWS-GR_LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED",
        "AWS-GR_AUDIT_BUCKET_ENCRYPTION_ENABLED", "AWS-GR_S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC"],
    7: ["AWS-GR_AUDIT_BUCKET_RETENTION_POLICY"],
    8: ["AWS-GR_REGION_DENY", "AWS-GR_DISALLOW_CROSS_REGION_NETWORKING"],
}

RECOMMENDED_RBI: dict[int, list[str]] = {
    4: ["AWS-GR_ENCRYPTED_VOLUMES", "AWS-GR_RDS_STORAGE_ENCRYPTED", "AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED",
        "AWS-GR_RESTRICT_ROOT_USER", "AWS-GR_MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS", "AWS-GR_EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"],
    5: ["AWS-GR_EC2_INSTANCE_NO_PUBLIC_IP", "AWS-GR_LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED", "AWS-GR_SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED"],
    7: ["AWS-GR_CLOUDTRAIL_ENABLED", "AWS-GR_CLOUDTRAIL_VALIDATION_ENABLED", "AWS-GR_AUDIT_BUCKET_LOGGING_ENABLED", "AWS-GR_LOG_GROUP_ENCRYPTED"],
}

RECOMMENDED_SEBI: dict[int, list[str]] = {
    1: ["AWS-GR_REGION_DENY", "AWS-GR_DISALLOW_CROSS_REGION_NETWORKING"],
    2: ["AWS-GR_CLOUDTRAIL_ENABLED", "AWS-GR_CLOUDTRAIL_VALIDATION_ENABLED"],
    3: ["AWS-GR_ENCRYPTED_VOLUMES", "AWS-GR_RDS_STORAGE_ENCRYPTED", "AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED",
        "AWS-GR_S3_BUCKET_PUBLIC_WRITE_PROHIBITED", "AWS-GR_RESTRICT_ROOT_USER", "AWS-GR_MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS",
        "AWS-GR_EC2_INSTANCE_NO_PUBLIC_IP", "AWS-GR_LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED", "AWS-GR_SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED"],
    4: ["AWS-GR_AUDIT_BUCKET_LOGGING_ENABLED", "AWS-GR_LOG_GROUP_ENCRYPTED", "AWS-GR_CLOUDTRAIL_ENABLED"],
    6: ["AWS-GR_AUDIT_BUCKET_RETENTION_POLICY"],
}

RECOMMENDED_CERTIN: dict[int, list[str]] = {
    1: ["AWS-GR_CLOUDTRAIL_ENABLED", "AWS-GR_CLOUDTRAIL_VALIDATION_ENABLED", "AWS-GR_AUDIT_BUCKET_LOGGING_ENABLED", "AWS-GR_ENSURE_CLOUDTRAIL_ENABLED_ON"],
    2: ["AWS-GR_AUDIT_BUCKET_RETENTION_POLICY", "AWS-GR_LOG_GROUP_ENCRYPTED"],
    4: ["AWS-GR_CLOUDTRAIL_ENABLED", "AWS-GR_AUDIT_BUCKET_LOGGING_ENABLED", "AWS-GR_ENSURE_CLOUDTRAIL_ENABLED_ON"],
}


def scan_control_tower(region: str) -> dict[str, Any]:
    """Discover Control Tower landing zone and enabled controls.

    Must be run from the management account. Queries the Control Tower
    and Organizations APIs to enumerate OUs and their enabled controls.

    Args:
        region: AWS region where Control Tower is deployed.

    Returns:
        Dict with landing_zone, enabled_controls, and ous.
    """
    import boto3

    session = boto3.Session(region_name=region)
    ct = session.client("controltower")
    result: dict[str, Any] = {"landing_zone": None, "enabled_controls": [], "ous": []}

    # Landing zone
    try:
        lzs = ct.list_landing_zones().get("landingZones", [])
        if lzs:
            lz = ct.get_landing_zone(landingZoneIdentifier=lzs[0]["arn"]).get("landingZone", {})
            result["landing_zone"] = {
                "arn": lzs[0]["arn"], "version": lz.get("version", ""),
                "status": lz.get("status", ""), "drift_status": lz.get("driftStatus", {}).get("status", ""),
            }
    except Exception as e:
        result["landing_zone_error"] = str(e)

    # OUs and controls
    try:
        orgs = session.client("organizations")
        roots = orgs.list_roots().get("Roots", [])
        ou_targets: list[dict] = []
        for root in roots:
            ou_targets.append({"id": root["Id"], "name": root.get("Name", "Root"), "arn": root["Arn"]})
            try:
                for page in orgs.get_paginator("list_organizational_units_for_parent").paginate(ParentId=root["Id"]):
                    for ou in page.get("OrganizationalUnits", []):
                        ou_targets.append({"id": ou["Id"], "name": ou.get("Name", ""), "arn": ou["Arn"]})
            except Exception:
                _logger.debug("Could not list OUs for parent %s", root["Id"])
        result["ous"] = ou_targets

        controls: list[dict] = []
        for ou in ou_targets:
            try:
                for page in ct.get_paginator("list_enabled_controls").paginate(targetIdentifier=ou["arn"]):
                    for ctrl in page.get("enabledControls", []):
                        ctrl_id = ctrl.get("controlIdentifier", "")
                        short = ctrl_id.split("/")[-1] if "/" in ctrl_id else ctrl_id
                        controls.append({
                            "control_id": short, "control_arn": ctrl_id,
                            "target_ou": ou["name"], "target_ou_id": ou["id"],
                            "status": ctrl.get("statusSummary", {}).get("status", ""),
                        })
            except Exception:
                _logger.debug("Could not list controls for OU %s", ou.get("name", ""))
                continue
        result["enabled_controls"] = controls
    except Exception as e:
        result["controls_error"] = str(e)

    return result


def assess_control_tower(ct_data: dict, is_sdf: bool = False, is_rbi: bool = False, is_sebi: bool = False) -> dict[str, Any]:
    """Assess Control Tower controls against DPDP/RBI/SEBI requirements.

    Compares enabled controls against recommended controls for each
    compliance domain and generates gap analysis with recommendations.

    Args:
        ct_data: Output from scan_control_tower().
        is_sdf: Significant Data Fiduciary flag.
        is_rbi: RBI-regulated entity flag.
        is_sebi: SEBI-regulated entity flag.

    Returns:
        Dict with posture scores, gaps, and recommended controls.
    """
    enabled_ids = {c["control_id"] for c in ct_data.get("enabled_controls", [])}
    gaps: list[dict] = []
    recommendations: list[dict] = []
    dpdp_covered: set[int] = set()
    rbi_covered: set[int] = set()
    sebi_covered: set[int] = set()
    certin_covered: set[int] = set()

    for ctrl_id in enabled_ids:
        mapping = CT_CONTROL_MAP.get(ctrl_id, {})
        dpdp_covered.update(mapping.get("dpdp", []))
        rbi_covered.update(mapping.get("rbi", []))
        sebi_covered.update(mapping.get("sebi", []))
        certin_covered.update(mapping.get("certin", []))

    # DPDP gaps
    for domain_num, rec_controls in RECOMMENDED_DPDP.items():
        missing = [c for c in rec_controls if c not in enabled_ids]
        if missing:
            for ctrl_id in missing:
                m = CT_CONTROL_MAP.get(ctrl_id, {})
                recommendations.append({
                    "control_id": ctrl_id, "description": m.get("desc", ctrl_id),
                    "framework": "dpdp", "domain": domain_num,
                    "domain_name": DPDP_DOMAINS.get(domain_num, ""),
                    "priority": "high" if domain_num in (5, 6) else "medium",
                    "confidence": "high",
                    "confidence_rationale": "Direct mapping: Control Tower guardrail to compliance domain",
                })
            gaps.append({
                "framework": "dpdp", "domain": domain_num,
                "domain_name": DPDP_DOMAINS.get(domain_num, ""),
                "gap": f"Missing {len(missing)} Control Tower controls for {DPDP_DOMAINS.get(domain_num, '')}",
                "missing_controls": missing,
                "confidence": "high",
                "confidence_rationale": "Direct mapping: Control Tower guardrail to compliance domain",
            })

    # RBI gaps
    if is_rbi:
        for domain_num, rec_controls in RECOMMENDED_RBI.items():
            missing = [c for c in rec_controls if c not in enabled_ids]
            if missing:
                for ctrl_id in missing:
                    m = CT_CONTROL_MAP.get(ctrl_id, {})
                    recommendations.append({
                        "control_id": ctrl_id, "description": m.get("desc", ctrl_id),
                        "framework": "rbi", "domain": domain_num,
                        "domain_name": RBI_DOMAINS.get(domain_num, ""),
                        "priority": "high" if domain_num in (4, 5) else "medium",
                        "confidence": "high",
                        "confidence_rationale": "Direct mapping: Control Tower guardrail to compliance domain",
                    })
                gaps.append({
                    "framework": "rbi", "domain": domain_num,
                    "domain_name": RBI_DOMAINS.get(domain_num, ""),
                    "gap": f"Missing {len(missing)} Control Tower controls for {RBI_DOMAINS.get(domain_num, '')}",
                    "missing_controls": missing,
                    "confidence": "high",
                    "confidence_rationale": "Direct mapping: Control Tower guardrail to compliance domain",
                })

    # SEBI gaps
    if is_sebi:
        for domain_num, rec_controls in RECOMMENDED_SEBI.items():
            missing = [c for c in rec_controls if c not in enabled_ids]
            if missing:
                for ctrl_id in missing:
                    m = CT_CONTROL_MAP.get(ctrl_id, {})
                    recommendations.append({
                        "control_id": ctrl_id, "description": m.get("desc", ctrl_id),
                        "framework": "sebi", "domain": domain_num,
                        "domain_name": SEBI_DOMAINS.get(domain_num, ""),
                        "priority": "high" if domain_num in (3, 4) else "medium",
                        "confidence": "high",
                        "confidence_rationale": "Direct mapping: Control Tower guardrail to compliance domain",
                    })
                gaps.append({
                    "framework": "sebi", "domain": domain_num,
                    "domain_name": SEBI_DOMAINS.get(domain_num, ""),
                    "gap": f"Missing {len(missing)} Control Tower controls for {SEBI_DOMAINS.get(domain_num, '')}",
                    "missing_controls": missing,
                    "confidence": "high",
                    "confidence_rationale": "Direct mapping: Control Tower guardrail to compliance domain",
                })

    # Landing zone checks
    lz = ct_data.get("landing_zone")
    if not lz:
        gaps.append({"framework": "dpdp", "domain": 6, "domain_name": DPDP_DOMAINS[6],
                      "gap": "No Control Tower landing zone detected", "missing_controls": [],
                      "confidence": "high",
                      "confidence_rationale": "Direct mapping: Control Tower guardrail to compliance domain"})
    elif lz.get("drift_status") == "DRIFTED":
        gaps.append({"framework": "dpdp", "domain": 6, "domain_name": DPDP_DOMAINS[6],
                      "gap": "Control Tower landing zone has drifted from baseline", "missing_controls": [],
                      "confidence": "high",
                      "confidence_rationale": "Direct mapping: Control Tower guardrail to compliance domain"})

    # CERT-In gaps
    for domain_num, rec_controls in RECOMMENDED_CERTIN.items():
        missing = [c for c in rec_controls if c not in enabled_ids]
        if missing:
            for ctrl_id in missing:
                m = CT_CONTROL_MAP.get(ctrl_id, {})
                recommendations.append({
                    "control_id": ctrl_id, "description": m.get("desc", ctrl_id),
                    "framework": "certin", "domain": domain_num,
                    "domain_name": CERTIN_DOMAINS.get(domain_num, ""),
                    "priority": "high" if domain_num in (1, 2) else "medium",
                    "confidence": "high",
                    "confidence_rationale": "Direct mapping: Control Tower guardrail to compliance domain",
                })
            gaps.append({
                "framework": "certin", "domain": domain_num,
                "domain_name": CERTIN_DOMAINS.get(domain_num, ""),
                "gap": f"Missing {len(missing)} Control Tower controls for {CERTIN_DOMAINS.get(domain_num, '')}",
                "missing_controls": missing,
                "confidence": "high",
                "confidence_rationale": "Direct mapping: Control Tower guardrail to compliance domain",
            })

    # Deduplicate recommendations
    seen: set[str] = set()
    unique_recs = [r for r in recommendations if r["control_id"] not in seen and not seen.add(r["control_id"])]  # type: ignore[func-returns-value]

    # Per-OU grouping
    per_ou: dict[str, dict[str, Any]] = {}
    for ctrl in ct_data.get("enabled_controls", []):
        ou_name = ctrl.get("target_ou", "Unknown")
        ou_entry = per_ou.setdefault(ou_name, {
            "enabled_count": 0,
            "dpdp_covered": set(),
            "rbi_covered": set(),
            "sebi_covered": set(),
            "certin_covered": set(),
        })
        ou_entry["enabled_count"] += 1
        mapping = CT_CONTROL_MAP.get(ctrl.get("control_id", ""), {})
        ou_entry["dpdp_covered"].update(mapping.get("dpdp", []))
        ou_entry["rbi_covered"].update(mapping.get("rbi", []))
        ou_entry["sebi_covered"].update(mapping.get("sebi", []))
        ou_entry["certin_covered"].update(mapping.get("certin", []))

    # Convert sets to counts for JSON serialization
    per_ou_result: dict[str, dict[str, Any]] = {}
    for ou_name, data in per_ou.items():
        per_ou_result[ou_name] = {
            "enabled_controls": data["enabled_count"],
            "dpdp_domains_covered": len(data["dpdp_covered"]),
            "rbi_domains_covered": len(data["rbi_covered"]) if is_rbi else None,
            "sebi_domains_covered": len(data["sebi_covered"]) if is_sebi else None,
            "certin_domains_covered": len(data["certin_covered"]),
        }

    certin_total = len(CERTIN_DOMAINS)
    return {
        "landing_zone": lz,
        "total_ous": len(ct_data.get("ous", [])),
        "total_enabled_controls": len(ct_data.get("enabled_controls", [])),
        "gaps": gaps,
        "recommendations": unique_recs,
        "dpdp_posture": {"covered_domains": len(dpdp_covered), "total": 10, "score": round(len(dpdp_covered) / 10 * 100, 1)},
        "rbi_posture": {"covered_domains": len(rbi_covered), "total": 7, "score": round(len(rbi_covered) / 7 * 100, 1)} if is_rbi else None,
        "sebi_posture": {"covered_domains": len(sebi_covered), "total": 6, "score": round(len(sebi_covered) / 6 * 100, 1)} if is_sebi else None,
        "certin_posture": {"covered_domains": len(certin_covered), "total": certin_total, "score": round(len(certin_covered) / certin_total * 100, 1)},
        "per_ou": per_ou_result,
    }
