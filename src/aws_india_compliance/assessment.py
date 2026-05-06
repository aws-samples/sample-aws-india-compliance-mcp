"""Compliance assessment engine.

Evaluates infrastructure components against DPDP Act, RBI Master
Direction, SEBI CSCRF, and CERT-In Directions control domains.
Checks resource-level configurations including encryption, public
access, logging, retention, TLS enforcement, and more.
"""

from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Any

from .domains import CERTIN_DOMAINS, DPDP_DOMAINS, RBI_DOMAINS, SEBI_DOMAINS

_INDIAN_REGIONS = {"ap-south-1", "ap-south-2"}

# Resource classification for data localization (Task 6.1)
_STORAGE_TYPES = {"S3::Bucket", "RDS::DB", "DynamoDB::Table", "EFS::FileSystem", "Redshift::Cluster"}
_COMPUTE_TYPES = {"Lambda::Function", "EC2::Instance", "ECS::Cluster", "EKS::Cluster"}
_GLOBAL_SERVICES = {"IAM::Role", "CloudFront::Distribution", "Route53", "WAFv2::WebACL"}


class _DomainResourceTracker:
    """Track which resources were checked against which domains and whether they passed."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, set[str]]] = {}

    def record(self, fw: str, domain: int, resource: str, passed: bool) -> None:
        key = f"{fw}:{domain}"
        entry = self._data.setdefault(key, {"checked": set(), "failed": set()})
        entry["checked"].add(resource)
        if not passed:
            entry["failed"].add(resource)

    def summary(self) -> dict[str, dict[str, Any]]:
        """Return per-domain resource compliance: {fw:domain -> {checked, passed, failed, pct}}."""
        result: dict[str, dict[str, Any]] = {}
        for key, entry in self._data.items():
            checked = len(entry["checked"])
            failed = len(entry["failed"])
            passed = checked - failed
            result[key] = {
                "checked": checked,
                "passed": passed,
                "failed": failed,
                "pct": round(passed / checked * 100, 1) if checked > 0 else 100.0,
            }
        return result


def _filter_by_tags(
    components: list[dict],
    filter_tags: dict[str, str] | None,
    exclude_tags: dict[str, str] | None,
) -> list[dict]:
    """Filter components by tag inclusion/exclusion.

    Args:
        components: List of component dicts.
        filter_tags: Include only components whose tags contain ALL specified key-value pairs.
        exclude_tags: Exclude components whose tags match ANY specified key-value pair.

    Returns:
        Filtered list of components.
    """
    result = components

    if filter_tags:
        result = [
            c for c in result
            if all(c.get("tags", {}).get(k) == v for k, v in filter_tags.items())
        ]

    if exclude_tags:
        result = [
            c for c in result
            if not any(c.get("tags", {}).get(k) == v for k, v in exclude_tags.items())
        ]

    return result


def _apply_exceptions(
    gaps: list[dict],
    exceptions: list[dict] | None,
) -> tuple[list[dict], list[dict]]:
    """Partition gaps into active and suppressed based on exception rules.

    Exception rule format:
    {
        "resource_pattern": "AWSControlTower*",  # fnmatch pattern (optional)
        "exclude_tag": {"key": "Environment", "value": "dev"},  # (optional)
        "reason": "Control Tower service role"
    }

    Auto-suppression: AWSControlTowerExecution with AdministratorAccess.

    Returns:
        Tuple of (active_gaps, suppressed_gaps).
    """
    # Build effective exception list including auto-suppression rules
    effective_exceptions: list[dict] = []

    # Auto-suppress AWSControlTowerExecution with AdministratorAccess
    effective_exceptions.append({
        "resource_pattern": "AWSControlTowerExecution",
        "reason": "Control Tower service role — by design",
        "_auto": True,
    })

    if exceptions:
        for exc in exceptions:
            if isinstance(exc, dict) and (exc.get("resource_pattern") or exc.get("exclude_tag")):
                effective_exceptions.append(exc)

    active: list[dict] = []
    suppressed: list[dict] = []

    for gap in gaps:
        matched = False
        for exc in effective_exceptions:
            # Check resource_pattern match
            pattern = exc.get("resource_pattern", "")
            if pattern and fnmatch(gap.get("component", ""), pattern):
                # For auto-suppress of CT execution, also check the gap mentions AdministratorAccess
                if exc.get("_auto"):
                    if "AdministratorAccess" in gap.get("gap", ""):
                        suppressed_gap = dict(gap)
                        suppressed_gap["suppression_reason"] = exc.get("reason", "")
                        suppressed.append(suppressed_gap)
                        matched = True
                        break
                else:
                    suppressed_gap = dict(gap)
                    suppressed_gap["suppression_reason"] = exc.get("reason", "")
                    suppressed.append(suppressed_gap)
                    matched = True
                    break

            # Check exclude_tag match
            exclude_tag = exc.get("exclude_tag")
            if exclude_tag and isinstance(exclude_tag, dict):
                tag_key = exclude_tag.get("key", "")
                tag_value = exclude_tag.get("value", "")
                # We need component tags — stored in gap evidence or matched by component name
                # Since gaps don't carry tags directly, exclude_tag matching works on the
                # gap component name pattern as a fallback
                if tag_key and tag_value and not pattern:
                    # exclude_tag without resource_pattern — skip (tags checked at component level)
                    pass

        if not matched:
            active.append(gap)

    return active, suppressed


def _group_by_account(
    components: list[dict],
    gaps: list[dict],
    is_rbi: bool,
    is_sebi: bool,
) -> dict[str, Any]:
    """Group gaps by account_id and compute per-account posture.

    Returns:
        Dict of {account_id: {gap_count, dpdp_posture, rbi_posture, sebi_posture}}.
    """
    # Collect all account IDs from components
    account_ids: set[str] = set()
    for c in components:
        aid = c.get("account_id", "")
        if aid:
            account_ids.add(aid)

    if not account_ids:
        return {}

    result: dict[str, Any] = {}
    for aid in sorted(account_ids):
        account_gaps = [g for g in gaps if _gap_belongs_to_account(g, aid, components)]
        dpdp_gap_count = sum(1 for g in account_gaps if g.get("framework") == "dpdp")
        rbi_gap_count = sum(1 for g in account_gaps if g.get("framework") == "rbi")
        sebi_gap_count = sum(1 for g in account_gaps if g.get("framework") == "sebi")

        # Simple posture: fewer gaps = higher score (capped at 100)
        account_components = [c for c in components if c.get("account_id") == aid]
        total = max(len(account_components), 1)

        dpdp_score = max(0.0, round((1 - dpdp_gap_count / (total * 10)) * 100, 1))
        dpdp_score = min(dpdp_score, 100.0)

        entry: dict[str, Any] = {
            "gap_count": len(account_gaps),
            "dpdp_posture": {"score": dpdp_score},
        }
        if is_rbi:
            rbi_score = max(0.0, round((1 - rbi_gap_count / (total * 7)) * 100, 1))
            rbi_score = min(rbi_score, 100.0)
            entry["rbi_posture"] = {"score": rbi_score}
        if is_sebi:
            sebi_score = max(0.0, round((1 - sebi_gap_count / (total * 6)) * 100, 1))
            sebi_score = min(sebi_score, 100.0)
            entry["sebi_posture"] = {"score": sebi_score}

        result[aid] = entry

    return result


def _gap_belongs_to_account(gap: dict, account_id: str, components: list[dict]) -> bool:
    """Check if a gap belongs to a specific account based on component name matching."""
    comp_name = gap.get("component", "")
    # Architecture-level and organization-level gaps belong to all accounts
    if comp_name in ("architecture", "organization"):
        return True
    for c in components:
        if c.get("name") == comp_name and c.get("account_id") == account_id:
            return True
    return False



def assess(
    components: list[dict],
    is_sdf: bool = False,
    is_rbi: bool = False,
    is_sebi: bool = False,
    *,
    sebi_entity_tier: str = "",
    exceptions: list[dict] | None = None,
    filter_tags: dict[str, str] | None = None,
    exclude_tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run compliance assessment against DPDP, RBI, SEBI, and CERT-In domains.

    Performs per-resource checks based on resource type and configuration
    properties. Returns posture scores, gap list, and component counts.

    Args:
        components: List of component dicts (from parsers or AWS scanner).
        is_sdf: Whether the organization is a Significant Data Fiduciary.
        is_rbi: Whether the organization is RBI-regulated.
        is_sebi: Whether the organization is SEBI-regulated.
        sebi_entity_tier: SEBI entity tier ("mii", "qualified_re", "other_re").
        exceptions: Exception rules for gap suppression.
        filter_tags: Include only components whose tags contain ALL specified key-value pairs.
        exclude_tags: Exclude components whose tags match ANY specified key-value pair.

    Returns:
        Dict with gaps, posture scores, resource_compliance, per_account, and more.
    """
    # Apply tag-based filtering before assessment (Task 9.1)
    filtered_components = _filter_by_tags(components, filter_tags, exclude_tags)

    gaps: list[dict] = []
    dpdp_satisfied: set[int] = set()
    rbi_satisfied: set[int] = set()
    sebi_satisfied: set[int] = set()
    certin_satisfied: set[int] = set()

    # Instantiate domain resource tracker (Task 5.1)
    tracker = _DomainResourceTracker()

    has_guardduty = any("guardduty" in c["type"].lower() for c in filtered_components)
    has_securityhub = any("securityhub" in c["type"].lower() or "security_hub" in c["type"].lower() for c in filtered_components)
    has_kms = any("kms" in c["type"].lower() for c in filtered_components)
    has_cloudtrail = any("cloudtrail" in c["type"].lower() for c in filtered_components)
    has_waf = any("waf" in c["type"].lower() for c in filtered_components)
    has_eventbridge = any("events" in c["type"].lower() or "eventbridge" in c["type"].lower() for c in filtered_components)
    has_sns = any("sns" in c["type"].lower() for c in filtered_components)
    has_detective = any("detective" in c["type"].lower() for c in filtered_components)
    has_inspector = any("inspector" in c["type"].lower() for c in filtered_components)
    has_backup = any("backup" in c["type"].lower() for c in filtered_components)
    has_shield = any("shield" in c["type"].lower() for c in filtered_components)
    has_network_firewall = any("networkfirewall" in c["type"].lower() or "network_firewall" in c["type"].lower() for c in filtered_components)
    has_macie = any("macie" in c["type"].lower() for c in filtered_components)
    has_cloudfront = any("cloudfront" in c["type"].lower() for c in filtered_components)
    has_access_analyzer = any("accessanalyzer" in c["type"].lower() or "access_analyzer" in c["type"].lower() for c in filtered_components)

    # Enhanced _gap() closure with confidence, evidence, checked_at (Task 4.1)
    domain_map = {"dpdp": DPDP_DOMAINS, "rbi": RBI_DOMAINS, "sebi": SEBI_DOMAINS, "certin": CERTIN_DOMAINS}

    def _gap(
        comp_name: str, fw: str, dom: int, risk: str, desc: str, fix: str, ref: str,
        *,
        confidence: str = "medium",
        confidence_rationale: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> None:
        # Auto-generate rationale when empty (Task 4.1)
        if not confidence_rationale:
            if confidence == "high":
                confidence_rationale = "Direct technical check"
            elif confidence == "low":
                confidence_rationale = "Organizational requirement — infrastructure proxy"
            else:
                confidence_rationale = "Interpretive mapping from regulatory requirement"

        # Penalty exposure
        if fw == "dpdp":
            if dom == 9:
                penalty = "Up to INR 200 Crore"
            elif dom == 10:
                penalty = "Up to INR 150 Crore"
            else:
                penalty = "Up to INR 50 Crore"
        elif fw == "rbi":
            penalty = "As per RBI enforcement framework"
        elif fw == "sebi":
            penalty = "As per SEBI adjudication guidelines"
        else:
            penalty = "As per IT Act Section 70B penalties"

        # Responsibility type (from RBI shared responsibility model)
        if fw in ("rbi", "sebi") and confidence == "high":
            responsibility = "shared"  # Technical checks are shared responsibility
        elif fw in ("rbi", "sebi") and confidence == "low":
            responsibility = "customer"  # Organizational controls are customer responsibility
        elif fw == "dpdp" and dom in (1, 2, 3, 4, 9, 10):
            responsibility = "customer"  # DPDP organizational domains
        else:
            responsibility = "shared"

        gaps.append({
            "component": comp_name,
            "framework": fw,
            "domain": dom,
            "domain_name": domain_map.get(fw, DPDP_DOMAINS).get(dom, ""),
            "risk": risk,
            "gap": desc,
            "remediation": fix,
            "reference": ref,
            "confidence": confidence,
            "confidence_rationale": confidence_rationale,
            "evidence": evidence,
            "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "penalty_exposure": penalty,
            "responsibility_type": responsibility,
        })

    for comp in filtered_components:
        name = comp["name"]
        rtype = comp["type"]
        cat = comp.get("category", "other")
        p = comp.get("properties", {})
        tags = comp.get("tags", {})

        _check_s3(name, rtype, p, is_rbi, has_kms, _gap, dpdp_satisfied, tracker)
        _check_dynamodb(name, rtype, p, is_rbi, _gap, tracker)
        _check_rds(name, rtype, p, is_rbi, _gap, tracker)
        _check_lambda(name, rtype, p, is_rbi, _gap, tracker)
        _check_ec2(name, rtype, p, is_rbi, _gap, tracker)
        _check_eks(name, rtype, p, is_rbi, _gap, tracker)
        _check_ecs(name, rtype, p, is_rbi, _gap, tracker)
        _check_api_gateway(name, rtype, is_rbi, has_waf, _gap, tracker)
        _check_cloudfront(name, rtype, p, is_rbi, _gap, tracker)
        _check_sqs(name, rtype, p, _gap, tracker)
        _check_sagemaker(name, rtype, p, is_rbi, _gap, tracker)
        _check_kms(name, rtype, p, is_rbi, _gap, tracker)
        _check_cloudtrail(name, rtype, p, is_rbi, _gap, tracker)
        _check_sns(name, rtype, p, _gap, tracker)
        _check_cloudwatch_logs(name, rtype, p, is_rbi, _gap, tracker)
        _check_iam_role(name, rtype, p, is_rbi, _gap, tracker)

        # New check functions (Task 7.1-7.5)
        _check_s3_tls(name, rtype, p, is_rbi, _gap, tracker)
        _check_rds_ssl(name, rtype, p, is_rbi, _gap, tracker)
        _check_vpc(name, rtype, p, is_rbi, _gap, tracker)
        _check_security_group(name, rtype, p, is_rbi, _gap, tracker)
        _check_backup_resource(name, rtype, p, is_rbi, _gap, tracker)
        _check_secrets_manager(name, rtype, p, is_rbi, _gap, tracker)
        _check_inspector_resource(name, rtype, p, is_sebi, sebi_entity_tier, _gap, tracker)
        _check_kms_byok(name, rtype, p, is_sebi, sebi_entity_tier, _gap, tracker)

        # Data residency check for RBI-regulated entities (Task 6.1 — nuanced version)
        region = comp.get("region", "")
        if is_rbi and region and region not in _INDIAN_REGIONS and region != "global":
            _apply_data_localization(name, rtype, region, tags, _gap, tracker)

        if cat == "security":
            dpdp_satisfied.add(6)
            if is_rbi:
                rbi_satisfied.update([3, 4])
        if is_sebi and cat == "security":
            sebi_satisfied.update([3, 4])

    # Architecture-level checks
    if has_guardduty:
        dpdp_satisfied.add(5)
        if is_rbi:
            rbi_satisfied.add(5)
    else:
        _gap("architecture", "dpdp", 5, "critical", "No GuardDuty for breach detection",
             "Enable GuardDuty", "DPDP Act Section 8(5)",
             confidence="high", evidence={"guardduty_enabled": False, "expected": True})

    if not has_securityhub:
        _gap("architecture", "dpdp", 5, "critical", "No Security Hub for centralized findings",
             "Enable Security Hub", "DPDP Act Section 8(5)",
             confidence="high", evidence={"securityhub_enabled": False, "expected": True})

    if has_cloudtrail:
        if is_rbi:
            rbi_satisfied.add(7)
    elif is_rbi:
        _gap("architecture", "rbi", 7, "critical", "No CloudTrail for audit logging",
             "Enable CloudTrail", "RBI MD Chapter VII",
             confidence="high", evidence={"cloudtrail_enabled": False, "expected": True})

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

    # SEBI architecture-level checks
    if is_sebi:
        if has_guardduty or has_securityhub:
            sebi_satisfied.add(4)
        if has_cloudtrail:
            sebi_satisfied.add(2)
        if has_kms:
            sebi_satisfied.add(3)
        if has_waf:
            sebi_satisfied.add(3)
        sebi_satisfied.update([1, 5, 6])  # Governance, Response, Recovery — org-level

    # SEBI entity tiering checks (Task 7.5)
    if is_sebi and sebi_entity_tier == "mii":
        # C-SOC readiness: need GuardDuty + Security Hub + Detective
        if not (has_guardduty and has_securityhub and has_detective):
            _gap("architecture", "sebi", 4, "high",
                 "MII tier requires C-SOC readiness (GuardDuty + Security Hub + Detective)",
                 "Enable GuardDuty, Security Hub, and Detective for C-SOC",
                 "SEBI CSCRF C-SOC Requirement",
                 confidence="high",
                 evidence={"guardduty": has_guardduty, "securityhub": has_securityhub,
                           "detective": has_detective, "expected": "all enabled"})

    # Backup architecture-level check (Task 7.3)
    if is_rbi and not has_backup:
        _gap("architecture", "rbi", 6, "high",
             "No AWS Backup plans found for disaster recovery",
             "Create AWS Backup plans for critical resources",
             "RBI MD Chapter VI",
             confidence="high",
             evidence={"backup_plans_found": False, "expected": True})

    # Inspector architecture-level check (Task 7.3)
    if is_sebi and not has_inspector:
        _gap("architecture", "sebi", 2, "high",
             "Amazon Inspector not enabled — SEBI CSCRF requires quarterly VAPT",
             "Enable Amazon Inspector for continuous vulnerability assessment",
             "SEBI CSCRF VAPT Requirement",
             confidence="high",
             evidence={"inspector_enabled": False, "expected": True})

    # RBI 2016 Cyber Security Framework checks
    if is_rbi:
        # Section 8: User Access Control - Access Analyzer for unused permissions
        if not has_access_analyzer:
            _gap("architecture", "rbi", 4, "medium",
                 "No IAM Access Analyzer for identifying unused permissions and external access (RBI 2016 Section 8.5)",
                 "Enable IAM Access Analyzer to identify unused permissions and external resource sharing",
                 "RBI Cyber Security Framework 2016 Section 8.5",
                 confidence="high",
                 evidence={"access_analyzer_enabled": False, "expected": True})

        # Section 1.2: Data Classification - Macie
        if not has_macie:
            _gap("architecture", "rbi", 4, "medium",
                 "No Amazon Macie for automated data classification (RBI 2016 Section 1.2)",
                 "Enable Amazon Macie for automated sensitive data discovery and classification",
                 "RBI Cyber Security Framework 2016 Section 1.2",
                 confidence="medium",
                 confidence_rationale="Macie is one approach to data classification; manual classification also satisfies the requirement")

    if is_sdf:
        _gap("organization", "dpdp", 10, "high", "SDF must appoint DPO and conduct DPIA",
             "Appoint DPO, conduct annual DPIA", "DPDP Act Section 10(2)",
             confidence="low")

    # CERT-In assessment (Task 7.4)
    certin_posture_result = None
    if is_rbi:
        # Domain 1: Incident Reporting Readiness — GuardDuty + EventBridge + SNS
        if has_guardduty and has_eventbridge and has_sns:
            certin_satisfied.add(1)
        else:
            _gap("architecture", "certin", 1, "high",
                 "Incomplete incident reporting pipeline (need GuardDuty + EventBridge + SNS)",
                 "Enable GuardDuty, EventBridge rules, and SNS for automated alerting",
                 "CERT-In Directions 2022 Direction 1-3",
                 confidence="high",
                 evidence={"guardduty": has_guardduty, "eventbridge": has_eventbridge,
                           "sns": has_sns, "expected": "all enabled"})

        # Domain 2: Log Retention — checked per-resource in _check_cloudwatch_logs
        # Mark satisfied if no log groups with < 180 days found
        log_retention_gaps = [g for g in gaps if g.get("framework") == "certin" and g.get("domain") == 2]
        if not log_retention_gaps:
            certin_satisfied.add(2)

        # Domain 3: NTP Synchronization — advisory (cannot verify via Config)
        _gap("architecture", "certin", 3, "low",
             "NTP synchronization cannot be verified via infrastructure scan — AWS uses Amazon Time Sync Service by default on EC2/ECS/EKS",
             "Verify NTP configuration on any on-premises or custom instances",
             "CERT-In Directions 2022 Direction 5",
             confidence="low",
             confidence_rationale="Cannot verify NTP configuration via AWS Config — advisory only")

        # Domain 4: Reportable Incident Awareness — Security Hub
        if has_securityhub:
            certin_satisfied.add(4)
        else:
            _gap("architecture", "certin", 4, "medium",
                 "No Security Hub for reportable incident awareness",
                 "Enable Security Hub for centralized security findings",
                 "CERT-In Directions 2022 Direction 6",
                 confidence="high",
                 evidence={"securityhub_enabled": False, "expected": True})

        # Domain 5: DDoS and Bot Protection
        if has_shield or (has_waf and has_cloudfront):
            certin_satisfied.add(5)
        else:
            _gap("architecture", "certin", 5, "medium",
                 "No Shield Advanced or WAF+CloudFront for DDoS/Bot protection",
                 "Enable AWS Shield Advanced or WAF with Bot Control on CloudFront",
                 "CERT-In Directions 2022 - DDoS/Bot Attacks",
                 confidence="high",
                 evidence={"shield": has_shield, "waf": has_waf, "expected": "Shield Advanced or WAF+CloudFront"})

        # Domain 6: Network Security and DNS Protection
        if has_network_firewall:
            certin_satisfied.add(6)
        else:
            _gap("architecture", "certin", 6, "medium",
                 "No AWS Network Firewall for network-level threat detection",
                 "Deploy AWS Network Firewall for network traffic inspection",
                 "CERT-In Directions 2022 - Network Compromise",
                 confidence="medium",
                 confidence_rationale="Network Firewall is one of several valid approaches to network security")

        # Domain 7: Endpoint and Malware Protection
        if has_guardduty and has_inspector:
            certin_satisfied.add(7)
        else:
            _gap("architecture", "certin", 7, "medium",
                 "Incomplete endpoint/malware protection (need GuardDuty Malware Protection + Inspector)",
                 "Enable GuardDuty Malware Protection and Amazon Inspector",
                 "CERT-In Directions 2022 - Malware/Ransomware",
                 confidence="high",
                 evidence={"guardduty": has_guardduty, "inspector": has_inspector, "expected": "both enabled"})

        # Domain 8: Data Leakage Prevention
        if has_macie or (has_kms and not any(g.get("gap", "").startswith("S3") and "public" in g.get("gap", "").lower() for g in gaps)):
            certin_satisfied.add(8)
        else:
            _gap("architecture", "certin", 8, "medium",
                 "No Macie for data discovery/DLP and S3 public access gaps exist",
                 "Enable Amazon Macie for sensitive data discovery and ensure S3 Block Public Access",
                 "CERT-In Directions 2022 - Data Breach/Leaks",
                 confidence="medium",
                 evidence={"macie": has_macie, "kms": has_kms})

        certin_score = len(certin_satisfied) / 8 * 100
        certin_posture_result = {
            "satisfied": len(certin_satisfied),
            "total": 8,
            "score": round(certin_score, 1),
        }

    dpdp_score = len(dpdp_satisfied) / 10 * 100
    rbi_score = len(rbi_satisfied) / 7 * 100 if is_rbi else None
    sebi_score = len(sebi_satisfied) / 6 * 100 if is_sebi else None

    # Apply exception management (Task 9.2)
    active_gaps, suppressed_gaps = _apply_exceptions(gaps, exceptions)

    # Group by account (Task 9.3)
    per_account = _group_by_account(filtered_components, active_gaps, is_rbi, is_sebi)

    return {
        "gaps": active_gaps,
        "dpdp_posture": {"satisfied": len(dpdp_satisfied), "total": 10, "score": round(dpdp_score, 1)},
        "rbi_posture": {"satisfied": len(rbi_satisfied), "total": 7, "score": round(rbi_score, 1)} if is_rbi else None,
        "sebi_posture": {"satisfied": len(sebi_satisfied), "total": 6, "score": round(sebi_score, 1)} if is_sebi else None,
        "total_components": len(filtered_components),
        "total_gaps": len(active_gaps),
        # New fields (additive only)
        "certin_posture": certin_posture_result,
        "resource_compliance": tracker.summary(),
        "per_account": per_account if per_account else None,
        "suppressed_gaps": suppressed_gaps,
        "suppressed_count": len(suppressed_gaps),
    }



# ---- Data localization helper (Task 6.1) ----

def _apply_data_localization(
    name: str, rtype: str, region: str, tags: dict[str, str],
    gap: Any, tracker: _DomainResourceTracker,
) -> None:
    """Apply nuanced data localization checks based on resource type."""
    # Determine resource classification
    is_storage = any(st in rtype for st in _STORAGE_TYPES)
    is_compute = any(ct in rtype for ct in _COMPUTE_TYPES)
    is_global = any(gs in rtype for gs in _GLOBAL_SERVICES)

    if is_global:
        # Global services excluded from data localization checks
        return

    data_class = tags.get("DataClassification", "")
    class_suffix = f" (DataClassification: {data_class})" if data_class else ""

    if is_storage:
        gap(name, "rbi", 4, "high",
            f"Storage resource '{name}' ({rtype}) deployed in {region}, outside India{class_suffix}",
            "Deploy in ap-south-1 or ap-south-2 for RBI data localization",
            "RBI Data Localization Circular 2018",
            confidence="high",
            evidence={"region": region, "expected": "ap-south-1 or ap-south-2",
                      "resource_type": rtype, "classification": "storage"})
        tracker.record("rbi", 4, name, passed=False)
    elif is_compute:
        gap(name, "rbi", 4, "medium",
            f"Compute resource '{name}' ({rtype}) deployed in {region}, outside India — storage of payment data outside India is restricted but compute processing may be permissible{class_suffix}",
            "Review if compute processes or stores regulated data; consider deploying in ap-south-1/ap-south-2",
            "RBI Data Localization Circular 2018",
            confidence="medium",
            confidence_rationale="Compute processing outside India may be permissible; storage is restricted",
            evidence={"region": region, "expected": "ap-south-1 or ap-south-2",
                      "resource_type": rtype, "classification": "compute"})
        tracker.record("rbi", 4, name, passed=False)
    else:
        # Other resource types outside India — flag as medium
        gap(name, "rbi", 4, "high",
            f"Resource '{name}' ({rtype}) deployed in {region}, outside India{class_suffix}",
            "Deploy in ap-south-1 or ap-south-2 for RBI data localization",
            "RBI Data Localization Circular 2018",
            confidence="medium",
            evidence={"region": region, "expected": "ap-south-1 or ap-south-2"})
        tracker.record("rbi", 4, name, passed=False)


# ---- Per-resource check functions (updated with confidence + tracker) ----

def _check_s3(name: str, rtype: str, p: dict, is_rbi: bool, has_kms: bool,
              gap: Any, dpdp_satisfied: set[int], tracker: _DomainResourceTracker) -> None:
    if "S3::Bucket" not in rtype:
        return
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "high", f"S3 '{name}' lacks encryption at rest",
            "Enable SSE-KMS encryption", "DPDP Act Section 8(4)",
            confidence="high", evidence={"encryption": p.get("encryption"), "expected": "SSE-KMS"})
        tracker.record("dpdp", 6, name, passed=False)
    else:
        dpdp_satisfied.add(6)
        tracker.record("dpdp", 6, name, passed=True)
    if not p.get("lifecycle_policy"):
        gap(name, "dpdp", 7, "medium", f"S3 '{name}' lacks lifecycle/retention policy",
            "Add lifecycle rules for data retention", "DPDP Act Section 8(6)",
            confidence="high", evidence={"lifecycle_policy": p.get("lifecycle_policy"), "expected": True})
        tracker.record("dpdp", 7, name, passed=False)
    else:
        tracker.record("dpdp", 7, name, passed=True)
    if not p.get("public_access_blocked"):
        gap(name, "dpdp", 6, "high", f"S3 '{name}' public access not fully blocked",
            "Enable S3 Block Public Access (all 4 settings)", "DPDP Act Section 8(4)",
            confidence="high", evidence={"public_access_blocked": p.get("public_access_blocked"), "expected": True})
        if is_rbi:
            gap(name, "rbi", 4, "high", f"S3 '{name}' public access not blocked",
                "Enable S3 Block Public Access", "RBI MD Chapter IV",
                confidence="high", evidence={"public_access_blocked": p.get("public_access_blocked"), "expected": True})
            tracker.record("rbi", 4, name, passed=False)
    else:
        if is_rbi:
            tracker.record("rbi", 4, name, passed=True)
    if not p.get("versioning") and is_rbi:
        gap(name, "rbi", 6, "medium", f"S3 '{name}' lacks versioning for data recovery",
            "Enable versioning", "RBI MD Chapter VI",
            confidence="high", evidence={"versioning": p.get("versioning"), "expected": True})
        tracker.record("rbi", 6, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 6, name, passed=True)
    if not p.get("access_logging") and is_rbi:
        gap(name, "rbi", 7, "medium", f"S3 '{name}' lacks access logging",
            "Enable server access logging", "RBI MD Chapter VII",
            confidence="high", evidence={"access_logging": p.get("access_logging"), "expected": True})
        tracker.record("rbi", 7, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 7, name, passed=True)
    # Audit bucket immutability check (CERT-In 180-day log retention)
    if is_rbi and ("cloudtrail" in name.lower() or "audit" in name.lower() or "log" in name.lower()):
        if not p.get("object_lock"):
            gap(name, "rbi", 7, "medium", f"S3 audit bucket '{name}' lacks Object Lock for immutable retention",
                "Enable S3 Object Lock to meet CERT-In 180-day log retention", "CERT-In Directions 2022",
                confidence="high", evidence={"object_lock": p.get("object_lock"), "expected": True})


def _check_dynamodb(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                    tracker: _DomainResourceTracker) -> None:
    if "DynamoDB::Table" not in rtype:
        return
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "high", f"DynamoDB '{name}' lacks KMS encryption",
            "Enable KMS encryption", "DPDP Act Section 8(4)",
            confidence="high", evidence={"encryption": p.get("encryption"), "expected": "KMS"})
        tracker.record("dpdp", 6, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)
    if not p.get("lifecycle_policy"):
        gap(name, "dpdp", 7, "medium", f"DynamoDB '{name}' lacks TTL for data retention",
            "Enable TTL", "DPDP Act Section 8(6)",
            confidence="high", evidence={"lifecycle_policy": p.get("lifecycle_policy"), "expected": True})
        tracker.record("dpdp", 7, name, passed=False)
    else:
        tracker.record("dpdp", 7, name, passed=True)
    if not p.get("pitr_enabled") and is_rbi:
        gap(name, "rbi", 6, "medium", f"DynamoDB '{name}' lacks point-in-time recovery",
            "Enable PITR", "RBI MD Chapter VI",
            confidence="high", evidence={"pitr_enabled": p.get("pitr_enabled"), "expected": True})
        tracker.record("rbi", 6, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 6, name, passed=True)


def _check_rds(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
               tracker: _DomainResourceTracker) -> None:
    if "RDS::DB" not in rtype:
        return
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "critical", f"RDS '{name}' storage not encrypted",
            "Enable RDS encryption", "DPDP Act Section 8(4)",
            confidence="high", evidence={"encryption": p.get("encryption"), "expected": "encrypted"})
        tracker.record("dpdp", 6, name, passed=False)
        if is_rbi:
            gap(name, "rbi", 4, "critical", f"RDS '{name}' not encrypted",
                "Enable encryption", "RBI MD Chapter IV",
                confidence="high", evidence={"encryption": p.get("encryption"), "expected": "encrypted"})
            tracker.record("rbi", 4, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)
        if is_rbi:
            tracker.record("rbi", 4, name, passed=True)
    if p.get("publicly_accessible"):
        gap(name, "dpdp", 6, "critical", f"RDS '{name}' is publicly accessible",
            "Disable public access", "DPDP Act Section 8(4)",
            confidence="high", evidence={"publicly_accessible": True, "expected": False})
        if is_rbi:
            gap(name, "rbi", 5, "critical", f"RDS '{name}' publicly accessible",
                "Move to private subnet", "RBI MD Chapter V",
                confidence="high", evidence={"publicly_accessible": True, "expected": False})
            tracker.record("rbi", 5, name, passed=False)
    else:
        if is_rbi:
            tracker.record("rbi", 5, name, passed=True)
    if not p.get("multi_az") and is_rbi:
        gap(name, "rbi", 6, "medium", f"RDS '{name}' not Multi-AZ",
            "Enable Multi-AZ", "RBI MD Chapter VI",
            confidence="high", evidence={"multi_az": p.get("multi_az"), "expected": True})
        tracker.record("rbi", 6, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 6, name, passed=True)
    if not p.get("audit_logging") and is_rbi:
        gap(name, "rbi", 7, "medium", f"RDS '{name}' lacks audit logging",
            "Enable CloudWatch log exports", "RBI MD Chapter VII",
            confidence="high", evidence={"audit_logging": p.get("audit_logging"), "expected": True})
        tracker.record("rbi", 7, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 7, name, passed=True)


def _check_lambda(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                  tracker: _DomainResourceTracker) -> None:
    if "Lambda::Function" not in rtype:
        return
    if p.get("suspect_env_vars"):
        gap(name, "dpdp", 6, "high",
            f"Lambda '{name}' has suspect secrets in env vars: {p['suspect_env_vars']}",
            "Use Secrets Manager or Parameter Store", "DPDP Act Section 8(4)",
            confidence="high", evidence={"suspect_env_vars": p["suspect_env_vars"], "expected": []})
        tracker.record("dpdp", 6, name, passed=False)
        if is_rbi:
            gap(name, "rbi", 4, "high", f"Lambda '{name}' secrets in env vars",
                "Use Secrets Manager", "RBI MD Chapter IV",
                confidence="high", evidence={"suspect_env_vars": p["suspect_env_vars"], "expected": []})
            tracker.record("rbi", 4, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)
        if is_rbi:
            tracker.record("rbi", 4, name, passed=True)
    if not p.get("dlq_configured") and is_rbi:
        gap(name, "rbi", 2, "low", f"Lambda '{name}' lacks dead letter queue",
            "Configure DLQ for error handling", "RBI MD Chapter III",
            confidence="medium",
            confidence_rationale="DLQ is a best practice for reliability, not a direct regulatory mandate",
            evidence={"dlq_configured": p.get("dlq_configured"), "expected": True})
        tracker.record("rbi", 2, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 2, name, passed=True)



def _check_ec2(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
               tracker: _DomainResourceTracker) -> None:
    if "EC2::Instance" not in rtype:
        return
    if p.get("public_ip"):
        gap(name, "dpdp", 6, "high", f"EC2 '{name}' has public IP",
            "Remove public IP, use private subnet + NAT", "DPDP Act Section 8(4)",
            confidence="high", evidence={"public_ip": True, "expected": False})
        tracker.record("dpdp", 6, name, passed=False)
        if is_rbi:
            gap(name, "rbi", 5, "high", f"EC2 '{name}' has public IP",
                "Move to private subnet", "RBI MD Chapter V",
                confidence="high", evidence={"public_ip": True, "expected": False})
            tracker.record("rbi", 5, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)
        if is_rbi:
            tracker.record("rbi", 5, name, passed=True)
    if not p.get("imdsv2_required"):
        gap(name, "dpdp", 6, "medium", f"EC2 '{name}' does not require IMDSv2",
            "Enforce IMDSv2 (HttpTokens=required)", "DPDP Act Section 8(4)",
            confidence="medium",
            confidence_rationale="IMDSv2 enforcement is a security best practice mapped to reasonable safeguards",
            evidence={"imdsv2_required": p.get("imdsv2_required"), "expected": True})
        if is_rbi:
            gap(name, "rbi", 5, "medium", f"EC2 '{name}' IMDSv2 not enforced",
                "Require IMDSv2", "RBI MD Chapter V",
                confidence="medium",
                confidence_rationale="IMDSv2 enforcement is a security best practice mapped to reasonable safeguards",
                evidence={"imdsv2_required": p.get("imdsv2_required"), "expected": True})
    if p.get("unencrypted_ebs"):
        gap(name, "dpdp", 6, "high", f"EC2 '{name}' has unencrypted EBS volumes",
            "Enable EBS encryption", "DPDP Act Section 8(4)",
            confidence="high", evidence={"unencrypted_ebs": True, "expected": False})


def _check_eks(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
               tracker: _DomainResourceTracker) -> None:
    if "EKS::Cluster" not in rtype:
        return
    if not p.get("secrets_encryption"):
        gap(name, "dpdp", 6, "high", f"EKS '{name}' lacks secrets encryption",
            "Enable envelope encryption for K8s secrets", "DPDP Act Section 8(4)",
            confidence="high", evidence={"secrets_encryption": p.get("secrets_encryption"), "expected": True})
        tracker.record("dpdp", 6, name, passed=False)
        if is_rbi:
            gap(name, "rbi", 4, "high", f"EKS '{name}' secrets not encrypted",
                "Enable KMS encryption for secrets", "RBI MD Chapter IV",
                confidence="high", evidence={"secrets_encryption": p.get("secrets_encryption"), "expected": True})
            tracker.record("rbi", 4, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)
        if is_rbi:
            tracker.record("rbi", 4, name, passed=True)
    if p.get("public_endpoint") and not p.get("private_endpoint"):
        gap(name, "dpdp", 6, "high", f"EKS '{name}' API server is public-only",
            "Enable private endpoint, restrict public access", "DPDP Act Section 8(4)",
            confidence="high",
            evidence={"public_endpoint": p.get("public_endpoint"),
                      "private_endpoint": p.get("private_endpoint"), "expected": "private_endpoint=True"})
        if is_rbi:
            gap(name, "rbi", 5, "high", f"EKS '{name}' public API endpoint",
                "Enable private endpoint", "RBI MD Chapter V",
                confidence="high",
                evidence={"public_endpoint": p.get("public_endpoint"),
                          "private_endpoint": p.get("private_endpoint"), "expected": "private_endpoint=True"})
            tracker.record("rbi", 5, name, passed=False)
    else:
        if is_rbi:
            tracker.record("rbi", 5, name, passed=True)
    if not p.get("audit_logging"):
        gap(name, "dpdp", 5, "medium", f"EKS '{name}' lacks audit logging",
            "Enable control plane logging (audit, api, authenticator)", "DPDP Act Section 8(5)",
            confidence="high", evidence={"audit_logging": p.get("audit_logging"), "expected": True})
        if is_rbi:
            gap(name, "rbi", 7, "medium", f"EKS '{name}' no audit logs",
                "Enable cluster logging", "RBI MD Chapter VII",
                confidence="high", evidence={"audit_logging": p.get("audit_logging"), "expected": True})
            tracker.record("rbi", 7, name, passed=False)
    else:
        if is_rbi:
            tracker.record("rbi", 7, name, passed=True)


def _check_ecs(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
               tracker: _DomainResourceTracker) -> None:
    if "ECS::Cluster" not in rtype:
        return
    if not p.get("container_insights") and is_rbi:
        gap(name, "rbi", 2, "medium", f"ECS '{name}' lacks Container Insights",
            "Enable Container Insights for monitoring", "RBI MD Chapter III",
            confidence="medium",
            confidence_rationale="Container Insights is a monitoring best practice mapped to IT infrastructure management",
            evidence={"container_insights": p.get("container_insights"), "expected": True})
        tracker.record("rbi", 2, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 2, name, passed=True)


def _check_api_gateway(name: str, rtype: str, is_rbi: bool, has_waf: bool, gap: Any,
                       tracker: _DomainResourceTracker) -> None:
    if "ApiGateway" not in rtype:
        return
    if is_rbi and not has_waf:
        gap(name, "rbi", 5, "high", f"API Gateway '{name}' lacks WAF protection",
            "Attach WAF WebACL", "RBI MD Chapter V",
            confidence="high", evidence={"waf_attached": False, "expected": True})
        tracker.record("rbi", 5, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 5, name, passed=True)


def _check_cloudfront(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                      tracker: _DomainResourceTracker) -> None:
    if "CloudFront" not in rtype:
        return
    if not p.get("waf_attached") and is_rbi:
        gap(name, "rbi", 5, "high", f"CloudFront '{name}' lacks WAF",
            "Attach WAF WebACL", "RBI MD Chapter V",
            confidence="high", evidence={"waf_attached": p.get("waf_attached"), "expected": True})
        tracker.record("rbi", 5, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 5, name, passed=True)
    if not p.get("access_logging") and is_rbi:
        gap(name, "rbi", 7, "medium", f"CloudFront '{name}' lacks access logging",
            "Enable access logging", "RBI MD Chapter VII",
            confidence="high", evidence={"access_logging": p.get("access_logging"), "expected": True})
        tracker.record("rbi", 7, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 7, name, passed=True)


def _check_sqs(name: str, rtype: str, p: dict, gap: Any,
               tracker: _DomainResourceTracker) -> None:
    if "SQS::Queue" not in rtype:
        return
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "medium", f"SQS '{name}' lacks encryption",
            "Enable SSE-KMS or SSE-SQS", "DPDP Act Section 8(4)",
            confidence="high", evidence={"encryption": p.get("encryption"), "expected": "SSE-KMS or SSE-SQS"})
        tracker.record("dpdp", 6, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)


def _check_sagemaker(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                     tracker: _DomainResourceTracker) -> None:
    if "SageMaker" not in rtype:
        return
    if p.get("direct_internet"):
        gap(name, "dpdp", 6, "high", f"SageMaker '{name}' has direct internet access",
            "Disable direct internet, use VPC", "DPDP Act Section 8(4)",
            confidence="high", evidence={"direct_internet": True, "expected": False})
        tracker.record("dpdp", 6, name, passed=False)
        if is_rbi:
            gap(name, "rbi", 5, "high", f"SageMaker '{name}' direct internet",
                "Disable direct internet access", "RBI MD Chapter V",
                confidence="high", evidence={"direct_internet": True, "expected": False})
            tracker.record("rbi", 5, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)
        if is_rbi:
            tracker.record("rbi", 5, name, passed=True)
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "high", f"SageMaker '{name}' lacks encryption",
            "Enable KMS encryption", "DPDP Act Section 8(4)",
            confidence="high", evidence={"encryption": p.get("encryption"), "expected": "KMS"})
    gap(name, "dpdp", 1, "high",
        f"ML component '{name}' — verify consent for training data",
        "Implement consent tracking for ML training data", "DPDP Act Section 6",
        confidence="low",
        confidence_rationale="Consent tracking for ML training data is an organizational requirement that cannot be verified via infrastructure")


def _check_kms(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
               tracker: _DomainResourceTracker) -> None:
    if "KMS::Key" not in rtype:
        return
    if p.get("key_manager") == "CUSTOMER" and not p.get("key_rotation"):
        gap(name, "dpdp", 6, "medium", f"KMS key '{name}' lacks automatic rotation",
            "Enable annual key rotation", "DPDP Act Section 8(4)",
            confidence="high", evidence={"key_rotation": p.get("key_rotation"), "expected": True})
        tracker.record("dpdp", 6, name, passed=False)
        if is_rbi:
            gap(name, "rbi", 4, "medium", f"KMS key '{name}' no rotation",
                "Enable key rotation", "RBI MD Chapter IV",
                confidence="high", evidence={"key_rotation": p.get("key_rotation"), "expected": True})
            tracker.record("rbi", 4, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)
        if is_rbi:
            tracker.record("rbi", 4, name, passed=True)


def _check_cloudtrail(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                      tracker: _DomainResourceTracker) -> None:
    if "CloudTrail::Trail" not in rtype:
        return
    if not p.get("log_validation"):
        gap(name, "dpdp", 5, "medium", f"CloudTrail '{name}' lacks log file validation",
            "Enable log file validation", "DPDP Act Section 8(5)",
            confidence="high", evidence={"log_validation": p.get("log_validation"), "expected": True})
        tracker.record("dpdp", 5, name, passed=False)
        if is_rbi:
            gap(name, "rbi", 7, "medium", f"CloudTrail '{name}' no log validation",
                "Enable validation", "RBI MD Chapter VII",
                confidence="high", evidence={"log_validation": p.get("log_validation"), "expected": True})
            tracker.record("rbi", 7, name, passed=False)
    else:
        tracker.record("dpdp", 5, name, passed=True)
        if is_rbi:
            tracker.record("rbi", 7, name, passed=True)
    if not p.get("encryption") and is_rbi:
        gap(name, "rbi", 7, "medium", f"CloudTrail '{name}' logs not encrypted",
            "Enable KMS encryption for trail", "RBI MD Chapter VII",
            confidence="high", evidence={"encryption": p.get("encryption"), "expected": "KMS"})
    if not p.get("cloudwatch_logs"):
        gap(name, "dpdp", 5, "medium", f"CloudTrail '{name}' not forwarding to CloudWatch Logs",
            "Enable CloudWatch Logs integration for real-time alerting", "CERT-In 6-hour reporting",
            confidence="high", evidence={"cloudwatch_logs": p.get("cloudwatch_logs"), "expected": True})


def _check_sns(name: str, rtype: str, p: dict, gap: Any,
               tracker: _DomainResourceTracker) -> None:
    if "SNS::Topic" not in rtype:
        return
    if not p.get("encryption"):
        gap(name, "dpdp", 6, "low", f"SNS '{name}' lacks encryption",
            "Enable SSE-KMS", "DPDP Act Section 8(4)",
            confidence="medium",
            confidence_rationale="SNS encryption is a best practice; risk depends on message content sensitivity",
            evidence={"encryption": p.get("encryption"), "expected": "SSE-KMS"})
        tracker.record("dpdp", 6, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)


def _check_cloudwatch_logs(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                           tracker: _DomainResourceTracker) -> None:
    if "Logs::LogGroup" not in rtype:
        return
    retention = p.get("retention_days", 0)
    if is_rbi and retention < 180:
        gap(name, "rbi", 7, "medium",
            f"CloudWatch LogGroup '{name}' retention {retention} days (CERT-In requires 180)",
            "Set retention to at least 180 days", "CERT-In Directions 2022",
            confidence="high",
            evidence={"retention_days": retention, "expected": ">=180"})
        tracker.record("rbi", 7, name, passed=False)
        # Also record under CERT-In domain 2 (Log Retention)
        gap(name, "certin", 2, "medium",
            f"CloudWatch LogGroup '{name}' retention {retention} days (CERT-In requires 180)",
            "Set retention to at least 180 days", "CERT-In Directions 2022",
            confidence="high",
            evidence={"retention_days": retention, "expected": ">=180"})
        tracker.record("certin", 2, name, passed=False)
    else:
        if is_rbi:
            tracker.record("rbi", 7, name, passed=True)
            tracker.record("certin", 2, name, passed=True)


def _check_iam_role(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                    tracker: _DomainResourceTracker) -> None:
    if "IAM::Role" not in rtype:
        return
    policies = p.get("attached_policies", [])
    dangerous = {"AdministratorAccess", "IAMFullAccess", "PowerUserAccess"}
    found_dangerous = False
    for pol in policies:
        if pol in dangerous:
            found_dangerous = True
            gap(name, "dpdp", 6, "critical",
                f"IAM role '{name}' has overly broad policy: {pol}",
                "Replace with least-privilege custom policy", "DPDP Act Section 8(4)",
                confidence="high",
                evidence={"policy": pol, "expected": "least-privilege custom policy"})
            if is_rbi:
                gap(name, "rbi", 4, "critical",
                    f"IAM role '{name}' has dangerous policy: {pol}",
                    "Implement least-privilege IAM", "RBI MD Chapter IV",
                    confidence="high",
                    evidence={"policy": pol, "expected": "least-privilege custom policy"})
    if found_dangerous:
        tracker.record("dpdp", 6, name, passed=False)
        if is_rbi:
            tracker.record("rbi", 4, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)
        if is_rbi:
            tracker.record("rbi", 4, name, passed=True)



# ---- New check functions (Task 7.1-7.5) ----

def _check_s3_tls(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                  tracker: _DomainResourceTracker) -> None:
    """Check S3 bucket for TLS enforcement via bucket policy."""
    if "S3::Bucket" not in rtype:
        return
    if not p.get("tls_enforced"):
        gap(name, "dpdp", 6, "high",
            f"S3 '{name}' does not enforce TLS (aws:SecureTransport)",
            "Add bucket policy denying non-TLS requests", "DPDP Act Section 8(4), Rules 2025 Rule 6",
            confidence="high",
            evidence={"tls_enforced": p.get("tls_enforced"), "expected": True})
        tracker.record("dpdp", 6, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)


def _check_rds_ssl(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                   tracker: _DomainResourceTracker) -> None:
    """Check RDS instance for SSL enforcement."""
    if "RDS::DB" not in rtype:
        return
    if not p.get("ssl_enforced"):
        gap(name, "dpdp", 6, "high",
            f"RDS '{name}' does not enforce SSL connections",
            "Enable SSL enforcement via parameter group (rds.force_ssl or require_secure_transport)",
            "DPDP Act Section 8(4), RBI MD Chapter IV",
            confidence="high",
            evidence={"ssl_enforced": p.get("ssl_enforced"), "expected": True})
        tracker.record("dpdp", 6, name, passed=False)
        if is_rbi:
            gap(name, "rbi", 4, "high",
                f"RDS '{name}' SSL not enforced",
                "Enable SSL enforcement", "RBI MD Chapter IV",
                confidence="high",
                evidence={"ssl_enforced": p.get("ssl_enforced"), "expected": True})
            tracker.record("rbi", 4, name, passed=False)
    else:
        tracker.record("dpdp", 6, name, passed=True)
        if is_rbi:
            tracker.record("rbi", 4, name, passed=True)


def _check_vpc(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
               tracker: _DomainResourceTracker) -> None:
    """Check VPC for flow logs enablement and retention."""
    if "EC2::VPC" not in rtype or "SecurityGroup" in rtype:
        return
    if not p.get("flow_logs_enabled"):
        gap(name, "rbi", 5, "high" if is_rbi else "medium",
            f"VPC '{name}' lacks Flow Logs for network monitoring",
            "Enable VPC Flow Logs to CloudWatch Logs or S3",
            "RBI MD Chapter V",
            confidence="high",
            evidence={"flow_logs_enabled": p.get("flow_logs_enabled"), "expected": True})
        tracker.record("rbi", 5, name, passed=False)
    else:
        tracker.record("rbi", 5, name, passed=True)

    # Check flow log retention for CERT-In compliance
    flow_log_retention = p.get("flow_log_retention_days", 0)
    if is_rbi and p.get("flow_logs_enabled") and flow_log_retention and flow_log_retention < 180:
        gap(name, "certin", 2, "medium",
            f"VPC '{name}' flow log retention {flow_log_retention} days (CERT-In requires 180)",
            "Set flow log retention to at least 180 days",
            "CERT-In Directions 2022",
            confidence="high",
            evidence={"flow_log_retention_days": flow_log_retention, "expected": ">=180"})
        tracker.record("certin", 2, name, passed=False)


def _check_security_group(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                          tracker: _DomainResourceTracker) -> None:
    """Check security group for open SSH/RDP from internet."""
    if "EC2::SecurityGroup" not in rtype:
        return
    open_ports = p.get("open_to_internet", [])
    if 22 in open_ports:
        gap(name, "rbi", 5, "high",
            f"Security Group '{name}' allows SSH (port 22) from 0.0.0.0/0",
            "Restrict SSH access to specific IP ranges or use SSM Session Manager",
            "RBI MD Chapter V, DPDP Act Section 8(4)",
            confidence="high",
            evidence={"open_ssh": True, "cidr": "0.0.0.0/0", "expected": "restricted"})
        gap(name, "dpdp", 6, "high",
            f"Security Group '{name}' allows SSH (port 22) from 0.0.0.0/0",
            "Restrict SSH access to specific IP ranges",
            "DPDP Act Section 8(4)",
            confidence="high",
            evidence={"open_ssh": True, "cidr": "0.0.0.0/0", "expected": "restricted"})
        tracker.record("rbi", 5, name, passed=False)
        tracker.record("dpdp", 6, name, passed=False)
    if 3389 in open_ports:
        gap(name, "rbi", 5, "high",
            f"Security Group '{name}' allows RDP (port 3389) from 0.0.0.0/0",
            "Restrict RDP access to specific IP ranges or use SSM Session Manager",
            "RBI MD Chapter V, DPDP Act Section 8(4)",
            confidence="high",
            evidence={"open_rdp": True, "cidr": "0.0.0.0/0", "expected": "restricted"})
        gap(name, "dpdp", 6, "high",
            f"Security Group '{name}' allows RDP (port 3389) from 0.0.0.0/0",
            "Restrict RDP access to specific IP ranges",
            "DPDP Act Section 8(4)",
            confidence="high",
            evidence={"open_rdp": True, "cidr": "0.0.0.0/0", "expected": "restricted"})
        tracker.record("rbi", 5, name, passed=False)
        tracker.record("dpdp", 6, name, passed=False)
    if not open_ports:
        tracker.record("rbi", 5, name, passed=True)
        tracker.record("dpdp", 6, name, passed=True)


def _check_backup_resource(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                           tracker: _DomainResourceTracker) -> None:
    """Check individual backup plan resources for vault lock."""
    if "Backup::BackupPlan" not in rtype:
        return
    if is_rbi and not p.get("vault_lock"):
        gap(name, "rbi", 6, "medium",
            f"Backup plan '{name}' lacks vault lock for immutable backups",
            "Enable AWS Backup Vault Lock for compliance retention",
            "RBI MD Chapter VI",
            confidence="high",
            evidence={"vault_lock": p.get("vault_lock"), "expected": True})
        tracker.record("rbi", 6, name, passed=False)
    elif is_rbi:
        tracker.record("rbi", 6, name, passed=True)


def _check_secrets_manager(name: str, rtype: str, p: dict, is_rbi: bool, gap: Any,
                           tracker: _DomainResourceTracker) -> None:
    """Check Secrets Manager secret for rotation enablement."""
    if "SecretsManager::Secret" not in rtype:
        return
    if not p.get("rotation_enabled"):
        gap(name, "rbi", 4, "medium",
            f"Secret '{name}' lacks automatic rotation",
            "Enable automatic rotation for the secret",
            "RBI MD Chapter IV",
            confidence="medium",
            confidence_rationale="Secret rotation is a security best practice mapped to information security requirements",
            evidence={"rotation_enabled": p.get("rotation_enabled"), "expected": True})
        tracker.record("rbi", 4, name, passed=False)
    else:
        tracker.record("rbi", 4, name, passed=True)


def _check_inspector_resource(name: str, rtype: str, p: dict, is_sebi: bool,
                              sebi_tier: str, gap: Any,
                              tracker: _DomainResourceTracker) -> None:
    """Check Inspector resource (handled at architecture level)."""
    # Inspector checks are architecture-level, handled in assess() body
    pass


def _check_kms_byok(name: str, rtype: str, p: dict, is_sebi: bool,
                    sebi_tier: str, gap: Any,
                    tracker: _DomainResourceTracker) -> None:
    """Check KMS key for BYOK (customer-managed) requirement under SEBI."""
    if "KMS::Key" not in rtype:
        return
    if not is_sebi:
        return
    if sebi_tier not in ("mii", "qualified_re"):
        return
    # SEBI MII and qualified_re require customer-managed keys (BYOK)
    if p.get("key_manager") != "CUSTOMER":
        gap(name, "sebi", 3, "high",
            f"KMS key '{name}' is AWS-managed — SEBI {sebi_tier.upper()} tier requires customer-managed keys (BYOK)",
            "Create and use customer-managed KMS keys (CMK) instead of AWS-managed keys",
            "SEBI CSCRF Cloud Framework BYOK Requirement",
            confidence="high",
            evidence={"key_manager": p.get("key_manager"), "expected": "CUSTOMER"})
        tracker.record("sebi", 3, name, passed=False)
    else:
        tracker.record("sebi", 3, name, passed=True)
