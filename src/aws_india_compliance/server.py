"""MCP server entry point — tool and resource registration.

This is the only file that imports the MCP SDK. All business logic
lives in the other modules (assessment, parsers, aws_scanner, etc.).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import __version__
from .assessment import assess
from .aws_scanner import scan_via_config
from .conformance_pack import generate_conformance_pack
from .control_tower import assess_control_tower, scan_control_tower
from .domains import DPDP_DOMAINS, RBI_DOMAINS, check_staleness
from .knowledge import search_live, monitor_source_changes, update_content_hashes
from .parsers import parse_cloudformation, parse_drawio, parse_terraform

_logger = logging.getLogger(__name__)

# --- Input validation helpers ---

_VALID_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+-\d+)?$")
_VALID_AGGREGATOR_RE = re.compile(r"^[a-zA-Z0-9_-]{1,256}$")
_MAX_TOP_K = 50


def _validate_region(region: str) -> str:
    """Validate AWS region format. Returns sanitized region or raises ValueError."""
    region = region.strip()
    if not _VALID_REGION_RE.match(region):
        raise ValueError(f"Invalid region format: {region!r}")
    return region


def _validate_aggregator(name: str) -> str:
    """Validate Config Aggregator name. Returns sanitized name or raises ValueError."""
    name = name.strip()
    if name and not _VALID_AGGREGATOR_RE.match(name):
        raise ValueError(f"Invalid aggregator name format: {name!r}")
    return name


def _get_report_dir() -> str:
    """Return the reports directory path.

    Priority:
    1. REPORT_DIR environment variable (explicit override).
    2. Current working directory + /reports (user's project root).
    3. Fallback to OS temp directory if cwd/reports is not writable.
    """
    env_dir = os.environ.get("REPORT_DIR", "")
    if env_dir:
        return env_dir
    cwd_reports = os.path.join(os.getcwd(), "reports")
    # Check if we can write to the cwd-based reports dir
    try:
        os.makedirs(cwd_reports, exist_ok=True)
        # Verify write access with a test file
        test_file = os.path.join(cwd_reports, ".write_test")
        with open(test_file, "w") as f:
            f.write("")
        os.remove(test_file)
        return cwd_reports
    except OSError:
        # Fall back to temp directory
        import tempfile
        return os.path.join(tempfile.gettempdir(), "aws-india-compliance-reports")


def _safe_report_path(report_path: str) -> str:
    """Validate report_path to prevent path traversal. Must be under reports/ dir."""
    report_dir = _get_report_dir()
    resolved = os.path.realpath(report_path)
    if not resolved.startswith(os.path.realpath(report_dir)):
        raise ValueError("report_path must be within the reports/ directory")
    return resolved


def _sanitize_error(e: Exception) -> str:
    """Sanitize exception message to avoid leaking internal filesystem paths."""
    msg = str(e)
    # Strip absolute path prefixes
    home = os.path.expanduser("~")
    if home in msg:
        msg = msg.replace(home, "~")
    return msg

_MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
try:
    _MCP_PORT = max(1, min(65535, int(os.environ.get("MCP_PORT", "8000"))))
except (ValueError, TypeError):
    _MCP_PORT = 8000

# Only enable HTTP settings when transport is explicitly set to http/streamable-http.
# For stdio (default, used by Claude Desktop and Kiro), these params are not needed.
_transport = os.environ.get("MCP_TRANSPORT", "stdio")
if _transport in ("streamable-http", "sse"):
    mcp = FastMCP("aws-india-compliance", host=_MCP_HOST, port=_MCP_PORT, stateless_http=True)
else:
    mcp = FastMCP("aws-india-compliance")


def _log_tool_manifest() -> None:
    """Log SHA-256 hashes of tool definitions for integrity verification."""
    tools = [
        "search_regulatory_text", "parse_architecture", "assess_compliance",
        "generate_report", "list_control_domains", "scan_aws_account", "scan_control_tower_tool",
        "check_regulatory_updates",
    ]
    manifest = {}
    for name in tools:
        h = hashlib.sha256(name.encode()).hexdigest()[:16]
        manifest[name] = h
    _logger.info("Tool manifest: %s", manifest)


def _get_staleness_warning() -> dict | None:
    """Check mapping staleness and return warning dict if any framework is stale."""
    staleness = check_staleness()
    if staleness["stale_frameworks"]:
        return {
            "mapping_staleness_warning": staleness["warnings"],
            "stale_frameworks": staleness["stale_frameworks"],
            "threshold_days": staleness["threshold_days"],
            "action": "Run check_regulatory_updates to review source changes and update mappings.",
        }
    return None


# ---- Tools ----

@mcp.tool()
def search_regulatory_text(query: str, framework: str = "", top_k: int = 5) -> str:
    """Search DPDP Act, RBI Master Direction, and SEBI CSCRF regulatory text.

    Searches live authoritative sources first. If a source is unreachable
    or returns no extractable text (e.g., JS-rendered pages), automatically
    falls back to the bundled control_mappings.json manifest. Fallback
    results include source="control_mappings_fallback".

    Args:
        query: Search query (e.g., "breach notification", "data retention", "cyber security")
        framework: Filter by "dpdp", "rbi", or "sebi". Empty = search all.
        top_k: Number of results to return (default 5).

    Returns:
        JSON with matching regulatory text chunks, sections, and relevance scores.
    """
    results = search_live(query, framework, min(top_k, _MAX_TOP_K))
    return json.dumps({"results": results, "count": len(results)}, indent=2)


@mcp.tool()
def parse_architecture(content: str, format: str = "cloudformation") -> str:
    """Parse an architecture diagram/template and extract infrastructure components.

    Args:
        content: The raw file content (YAML, JSON, HCL, or XML).
        format: One of "cloudformation", "terraform", "drawio".

    Returns:
        JSON with extracted components including name, type, and category.
    """
    try:
        parsers = {"cloudformation": parse_cloudformation, "terraform": parse_terraform, "drawio": parse_drawio}
        if format not in parsers:
            return json.dumps({"error": f"Unsupported format: {format}. Use: cloudformation, terraform, drawio"})
        components = parsers[format](content)
        return json.dumps({"components": components, "count": len(components)}, indent=2)
    except Exception as e:
        return json.dumps({"error": _sanitize_error(e)})


@mcp.tool()
def assess_compliance(components_json: str, is_significant_data_fiduciary: bool = False,
                      is_rbi_regulated: bool = False, is_sebi_regulated: bool = False,
                      sebi_entity_tier: str = "", exceptions: str = "",
                      filter_tags: str = "", exclude_tags: str = "") -> str:
    """Assess infrastructure components against DPDP and RBI control domains.

    Args:
        components_json: JSON string of components (from parse_architecture output).
        is_significant_data_fiduciary: Whether the org is an SDF under DPDP Act.
        is_rbi_regulated: Whether the org is regulated by RBI.
        is_sebi_regulated: Whether the org is regulated by SEBI.
        sebi_entity_tier: SEBI entity tier ("mii", "qualified_re", "other_re").
        exceptions: JSON string of exception rules for gap suppression.
        filter_tags: JSON string of {key: value} pairs — include only matching components.
        exclude_tags: JSON string of {key: value} pairs — exclude matching components.

    Returns:
        JSON with compliance gaps, posture scores, and remediation recommendations.
    """
    try:
        data = json.loads(components_json)
        components = data if isinstance(data, list) else data.get("components", [])
    except (json.JSONDecodeError, TypeError) as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})

    # Parse optional JSON string parameters
    parsed_exceptions = None
    if exceptions:
        try:
            parsed_exceptions = json.loads(exceptions)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid exceptions JSON: {e}"})

    parsed_filter_tags = None
    if filter_tags:
        try:
            parsed_filter_tags = json.loads(filter_tags)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid filter_tags JSON: {e}"})

    parsed_exclude_tags = None
    if exclude_tags:
        try:
            parsed_exclude_tags = json.loads(exclude_tags)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid exclude_tags JSON: {e}"})

    scan_start = datetime.utcnow()
    result = assess(
        components, is_significant_data_fiduciary, is_rbi_regulated,
        is_sebi=is_sebi_regulated,
        sebi_entity_tier=sebi_entity_tier,
        exceptions=parsed_exceptions,
        filter_tags=parsed_filter_tags,
        exclude_tags=parsed_exclude_tags,
    )
    scan_end = datetime.utcnow()

    result["scan_metadata"] = {
        "scan_start": scan_start.isoformat(),
        "scan_end": scan_end.isoformat(),
        "region": "n/a",
        "tool_version": __version__,
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def generate_report(components_json: str, is_significant_data_fiduciary: bool = False,
                    is_rbi_regulated: bool = False, is_sebi_regulated: bool = False,
                    sebi_entity_tier: str = "", exceptions: str = "",
                    filter_tags: str = "", exclude_tags: str = "") -> str:
    """Generate a full compliance report with executive summary and remediation timeline.

    Args:
        components_json: JSON string of components (from parse_architecture output).
        is_significant_data_fiduciary: Whether the org is an SDF under DPDP Act.
        is_rbi_regulated: Whether the org is regulated by RBI.
        is_sebi_regulated: Whether the org is regulated by SEBI.
        sebi_entity_tier: SEBI entity tier ("mii", "qualified_re", "other_re").
        exceptions: JSON string of exception rules for gap suppression.
        filter_tags: JSON string of {key: value} pairs — include only matching components.
        exclude_tags: JSON string of {key: value} pairs — exclude matching components.

    Returns:
        JSON compliance report with posture scores, gaps, and phased remediation.
    """
    try:
        data = json.loads(components_json)
        components = data if isinstance(data, list) else data.get("components", [])
    except (json.JSONDecodeError, TypeError) as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})

    # Parse optional JSON string parameters
    parsed_exceptions = None
    if exceptions:
        try:
            parsed_exceptions = json.loads(exceptions)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid exceptions JSON: {e}"})

    parsed_filter_tags = None
    if filter_tags:
        try:
            parsed_filter_tags = json.loads(filter_tags)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid filter_tags JSON: {e}"})

    parsed_exclude_tags = None
    if exclude_tags:
        try:
            parsed_exclude_tags = json.loads(exclude_tags)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid exclude_tags JSON: {e}"})

    scan_start = datetime.utcnow()
    result = assess(
        components, is_significant_data_fiduciary, is_rbi_regulated,
        is_sebi=is_sebi_regulated,
        sebi_entity_tier=sebi_entity_tier,
        exceptions=parsed_exceptions,
        filter_tags=parsed_filter_tags,
        exclude_tags=parsed_exclude_tags,
    )
    scan_end = datetime.utcnow()

    dpdp = result["dpdp_posture"]
    summary = f"Assessed {result['total_components']} components. "
    summary += f"DPDP compliance: {dpdp['score']}% ({dpdp['satisfied']}/{dpdp['total']} domains). "
    if result["rbi_posture"]:
        rbi = result["rbi_posture"]
        summary += f"RBI compliance: {rbi['score']}% ({rbi['satisfied']}/{rbi['total']} domains). "
    if result.get("sebi_posture"):
        sebi = result["sebi_posture"]
        summary += f"SEBI: {sebi['score']}% ({sebi['satisfied']}/{sebi['total']}). "
    if result.get("certin_posture"):
        certin = result["certin_posture"]
        summary += f"CERT-In: {certin['score']}% ({certin['satisfied']}/{certin['total']}). "
    summary += f"Found {result['total_gaps']} compliance gaps."

    critical = [g for g in result["gaps"] if g["risk"] == "critical"]
    high = [g for g in result["gaps"] if g["risk"] == "high"]
    medium = [g for g in result["gaps"] if g["risk"] == "medium"]
    timeline = []
    if critical:
        timeline.append({"phase": "Immediate (0-30 days)", "items": list({g["remediation"] for g in critical})})
    if high:
        timeline.append({"phase": "Short-term (30-90 days)", "items": list({g["remediation"] for g in high})})
    if medium:
        timeline.append({"phase": "Medium-term (90-180 days)", "items": list({g["remediation"] for g in medium})})

    result["scan_metadata"] = {
        "scan_start": scan_start.isoformat(),
        "scan_end": scan_end.isoformat(),
        "region": "n/a",
        "tool_version": __version__,
    }

    return json.dumps({"executive_summary": summary, **result, "remediation_timeline": timeline}, indent=2)


@mcp.tool()
def list_control_domains(framework: str = "dpdp") -> str:
    """List the control domains for DPDP Act, RBI Master Direction, or SEBI CSCRF.

    Args:
        framework: "dpdp", "rbi", or "sebi".

    Returns:
        JSON with numbered control domains.
    """
    from .domains import SEBI_DOMAINS
    if framework.lower() == "sebi":
        domains = SEBI_DOMAINS
    elif framework.lower() == "rbi":
        domains = RBI_DOMAINS
    else:
        domains = DPDP_DOMAINS
    return json.dumps({"framework": framework, "domains": {str(k): v for k, v in domains.items()}}, indent=2)


@mcp.tool()
def generate_conformance_pack_tool(
    framework: str = "dpdp",
    include_domains: str = "",
    exclude_domains: str = "",
    pack_name_prefix: str = "",
) -> str:
    """Generate an AWS Config conformance pack YAML for a compliance framework.

    Creates a deployable AWS Config conformance pack template containing
    validated managed rules mapped to the specified regulatory framework's
    control domains. All rule identifiers are validated against AWS documentation.

    Supported frameworks: dpdp, rbi, sebi, certin.

    Args:
        framework: One of "dpdp", "rbi", "sebi", "certin". Default "dpdp".
        include_domains: Comma-separated domain numbers to include (empty = all).
        exclude_domains: Comma-separated domain numbers to exclude (empty = none).
        pack_name_prefix: Optional prefix for the conformance pack name.

    Returns:
        JSON with yaml_content (the full template), pack_name, rule_count,
        domains_covered, and deployment instructions.
    """
    # Parse domain filters
    parsed_include: list[int] | None = None
    if include_domains.strip():
        try:
            parsed_include = [int(d.strip()) for d in include_domains.split(",") if d.strip()]
        except ValueError:
            return json.dumps({"error": "include_domains must be comma-separated integers"})

    parsed_exclude: list[int] | None = None
    if exclude_domains.strip():
        try:
            parsed_exclude = [int(d.strip()) for d in exclude_domains.split(",") if d.strip()]
        except ValueError:
            return json.dumps({"error": "exclude_domains must be comma-separated integers"})

    result = generate_conformance_pack(
        framework=framework,
        include_domains=parsed_include,
        exclude_domains=parsed_exclude,
        pack_name_prefix=pack_name_prefix,
    )

    if "error" in result:
        return json.dumps(result)

    # Add deployment instructions
    result["deployment_command"] = (
        f"aws configservice put-conformance-pack "
        f"--conformance-pack-name {result['pack_name']} "
        f"--template-body file://<filename>.yaml"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def scan_aws_account(region: str = "ap-south-1", is_significant_data_fiduciary: bool = False,
                     is_rbi_regulated: bool = False, is_sebi_regulated: bool = False,
                     aggregator_name: str = "",
                     sebi_entity_tier: str = "", exceptions: str = "",
                     filter_tags: str = "", exclude_tags: str = "") -> str:
    """Scan an AWS account's resources via AWS Config and assess compliance against DPDP and RBI.

    Uses AWS Config Advanced Query to pull all resource configurations in a single fast query.
    Requires AWS Config recorder to be enabled. Uses caller's AWS credentials.
    For org-wide scan, provide a Config Aggregator name.

    Args:
        region: AWS region to scan (default "ap-south-1").
        is_significant_data_fiduciary: Whether the org is an SDF under DPDP Act.
        is_rbi_regulated: Whether the org is regulated by RBI.
        is_sebi_regulated: Whether the org is regulated by SEBI.
        aggregator_name: Config Aggregator name for org-wide scan. Empty = auto-discover.
        sebi_entity_tier: SEBI entity tier ("mii", "qualified_re", "other_re").
        exceptions: JSON string of exception rules for gap suppression.
        filter_tags: JSON string of {key: value} pairs — include only matching components.
        exclude_tags: JSON string of {key: value} pairs — exclude matching components.

    Returns:
        JSON with discovered resources, compliance gaps, posture scores, and remediation.
    """
    # Validate inputs
    try:
        region = _validate_region(region)
    except ValueError as e:
        return json.dumps({"error": str(e)})
    try:
        aggregator_name = _validate_aggregator(aggregator_name)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    # Parse optional JSON string parameters
    parsed_exceptions = None
    if exceptions:
        try:
            parsed_exceptions = json.loads(exceptions)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid exceptions JSON: {e}"})

    parsed_filter_tags = None
    if filter_tags:
        try:
            parsed_filter_tags = json.loads(filter_tags)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid filter_tags JSON: {e}"})

    parsed_exclude_tags = None
    if exclude_tags:
        try:
            parsed_exclude_tags = json.loads(exclude_tags)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid exclude_tags JSON: {e}"})

    try:
        components, resolved_aggregator = scan_via_config(region, aggregator_name)
        if not components:
            return json.dumps({"error": "No resources found. Ensure AWS Config recorder is enabled.", "region": region})

        scan_start = datetime.utcnow()
        result = assess(
            components, is_significant_data_fiduciary, is_rbi_regulated,
            is_sebi=is_sebi_regulated,
            sebi_entity_tier=sebi_entity_tier,
            exceptions=parsed_exceptions,
            filter_tags=parsed_filter_tags,
            exclude_tags=parsed_exclude_tags,
        )
        scan_end = datetime.utcnow()

        dpdp = result["dpdp_posture"]
        summary = f"Scanned {len(components)} resources in {region}. "
        summary += f"DPDP: {dpdp['score']}% ({dpdp['satisfied']}/{dpdp['total']}). "
        if result["rbi_posture"]:
            rbi = result["rbi_posture"]
            summary += f"RBI: {rbi['score']}% ({rbi['satisfied']}/{rbi['total']}). "
        if result.get("sebi_posture"):
            sebi = result["sebi_posture"]
            summary += f"SEBI: {sebi['score']}% ({sebi['satisfied']}/{sebi['total']}). "
        if result.get("certin_posture"):
            certin = result["certin_posture"]
            summary += f"CERT-In: {certin['score']}% ({certin['satisfied']}/{certin['total']}). "
        summary += f"{result['total_gaps']} gaps found."

        critical = [g for g in result["gaps"] if g["risk"] == "critical"]
        high = [g for g in result["gaps"] if g["risk"] == "high"]
        medium = [g for g in result["gaps"] if g["risk"] == "medium"]
        timeline = []
        if critical:
            timeline.append({"phase": "Immediate (0-30 days)", "items": list({g["remediation"] for g in critical})})
        if high:
            timeline.append({"phase": "Short-term (30-90 days)", "items": list({g["remediation"] for g in high})})
        if medium:
            timeline.append({"phase": "Medium-term (90-180 days)", "items": list({g["remediation"] for g in medium})})

        result["scan_metadata"] = {
            "scan_start": scan_start.isoformat(),
            "scan_end": scan_end.isoformat(),
            "region": region,
            "tool_version": __version__,
        }

        # --- Response size management ---
        # Large org scans can produce thousands of gaps. To keep the MCP
        # response within transport limits, we cap inline gaps and write
        # the full report to a file when the payload would be too large.
        all_gaps = result["gaps"]
        full_report_path = None
        gap_cap = 100  # max gaps inline

        # Build gap summary by framework and risk (needed for both file and response)
        gap_summary: dict[str, dict[str, int]] = {}
        for g in all_gaps:
            fw = g.get("framework", "unknown")
            risk = g.get("risk", "unknown")
            gap_summary.setdefault(fw, {}).setdefault(risk, 0)
            gap_summary[fw][risk] += 1

        # Confidence distribution (needed for both file and response)
        conf_dist: dict[str, int] = {}
        for g in all_gaps:
            c = g.get("confidence", "unknown")
            conf_dist[c] = conf_dist.get(c, 0) + 1

        if len(all_gaps) > gap_cap:
            import os, tempfile
            # Write full result to a report file (includes all new fields)
            full_result = {
                "region": region, "aggregator": resolved_aggregator or "single-account",
                "executive_summary": summary,
                "scan_metadata": {
                    "scan_start": scan_start.isoformat(),
                    "scan_end": scan_end.isoformat(),
                    "region": region,
                    "tool_version": __version__,
                },
                "discovered_resources": [{"name": c["name"], "type": c["type"], "category": c["category"],
                                           "region": c.get("region", ""), "account": c.get("account_id", "")} for c in components],
                "gap_summary_by_framework": gap_summary,
                "confidence_distribution": conf_dist,
                **result, "remediation_timeline": timeline,
                **({"staleness_warning": sw} if (sw := _get_staleness_warning()) else {}),
            }
            report_dir = os.environ.get("REPORT_DIR", _get_report_dir())
            os.makedirs(report_dir, exist_ok=True)
            report_file = os.path.join(report_dir, f"scan_report_{region}_{scan_start.strftime('%Y%m%d_%H%M%S')}.json")
            try:
                with open(report_file, "w") as f:
                    json.dump(full_result, f, indent=2, default=str)
                full_report_path = report_file
            except OSError:
                full_report_path = None

            # Inline: only critical + high gaps, capped
            priority_gaps = [g for g in all_gaps if g["risk"] in ("critical", "high")][:gap_cap]
            result_gaps = priority_gaps
        else:
            result_gaps = all_gaps

        response: dict[str, Any] = {
            "region": region, "aggregator": resolved_aggregator or "single-account",
            "executive_summary": summary,
            "scan_metadata": result["scan_metadata"],
            "dpdp_posture": result["dpdp_posture"],
            "rbi_posture": result["rbi_posture"],
            "sebi_posture": result.get("sebi_posture"),
            "certin_posture": result.get("certin_posture"),
            "total_components": result["total_components"],
            "total_gaps": result["total_gaps"],
            "suppressed_count": result["suppressed_count"],
            "gap_summary_by_framework": gap_summary,
            "confidence_distribution": conf_dist,
            "per_account": result.get("per_account"),
            "resource_compliance": result.get("resource_compliance"),
            "gaps": result_gaps,
            "remediation_timeline": timeline,
        }
        if full_report_path:
            response["full_report_file"] = full_report_path
            response["note"] = f"Response trimmed to {len(result_gaps)} priority gaps. Full {len(all_gaps)} gaps saved to {full_report_path}"
        if (sw2 := _get_staleness_warning()):
            response["staleness_warning"] = sw2

        return json.dumps(response, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": _sanitize_error(e), "region": region})


@mcp.tool()
def scan_control_tower_tool(region: str = "ap-south-1", is_significant_data_fiduciary: bool = False,
                            is_rbi_regulated: bool = False, is_sebi_regulated: bool = False) -> str:
    """Scan Control Tower configuration and assess governance controls against DPDP and RBI.

    Must be run from the management account. Discovers landing zone config,
    enabled controls per OU, and recommends missing controls based on DPDP/RBI requirements.

    Args:
        region: AWS region where Control Tower is deployed (default "ap-south-1").
        is_significant_data_fiduciary: Whether the org is an SDF under DPDP Act.
        is_rbi_regulated: Whether the org is regulated by RBI.
        is_sebi_regulated: Whether the org is regulated by SEBI.

    Returns:
        JSON with landing zone status, enabled controls, compliance gaps,
        and recommended controls to enable for DPDP/RBI compliance.
    """
    try:
        region = _validate_region(region)
        ct_data = scan_control_tower(region)
        scan_start = datetime.utcnow()
        result = assess_control_tower(ct_data, is_significant_data_fiduciary, is_rbi_regulated, is_sebi=is_sebi_regulated)
        scan_end = datetime.utcnow()

        dpdp = result["dpdp_posture"]
        summary = f"Control Tower: {result['total_enabled_controls']} controls enabled across {result['total_ous']} OUs. "
        summary += f"DPDP domain coverage: {dpdp['score']}% ({dpdp['covered_domains']}/{dpdp['total']}). "
        if result["rbi_posture"]:
            rbi = result["rbi_posture"]
            summary += f"RBI domain coverage: {rbi['score']}% ({rbi['covered_domains']}/{rbi['total']}). "
        if result.get("sebi_posture"):
            sebi = result["sebi_posture"]
            summary += f"SEBI domain coverage: {sebi['score']}% ({sebi['covered_domains']}/{sebi['total']}). "
        if result.get("certin_posture"):
            certin = result["certin_posture"]
            summary += f"CERT-In domain coverage: {certin['score']}% ({certin['covered_domains']}/{certin['total']}). "
        summary += f"{len(result['recommendations'])} controls recommended."

        result["scan_metadata"] = {
            "scan_start": scan_start.isoformat(),
            "scan_end": scan_end.isoformat(),
            "region": region,
            "tool_version": __version__,
        }

        response = {"region": region, "executive_summary": summary, **result}
        sw = _get_staleness_warning()
        if sw:
            response["staleness_warning"] = sw
        return json.dumps(response, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Control Tower scan failed: {_sanitize_error(e)}. Must run from management account.", "region": region})


@mcp.tool()
def check_regulatory_updates() -> str:
    """Check for regulatory updates since the last control mapping verification.

    Performs three levels of checking:
    1. Staleness: flags frameworks where last_verified exceeds the threshold (default 30 days).
    2. Content hashing: fetches regulatory source pages and compares SHA-256 hashes
       against stored baselines to detect any content changes.
    3. New circular detection: scans RBI and SEBI circular listing pages for
       publications dated after last_verified that match compliance keywords.

    Returns:
        JSON with manifest metadata, staleness warnings, content change detection,
        new circular alerts, and regulatory source URLs.
    """
    from .domains import load_manifest
    try:
        manifest = load_manifest()
        frameworks = manifest.get("frameworks", {})
        sources = manifest.get("regulatory_sources", {})

        # Tier 1: Staleness check
        staleness = check_staleness()

        # Tier 2 + 3: Content hash monitoring + circular detection
        source_changes = monitor_source_changes()

        result: dict[str, Any] = {
            "manifest_version": manifest.get("manifest_version", "unknown"),
            "last_updated": manifest.get("last_updated", "unknown"),
            "staleness": staleness,
            "frameworks": {},
            "source_monitoring": source_changes,
            "regulatory_sources": sources,
        }

        # Build per-framework summary
        any_action_needed = False
        for fw_key, fw_data in frameworks.items():
            fw_info: dict[str, Any] = {
                "name": fw_data.get("name", ""),
                "version": fw_data.get("version", ""),
                "last_verified": fw_data.get("last_verified", ""),
                "source_url": fw_data.get("source_url", ""),
                "domain_count": len(fw_data.get("domains", {})),
                "status": "current",
            }

            # Check if stale
            if fw_key in staleness.get("stale_frameworks", []):
                fw_info["status"] = "stale"
                any_action_needed = True

            # Check if content changed
            sc = source_changes.get(fw_key, {})
            if sc.get("hash_changed"):
                fw_info["status"] = "source_content_changed"
                any_action_needed = True
            elif sc.get("hash_changed") is None:
                fw_info["content_hash_baseline"] = "not_set"

            # Check for new circulars
            new_circulars = sc.get("new_circulars", [])
            if new_circulars:
                fw_info["status"] = "new_circulars_detected"
                fw_info["new_circular_count"] = len(new_circulars)
                any_action_needed = True

            result["frameworks"][fw_key] = fw_info

        if any_action_needed:
            result["action_required"] = (
                "One or more frameworks have detected changes. Review the source_monitoring "
                "section for details. Update control_mappings.json and assessment rules if "
                "new requirements are found. Then run update_content_hashes to reset baselines."
            )
        else:
            result["action_required"] = "All frameworks appear current. No action needed."

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": _sanitize_error(e)})


@mcp.tool()
def propose_mapping_update(framework: str, regulatory_text: str, source_url: str = "",
                           circular_date: str = "") -> str:
    """Analyze regulatory text and propose updates to control_mappings.json.

    This tool is designed to be called by an LLM client after detecting new
    circulars or regulatory changes. It provides the current mappings for the
    specified framework alongside the new regulatory text, enabling the LLM
    to propose structured mapping updates.

    The tool returns the current mappings and a structured prompt. The LLM
    client should then call apply_mapping_update with the proposed changes.

    Args:
        framework: "dpdp", "rbi", or "sebi".
        regulatory_text: The new regulatory text (circular, amendment, direction) to analyze.
        source_url: URL where the regulatory text was found.
        circular_date: Publication date of the circular (YYYY-MM-DD).

    Returns:
        JSON with current mappings, analysis prompt, and expected response schema.
    """
    from .domains import load_manifest
    try:
        manifest = load_manifest()
        fw_data = manifest.get("frameworks", {}).get(framework.lower())
        if not fw_data:
            return json.dumps({"error": f"Unknown framework: {framework}. Use: dpdp, rbi, sebi"})

        # Build the analysis context
        current_domains = fw_data.get("domains", {})

        analysis_prompt = f"""Analyze the following regulatory text and determine if it requires updates to the {fw_data['name']} compliance mappings.

CURRENT MAPPINGS for {framework.upper()}:
{json.dumps(current_domains, indent=2)}

NEW REGULATORY TEXT:
{regulatory_text[:10000]}

SOURCE: {source_url}
DATE: {circular_date}

INSTRUCTIONS:
1. Read the new regulatory text carefully.
2. For each control domain, determine if the new text:
   a. Adds new requirements that need new AWS controls, Config rules, or guardrails
   b. Modifies existing requirements (stricter, relaxed, clarified)
   c. Adds entirely new domains
   d. Has no impact on this domain
3. For any changes, propose the specific updates in the schema below.
4. Be conservative — only propose changes where the regulatory text clearly mandates them.
5. Include the specific section/clause reference from the new text.

Respond with a JSON object matching this schema:
{{
  "analysis_summary": "Brief description of what changed",
  "impact_level": "none | low | medium | high",
  "affected_domains": [list of domain numbers affected],
  "proposed_changes": [
    {{
      "domain": "domain number as string",
      "change_type": "add_control | remove_control | modify_section | add_domain",
      "field": "aws_controls | config_rules | guardrails | section | name",
      "action": "add | remove | replace",
      "value": "the new value to add/replace",
      "old_value": "the old value being replaced (for replace actions)",
      "justification": "specific clause/section reference from the new text",
      "confidence": "high | medium | low"
    }}
  ],
  "new_domains": [
    {{
      "number": "next available domain number",
      "name": "Domain name",
      "section": "Section reference",
      "type": "technical | organizational",
      "aws_controls": [],
      "config_rules": [],
      "guardrails": [],
      "justification": "why this new domain is needed"
    }}
  ],
  "no_change_reason": "explanation if impact_level is none"
}}"""

        return json.dumps({
            "framework": framework,
            "framework_name": fw_data["name"],
            "current_version": fw_data.get("version", ""),
            "current_domain_count": len(current_domains),
            "current_mappings": current_domains,
            "regulatory_text_length": len(regulatory_text),
            "source_url": source_url,
            "circular_date": circular_date,
            "analysis_prompt": analysis_prompt,
            "instructions": (
                "Use the analysis_prompt above to analyze the regulatory text against current mappings. "
                "Then call apply_mapping_update with the proposed changes JSON to apply them."
            ),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": _sanitize_error(e)})


@mcp.tool()
def apply_mapping_update(framework: str, proposed_changes_json: str, source_url: str = "",
                         circular_date: str = "", auto_apply: bool = False) -> str:
    """Validate and apply proposed mapping updates to control_mappings.json.

    Takes the LLM-generated proposed changes (from propose_mapping_update analysis),
    validates them against the schema, and either saves them directly or returns
    them for human review.

    Args:
        framework: "dpdp", "rbi", or "sebi".
        proposed_changes_json: JSON string with proposed changes matching the schema
            from propose_mapping_update.
        source_url: URL of the regulatory source that triggered the update.
        circular_date: Publication date of the circular (YYYY-MM-DD).
        auto_apply: If True, apply changes directly to control_mappings.json.
            If False (default), return the changes for human review.

    Returns:
        JSON with validation results, diff preview, and application status.
    """
    from datetime import date
    from .domains import load_manifest, save_manifest

    try:
        proposed = json.loads(proposed_changes_json)
    except (json.JSONDecodeError, TypeError) as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})

    try:
        manifest = load_manifest()
    except (OSError, ValueError) as e:
        return json.dumps({"error": f"Could not load manifest: {e}"})

    fw_key = framework.lower()
    fw_data = manifest.get("frameworks", {}).get(fw_key)
    if not fw_data:
        return json.dumps({"error": f"Unknown framework: {framework}"})

    # Validate proposed changes
    impact_level = proposed.get("impact_level", "none")
    if impact_level == "none":
        return json.dumps({
            "status": "no_changes_needed",
            "reason": proposed.get("no_change_reason", "No impact detected"),
            "framework": fw_key,
        })

    changes = proposed.get("proposed_changes", [])
    new_domains = proposed.get("new_domains", [])
    validation_errors: list[str] = []
    validated_changes: list[dict] = []

    valid_fields = {"aws_controls", "config_rules", "guardrails", "section", "name", "type"}
    valid_actions = {"add", "remove", "replace"}
    valid_change_types = {"add_control", "remove_control", "modify_section", "add_domain"}

    for i, change in enumerate(changes):
        # Validate required fields
        if "domain" not in change:
            validation_errors.append(f"Change {i}: missing 'domain'")
            continue
        if change.get("domain") not in fw_data.get("domains", {}):
            validation_errors.append(f"Change {i}: domain '{change.get('domain')}' does not exist")
            continue
        if change.get("field") not in valid_fields:
            validation_errors.append(f"Change {i}: invalid field '{change.get('field')}'")
            continue
        if change.get("action") not in valid_actions:
            validation_errors.append(f"Change {i}: invalid action '{change.get('action')}'")
            continue
        if change.get("change_type") not in valid_change_types:
            validation_errors.append(f"Change {i}: invalid change_type '{change.get('change_type')}'")
            continue
        if not change.get("justification"):
            validation_errors.append(f"Change {i}: missing justification")
            continue

        validated_changes.append(change)

    # Validate new domains
    validated_new_domains: list[dict] = []
    for i, nd in enumerate(new_domains):
        if not nd.get("name"):
            validation_errors.append(f"New domain {i}: missing name")
            continue
        if not nd.get("section"):
            validation_errors.append(f"New domain {i}: missing section")
            continue
        validated_new_domains.append(nd)

    # Build diff preview
    diff_preview: list[dict] = []
    for change in validated_changes:
        dom_num = change["domain"]
        field = change["field"]
        action = change["action"]
        current_value = fw_data["domains"][dom_num].get(field, [])

        if action == "add" and isinstance(current_value, list):
            new_value = current_value + [change["value"]]
        elif action == "remove" and isinstance(current_value, list):
            new_value = [v for v in current_value if v != change.get("old_value", change["value"])]
        elif action == "replace":
            new_value = change["value"]
        else:
            new_value = change["value"]

        diff_preview.append({
            "domain": dom_num,
            "domain_name": fw_data["domains"][dom_num].get("name", ""),
            "field": field,
            "action": action,
            "before": current_value,
            "after": new_value,
            "justification": change.get("justification", ""),
            "confidence": change.get("confidence", "medium"),
        })

    result: dict[str, Any] = {
        "framework": fw_key,
        "impact_level": impact_level,
        "analysis_summary": proposed.get("analysis_summary", ""),
        "total_changes": len(validated_changes),
        "total_new_domains": len(validated_new_domains),
        "validation_errors": validation_errors,
        "diff_preview": diff_preview,
        "new_domains_preview": validated_new_domains,
    }

    if validation_errors:
        result["status"] = "validation_failed"
        result["message"] = f"{len(validation_errors)} validation errors. Fix and resubmit."
        return json.dumps(result, indent=2)

    if not auto_apply:
        result["status"] = "pending_review"
        result["message"] = (
            "Changes validated successfully. Review the diff_preview above. "
            "To apply, call apply_mapping_update again with auto_apply=True."
        )
        return json.dumps(result, indent=2)

    # Apply changes
    domains = fw_data["domains"]
    applied: list[str] = []

    for change in validated_changes:
        dom_num = change["domain"]
        field = change["field"]
        action = change["action"]
        current = domains[dom_num].get(field, [])

        if action == "add" and isinstance(current, list):
            if change["value"] not in current:
                current.append(change["value"])
                domains[dom_num][field] = current
                applied.append(f"Added '{change['value']}' to domain {dom_num}.{field}")
        elif action == "remove" and isinstance(current, list):
            target = change.get("old_value", change["value"])
            if target in current:
                current.remove(target)
                domains[dom_num][field] = current
                applied.append(f"Removed '{target}' from domain {dom_num}.{field}")
        elif action == "replace":
            old = domains[dom_num].get(field)
            domains[dom_num][field] = change["value"]
            applied.append(f"Replaced domain {dom_num}.{field}: '{old}' → '{change['value']}'")

    # Add new domains
    for nd in validated_new_domains:
        next_num = str(max(int(k) for k in domains.keys()) + 1)
        domains[next_num] = {
            "name": nd["name"],
            "section": nd["section"],
            "type": nd.get("type", "technical"),
            "aws_controls": nd.get("aws_controls", []),
            "config_rules": nd.get("config_rules", []),
            "guardrails": nd.get("guardrails", []),
        }
        applied.append(f"Added new domain {next_num}: {nd['name']}")

    # Update metadata
    today = date.today().isoformat()
    fw_data["last_verified"] = today
    if circular_date:
        fw_data["version"] = f"{fw_data.get('version', '')} + update {circular_date}"
    manifest["last_updated"] = today

    # Add update history
    if "update_history" not in manifest:
        manifest["update_history"] = []
    manifest["update_history"].append({
        "date": today,
        "framework": fw_key,
        "source_url": source_url,
        "circular_date": circular_date,
        "changes_applied": len(applied),
        "summary": proposed.get("analysis_summary", ""),
    })

    try:
        save_manifest(manifest)
    except OSError as e:
        result["status"] = "save_failed"
        result["error"] = str(e)
        return json.dumps(result, indent=2)

    result["status"] = "applied"
    result["applied_changes"] = applied
    result["last_verified_updated_to"] = today
    result["message"] = (
        f"Applied {len(applied)} changes to {fw_key} mappings. "
        f"last_verified updated to {today}. "
        "Run update_content_hashes to reset content baselines."
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def format_report(report_path: str = "", report_json: str = "", report_type: str = "auto",
                  output_format: str = "markdown") -> str:
    """Format a scan report JSON into a human-readable Markdown report.

    Accepts either a file path to a previously saved scan report JSON, or
    inline JSON. Detects report type (account scan vs Control Tower) automatically.

    Args:
        report_path: Path to a scan report JSON file (from scan_aws_account output).
        report_json: Inline JSON string of a scan report (alternative to report_path).
        report_type: "account", "control_tower", or "auto" (detect automatically).
        output_format: "markdown" or "docx". Docx generates a production-grade Word report with color coding.

    Returns:
        Formatted Markdown compliance report with executive summary, posture scores,
        per-account breakdown, gap tables, and remediation timeline.
        For docx format, returns the file path of the generated .docx file.
    """
    from .report_formatter import format_account_scan, format_control_tower_scan

    # Load report data
    data: dict[str, Any] = {}
    source = ""

    if report_path:
        try:
            safe_path = _safe_report_path(report_path)
            with open(safe_path, "r") as f:
                data = json.load(f)
            source = safe_path
        except ValueError as e:
            return json.dumps({"error": str(e)})
        except FileNotFoundError:
            return json.dumps({"error": f"File not found: {os.path.basename(report_path)}"})
        except (json.JSONDecodeError, OSError) as e:
            return json.dumps({"error": f"Failed to read report: {_sanitize_error(e)}"})
    elif report_json:
        try:
            data = json.loads(report_json)
            source = "inline"
        except (json.JSONDecodeError, TypeError) as e:
            return json.dumps({"error": f"Invalid JSON: {_sanitize_error(e)}"})
    else:
        # Try to find the latest report in the reports directory
        report_dir = _get_report_dir()
        if os.path.isdir(report_dir):
            json_files = sorted(
                [f for f in os.listdir(report_dir) if f.endswith(".json")],
                reverse=True,
            )
            if json_files:
                latest = os.path.join(report_dir, json_files[0])
                try:
                    with open(latest, "r") as f:
                        data = json.load(f)
                    source = latest
                except (json.JSONDecodeError, OSError) as e:
                    return json.dumps({"error": f"Failed to read latest report: {_sanitize_error(e)}"})
            else:
                return json.dumps({"error": "No report files found. Run scan_aws_account or scan_control_tower_tool first."})
        else:
            return json.dumps({"error": "No report_path or report_json provided, and no reports/ directory found."})

    if not data:
        return json.dumps({"error": "Empty report data."})

    # Detect report type
    if report_type == "auto":
        if "landing_zone" in data or "total_enabled_controls" in data:
            report_type = "control_tower"
        else:
            report_type = "account"

    # Generate DOCX if requested
    if output_format.lower() == "docx":
        from .docx_formatter import generate_docx
        report_dir = _get_report_dir()
        os.makedirs(report_dir, exist_ok=True)

        # For docx, we pass CT data as second arg if available
        ct_data = None
        if report_type == "control_tower":
            ct_data = data
            data_for_docx = {}  # no org data
        else:
            data_for_docx = data

        doc = generate_docx(data_for_docx if data_for_docx else data, ct_data=ct_data)
        docx_path = os.path.join(report_dir, f"compliance_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.docx")
        doc.save(docx_path)
        return json.dumps({
            "status": "success",
            "format": "docx",
            "file_path": docx_path,
            "message": f"Production-grade DOCX report saved to {docx_path}",
        })

    # Format as Markdown
    if report_type == "control_tower":
        markdown = format_control_tower_scan(data)
    else:
        markdown = format_account_scan(data)

    # Save the markdown report alongside the JSON (only within reports/ dir)
    md_path = None
    if source and source != "inline":
        try:
            candidate = source.rsplit(".", 1)[0] + ".md"
            _safe_report_path(candidate)  # validate it's within reports/
            md_path = candidate
            with open(md_path, "w") as f:
                f.write(markdown)
        except (OSError, ValueError):
            md_path = None

    return markdown


# ---- Entry point ----

def main() -> None:
    """Run the MCP server."""
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=getattr(logging, log_level, logging.INFO), format="%(levelname)s %(name)s: %(message)s")

    _log_tool_manifest()

    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
