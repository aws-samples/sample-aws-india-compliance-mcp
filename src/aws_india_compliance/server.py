"""MCP server entry point — tool and resource registration.

This is the only file that imports the MCP SDK. All business logic
lives in the other modules (assessment, parsers, aws_scanner, etc.).

Architecture: compact summary + drill-down pattern.
- scan_aws_account returns a compact summary (~2-3K tokens)
- get_compliance_gaps provides paginated access to full gap details
- Maintainer tools (regulatory updates) are CLI-only, not exposed via MCP
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
from .control_tower import assess_control_tower, scan_control_tower as _scan_ct
from .domains import DPDP_DOMAINS, RBI_DOMAINS
from .knowledge import search_live
from .parsers import parse_cloudformation, parse_drawio, parse_terraform

_logger = logging.getLogger(__name__)

# --- In-memory scan result cache (for drill-down) ---
_last_scan_result: dict[str, Any] = {}

# --- Input validation helpers ---

_VALID_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+-\d+)?$")
_VALID_AGGREGATOR_RE = re.compile(r"^[a-zA-Z0-9_-]{1,256}$")
_MAX_TOP_K = 50
_SUMMARY_GAP_CAP = 10  # Max gaps returned in scan summary


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
    """Return the reports directory path (only used when save_to_file=True).

    Priority:
    1. REPORT_DIR environment variable (explicit override).
    2. Current working directory + /reports (user's project root).
    """
    env_dir = os.environ.get("REPORT_DIR", "")
    if env_dir:
        return env_dir
    return os.path.join(os.getcwd(), "reports")


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
    home = os.path.expanduser("~")
    if home in msg:
        msg = msg.replace(home, "~")
    return msg


def _parse_json_param(value: str, name: str) -> dict | list | None:
    """Parse an optional JSON string parameter. Returns None if empty."""
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid {name} JSON: {e}")


# --- MCP Server Setup ---

_MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
try:
    _MCP_PORT = max(1, min(65535, int(os.environ.get("MCP_PORT", "8000"))))
except (ValueError, TypeError):
    _MCP_PORT = 8000

_transport = os.environ.get("MCP_TRANSPORT", "stdio")
if _transport in ("streamable-http", "sse"):
    mcp = FastMCP("aws-india-compliance", host=_MCP_HOST, port=_MCP_PORT, stateless_http=True)
else:
    mcp = FastMCP("aws-india-compliance")


# ---- User-Facing Tools (7) ----


@mcp.tool()
def scan_aws_account(
    region: str = "ap-south-1",
    is_significant_data_fiduciary: bool = False,
    is_rbi_regulated: bool = False,
    is_sebi_regulated: bool = False,
    aggregator_name: str = "",
    sebi_entity_tier: str = "",
    exceptions: str = "",
    filter_tags: str = "",
    exclude_tags: str = "",
    save_to_file: bool = False,
) -> str:
    """Scan AWS account resources and assess compliance against Indian regulatory frameworks.

    Use this when the user says: "scan my AWS account", "scan my AWS organization",
    "check my AWS compliance", or "assess my infrastructure".

    Returns a compact summary with posture scores, gap counts, and top critical findings.
    Use get_compliance_gaps to drill into specific gaps by framework, risk level, or domain.

    Args:
        region: AWS region to scan (default "ap-south-1").
        is_significant_data_fiduciary: Whether the org is an SDF under DPDP Act.
        is_rbi_regulated: Whether the org is regulated by RBI.
        is_sebi_regulated: Whether the org is regulated by SEBI.
        aggregator_name: Config Aggregator name for org-wide scan. Empty = auto-discover.
        sebi_entity_tier: SEBI entity tier ("mii", "qualified_re", "other_re").
        exceptions: JSON string of exception rules for gap suppression.
        filter_tags: JSON string of {key: value} pairs — include only matching resources.
        exclude_tags: JSON string of {key: value} pairs — exclude matching resources.
        save_to_file: If True, save full report JSON to the reports/ directory.

    Returns:
        Compact JSON summary with posture scores, gap counts, top findings, and remediation timeline.
        Call get_compliance_gaps for full gap details.
    """
    global _last_scan_result

    # Validate inputs
    try:
        region = _validate_region(region)
        aggregator_name = _validate_aggregator(aggregator_name)
        parsed_exceptions = _parse_json_param(exceptions, "exceptions")
        parsed_filter_tags = _parse_json_param(filter_tags, "filter_tags")
        parsed_exclude_tags = _parse_json_param(exclude_tags, "exclude_tags")
    except ValueError as e:
        return json.dumps({"error": str(e)})

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

        all_gaps = result["gaps"]

        # Store full results for drill-down via get_compliance_gaps
        _last_scan_result = {
            "scan_type": "account",
            "region": region,
            "aggregator": resolved_aggregator or "single-account",
            "scan_time": scan_start.isoformat(),
            "gaps": all_gaps,
            "total_components": result["total_components"],
            "suppressed_gaps": result.get("suppressed_gaps", []),
            "per_account": result.get("per_account"),
            "resource_compliance": result.get("resource_compliance"),
        }

        # Build compact summary
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

        # Gap counts by framework and risk
        gap_summary: dict[str, dict[str, int]] = {}
        for g in all_gaps:
            fw = g.get("framework", "unknown")
            risk = g.get("risk", "unknown")
            gap_summary.setdefault(fw, {}).setdefault(risk, 0)
            gap_summary[fw][risk] += 1

        # Top critical + high gaps (capped)
        priority_gaps = [g for g in all_gaps if g["risk"] in ("critical", "high")]
        top_gaps = priority_gaps[:_SUMMARY_GAP_CAP]
        # Slim down gap objects for summary
        top_gaps_slim = [
            {
                "resource": g.get("resource", ""),
                "framework": g.get("framework", ""),
                "domain": g.get("domain", ""),
                "risk": g.get("risk", ""),
                "description": g.get("description", ""),
                "remediation": g.get("remediation", ""),
            }
            for g in top_gaps
        ]

        # Remediation timeline
        critical = [g for g in all_gaps if g["risk"] == "critical"]
        high = [g for g in all_gaps if g["risk"] == "high"]
        medium = [g for g in all_gaps if g["risk"] == "medium"]
        timeline = []
        if critical:
            timeline.append({"phase": "Immediate (0-30 days)", "count": len(critical), "items": list({g["remediation"] for g in critical})[:5]})
        if high:
            timeline.append({"phase": "Short-term (30-90 days)", "count": len(high), "items": list({g["remediation"] for g in high})[:5]})
        if medium:
            timeline.append({"phase": "Medium-term (90-180 days)", "count": len(medium), "items": list({g["remediation"] for g in medium})[:5]})

        response: dict[str, Any] = {
            "executive_summary": summary,
            "region": region,
            "aggregator": resolved_aggregator or "single-account",
            "scan_metadata": {
                "scan_start": scan_start.isoformat(),
                "scan_end": scan_end.isoformat(),
                "tool_version": __version__,
            },
            "posture_scores": {
                "dpdp": result["dpdp_posture"],
                "rbi": result["rbi_posture"],
                "sebi": result.get("sebi_posture"),
                "certin": result.get("certin_posture"),
            },
            "total_resources": result["total_components"],
            "total_gaps": result["total_gaps"],
            "suppressed_count": result["suppressed_count"],
            "gap_counts_by_framework": gap_summary,
            "top_findings": top_gaps_slim,
            "remediation_timeline": timeline,
            "drill_down_hint": (
                f"Showing top {len(top_gaps_slim)} of {result['total_gaps']} gaps. "
                "Use get_compliance_gaps to see all gaps filtered by framework, risk, or domain."
            ),
        }

        # Optionally persist full report to disk
        if save_to_file:
            report_dir = _get_report_dir()
            try:
                os.makedirs(report_dir, exist_ok=True)
                full_response = {**response, "gaps": all_gaps}
                report_file = os.path.join(report_dir, f"scan_report_{region}_{scan_start.strftime('%Y%m%d_%H%M%S')}.json")
                with open(report_file, "w") as f:
                    json.dump(full_response, f, indent=2, default=str)
                response["saved_to_file"] = report_file
            except OSError as e:
                response["save_error"] = f"Could not write report file: {_sanitize_error(e)}"

        return json.dumps(response, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": _sanitize_error(e), "region": region})


@mcp.tool()
def scan_control_tower_tool(
    region: str = "ap-south-1",
    is_significant_data_fiduciary: bool = False,
    is_rbi_regulated: bool = False,
    is_sebi_regulated: bool = False,
) -> str:
    """Scan Control Tower guardrails and assess governance coverage against regulatory frameworks.

    Use this when the user says: "scan my Control Tower", "check my guardrails",
    "assess my landing zone", or "scan my AWS organization governance".

    Must be run from the management account.

    Args:
        region: AWS region where Control Tower is deployed (default "ap-south-1").
        is_significant_data_fiduciary: Whether the org is an SDF under DPDP Act.
        is_rbi_regulated: Whether the org is regulated by RBI.
        is_sebi_regulated: Whether the org is regulated by SEBI.

    Returns:
        JSON with landing zone status, posture scores, enabled controls,
        and recommended controls to enable.
    """
    try:
        region = _validate_region(region)
        ct_data = _scan_ct(region)
        scan_start = datetime.utcnow()
        result = assess_control_tower(ct_data, is_significant_data_fiduciary, is_rbi_regulated, is_sebi=is_sebi_regulated)
        scan_end = datetime.utcnow()

        dpdp = result["dpdp_posture"]
        summary = f"Control Tower: {result['total_enabled_controls']} controls enabled across {result['total_ous']} OUs. "
        summary += f"DPDP coverage: {dpdp['score']}% ({dpdp['covered_domains']}/{dpdp['total']}). "
        if result["rbi_posture"]:
            rbi = result["rbi_posture"]
            summary += f"RBI: {rbi['score']}% ({rbi['covered_domains']}/{rbi['total']}). "
        if result.get("sebi_posture"):
            sebi = result["sebi_posture"]
            summary += f"SEBI: {sebi['score']}% ({sebi['covered_domains']}/{sebi['total']}). "
        if result.get("certin_posture"):
            certin = result["certin_posture"]
            summary += f"CERT-In: {certin['score']}% ({certin['covered_domains']}/{certin['total']}). "
        summary += f"{len(result['recommendations'])} controls recommended."

        result["scan_metadata"] = {
            "scan_start": scan_start.isoformat(),
            "scan_end": scan_end.isoformat(),
            "region": region,
            "tool_version": __version__,
        }

        response = {"executive_summary": summary, "region": region, **result}
        return json.dumps(response, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Control Tower scan failed: {_sanitize_error(e)}. Must run from management account.", "region": region})


@mcp.tool()
def get_compliance_gaps(
    framework: str = "",
    risk: str = "",
    domain: str = "",
    page: int = 1,
    page_size: int = 20,
) -> str:
    """Get detailed compliance gaps from the most recent scan, with filtering and pagination.

    Call this after scan_aws_account to drill into specific gaps.
    Filters can be combined (e.g., framework="dpdp" + risk="critical").

    Args:
        framework: Filter by framework ("dpdp", "rbi", "sebi", "certin"). Empty = all.
        risk: Filter by risk level ("critical", "high", "medium", "low"). Empty = all.
        domain: Filter by control domain name or number (partial match). Empty = all.
        page: Page number (1-indexed). Default 1.
        page_size: Number of gaps per page (max 50). Default 20.

    Returns:
        JSON with filtered gaps, pagination info, and total counts.
    """
    if not _last_scan_result:
        return json.dumps({
            "error": "No scan results available. Run scan_aws_account first.",
            "hint": "Use scan_aws_account to scan your infrastructure, then call get_compliance_gaps to drill into results."
        })

    all_gaps = _last_scan_result.get("gaps", [])
    page_size = min(max(1, page_size), 50)
    page = max(1, page)

    # Apply filters
    filtered = all_gaps
    if framework:
        filtered = [g for g in filtered if g.get("framework", "").lower() == framework.lower()]
    if risk:
        filtered = [g for g in filtered if g.get("risk", "").lower() == risk.lower()]
    if domain:
        domain_lower = domain.lower()
        filtered = [g for g in filtered if domain_lower in g.get("domain", "").lower() or domain_lower in str(g.get("domain_number", ""))]

    # Paginate
    total = len(filtered)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, total_pages)
    start = (page - 1) * page_size
    end = start + page_size
    page_gaps = filtered[start:end]

    return json.dumps({
        "scan_type": _last_scan_result.get("scan_type", "account"),
        "scan_region": _last_scan_result.get("region", ""),
        "scan_time": _last_scan_result.get("scan_time", ""),
        "filters_applied": {
            "framework": framework or "all",
            "risk": risk or "all",
            "domain": domain or "all",
        },
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_gaps": total,
            "total_pages": total_pages,
            "has_more": page < total_pages,
        },
        "gaps": page_gaps,
    }, indent=2, default=str)


@mcp.tool()
def list_control_domains(framework: str = "dpdp") -> str:
    """List the control domains for a regulatory framework.

    Args:
        framework: "dpdp" (10 domains), "rbi" (7), "sebi" (6), or "certin" (4).

    Returns:
        JSON with numbered control domains.
    """
    from .domains import SEBI_DOMAINS, CERTIN_DOMAINS
    frameworks = {
        "dpdp": DPDP_DOMAINS,
        "rbi": RBI_DOMAINS,
        "sebi": SEBI_DOMAINS,
        "certin": CERTIN_DOMAINS,
    }
    domains = frameworks.get(framework.lower(), DPDP_DOMAINS)
    return json.dumps({"framework": framework, "domains": {str(k): v for k, v in domains.items()}}, indent=2)


@mcp.tool()
def search_regulatory_text(query: str, framework: str = "", top_k: int = 5) -> str:
    """Search DPDP Act, RBI Master Direction, and SEBI CSCRF regulatory text.

    Searches live authoritative sources first with automatic fallback to
    bundled control_mappings.json when sources are unreachable.

    Args:
        query: Search query (e.g., "breach notification", "data retention")
        framework: Filter by "dpdp", "rbi", or "sebi". Empty = search all.
        top_k: Number of results to return (default 5).

    Returns:
        JSON with matching regulatory text chunks, sections, and relevance scores.
    """
    results = search_live(query, framework, min(top_k, _MAX_TOP_K))
    return json.dumps({"results": results, "count": len(results)}, indent=2)


@mcp.tool()
def generate_conformance_pack(
    framework: str = "dpdp",
    include_domains: str = "",
    exclude_domains: str = "",
    pack_name_prefix: str = "",
) -> str:
    """Generate an AWS Config conformance pack YAML for a compliance framework.

    Creates a deployable template with AWS-managed Config rules mapped to
    regulatory control domains.

    Args:
        framework: One of "dpdp", "rbi", "sebi", "certin". Default "dpdp".
        include_domains: Comma-separated domain numbers to include (empty = all).
        exclude_domains: Comma-separated domain numbers to exclude (empty = none).
        pack_name_prefix: Optional prefix for the conformance pack name.

    Returns:
        JSON with yaml_content, pack_name, rule_count, and deployment command.
    """
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

    from .conformance_pack import generate_conformance_pack as _gen
    result = _gen(
        framework=framework,
        include_domains=parsed_include,
        exclude_domains=parsed_exclude,
        pack_name_prefix=pack_name_prefix,
    )

    if "error" in result:
        return json.dumps(result)

    result["deployment_command"] = (
        f"aws configservice put-conformance-pack "
        f"--conformance-pack-name {result['pack_name']} "
        f"--template-body file://<filename>.yaml"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def format_report(
    report_json: str = "",
    report_path: str = "",
    output_format: str = "docx",
    save_to_file: bool = True,
) -> str:
    """Generate a production-grade DOCX compliance report from scan results.

    Use this when the user wants a downloadable Word document for sharing
    with auditors or management.

    Args:
        report_json: Inline JSON string of scan results (from scan_aws_account).
        report_path: Path to a previously saved scan report JSON file.
        output_format: "docx" (default) or "markdown".
        save_to_file: If True (default), save to reports/ directory.

    Returns:
        File path of the generated report, or markdown content inline.
    """
    from .report_formatter import format_account_scan, format_control_tower_scan

    # Load report data
    data: dict[str, Any] = {}

    if report_json:
        try:
            data = json.loads(report_json)
        except (json.JSONDecodeError, TypeError) as e:
            return json.dumps({"error": f"Invalid JSON: {_sanitize_error(e)}"})
    elif report_path:
        try:
            safe_path = _safe_report_path(report_path)
            with open(safe_path, "r") as f:
                data = json.load(f)
        except ValueError as e:
            return json.dumps({"error": str(e)})
        except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
            return json.dumps({"error": f"Failed to read report: {_sanitize_error(e)}"})
    elif _last_scan_result and _last_scan_result.get("gaps"):
        # Use cached scan result
        data = _last_scan_result
    else:
        return json.dumps({"error": "No report data provided. Run scan_aws_account first, or pass report_json/report_path."})

    if not data:
        return json.dumps({"error": "Empty report data."})

    # Detect report type
    is_ct = "landing_zone" in data or "total_enabled_controls" in data

    if output_format.lower() == "docx":
        from .docx_formatter import generate_docx
        import base64
        import io

        ct_data = data if is_ct else None
        scan_data = {} if is_ct else data

        doc = generate_docx(scan_data if scan_data else data, ct_data=ct_data)

        if save_to_file:
            report_dir = _get_report_dir()
            os.makedirs(report_dir, exist_ok=True)
            docx_path = os.path.join(report_dir, f"compliance_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.docx")
            doc.save(docx_path)
            return json.dumps({
                "status": "success",
                "format": "docx",
                "file_path": docx_path,
                "message": f"DOCX report saved to {docx_path}",
            })
        else:
            buf = io.BytesIO()
            doc.save(buf)
            b64 = base64.b64encode(buf.getvalue()).decode("ascii")
            return json.dumps({
                "status": "success",
                "format": "docx",
                "content_base64": b64,
                "filename": f"compliance_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.docx",
            })

    # Markdown format
    if is_ct:
        markdown = format_control_tower_scan(data)
    else:
        markdown = format_account_scan(data)

    if save_to_file:
        report_dir = _get_report_dir()
        os.makedirs(report_dir, exist_ok=True)
        md_path = os.path.join(report_dir, f"compliance_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md")
        try:
            with open(md_path, "w") as f:
                f.write(markdown)
            return json.dumps({"status": "success", "format": "markdown", "file_path": md_path})
        except OSError as e:
            return json.dumps({"status": "partial", "content": markdown, "save_error": _sanitize_error(e)})

    return markdown


# ---- Entry point ----

def main() -> None:
    """Run the MCP server."""
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=getattr(logging, log_level, logging.INFO), format="%(levelname)s %(name)s: %(message)s")

    _logger.info("aws-india-compliance v%s — 7 tools exposed", __version__)

    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
