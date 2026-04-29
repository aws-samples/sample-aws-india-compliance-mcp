"""MCP server entry point — tool and resource registration.

This is the only file that imports the MCP SDK. All business logic
lives in the other modules (assessment, parsers, aws_scanner, etc.).
"""

from __future__ import annotations

import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import __version__
from .assessment import assess
from .aws_scanner import scan_via_config
from .control_tower import assess_control_tower, scan_control_tower
from .domains import DPDP_DOMAINS, RBI_DOMAINS
from .knowledge import search_live
from .parsers import parse_cloudformation, parse_drawio, parse_terraform

_MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
_MCP_PORT = int(os.environ.get("MCP_PORT", "8000"))

mcp = FastMCP("aws-india-compliance", host=_MCP_HOST, port=_MCP_PORT, stateless_http=True)


# ---- Tools ----

@mcp.tool()
def search_regulatory_text(query: str, framework: str = "", top_k: int = 5) -> str:
    """Search DPDP Act, DPDP Rules, and RBI Master Direction text.

    Args:
        query: Search query (e.g., "breach notification", "data retention", "cyber security")
        framework: Filter by "dpdp" or "rbi". Empty = search all.
        top_k: Number of results to return (default 5).

    Returns:
        JSON with matching regulatory text chunks, sections, and relevance scores.
    """
    results = search_live(query, framework, top_k)
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
        return json.dumps({"error": str(e)})


@mcp.tool()
def assess_compliance(components_json: str, is_significant_data_fiduciary: bool = False,
                      is_rbi_regulated: bool = False) -> str:
    """Assess infrastructure components against DPDP and RBI control domains.

    Args:
        components_json: JSON string of components (from parse_architecture output).
        is_significant_data_fiduciary: Whether the org is an SDF under DPDP Act.
        is_rbi_regulated: Whether the org is regulated by RBI.

    Returns:
        JSON with compliance gaps, posture scores, and remediation recommendations.
    """
    try:
        data = json.loads(components_json)
        components = data if isinstance(data, list) else data.get("components", [])
        return json.dumps(assess(components, is_significant_data_fiduciary, is_rbi_regulated), indent=2)
    except (json.JSONDecodeError, TypeError) as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})


@mcp.tool()
def generate_report(components_json: str, is_significant_data_fiduciary: bool = False,
                    is_rbi_regulated: bool = False) -> str:
    """Generate a full compliance report with executive summary and remediation timeline.

    Args:
        components_json: JSON string of components (from parse_architecture output).
        is_significant_data_fiduciary: Whether the org is an SDF under DPDP Act.
        is_rbi_regulated: Whether the org is regulated by RBI.

    Returns:
        JSON compliance report with posture scores, gaps, and phased remediation.
    """
    try:
        data = json.loads(components_json)
        components = data if isinstance(data, list) else data.get("components", [])
        result = assess(components, is_significant_data_fiduciary, is_rbi_regulated)

        dpdp = result["dpdp_posture"]
        summary = f"Assessed {result['total_components']} components. "
        summary += f"DPDP compliance: {dpdp['score']}% ({dpdp['satisfied']}/{dpdp['total']} domains). "
        if result["rbi_posture"]:
            rbi = result["rbi_posture"]
            summary += f"RBI compliance: {rbi['score']}% ({rbi['satisfied']}/{rbi['total']} domains). "
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

        return json.dumps({"executive_summary": summary, **result, "remediation_timeline": timeline}, indent=2)
    except (json.JSONDecodeError, TypeError) as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})


@mcp.tool()
def list_control_domains(framework: str = "dpdp") -> str:
    """List the control domains for DPDP Act or RBI Master Direction.

    Args:
        framework: "dpdp" for DPDP Act domains, "rbi" for RBI Master Direction domains.

    Returns:
        JSON with numbered control domains.
    """
    domains = DPDP_DOMAINS if framework.lower() == "dpdp" else RBI_DOMAINS
    return json.dumps({"framework": framework, "domains": {str(k): v for k, v in domains.items()}}, indent=2)


@mcp.tool()
def scan_aws_account(region: str = "ap-south-1", is_significant_data_fiduciary: bool = False,
                     is_rbi_regulated: bool = False, aggregator_name: str = "") -> str:
    """Scan an AWS account's resources via AWS Config and assess compliance against DPDP and RBI.

    Uses AWS Config Advanced Query to pull all resource configurations in a single fast query.
    Requires AWS Config recorder to be enabled. Uses caller's AWS credentials.
    For org-wide scan, provide a Config Aggregator name.

    Args:
        region: AWS region to scan (default "ap-south-1").
        is_significant_data_fiduciary: Whether the org is an SDF under DPDP Act.
        is_rbi_regulated: Whether the org is regulated by RBI.
        aggregator_name: Config Aggregator name for org-wide scan. Empty = single account.

    Returns:
        JSON with discovered resources, compliance gaps, posture scores, and remediation.
    """
    try:
        components = scan_via_config(region, aggregator_name)
        if not components:
            return json.dumps({"error": "No resources found. Ensure AWS Config recorder is enabled.", "region": region})

        result = assess(components, is_significant_data_fiduciary, is_rbi_regulated)
        dpdp = result["dpdp_posture"]
        summary = f"Scanned {len(components)} resources in {region}. "
        summary += f"DPDP: {dpdp['score']}% ({dpdp['satisfied']}/{dpdp['total']}). "
        if result["rbi_posture"]:
            rbi = result["rbi_posture"]
            summary += f"RBI: {rbi['score']}% ({rbi['satisfied']}/{rbi['total']}). "
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

        return json.dumps({
            "region": region, "aggregator": aggregator_name or "single-account",
            "executive_summary": summary,
            "discovered_resources": [{"name": c["name"], "type": c["type"], "category": c["category"],
                                       "region": c.get("region", ""), "account": c.get("account_id", "")} for c in components],
            **result, "remediation_timeline": timeline,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "region": region})


@mcp.tool()
def scan_control_tower_tool(region: str = "ap-south-1", is_significant_data_fiduciary: bool = False,
                            is_rbi_regulated: bool = False) -> str:
    """Scan Control Tower configuration and assess governance controls against DPDP and RBI.

    Must be run from the management account. Discovers landing zone config,
    enabled controls per OU, and recommends missing controls based on DPDP/RBI requirements.

    Args:
        region: AWS region where Control Tower is deployed (default "ap-south-1").
        is_significant_data_fiduciary: Whether the org is an SDF under DPDP Act.
        is_rbi_regulated: Whether the org is regulated by RBI.

    Returns:
        JSON with landing zone status, enabled controls, compliance gaps,
        and recommended controls to enable for DPDP/RBI compliance.
    """
    try:
        ct_data = scan_control_tower(region)
        result = assess_control_tower(ct_data, is_significant_data_fiduciary, is_rbi_regulated)
        dpdp = result["dpdp_posture"]
        summary = f"Control Tower: {result['total_enabled_controls']} controls enabled across {result['total_ous']} OUs. "
        summary += f"DPDP domain coverage: {dpdp['score']}% ({dpdp['covered_domains']}/{dpdp['total']}). "
        if result["rbi_posture"]:
            rbi = result["rbi_posture"]
            summary += f"RBI domain coverage: {rbi['score']}% ({rbi['covered_domains']}/{rbi['total']}). "
        summary += f"{len(result['recommendations'])} controls recommended."
        return json.dumps({"region": region, "executive_summary": summary, **result}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Control Tower scan failed: {e}. Must run from management account.", "region": region})


# ---- Entry point ----

def main() -> None:
    """Run the MCP server."""
    import logging
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=getattr(logging, log_level, logging.INFO), format="%(levelname)s %(name)s: %(message)s")

    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
