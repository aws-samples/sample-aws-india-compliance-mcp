"""Report formatter — converts scan JSON into human-readable Markdown.

Handles both AWS account/org scan results and Control Tower scan results.
Produces a structured Markdown report with executive summary, posture
scores, per-account breakdown, gap tables, and remediation timeline.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


def format_account_scan(data: dict[str, Any]) -> str:
    """Format an AWS account/org scan result as Markdown."""
    lines: list[str] = []

    # Header
    region = data.get("region", "unknown")
    aggregator = data.get("aggregator", "single-account")
    scan_meta = data.get("scan_metadata", {})
    scan_time = scan_meta.get("scan_start", "unknown")
    version = scan_meta.get("tool_version", "unknown")

    lines.append(f"# AWS India Compliance Report")
    lines.append("")
    lines.append(f"**Region:** {region}  ")
    lines.append(f"**Scope:** {aggregator}  ")
    lines.append(f"**Scan Time:** {scan_time}  ")
    lines.append(f"**Tool Version:** {version}  ")
    lines.append(f"**Generated:** {datetime.utcnow().isoformat()}Z")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(data.get("executive_summary", "No summary available."))
    lines.append("")

    # Posture Scores
    lines.append("## Compliance Posture")
    lines.append("")
    lines.append("| Framework | Score | Satisfied | Total | Status |")
    lines.append("|---|---|---|---|---|")

    for fw_key, fw_label in [("dpdp_posture", "DPDP Act 2023"), ("rbi_posture", "RBI Master Direction"),
                              ("sebi_posture", "SEBI CSCRF"), ("certin_posture", "CERT-In Directions")]:
        posture = data.get(fw_key)
        if posture:
            score = posture.get("score", 0)
            satisfied = posture.get("satisfied", posture.get("covered_domains", 0))
            total = posture.get("total", 0)
            status = "🟢" if score >= 80 else "🟡" if score >= 50 else "🔴"
            lines.append(f"| {fw_label} | {score}% | {satisfied} | {total} | {status} |")

    lines.append("")
    lines.append(f"**Total Resources Scanned:** {data.get('total_components', 0)}  ")
    lines.append(f"**Total Gaps Found:** {data.get('total_gaps', 0)}  ")
    lines.append(f"**Gaps Suppressed:** {data.get('suppressed_count', 0)}")
    lines.append("")

    # Confidence Distribution
    conf = data.get("confidence_distribution", {})
    if conf:
        lines.append("## Confidence Distribution")
        lines.append("")
        lines.append("| Level | Count | Meaning |")
        lines.append("|---|---|---|")
        lines.append(f"| 🟢 High | {conf.get('high', 0)} | Direct technical check — verifiable from AWS config |")
        lines.append(f"| 🟡 Medium | {conf.get('medium', 0)} | Interpretive mapping — regulatory requirement to AWS control |")
        lines.append(f"| 🔴 Low | {conf.get('low', 0)} | Organizational requirement — infrastructure proxy only |")
        lines.append("")

    # Gap Summary by Framework
    gap_summary = data.get("gap_summary_by_framework", {})
    if gap_summary:
        lines.append("## Gap Summary by Framework")
        lines.append("")
        lines.append("| Framework | Critical | High | Medium | Low | Total |")
        lines.append("|---|---|---|---|---|---|")
        for fw, risks in sorted(gap_summary.items()):
            c = risks.get("critical", 0)
            h = risks.get("high", 0)
            m = risks.get("medium", 0)
            lo = risks.get("low", 0)
            lines.append(f"| {fw.upper()} | {c} | {h} | {m} | {lo} | {c+h+m+lo} |")
        lines.append("")

    # Resource Compliance
    rc = data.get("resource_compliance", {})
    if rc:
        lines.append("## Resource-Level Compliance")
        lines.append("")
        lines.append("| Domain | Checked | Passed | Failed | Pass Rate |")
        lines.append("|---|---|---|---|---|")
        for domain_key in sorted(rc.keys()):
            d = rc[domain_key]
            pct = d.get("pct", 0)
            status = "🟢" if pct >= 80 else "🟡" if pct >= 50 else "🔴"
            lines.append(f"| {domain_key} | {d['checked']} | {d['passed']} | {d['failed']} | {status} {pct}% |")
        lines.append("")

    # Per-Account Breakdown
    pa = data.get("per_account", {})
    if pa:
        lines.append("## Per-Account Breakdown")
        lines.append("")
        lines.append("| Account ID | Gaps | DPDP | RBI | SEBI |")
        lines.append("|---|---|---|---|---|")
        for acct in sorted(pa.keys()):
            ad = pa[acct]
            dpdp_s = ad.get("dpdp_posture", {}).get("score", "n/a")
            rbi_s = ad.get("rbi_posture", {}).get("score", "n/a")
            sebi_s = ad.get("sebi_posture", {}).get("score", "n/a")
            lines.append(f"| `{acct}` | {ad['gap_count']} | {dpdp_s}% | {rbi_s}% | {sebi_s}% |")
        lines.append("")

    # Critical and High Gaps
    gaps = data.get("gaps", [])
    critical_gaps = [g for g in gaps if g.get("risk") == "critical"]
    high_gaps = [g for g in gaps if g.get("risk") == "high"]

    if critical_gaps:
        lines.append("## Critical Gaps")
        lines.append("")
        _format_gap_table(lines, critical_gaps)

    if high_gaps:
        lines.append("## High-Risk Gaps")
        lines.append("")
        _format_gap_table(lines, high_gaps[:50])
        if len(high_gaps) > 50:
            lines.append(f"*... and {len(high_gaps) - 50} more high-risk gaps (see full report JSON)*")
            lines.append("")

    # Medium and Low summary (counts only)
    medium_gaps = [g for g in gaps if g.get("risk") == "medium"]
    low_gaps = [g for g in gaps if g.get("risk") == "low"]
    if medium_gaps or low_gaps:
        lines.append("## Medium & Low Risk Summary")
        lines.append("")
        if medium_gaps:
            lines.append(f"- **Medium risk:** {len(medium_gaps)} gaps")
        if low_gaps:
            lines.append(f"- **Low risk:** {len(low_gaps)} gaps")
        lines.append("")

    # Suppressed Gaps
    suppressed = data.get("suppressed_gaps", [])
    if suppressed:
        lines.append("## Suppressed Gaps")
        lines.append("")
        lines.append("| Component | Framework | Gap | Suppression Reason |")
        lines.append("|---|---|---|---|")
        for s in suppressed[:20]:
            comp = s.get("component", "")
            fw = s.get("framework", "")
            gap_desc = s.get("gap", "")[:80]
            reason = s.get("suppression_reason", "")
            lines.append(f"| {comp} | {fw} | {gap_desc} | {reason} |")
        if len(suppressed) > 20:
            lines.append(f"*... and {len(suppressed) - 20} more suppressed*")
        lines.append("")

    # Remediation Timeline
    timeline = data.get("remediation_timeline", [])
    if timeline:
        lines.append("## Remediation Timeline")
        lines.append("")
        for phase in timeline:
            lines.append(f"### {phase['phase']}")
            lines.append("")
            for item in phase.get("items", []):
                lines.append(f"- {item}")
            lines.append("")

    # Staleness Warning
    sw = data.get("staleness_warning")
    if sw:
        lines.append("## ⚠️ Mapping Staleness Warning")
        lines.append("")
        lines.append(f"Stale frameworks: {sw.get('stale_frameworks', [])}")
        lines.append(f"Action: {sw.get('action', '')}")
        lines.append("")

    return "\n".join(lines)


def format_control_tower_scan(data: dict[str, Any]) -> str:
    """Format a Control Tower scan result as Markdown."""
    lines: list[str] = []

    region = data.get("region", "unknown")
    scan_meta = data.get("scan_metadata", {})
    scan_time = scan_meta.get("scan_start", "unknown")
    version = scan_meta.get("tool_version", "unknown")

    lines.append("# Control Tower Compliance Report")
    lines.append("")
    lines.append(f"**Region:** {region}  ")
    lines.append(f"**Scan Time:** {scan_time}  ")
    lines.append(f"**Tool Version:** {version}  ")
    lines.append(f"**Generated:** {datetime.utcnow().isoformat()}Z")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(data.get("executive_summary", "No summary available."))
    lines.append("")

    # Landing Zone
    lz = data.get("landing_zone", {})
    if lz:
        lines.append("## Landing Zone")
        lines.append("")
        lines.append(f"- **Status:** {lz.get('status', 'unknown')}")
        lines.append(f"- **Version:** {lz.get('version', 'unknown')}")
        lines.append(f"- **Drift:** {lz.get('drift_status', 'unknown')}")
        lines.append("")

    # Posture Scores
    lines.append("## Compliance Domain Coverage")
    lines.append("")
    lines.append("| Framework | Coverage | Covered | Total | Status |")
    lines.append("|---|---|---|---|---|")

    for fw_key, fw_label in [("dpdp_posture", "DPDP Act 2023"), ("rbi_posture", "RBI Master Direction"),
                              ("sebi_posture", "SEBI CSCRF"), ("certin_posture", "CERT-In Directions")]:
        posture = data.get(fw_key)
        if posture:
            score = posture.get("score", 0)
            covered = posture.get("covered_domains", 0)
            total = posture.get("total", 0)
            status = "🟢" if score >= 80 else "🟡" if score >= 50 else "🔴"
            lines.append(f"| {fw_label} | {score}% | {covered} | {total} | {status} |")
    lines.append("")

    # Per-OU Breakdown
    per_ou = data.get("per_ou", {})
    if per_ou:
        lines.append("## Per-OU Breakdown")
        lines.append("")
        lines.append("| OU | Controls | DPDP | RBI | SEBI | CERT-In |")
        lines.append("|---|---|---|---|---|---|")
        for ou_name, od in sorted(per_ou.items()):
            lines.append(f"| {ou_name} | {od.get('enabled_controls', 0)} | "
                         f"{od.get('dpdp_domains_covered', 0)} | {od.get('rbi_domains_covered', 0)} | "
                         f"{od.get('sebi_domains_covered', 0)} | {od.get('certin_domains_covered', 0)} |")
        lines.append("")

    # Gaps
    gaps = data.get("gaps", [])
    if gaps:
        lines.append("## Compliance Gaps")
        lines.append("")
        lines.append("| Framework | Domain | Gap | Missing Controls | Confidence |")
        lines.append("|---|---|---|---|---|")
        for g in gaps:
            fw = g.get("framework", "").upper()
            domain = g.get("domain_name", "")
            gap_desc = g.get("gap", "")
            missing = ", ".join(g.get("missing_controls", [])[:3])
            if len(g.get("missing_controls", [])) > 3:
                missing += f" +{len(g['missing_controls']) - 3} more"
            conf = g.get("confidence", "")
            lines.append(f"| {fw} | {domain} | {gap_desc} | {missing} | {conf} |")
        lines.append("")

    # Recommendations
    recs = data.get("recommendations", [])
    if recs:
        lines.append("## Recommended Controls to Enable")
        lines.append("")
        lines.append("| Priority | Control ID | Description | Framework | Domain |")
        lines.append("|---|---|---|---|---|")
        for r in recs:
            prio = "🔴" if r.get("priority") == "high" else "🟡"
            lines.append(f"| {prio} {r.get('priority', '')} | `{r.get('control_id', '')}` | "
                         f"{r.get('description', '')} | {r.get('framework', '').upper()} | {r.get('domain_name', '')} |")
        lines.append("")

    return "\n".join(lines)


def _format_gap_table(lines: list[str], gaps: list[dict]) -> None:
    """Append a gap detail table to lines."""
    lines.append("| Component | Framework | Domain | Gap | Confidence | Reference |")
    lines.append("|---|---|---|---|---|---|")
    for g in gaps:
        comp = g.get("component", "")[:40]
        fw = g.get("framework", "").upper()
        domain = g.get("domain_name", "")[:30]
        gap_desc = g.get("gap", "")[:60]
        conf = g.get("confidence", "")
        ref = g.get("reference", "")[:30]
        lines.append(f"| {comp} | {fw} | {domain} | {gap_desc} | {conf} | {ref} |")
    lines.append("")
