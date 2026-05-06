"""DPDP Act, RBI Master Direction, and SEBI CSCRF control domain definitions.

These are the official control domains used in all compliance mappings.
Do not abbreviate, rename, or reorder.

Versioned control mappings with AWS control references are in control_mappings.json.
"""

from __future__ import annotations

import os
from datetime import date, datetime
from typing import Any

# Staleness threshold in days — configurable via env var
STALENESS_THRESHOLD_DAYS: int = int(os.environ.get("STALENESS_THRESHOLD_DAYS", "30"))

DPDP_DOMAINS: dict[int, str] = {
    1: "Lawful Processing and Consent Management",
    2: "Data Minimization",
    3: "Privacy Notices",
    4: "Data Principal Rights",
    5: "Breach Notification",
    6: "Reasonable Security Safeguards",
    7: "Data Retention Limits",
    8: "Cross-Border Data Transfer",
    9: "Children's Data Protection",
    10: "Significant Data Fiduciary Obligations",
}

RBI_DOMAINS: dict[int, str] = {
    1: "IT Governance and Oversight",
    2: "IT Infrastructure and Service Management",
    3: "IT Risk Management",
    4: "Information Security",
    5: "Cyber Security",
    6: "Business Continuity and Disaster Recovery",
    7: "Information Systems Audit",
}

SEBI_DOMAINS: dict[int, str] = {
    1: "Cyber Governance",
    2: "Cyber Risk Identification",
    3: "Cyber Protection",
    4: "Cyber Detection",
    5: "Cyber Response",
    6: "Cyber Recovery",
}

CERTIN_DOMAINS: dict[int, str] = {
    1: "Incident Reporting Readiness",
    2: "Log Retention (180 days)",
    3: "NTP Synchronization",
    4: "Reportable Incident Awareness",
    5: "DDoS and Bot Protection",
    6: "Network Security and DNS Protection",
    7: "Endpoint and Malware Protection",
    8: "Data Leakage Prevention",
}

ALLOWED_SOURCE_DOMAINS: set[str] = {
    "rbi.org.in",
    "meity.gov.in",
    "egazette.gov.in",
    "dpdpact.in",
    "sebi.gov.in",
    "cert-in.org.in",
}


def get_manifest_path() -> str:
    """Return the path to the control_mappings.json manifest."""
    import os
    return os.path.join(os.path.dirname(__file__), "control_mappings.json")


def load_manifest() -> dict:
    """Load and return the control mappings manifest."""
    import json
    with open(get_manifest_path(), "r") as f:
        return json.load(f)


def save_manifest(manifest: dict) -> None:
    """Write the control mappings manifest back to disk."""
    import json
    with open(get_manifest_path(), "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def check_staleness() -> dict[str, Any]:
    """Check each framework's last_verified date against the staleness threshold.

    Returns a dict with:
        stale_frameworks: list of framework keys that are stale
        warnings: list of human-readable warning strings
        threshold_days: the configured threshold
    """
    try:
        manifest = load_manifest()
    except (OSError, ValueError):
        return {"stale_frameworks": [], "warnings": ["Could not load manifest"], "threshold_days": STALENESS_THRESHOLD_DAYS}

    today = date.today()
    stale: list[str] = []
    warnings: list[str] = []

    for fw_key, fw_data in manifest.get("frameworks", {}).items():
        last_verified_str = fw_data.get("last_verified", "")
        if not last_verified_str:
            stale.append(fw_key)
            warnings.append(f"{fw_data.get('name', fw_key)}: no last_verified date set")
            continue
        try:
            last_verified = datetime.strptime(last_verified_str, "%Y-%m-%d").date()
            age_days = (today - last_verified).days
            if age_days > STALENESS_THRESHOLD_DAYS:
                stale.append(fw_key)
                warnings.append(
                    f"{fw_data.get('name', fw_key)}: mappings last verified {age_days} days ago "
                    f"({last_verified_str}), threshold is {STALENESS_THRESHOLD_DAYS} days. "
                    f"Review {fw_data.get('source_url', 'source')} for updates."
                )
        except ValueError:
            stale.append(fw_key)
            warnings.append(f"{fw_data.get('name', fw_key)}: invalid last_verified date '{last_verified_str}'")

    return {"stale_frameworks": stale, "warnings": warnings, "threshold_days": STALENESS_THRESHOLD_DAYS}
