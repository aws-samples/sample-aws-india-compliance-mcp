"""DPDP Act, RBI Master Direction, and SEBI CSCRF control domain definitions.

These are the official control domains used in all compliance mappings.
Do not abbreviate, rename, or reorder.

Versioned control mappings with AWS control references are in control_mappings.json.
"""

from __future__ import annotations

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
