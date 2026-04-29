"""DPDP Act and RBI Master Direction control domain definitions.

These are the official control domains used in all compliance mappings.
Do not abbreviate, rename, or reorder.
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

ALLOWED_SOURCE_DOMAINS: set[str] = {
    "rbi.org.in",
    "meity.gov.in",
    "egazette.gov.in",
    "dpdpact.in",
}
