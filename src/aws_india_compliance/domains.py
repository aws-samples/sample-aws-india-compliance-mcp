"""Control domain definitions and manifest utilities.

This module provides the public API for accessing framework domain
definitions. It now delegates to framework_registry for the actual
data (loaded from YAML files), while maintaining the same module-level
dict constants for backward compatibility with existing code.

The DPDP_DOMAINS, RBI_DOMAINS, SEBI_DOMAINS, and CERTIN_DOMAINS dicts
are still importable and work exactly as before. They are populated
from the framework YAML files at import time.
"""

from __future__ import annotations

import json
import os
from datetime import date, datetime
from typing import Any

from . import framework_registry

# Staleness threshold in days, configurable via env var
STALENESS_THRESHOLD_DAYS: int = int(os.environ.get("STALENESS_THRESHOLD_DAYS", "30"))

# Public domain dicts populated from the registry.
# These maintain the same API as before so that all existing imports
# (from .domains import DPDP_DOMAINS) continue to work.
DPDP_DOMAINS: dict[int, str] = framework_registry.get_domains("dpdp")
RBI_DOMAINS: dict[int, str] = framework_registry.get_domains("rbi")
SEBI_DOMAINS: dict[int, str] = framework_registry.get_domains("sebi")
CERTIN_DOMAINS: dict[int, str] = framework_registry.get_domains("certin")

# Source domain allowlist, now populated from all registered frameworks.
ALLOWED_SOURCE_DOMAINS: set[str] = framework_registry.get_source_domains()


def get_manifest_path() -> str:
    """Return the path to the control_mappings.json manifest."""
    return os.path.join(os.path.dirname(__file__), "control_mappings.json")


def load_manifest() -> dict:
    """Load and return the control mappings manifest."""
    with open(get_manifest_path(), "r", encoding="utf-8") as f:
        return json.load(f)


def save_manifest(manifest: dict) -> None:
    """Write the control mappings manifest back to disk."""
    with open(get_manifest_path(), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def check_staleness() -> dict[str, Any]:
    """Check each framework's last_verified date against the staleness threshold.

    Reads last_verified from the framework registry (YAML source of truth).

    Returns a dict with:
        stale_frameworks: list of framework keys that are stale
        warnings: list of human-readable warning strings
        threshold_days: the configured threshold
    """
    today = date.today()
    stale: list[str] = []
    warnings: list[str] = []

    all_frameworks = framework_registry.get_all()
    if not all_frameworks:
        return {
            "stale_frameworks": [],
            "warnings": ["Could not load any frameworks"],
            "threshold_days": STALENESS_THRESHOLD_DAYS,
        }

    for fw_key, fw_data in all_frameworks.items():
        last_verified_str = fw_data.get("last_verified", "")
        name = fw_data.get("name", fw_key)
        source_url = fw_data.get("source_url", "source")

        if not last_verified_str:
            stale.append(fw_key)
            warnings.append(f"{name}: no last_verified date set")
            continue

        try:
            last_verified = datetime.strptime(last_verified_str, "%Y-%m-%d").date()
            age_days = (today - last_verified).days
            if age_days > STALENESS_THRESHOLD_DAYS:
                stale.append(fw_key)
                warnings.append(
                    f"{name}: mappings last verified {age_days} days ago "
                    f"({last_verified_str}), threshold is {STALENESS_THRESHOLD_DAYS} days. "
                    f"Review {source_url} for updates."
                )
        except ValueError:
            stale.append(fw_key)
            warnings.append(f"{name}: invalid last_verified date '{last_verified_str}'")

    return {
        "stale_frameworks": stale,
        "warnings": warnings,
        "threshold_days": STALENESS_THRESHOLD_DAYS,
    }
