"""Auto-discovers and loads compliance framework definitions from YAML files.

This module is the single entry point for all framework metadata at runtime.
It scans the frameworks/ directory for .yaml files (excluding _schema.yaml),
loads them, and provides accessor functions used by assessment, knowledge,
conformance_pack, control_tower, and server modules.

Adding a new framework is as simple as dropping a YAML file into the
frameworks/ directory. No other code changes are needed for discovery.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

import yaml

_logger = logging.getLogger(__name__)

# Cached registry of all loaded frameworks, keyed by framework id.
_FRAMEWORKS: dict[str, dict[str, Any]] = {}
_LOADED: bool = False

# Validation patterns
_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,30}$")
_REQUIRED_TOP_LEVEL = {"id", "name", "version", "source_url"}
_REQUIRED_DOMAIN_FIELDS = {"name", "section", "type"}
_VALID_DOMAIN_TYPES = {"organizational", "technical"}
_VALID_ACTIVATIONS = {"always", "opt_in"}


def _get_frameworks_dir() -> Path:
    """Return the path to the frameworks/ directory bundled with this package."""
    return Path(__file__).parent / "frameworks"


def _validate_framework(data: dict[str, Any], filepath: str) -> list[str]:
    """Validate a loaded framework dict against the expected schema.

    Returns a list of validation error strings. Empty list means valid.
    """
    errors: list[str] = []

    # Check required top-level fields
    for field in _REQUIRED_TOP_LEVEL:
        if field not in data or not data[field]:
            errors.append(f"Missing required field: {field}")

    # Validate id format
    fw_id = data.get("id", "")
    if fw_id and not _ID_PATTERN.match(fw_id):
        errors.append(
            f"Invalid id format: '{fw_id}'. Must be lowercase letters, digits, "
            f"and underscores, starting with a letter, 2 to 31 characters."
        )

    # Validate activation
    activation = data.get("activation", "opt_in")
    if activation not in _VALID_ACTIVATIONS:
        errors.append(f"Invalid activation: '{activation}'. Must be 'always' or 'opt_in'.")

    # Validate domains
    domains = data.get("domains", {})
    if not domains:
        errors.append("At least one domain is required.")
    else:
        for dom_key, dom_data in domains.items():
            if not isinstance(dom_data, dict):
                errors.append(f"Domain {dom_key}: must be a mapping.")
                continue
            for field in _REQUIRED_DOMAIN_FIELDS:
                if field not in dom_data:
                    errors.append(f"Domain {dom_key}: missing required field '{field}'.")
            dom_type = dom_data.get("type", "")
            if dom_type and dom_type not in _VALID_DOMAIN_TYPES:
                errors.append(
                    f"Domain {dom_key}: invalid type '{dom_type}'. "
                    f"Must be 'organizational' or 'technical'."
                )

    if errors:
        _logger.warning("Validation errors in %s: %s", filepath, "; ".join(errors))

    return errors


def _load_all() -> None:
    """Load all YAML framework files from the frameworks/ directory.

    Skips files starting with underscore (like _schema.yaml).
    Logs warnings for files that fail to parse or validate.
    """
    global _LOADED
    fw_dir = _get_frameworks_dir()

    if not fw_dir.is_dir():
        _logger.warning("Frameworks directory not found: %s", fw_dir)
        _LOADED = True
        return

    for filepath in sorted(fw_dir.glob("*.yaml")):
        # Skip schema and hidden files
        if filepath.name.startswith("_"):
            continue

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)

            if not isinstance(data, dict):
                _logger.warning("Skipping %s: not a valid YAML mapping.", filepath.name)
                continue

            errors = _validate_framework(data, str(filepath))
            if errors:
                _logger.warning(
                    "Framework %s has validation errors but will still be loaded: %s",
                    filepath.name, errors
                )

            fw_id = data.get("id", "")
            if not fw_id:
                _logger.warning("Skipping %s: no 'id' field.", filepath.name)
                continue

            # Normalize domain keys to integers
            raw_domains = data.get("domains", {})
            normalized_domains: dict[int, dict[str, Any]] = {}
            for key, value in raw_domains.items():
                try:
                    normalized_domains[int(key)] = value
                except (ValueError, TypeError):
                    _logger.warning(
                        "Framework %s: skipping domain with non-integer key '%s'.",
                        fw_id, key
                    )
            data["domains"] = normalized_domains

            _FRAMEWORKS[fw_id] = data
            _logger.debug("Loaded framework: %s (%s)", fw_id, data.get("name", ""))

        except yaml.YAMLError as e:
            _logger.error("Failed to parse %s: %s", filepath.name, e)
        except OSError as e:
            _logger.error("Failed to read %s: %s", filepath.name, e)

    _LOADED = True
    _logger.info("Framework registry loaded: %d frameworks", len(_FRAMEWORKS))


def _ensure_loaded() -> None:
    """Ensure frameworks are loaded. Called lazily on first access."""
    if not _LOADED:
        _load_all()


def reload() -> None:
    """Force reload all frameworks from disk. Useful after admin apply updates."""
    global _LOADED
    _FRAMEWORKS.clear()
    _LOADED = False
    _load_all()


# Public accessor functions

def get_all() -> dict[str, dict[str, Any]]:
    """Return all loaded frameworks as a dict keyed by framework id."""
    _ensure_loaded()
    return dict(_FRAMEWORKS)


def get(framework_id: str) -> dict[str, Any] | None:
    """Return a single framework by id, or None if not found."""
    _ensure_loaded()
    return _FRAMEWORKS.get(framework_id)


def get_ids() -> list[str]:
    """Return all registered framework ids in sorted order."""
    _ensure_loaded()
    return sorted(_FRAMEWORKS.keys())


def get_domains(framework_id: str) -> dict[int, str]:
    """Return the domain number to name mapping for a framework.

    This matches the format used by the existing DPDP_DOMAINS, RBI_DOMAINS, etc.
    dicts in domains.py for backward compatibility.
    """
    _ensure_loaded()
    fw = _FRAMEWORKS.get(framework_id)
    if not fw:
        return {}
    return {num: dom["name"] for num, dom in fw.get("domains", {}).items()}


def get_active_frameworks(flags: dict[str, bool]) -> list[dict[str, Any]]:
    """Return frameworks that should be assessed based on user provided flags.

    Frameworks with activation="always" are always included.
    Frameworks with activation="opt_in" are included only if their
    activation_param is present and True in the flags dict.

    Args:
        flags: Dict of parameter names to boolean values, for example
               {"is_rbi_regulated": True, "is_sebi_regulated": False}.

    Returns:
        List of framework dicts that are active for this assessment.
    """
    _ensure_loaded()
    result: list[dict[str, Any]] = []
    for fw in _FRAMEWORKS.values():
        activation = fw.get("activation", "opt_in")
        if activation == "always":
            result.append(fw)
        elif activation == "opt_in":
            param = fw.get("activation_param", "")
            if param and flags.get(param, False):
                result.append(fw)
    return result


def get_search_sources(framework_id: str = "") -> dict[str, list[str]]:
    """Return search source URLs, optionally filtered by framework id.

    If framework_id is empty, returns sources for all frameworks.
    """
    _ensure_loaded()
    result: dict[str, list[str]] = {}
    targets = [framework_id] if framework_id else list(_FRAMEWORKS.keys())
    for fw_id in targets:
        fw = _FRAMEWORKS.get(fw_id)
        if fw:
            sources = fw.get("search_sources", [])
            if sources:
                result[fw_id] = sources
    return result


def get_circular_sources() -> dict[str, list[str]]:
    """Return circular listing URLs for all frameworks that define them."""
    _ensure_loaded()
    result: dict[str, list[str]] = {}
    for fw_id, fw in _FRAMEWORKS.items():
        sources = fw.get("circular_sources", [])
        if sources:
            result[fw_id] = sources
    return result


def get_keywords(framework_id: str = "") -> dict[str, list[str]]:
    """Return keyword lists for circular filtering, optionally filtered by id."""
    _ensure_loaded()
    result: dict[str, list[str]] = {}
    targets = [framework_id] if framework_id else list(_FRAMEWORKS.keys())
    for fw_id in targets:
        fw = _FRAMEWORKS.get(fw_id)
        if fw:
            kw = fw.get("keywords", [])
            if kw:
                result[fw_id] = kw
    return result


def get_source_domains() -> set[str]:
    """Return the union of all source_domains across all frameworks.

    Used for allowlisting outbound HTTP requests to regulatory sites.
    """
    _ensure_loaded()
    domains: set[str] = set()
    for fw in _FRAMEWORKS.values():
        for d in fw.get("source_domains", []):
            domains.add(d)
    return domains


def get_config_rule_params(framework_id: str) -> dict[str, dict[str, str]]:
    """Return Config rule parameter overrides for a framework.

    Used by the conformance pack generator to apply framework-specific
    parameter values (for example different log retention periods).
    """
    _ensure_loaded()
    fw = _FRAMEWORKS.get(framework_id)
    if not fw:
        return {}
    return fw.get("config_rule_params", {})


def get_penalty(framework_id: str, domain_number: int) -> str:
    """Return the penalty text for a specific framework and domain.

    Checks penalty_overrides first, falls back to penalty_default.
    """
    _ensure_loaded()
    fw = _FRAMEWORKS.get(framework_id)
    if not fw:
        return ""
    overrides = fw.get("penalty_overrides", {})
    if domain_number in overrides:
        return overrides[domain_number]
    return fw.get("penalty_default", "")
