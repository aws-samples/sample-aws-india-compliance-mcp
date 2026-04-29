"""Tests for control domain constants."""

from aws_india_compliance.domains import DPDP_DOMAINS, RBI_DOMAINS


def test_dpdp_has_10_domains():
    assert len(DPDP_DOMAINS) == 10


def test_rbi_has_7_domains():
    assert len(RBI_DOMAINS) == 7


def test_dpdp_domain_6_is_security():
    assert "Security Safeguards" in DPDP_DOMAINS[6]


def test_rbi_domain_5_is_cyber():
    assert "Cyber Security" in RBI_DOMAINS[5]


def test_sebi_has_6_domains():
    from aws_india_compliance.domains import SEBI_DOMAINS
    assert len(SEBI_DOMAINS) == 6

def test_sebi_domain_3_is_protection():
    from aws_india_compliance.domains import SEBI_DOMAINS
    assert SEBI_DOMAINS[3] == "Cyber Protection"

def test_manifest_loads():
    from aws_india_compliance.domains import load_manifest
    m = load_manifest()
    assert "frameworks" in m
    assert "dpdp" in m["frameworks"]
    assert "rbi" in m["frameworks"]
    assert "sebi" in m["frameworks"]
    assert m["manifest_version"] == "1.0.0"

def test_manifest_has_aws_controls():
    from aws_india_compliance.domains import load_manifest
    m = load_manifest()
    dpdp_d6 = m["frameworks"]["dpdp"]["domains"]["6"]
    assert len(dpdp_d6["aws_controls"]) > 0
    assert len(dpdp_d6["config_rules"]) > 0
    assert len(dpdp_d6["guardrails"]) > 0
