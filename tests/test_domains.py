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
