"""Tests for Control Tower scanner and assessment."""

from aws_india_compliance.control_tower import assess_control_tower


def test_assess_ct_basic():
    ct_data = {
        "landing_zone": {"arn": "arn:...", "version": "3.3", "status": "ACTIVE", "drift_status": "IN_SYNC"},
        "enabled_controls": [
            {"control_id": "AWS-GR_ENCRYPTED_VOLUMES", "control_arn": "arn:...", "target_ou": "Prod", "target_ou_id": "ou-1", "status": "SUCCEEDED"},
            {"control_id": "AWS-GR_CLOUDTRAIL_ENABLED", "control_arn": "arn:...", "target_ou": "Prod", "target_ou_id": "ou-1", "status": "SUCCEEDED"},
        ],
        "ous": [{"id": "ou-1", "name": "Prod", "arn": "arn:..."}],
    }
    result = assess_control_tower(ct_data, is_rbi=True)
    assert result["total_enabled_controls"] == 2
    assert len(result["recommendations"]) > 0
    assert result["dpdp_posture"]["total"] == 10


def test_assess_ct_drifted():
    ct_data = {
        "landing_zone": {"arn": "arn:...", "version": "3.3", "status": "ACTIVE", "drift_status": "DRIFTED"},
        "enabled_controls": [], "ous": [],
    }
    result = assess_control_tower(ct_data)
    drift_gaps = [g for g in result["gaps"] if "drifted" in g["gap"].lower()]
    assert len(drift_gaps) > 0


def test_assess_ct_no_landing_zone():
    ct_data = {"landing_zone": None, "enabled_controls": [], "ous": []}
    result = assess_control_tower(ct_data)
    lz_gaps = [g for g in result["gaps"] if "landing zone" in g["gap"].lower()]
    assert len(lz_gaps) > 0
