"""Tests for compliance assessment engine."""

from aws_india_compliance.assessment import assess


def test_assess_basic():
    components = [{"name": "bucket", "type": "AWS::S3::Bucket", "category": "storage", "properties": {}}]
    result = assess(components)
    assert result["total_components"] == 1
    assert result["total_gaps"] > 0
    assert result["dpdp_posture"]["total"] == 10


def test_assess_with_rbi():
    components = [{"name": "bucket", "type": "AWS::S3::Bucket", "category": "storage", "properties": {}}]
    result = assess(components, is_rbi=True)
    assert result["rbi_posture"] is not None
    assert result["rbi_posture"]["total"] == 7


def test_assess_sdf():
    components = [{"name": "bucket", "type": "AWS::S3::Bucket", "category": "storage", "properties": {}}]
    result = assess(components, is_sdf=True)
    sdf_gaps = [g for g in result["gaps"] if g["domain"] == 10]
    assert len(sdf_gaps) > 0


def test_assess_encrypted_s3_no_encryption_gap():
    components = [{"name": "b", "type": "AWS::S3::Bucket", "category": "storage",
                   "properties": {"encryption": "aws:kms", "public_access_blocked": True, "lifecycle_policy": True}}]
    result = assess(components)
    enc_gaps = [g for g in result["gaps"] if "encryption" in g["gap"].lower() and g["component"] == "b"]
    assert len(enc_gaps) == 0


def test_assess_ec2_public_ip():
    components = [{"name": "i-123", "type": "AWS::EC2::Instance", "category": "compute",
                   "properties": {"public_ip": True}}]
    result = assess(components, is_rbi=True)
    public_gaps = [g for g in result["gaps"] if "public IP" in g["gap"]]
    assert len(public_gaps) >= 1


def test_assess_eks_no_secrets_encryption():
    components = [{"name": "cluster", "type": "AWS::EKS::Cluster", "category": "compute",
                   "properties": {"public_endpoint": True}}]
    result = assess(components, is_rbi=True)
    eks_gaps = [g for g in result["gaps"] if g["component"] == "cluster"]
    assert len(eks_gaps) >= 2  # secrets + public endpoint at minimum


def test_assess_with_sebi():
    components = [
        {"name": "b", "type": "AWS::S3::Bucket", "category": "storage", "properties": {}},
        {"name": "gd", "type": "AWS::GuardDuty::Detector", "category": "security", "properties": {}},
    ]
    result = assess(components, is_sebi=True)
    assert result["sebi_posture"] is not None
    assert result["sebi_posture"]["total"] == 6
    assert result["sebi_posture"]["score"] > 0
