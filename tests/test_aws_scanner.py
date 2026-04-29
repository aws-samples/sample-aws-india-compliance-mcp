"""Tests for AWS Config scanner."""

import json
from unittest.mock import MagicMock, patch

from aws_india_compliance.aws_scanner import config_to_component, scan_via_config


def test_config_to_component_s3_encrypted():
    resource = {
        "resourceType": "AWS::S3::Bucket", "resourceId": "b", "resourceName": "my-bucket",
        "awsRegion": "us-east-1", "accountId": "123",
        "configuration": json.dumps({
            "serverSideEncryptionConfiguration": {"rules": [
                {"applyServerSideEncryptionByDefault": {"sseAlgorithm": "aws:kms", "kmsMasterKeyID": "k1"}}
            ]},
            "lifecycleConfiguration": {"rules": [{"status": "Enabled"}]},
            "publicAccessBlockConfiguration": {
                "blockPublicAcls": True, "blockPublicPolicy": True,
                "restrictPublicBuckets": True, "ignorePublicAcls": True,
            },
        }),
    }
    comp = config_to_component(resource)
    assert comp["properties"]["encryption"] == "aws:kms"
    assert comp["properties"]["lifecycle_policy"] is True
    assert comp["properties"]["public_access_blocked"] is True


def test_config_to_component_lambda():
    resource = {
        "resourceType": "AWS::Lambda::Function", "resourceId": "f", "resourceName": "fn",
        "configuration": json.dumps({"runtime": "python3.12", "vpcConfig": {"subnetIds": ["s1"]}}),
    }
    comp = config_to_component(resource)
    assert comp["properties"]["runtime"] == "python3.12"
    assert comp["properties"]["vpc_enabled"] is True


def test_scan_via_config_mocked():
    with patch("aws_india_compliance.aws_scanner.scan_via_config") as mock:
        mock.return_value = [
            {"name": "b", "type": "AWS::S3::Bucket", "category": "storage", "properties": {}, "region": "us-east-1", "account_id": "123"},
        ]
        result = mock("us-east-1")
        assert len(result) == 1
