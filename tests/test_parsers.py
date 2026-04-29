"""Tests for architecture parsers."""

import json
from aws_india_compliance.parsers import (
    classify_service, parse_cloudformation, parse_terraform, parse_drawio,
)


def test_classify_s3():
    assert classify_service("AWS::S3::Bucket") == "storage"


def test_classify_lambda():
    assert classify_service("AWS::Lambda::Function") == "compute"


def test_classify_guardduty():
    assert classify_service("AWS::GuardDuty::Detector") == "security"


def test_classify_unknown():
    assert classify_service("unknown_thing") == "other"


def test_parse_cloudformation():
    cf = json.dumps({"Resources": {
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
        "Func": {"Type": "AWS::Lambda::Function", "Properties": {}},
    }})
    components = parse_cloudformation(cf)
    assert len(components) == 2
    assert components[0]["name"] == "Bucket"
    assert components[0]["category"] == "storage"


def test_parse_terraform():
    tf = 'resource "aws_s3_bucket" "data" {\n  bucket = "b"\n}\n'
    components = parse_terraform(tf)
    assert len(components) == 1
    assert components[0]["type"] == "aws_s3_bucket"


def test_parse_drawio():
    xml = (
        '<mxGraphModel><root>'
        '<mxCell id="0"/><mxCell id="1" parent="0"/>'
        '<mxCell id="2" value="S3" style="shape=rect" vertex="1" parent="1"/>'
        '</root></mxGraphModel>'
    )
    components = parse_drawio(xml)
    assert len(components) == 1
    assert components[0]["name"] == "S3"
