"""Architecture diagram and template parsers.

Extracts infrastructure components from CloudFormation YAML/JSON,
Terraform HCL, and draw.io XML files. Each parser returns a list
of component dicts with name, type, category, and properties.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

# Service classification sets
_STORAGE = {"s3", "rds", "dynamodb", "redshift", "efs", "ebs", "aurora", "elasticache"}
_COMPUTE = {"ec2", "lambda", "ecs", "eks", "fargate", "batch"}
_NETWORK = {"cloudfront", "apigateway", "api_gateway", "elb", "alb", "nlb", "route53", "vpc"}
_SECURITY = {"kms", "iam", "guardduty", "macie", "securityhub", "security_hub", "waf", "shield", "cloudtrail", "config"}
_ANALYTICS = {"sagemaker", "glue", "athena", "emr", "kinesis", "quicksight"}
_MESSAGING = {"sqs", "sns", "eventbridge", "mq"}


def classify_service(service: str) -> str:
    """Map an AWS service type string to a category name.

    Returns one of: storage, compute, networking, security,
    analytics_ml, messaging, other.
    """
    s = service.lower()
    # Extract the short service name from CF or TF type strings
    if "::" in s:
        s = s.split("::")[-1]
    elif s.startswith("aws_"):
        s = s[4:].split("_")[0]

    for name, svc_set in [
        ("storage", _STORAGE), ("compute", _COMPUTE), ("networking", _NETWORK),
        ("security", _SECURITY), ("analytics_ml", _ANALYTICS), ("messaging", _MESSAGING),
    ]:
        if s in svc_set or any(x in service.lower() for x in svc_set):
            return name
    return "other"


def parse_cloudformation(content: str) -> list[dict[str, Any]]:
    """Parse a CloudFormation YAML or JSON template.

    Returns a list of component dicts with name, type, category, properties.
    """
    import yaml  # lazy — only needed for CF parsing

    try:
        doc = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        doc = yaml.safe_load(content)

    resources = doc.get("Resources", {}) if isinstance(doc, dict) else {}
    components: list[dict[str, Any]] = []
    for logical_id, res in resources.items():
        if not isinstance(res, dict):
            continue
        rtype = res.get("Type", "")
        components.append({
            "name": logical_id,
            "type": rtype,
            "category": classify_service(rtype),
            "properties": res.get("Properties", {}),
        })
    return components


def parse_terraform(content: str) -> list[dict[str, Any]]:
    """Parse Terraform HCL using basic regex extraction.

    Returns a list of component dicts with name, type, category, properties.
    """
    components: list[dict[str, Any]] = []
    for m in re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"', content):
        rtype, name = m.group(1), m.group(2)
        components.append({
            "name": name,
            "type": rtype,
            "category": classify_service(rtype),
            "properties": {},
        })
    return components


def parse_drawio(content: str) -> list[dict[str, Any]]:
    """Parse a draw.io XML file and extract labeled components.

    Returns a list of component dicts with name, type, category, properties.
    """
    root = ET.fromstring(content)
    components: list[dict[str, Any]] = []
    for cell in root.iter("mxCell"):
        value = cell.get("value", "").strip()
        if value and cell.get("vertex") == "1" and cell.get("id") not in ("0", "1"):
            components.append({
                "name": value,
                "type": value.lower().replace(" ", "_"),
                "category": classify_service(value),
                "properties": {},
            })
    return components
