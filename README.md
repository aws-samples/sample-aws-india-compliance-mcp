# AWS India Compliance MCP Server

An MCP server that assesses AWS infrastructure against three Indian regulatory frameworks:

- DPDP Act 2023 (Digital Personal Data Protection)
- RBI Master Direction on IT Governance 2023
- SEBI CSCRF 2024 (Cybersecurity and Cyber Resilience Framework)

Works with Kiro, Claude Desktop, Cursor, or any MCP-compatible client.

## Quick start

```bash
# Install
pip install .

# Or with pinned dependencies
pip install . -c constraints.txt
```

Add to `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "aws-india-compliance": {
      "command": "python3",
      "args": ["-m", "aws_india_compliance.server"],
      "env": {
        "AWS_PROFILE": "your-sso-profile",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

For Claude Desktop, add the same block to `claude_desktop_config.json`.

## Prerequisites

- Python 3.10+
- AWS Config recorder enabled in target accounts/regions
- IAM credentials with read-only access (see IAM policy below)
- For org-wide scans: a Config Aggregator name

## Tools

| Tool | Purpose |
|---|---|
| `scan_aws_account` | Discover resources via AWS Config, assess against all frameworks. Pass `aggregator_name` for org-wide scans. |
| `scan_control_tower` | Enumerate enabled guardrails across OUs, recommend missing ones per framework. |
| `parse_architecture` | Parse CloudFormation (JSON/YAML), Terraform (HCL), or draw.io (XML) templates. Max 10 MB. |
| `assess_compliance` | Assess a component list against control domains. Accepts output from `parse_architecture`. |
| `generate_report` | Full report with posture scores, gap list, and phased remediation timeline. |
| `search_regulatory_text` | Search regulatory text from government sources. Falls back to bundled mappings when sites are unreachable. |
| `list_control_domains` | List domains for a framework: `dpdp` (10), `rbi` (7), or `sebi` (6). |
| `check_regulatory_updates` | Show manifest metadata, last verified dates, and source URLs for each framework. |

## How scanning works

1. AWS Config Advanced Query pulls resource configurations in a single API call.
2. The scanner extracts compliance-relevant properties per resource type (encryption, public access, logging, retention, key rotation, etc.).
3. Fallback API checks cover Security Hub, GuardDuty, CloudTrail, and WAF — services Config does not always track.
4. The assessment engine evaluates each resource against applicable DPDP, RBI, and SEBI control domains.
5. Results include risk-rated gaps, specific remediation steps, and regulatory section references.

For org-wide scans, pass the Config Aggregator name (e.g., `aws-controltower-ConfigAggregatorForOrganizations`). The aggregator must be configured in the management or delegated admin account.

## Resource checks

| Resource | What gets checked |
|---|---|
| S3 | Encryption at rest, lifecycle policies, Block Public Access, versioning, access logging, Object Lock (for audit buckets) |
| RDS | Storage encryption, public accessibility, Multi-AZ, audit logging |
| DynamoDB | KMS encryption, TTL, point-in-time recovery |
| Lambda | Secrets in environment variables, dead letter queue |
| EC2 | Public IP assignment, IMDSv2 enforcement, EBS encryption |
| EKS | Secrets envelope encryption, API server endpoint visibility, control plane logging |
| ECS | Container Insights |
| CloudTrail | Log file validation, KMS encryption, CloudWatch Logs integration |
| KMS | Automatic key rotation for customer-managed keys |
| API Gateway | WAF association |
| CloudFront | WAF association, access logging |
| SQS/SNS | Encryption at rest |
| SageMaker | Direct internet access, KMS encryption, VPC configuration |
| IAM Roles | Overprivileged policies (AdministratorAccess, PowerUserAccess, IAMFullAccess) |

RBI-regulated scans additionally flag resources deployed outside ap-south-1 and ap-south-2 per the RBI Data Localization Circular 2018.

## Control domains

DPDP Act (10 domains): Lawful Processing, Data Minimization, Privacy Notices, Data Principal Rights, Breach Notification, Reasonable Security Safeguards, Data Retention Limits, Cross-Border Data Transfer, Children's Data Protection, Significant Data Fiduciary Obligations.

RBI Master Direction (7 domains): IT Governance, IT Infrastructure, IT Risk Management, Information Security, Cyber Security, Business Continuity/DR, Information Systems Audit.

SEBI CSCRF (6 domains): Cyber Governance, Cyber Risk Identification, Cyber Protection, Cyber Detection, Cyber Response, Cyber Recovery.

## Regulatory version tracking

| Framework | Version | Source |
|---|---|---|
| DPDP Act | As enacted August 11, 2023 | dpdpact.in |
| RBI Master Direction | DoS.CO.CSITE.SEC.3/31.01.015/2023-24 (April 7, 2023) | rbi.org.in |
| SEBI CSCRF | Circular SEBI/HO/ITD/ITD-SEC-1/P/CIR/2024/113 (August 20, 2024) | sebi.gov.in |

Control mappings are maintained in `control_mappings.json` with `manifest_version`, `last_verified` dates, and source URLs per framework. Run `check_regulatory_updates` to see when mappings were last verified and where to check for new publications.

## Security

This server performs read-only operations. It does not modify AWS resources.

**Transport:** stdio by default (local process, no network exposure). For remote deployment over HTTP, set `MCP_API_KEY` and use OAuth 2.1 or equivalent authentication.

**Credentials:** Use IAM roles or SSO profiles. Do not hardcode credentials in config files or source code.

**Data handling:** No persistence, no telemetry, no caching by default. Scan results are held in memory and discarded on exit. Logs (stderr, INFO level) contain resource ARNs and type identifiers but not credential material or data values.

**XML parsing:** draw.io templates are parsed with `defusedxml`, which blocks XXE, DTD processing, and entity expansion.

**Outbound network:** HTTPS-only calls to regulatory sites (dpdpact.in, rbi.org.in, sebi.gov.in). Domain allowlist enforced. Response size capped at 5 MB. Rate-limited to 10 requests/minute per domain. 30-second timeout.

### Minimum IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ConfigAdvancedQuery",
      "Effect": "Allow",
      "Action": [
        "config:SelectAggregateResourceConfig",
        "config:SelectResourceConfig",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationAggregators"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecurityServices",
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "securityhub:DescribeHub",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ControlTower",
      "Effect": "Allow",
      "Action": [
        "controltower:ListLandingZones",
        "controltower:GetLandingZone",
        "controltower:ListEnabledControls",
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent"
      ],
      "Resource": "*"
    }
  ]
}
```

For org-wide scans, add `config:SelectAggregateResourceConfig` on the aggregator ARN. Consider adding an explicit Deny statement for destructive actions (DeleteTrail, StopLogging, DeleteDetector, etc.).

## Project structure

```
src/aws_india_compliance/
  server.py            # MCP tool registration, entry point
  assessment.py        # Compliance assessment engine (per-resource checks)
  aws_scanner.py       # AWS Config query + fallback API checks
  control_tower.py     # Control Tower scanner + guardrail mapping
  parsers.py           # CloudFormation/Terraform/draw.io parsers
  knowledge.py         # Live regulatory text search + fallback
  domains.py           # Domain definitions + manifest loader
  control_mappings.json # Versioned control-to-AWS mapping manifest
tests/
  test_assessment.py   # Assessment engine tests
  test_aws_scanner.py  # Scanner tests (mocked boto3)
  test_control_tower.py # Control Tower assessment tests
  test_domains.py      # Domain definition + manifest tests
  test_parsers.py      # Parser tests
```

## Tests

```bash
PYTHONPATH=src python3 -m pytest tests/ -v
```

28 tests covering assessment logic, scanner component extraction, Control Tower gap analysis, domain definitions, manifest integrity, and all three parsers.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `AWS_PROFILE` | — | AWS SSO profile name |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `REGULATORY_CACHE_TTL` | `0` | Seconds to cache regulatory site responses. 0 = no caching. |
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio` for local, `streamable-http` for remote |
| `MCP_HOST` | `127.0.0.1` | Host for HTTP transport |
| `MCP_PORT` | `8000` | Port for HTTP transport |

## License

Apache 2.0
