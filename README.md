# AWS India Compliance MCP Server

Assess your AWS infrastructure against India's Digital Personal Data Protection (DPDP) Act 2023 and the Reserve Bank of India (RBI) Master Direction on IT Governance, Risk, Controls and Assurance Practices 2023.

This is an MCP server. It works with any MCP-compatible client — Kiro, Claude Desktop, Cursor, or your own agents.

## What it does

- **Scans your AWS account** using AWS Config to discover resources and their configurations, then checks each one against DPDP and RBI control domains.
- **Scans your Control Tower** to find which governance controls are enabled, which are missing, and what you need to turn on for compliance.
- **Parses architecture templates** (CloudFormation, Terraform, draw.io) and assesses them before you deploy.
- **Searches regulatory text** from official Indian government sources at runtime — no stale bundled data.

## Setup

```bash
pip install .
```

### Add to Kiro

In `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "aws-india-compliance": {
      "command": "python3",
      "args": ["-m", "aws_india_compliance.server"],
      "env": {}
    }
  }
}
```

### Add to Claude Desktop

In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aws-india-compliance": {
      "command": "python3",
      "args": ["-m", "aws_india_compliance.server"]
    }
  }
}
```

## Tools

| Tool | What it does |
|---|---|
| `scan_aws_account` | Scan resources via AWS Config, assess against DPDP + RBI |
| `scan_control_tower` | Scan Control Tower controls, recommend missing ones |
| `parse_architecture` | Parse CloudFormation/Terraform/draw.io templates |
| `assess_compliance` | Assess a set of components against control domains |
| `generate_report` | Full report with posture scores and remediation timeline |
| `search_regulatory_text` | Live search from dpdpact.in and rbi.org.in |
| `list_control_domains` | List DPDP (10) or RBI (7) control domains |

## How the AWS scan works

1. Queries AWS Config Advanced Query — one API call returns all resource configurations.
2. Extracts compliance-relevant properties (encryption, public access, logging, retention, etc.) for each resource type.
3. Falls back to direct API checks for Security Hub, GuardDuty, CloudTrail, and WAF (Config doesn't always track these).
4. Runs each resource through the assessment engine against all applicable DPDP and RBI control domains.
5. Returns gaps with risk ratings, specific remediation steps, and regulatory references.

Requires AWS Config recorder to be enabled. For org-wide scans, provide a Config Aggregator name.

## What it checks

| Resource | DPDP Checks | RBI Checks |
|---|---|---|
| S3 | Encryption, lifecycle, public access block, versioning, logging | Same + cross-region replication |
| DynamoDB | Encryption, TTL | Same + PITR |
| RDS | Encryption, public access, backup retention | Same + Multi-AZ, audit logging |
| Lambda | Secrets in env vars, DLQ | Same |
| EC2 | Public IP, IMDSv2, EBS encryption | Same |
| EKS | Secrets encryption, public endpoint, audit logging | Same |
| ECS | Container Insights | Same |
| API Gateway | WAF | Same |
| CloudFront | WAF, access logging | Same |
| SQS | Encryption, DLQ | Same |
| SageMaker | Direct internet, encryption, VPC | Same |
| KMS | Key rotation | Same |
| CloudTrail | Log validation, encryption | Same |

## Control domains

### DPDP Act 2023

| # | Domain |
|---|---|
| 1 | Lawful Processing and Consent Management |
| 2 | Data Minimization |
| 3 | Privacy Notices |
| 4 | Data Principal Rights |
| 5 | Breach Notification |
| 6 | Reasonable Security Safeguards |
| 7 | Data Retention Limits |
| 8 | Cross-Border Data Transfer |
| 9 | Children's Data Protection |
| 10 | Significant Data Fiduciary Obligations |

### RBI Master Direction 2023

| # | Domain |
|---|---|
| 1 | IT Governance and Oversight |
| 2 | IT Infrastructure and Service Management |
| 3 | IT Risk Management |
| 4 | Information Security |
| 5 | Cyber Security |
| 6 | Business Continuity and Disaster Recovery |
| 7 | Information Systems Audit |

## Tests

```bash
python3 -m pytest tests/ -v
```

## License

Apache 2.0
