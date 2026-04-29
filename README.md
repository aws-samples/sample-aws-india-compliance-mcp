

# AWS India Compliance MCP Server

Assess your AWS infrastructure against India's Digital Personal Data Protection (DPDP) Act 2023 and the Reserve Bank of India (RBI) Master Direction on IT Governance, Risk, Controls and Assurance Practices 2023.

This is an MCP server. It works with any MCP-compatible client — Kiro, Claude Desktop, Cursor, or your own agents.

## What it does

- **Scans your AWS account** using AWS Config to discover resources and their configurations, then checks each one against DPDP and RBI control domains.
- **Scans your Control Tower** to find which governance controls are enabled, which are missing, and what you need to turn on for compliance.
- **Parses architecture templates** (CloudFormation, Terraform, draw.io) and assesses them before you deploy.
- **Searches regulatory text** from official Indian government sources at runtime — no stale bundled data.

## Regulatory versions

This server assesses against:

| Regulation | Version | Last mapping update |
|---|---|---|
| DPDP Act | 2023 (as enacted August 11, 2023) | 2026-04-01 |
| RBI Master Direction | DoS.CO.CSITE.SEC.3/31.01.015/2023-24 (April 7, 2023) | 2026-04-01 |

Control domain mappings are updated within 30 days of any published regulatory amendment. Check the `CHANGELOG.md` for mapping revision history.

## Security model

> **This server executes read-only operations against your AWS account and outbound HTTPS calls to regulatory sites. It does not modify any AWS resources.**

### Authentication

This MCP server runs as a local stdio process — it communicates only with the MCP client that spawned it, not over a network. There is no HTTP endpoint exposed by default.

If you deploy this server over HTTP/SSE (remote mode), secure it with authentication before exposing it:

- Use OAuth 2.1 (per the MCP specification) with your identity provider.
- At minimum, restrict access with an API key passed via environment variable.
- Do not expose an unauthenticated MCP server to any network.

Tool-level authorization is not implemented — any authenticated client can invoke all seven tools. If you need tool-level restrictions, implement them in a proxy layer or MCP gateway.

### AWS credential handling

The server requires AWS credentials with read access. Follow this priority order:

1. **IAM roles (recommended)** — If running on EC2, ECS, Lambda, or Cloud9, use the attached instance/task/execution role. No credentials to manage.
2. **AWS IAM Identity Center (SSO)** — Use `aws sso login --profile your-profile` and set `AWS_PROFILE` in the MCP config.
3. **Environment variables** — Set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN`. Use short-lived session credentials only.

> **Do not hardcode AWS credentials in the MCP config `env` block, source code, or version control.** Use `AWS_PROFILE` references or role-based access instead.

### Minimum IAM policy

Use the following least-privilege policy. Do **not** use `AdministratorAccess` or `ReadOnlyAccess`.

**Single-account scan:**

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
        "controltower:ListEnabledControls",
        "controltower:ListControls",
        "controltower:GetControlOperation"
      ],
      "Resource": "*"
    }
  ]
}
```

**Org-wide scan (with Config Aggregator):** Add the above policy to a role in the management/delegated admin account, plus:

```json
{
  "Sid": "CrossAccountAggregator",
  "Effect": "Allow",
  "Action": [
    "config:SelectAggregateResourceConfig",
    "config:DescribeConfigurationAggregators"
  ],
  "Resource": "arn:aws:config:*:*:config-aggregator/*"
}
```

### Data handling

- **No persistence.** The server does not write to disk, databases, or cloud storage. All scan results and compliance assessments are held in memory for the duration of the MCP session and discarded on exit.
- **No telemetry.** No data is sent to any endpoint other than the MCP client that invoked the tool and the regulatory sites (HTTPS only, see below).
- **Logging.** Logs are written to stderr at INFO level by default. Logs may contain AWS resource ARNs and resource type identifiers. They do **not** contain credential material, resource data values, or PII. Adjust log level via `LOG_LEVEL` environment variable.
- **Compliance reports.** Generated reports (from `generate_report`) are returned to the MCP client in-memory. They are not cached or stored server-side.
- **Template data.** Templates passed to `parse_architecture` are parsed in-memory and not retained after the response is returned.

> This tool is designed to assess DPDP and RBI compliance — it follows the same data minimization and purpose limitation principles it evaluates.

## Setup

### Install with dependency verification

```bash
pip install . --require-hashes -r requirements.txt
```

Or using the lock file:

```bash
pip install . -c constraints.txt
```

Dependencies are pinned with hashes in `requirements.txt`. Verify the SBOM at `sbom.json` (CycloneDX format) before deployment. See `CHANGELOG.md` for dependency update history.

### Add to Kiro

In `.kiro/settings/mcp.json`:

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

### Add to Claude Desktop

In `claude_desktop_config.json`:

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

## Tools

| Tool | What it does |
|---|---|
| `scan_aws_account` | Scan resources via AWS Config, assess against DPDP + RBI |
| `scan_control_tower` | Scan Control Tower controls, recommend missing ones |
| `parse_architecture` | Parse CloudFormation/Terraform/draw.io templates (see input limits below) |
| `assess_compliance` | Assess a set of components against control domains |
| `generate_report` | Full report with posture scores and remediation timeline |
| `search_regulatory_text` | Live HTTPS search from dpdpact.in and rbi.org.in |
| `list_control_domains` | List DPDP (10) or RBI (7) control domains |

### Template parsing — input validation (`parse_architecture`)

- **Supported formats:** CloudFormation (JSON/YAML), Terraform (HCL/JSON), draw.io (XML).
- **Maximum file size:** 10 MB per template.
- **Static analysis only.** Templates are parsed for structure and resource declarations. No code is executed, no external references are fetched, no provisioning occurs.
- **XML safety.** draw.io (XML) parsing uses `defusedxml`, which blocks external entity resolution (XXE), DTD processing, and entity expansion at the parser level.
- **Untrusted templates.** Review any template from an untrusted source before parsing. While the parser does not execute code, maliciously crafted templates could produce misleading compliance results.

### Regulatory text search — network security (`search_regulatory_text`)

- **HTTPS only.** All outbound requests use TLS 1.2+ to dpdpact.in and rbi.org.in over HTTPS. Plain HTTP is never used.
- **Response validation.** Responses are validated for content-type (text/html, application/json) and size (max 5 MB). Unexpected content types are rejected.
- **Timeouts.** Requests time out after 30 seconds. Failed requests return an error to the MCP client — they do not retry silently.
- **Rate limiting.** Outbound calls are rate-limited to 10 requests per minute per target domain.
- **No caching by default.** Each search hits the live source. Set `REGULATORY_CACHE_TTL=3600` (seconds) to enable local in-memory caching if you want to reduce external calls.
- **Fallback.** If a regulatory site is unreachable, the tool returns an explicit error with the domain and HTTP status — it does not fall back to stale data or alternative sources.

## How the AWS scan works

1. Queries AWS Config Advanced Query — one API call returns all resource configurations.
2. Extracts compliance-relevant properties (encryption, public access, logging, retention, etc.) for each resource type.
3. Falls back to direct API checks for Security Hub, GuardDuty, CloudTrail, and WAF (Config doesn't always track these).
4. Runs each resource through the assessment engine against all applicable DPDP and RBI control domains.
5. Returns gaps with risk ratings, specific remediation steps, and regulatory references.

**Prerequisites:**
- AWS Config recorder must be enabled in the target account/region.
- For org-wide scans, provide a Config Aggregator name.
- The IAM principal must have the minimum permissions listed above.

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
