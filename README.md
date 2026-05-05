# AWS India Compliance MCP Server

An MCP server that assesses AWS infrastructure against four Indian regulatory frameworks:

- **DPDP Act 2023** (Digital Personal Data Protection) + Rules 2025
- **RBI Master Direction** on IT Governance 2023
- **SEBI CSCRF 2024** (Cybersecurity and Cyber Resilience Framework)
- **CERT-In Directions 2022** (Incident reporting, log retention, NTP sync)

Works with Kiro, Claude Desktop, Cursor, or any MCP-compatible client.

**Important:** This tool provides automated assessment guidance based on
  published regulatory frameworks. It does not constitute legal advice or
  compliance certification. Organizations should consult qualified compliance
  and legal professionals for definitive regulatory compliance determinations.

## Quick start

### 1. Install

```bash
git clone https://github.com/aws-samples/sample-aws-india-compliance-mcp.git
cd sample-aws-india-compliance-mcp

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install
pip install .

# Or with pinned dependencies
pip install . -c constraints.txt
```

### 2. Configure AWS credentials

The server needs read-only AWS access. Use **AWS IAM Identity Center (SSO)** — this is the recommended approach for teams.

**First-time SSO setup:**
```bash
aws configure sso
```
Follow the prompts:
- SSO session name: `my-sso` (any name)
- SSO start URL: your org's SSO URL (e.g., `https://d-xxxxxxxxxx.awsapps.com/start`)
- SSO region: `us-east-1` (or wherever your Identity Center is)
- It opens a browser — sign in and authorize
- Select the account and role (e.g., `ReadOnlyAccess`)
- CLI profile name: `my-sso-profile` (remember this)

**Login before each session:**
```bash
aws sso login --profile my-sso-profile
```
This opens a browser for authentication. Once approved, your CLI has temporary credentials for ~8 hours.

**Verify it works:**
```bash
aws sts get-caller-identity --profile my-sso-profile
```

**Alternative: static credentials (not recommended for teams)**
If you have long-lived access keys in `~/.aws/credentials`, those work too — but SSO is preferred for security.

### 3. Add to your MCP client

Add to `.kiro/settings/mcp.json` (or `claude_desktop_config.json` for Claude Desktop):

```json
{
  "mcpServers": {
    "aws-india-compliance": {
      "command": "/path/to/your/.venv/bin/python3",
      "args": ["-m", "aws_india_compliance.server"],
      "env": {
        "PYTHONPATH": "/path/to/sample-aws-india-compliance-mcp/src",
        "AWS_PROFILE": "my-sso-profile",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

Replace `/path/to/your/.venv/bin/python3` with the actual path to your venv Python, and `my-sso-profile` with your SSO profile name.

**Tip:** Run `which python3` inside your activated venv to get the exact path.

### 4. Verify

Ask your MCP client:
> "List the DPDP control domains"

If it returns 10 domains, you're set. To scan your AWS account:
> "Scan my AWS account in ap-south-1 for DPDP and RBI compliance"

## Prerequisites

- Python 3.10+
- AWS Config recorder enabled in target accounts/regions
- IAM credentials with read-only access (see IAM policy below)
- For org-wide scans: a Config Aggregator name

## Tools (11)

| Tool | Purpose |
|---|---|
| `scan_aws_account` | Discover resources via AWS Config, assess against all frameworks. Pass `aggregator_name` for org-wide scans. Supports tag filtering, exception rules, and SEBI entity tiering. |
| `scan_control_tower_tool` | Enumerate enabled guardrails across OUs, recommend missing ones per framework including CERT-In. Per-OU breakdown with domain coverage. |
| `parse_architecture` | Parse CloudFormation (JSON/YAML), Terraform (HCL), or draw.io (XML) templates. Max 10 MB. |
| `assess_compliance` | Assess a component list against control domains. Supports tag filtering, exception suppression, and SEBI entity tiering. |
| `generate_report` | Full report with posture scores, gap list, and phased remediation timeline. |
| `search_regulatory_text` | Search regulatory text from government sources. Falls back to bundled mappings when sites are unreachable. |
| `list_control_domains` | List domains for a framework: `dpdp` (10), `rbi` (7), `sebi` (6), or `certin` (4). |
| `check_regulatory_updates` | Staleness check + content hash monitoring + new circular detection. Flags when mappings may be outdated. |
| `propose_mapping_update` | Feed new regulatory text to the LLM client for analysis. Returns current mappings + structured prompt for proposing changes. |
| `apply_mapping_update` | Validate and apply LLM-proposed mapping changes to control_mappings.json. Supports review-then-apply workflow. |
| `format_report` | Convert scan report JSON into Markdown or production-grade DOCX. Pass `output_format="docx"` for a styled Word report with color-coded risk levels, posture scores, cover page, and Control Tower guardrails. |

## Key features

### Confidence scoring
Every compliance gap includes a confidence level:
- **High** — Direct technical check verifiable from AWS Config (e.g., encryption disabled, public access enabled)
- **Medium** — Interpretive mapping from regulatory requirement to AWS control (e.g., data localization)
- **Low** — Organizational requirement where infrastructure is only a proxy (e.g., DPO appointment, consent tracking)

Each gap also carries `evidence` (triggering property values), `checked_at` (ISO 8601 timestamp), and `confidence_rationale`.

### CERT-In Directions 2022
Four control domains assessed:
1. Incident Reporting Readiness (GuardDuty + EventBridge + SNS pipeline)
2. Log Retention — 180 days (CloudWatch LogGroup retention check)
3. NTP Synchronization (advisory — AWS uses Amazon Time Sync by default)
4. Reportable Incident Awareness (Security Hub enablement)

### Per-account breakdown
Org-wide scans group gaps by AWS account ID with individual DPDP, RBI, and SEBI posture scores per account.

### Resource-level compliance tracking
Per-domain resource compliance percentages (e.g., "dpdp:6 — 482 checked, 320 passed, 66.4%").

### Exception management
- Auto-suppression of `AWSControlTowerExecution` roles (by design)
- Custom exception rules via `resource_pattern` (fnmatch) and `exclude_tag`
- Suppressed gaps tracked separately with suppression reason

### Tag-based filtering
- `filter_tags`: Include only resources matching ALL specified tag key-value pairs
- `exclude_tags`: Exclude resources matching ANY specified tag key-value pair

### SEBI entity tiering
- **MII** tier: C-SOC readiness checks (GuardDuty + Security Hub + Detective), BYOK verification
- **qualified_re** tier: BYOK check, skip C-SOC
- **other_re** tier: Baseline SEBI checks only

### Nuanced data localization
- Storage resources outside India → high-risk gap (RBI 2018 Circular)
- Compute resources outside India → medium-risk advisory (processing may be permissible)
- Global services (IAM, CloudFront, Route53, WAFv2) → excluded from localization checks
- `DataClassification` tag value included in gap description when present

### Report formatting
The `format_report` tool supports two output formats:

**Markdown** (default): Structured text report for chat display and quick review.

**DOCX** (`output_format="docx"`): Production-grade Word document suitable for sharing with customers and auditors. Features:
- Professional cover page with scan metadata and confidentiality notice
- Color-coded posture scores (green/orange/red based on thresholds)
- Dark blue styled table headers with alternating row shading
- Risk-level cell coloring (red for critical, orange for high, yellow for medium)
- Confidence-level cell coloring (green for high, orange for medium, red for low)
- Landscape orientation with full-width tables (no truncation of resource names)
- Control Tower section with guardrails, per-OU breakdown, and recommendations
- Phased remediation timeline
- Disclaimer page

Both formats include:
- Executive summary with posture scores
- Confidence distribution table
- Gap summary by framework and risk level
- Resource-level compliance pass rates
- Per-account breakdown
- Critical and high-risk gap tables with evidence
- Suppressed gaps with reasons
- Phased remediation timeline (Immediate / Short-term / Medium-term)

Large scan results (>100 gaps) are automatically saved to `reports/` as JSON, with the MCP response trimmed to priority gaps.

### Regulatory monitoring
Three-tier monitoring system:
1. **Staleness** — Flags frameworks where `last_verified` exceeds threshold (default 30 days)
2. **Content hashing** — Fetches regulatory source pages and compares SHA-256 hashes against baselines
3. **New circular detection** — Scans RBI and SEBI circular listing pages for publications matching compliance keywords

LLM-assisted mapping updates via `propose_mapping_update` → `apply_mapping_update` workflow.

## How scanning works

1. AWS Config Advanced Query pulls resource configurations in a single API call.
2. The scanner extracts compliance-relevant properties per resource type (encryption, public access, logging, retention, key rotation, TLS enforcement, VPC flow logs, security group rules, secrets rotation, backup plans, etc.).
3. Fallback API checks cover Security Hub, GuardDuty, CloudTrail, WAF, AWS Backup, and Amazon Inspector.
4. The assessment engine evaluates each resource against applicable DPDP, RBI, SEBI, and CERT-In control domains.
5. Results include risk-rated gaps with confidence levels, evidence, specific remediation steps, and regulatory section references.

For org-wide scans, pass the Config Aggregator name (e.g., `aws-controltower-ConfigAggregatorForOrganizations`). The aggregator must be configured in the management or delegated admin account.

## Resource checks

| Resource | What gets checked |
|---|---|
| S3 | Encryption at rest, lifecycle policies, Block Public Access, versioning, access logging, Object Lock (audit buckets), TLS enforcement (bucket policy) |
| RDS | Storage encryption, public accessibility, Multi-AZ, audit logging, SSL enforcement |
| DynamoDB | KMS encryption, TTL, point-in-time recovery |
| Lambda | Secrets in environment variables, dead letter queue |
| EC2 | Public IP assignment, IMDSv2 enforcement, EBS encryption |
| EKS | Secrets envelope encryption, API server endpoint visibility, control plane logging |
| ECS | Container Insights |
| CloudTrail | Log file validation, KMS encryption, CloudWatch Logs integration |
| KMS | Automatic key rotation for customer-managed keys, BYOK verification (SEBI) |
| API Gateway | WAF association |
| CloudFront | WAF association, access logging |
| SQS/SNS | Encryption at rest |
| SageMaker | Direct internet access, KMS encryption, VPC configuration, consent tracking for ML data |
| IAM Roles | Overprivileged policies (AdministratorAccess, PowerUserAccess, IAMFullAccess) |
| VPC | Flow Logs enablement and destination |
| Security Groups | Open SSH (22) and RDP (3389) to 0.0.0.0/0 |
| Secrets Manager | Automatic rotation configuration |
| AWS Backup | Backup plan existence, Vault Lock status |
| Amazon Inspector | Enablement status (SEBI VAPT requirement) |

RBI-regulated scans additionally flag resources deployed outside ap-south-1 and ap-south-2 per the RBI Data Localization Circular 2018, with nuanced classification (storage vs compute vs global services).

## Control domains

**DPDP Act (10 domains):** Lawful Processing, Data Minimization, Privacy Notices, Data Principal Rights, Breach Notification, Reasonable Security Safeguards, Data Retention Limits, Cross-Border Data Transfer, Children's Data Protection, Significant Data Fiduciary Obligations.

**RBI Master Direction (7 domains):** IT Governance, IT Infrastructure, IT Risk Management, Information Security, Cyber Security, Business Continuity/DR, Information Systems Audit.

**SEBI CSCRF (6 domains):** Cyber Governance, Cyber Risk Identification, Cyber Protection, Cyber Detection, Cyber Response, Cyber Recovery.

**CERT-In Directions (4 domains):** Incident Reporting Readiness, Log Retention (180 days), NTP Synchronization, Reportable Incident Awareness.

## Regulatory version tracking

| Framework | Version | Source |
|---|---|---|
| DPDP Act | As enacted August 11, 2023 + Rules 2025 (Nov 14, 2025) | dpdpact.in |
| RBI Master Direction | DoS.CO.CSITE.SEC.3/31.01.015/2023-24 (April 7, 2023) | rbi.org.in |
| SEBI CSCRF | Circular SEBI/HO/ITD/ITD-SEC-1/P/CIR/2024/113 (August 20, 2024) | sebi.gov.in |
| CERT-In Directions | Directions dated April 28, 2022 | cert-in.org.in |

Control mappings are maintained in `control_mappings.json` with `manifest_version`, `last_verified` dates, and source URLs per framework. Run `check_regulatory_updates` to see when mappings were last verified and where to check for new publications.

## Security

This server performs read-only operations. It does not modify AWS resources.

**Input validation:**
- AWS region format validated via regex (`^[a-z]{2}(-[a-z]+-\d+)?$`)
- Config Aggregator name validated (`^[a-zA-Z0-9_-]{1,256}$`)
- Report file paths constrained to `reports/` directory (path traversal blocked)
- `top_k` parameter capped at 50
- Error messages sanitized to avoid leaking filesystem paths

**Transport:** stdio by default (local process, no network exposure). For remote deployment over HTTP, set `MCP_API_KEY` and use OAuth 2.1 or equivalent authentication.

**Credentials:** Use IAM roles or SSO profiles. Do not hardcode credentials in config files or source code.

**Data handling:** No persistence, no telemetry, no caching by default. Scan results are held in memory and discarded on exit. Large scan reports are saved to `reports/` (gitignored). Logs (stderr, INFO level) contain resource ARNs and type identifiers but not credential material or data values.

**XML parsing:** draw.io templates are parsed with `defusedxml`, which blocks XXE, DTD processing, and entity expansion.

**Outbound network:** HTTPS-only calls to regulatory sites (dpdpact.in, rbi.org.in, sebi.gov.in, cert-in.org.in). Domain allowlist enforced. Response size capped at 5 MB. Rate-limited to 10 requests/minute per domain. 30-second timeout.

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
        "wafv2:GetWebACL",
        "backup:ListBackupPlans",
        "backup:ListBackupVaults",
        "inspector2:BatchGetAccountStatus"
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
  server.py              # MCP tool registration, entry point, input validation
  assessment.py          # Compliance assessment engine (confidence scoring, resource tracking, exceptions)
  aws_scanner.py         # AWS Config query + fallback API checks (Backup, Inspector)
  control_tower.py       # Control Tower scanner + per-OU guardrail mapping
  parsers.py             # CloudFormation/Terraform/draw.io parsers
  knowledge.py           # Live regulatory text search + content hash monitoring
  domains.py             # Domain definitions + manifest loader + staleness check
  report_formatter.py    # Markdown report generator (account scan + Control Tower)
  control_mappings.json  # Versioned control-to-AWS mapping manifest (DPDP, RBI, SEBI, CERT-In)
tests/
  test_assessment.py     # Assessment engine tests
  test_aws_scanner.py    # Scanner tests (mocked boto3)
  test_control_tower.py  # Control Tower assessment tests
  test_domains.py        # Domain definition + manifest tests
  test_parsers.py        # Parser tests
reports/                 # Scan report output (gitignored)
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
| `STALENESS_THRESHOLD_DAYS` | `30` | Days after last_verified before staleness warnings appear in scan results. |
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio` for local, `streamable-http` for remote |
| `MCP_HOST` | `127.0.0.1` | Host for HTTP transport |
| `MCP_PORT` | `8000` | Port for HTTP transport (validated 1-65535) |
| `REPORT_DIR` | `reports/` | Directory for full scan report JSON output |

**Disclaimer:** This is a sample tool for educational and assessment purposes.
  It performs read-only operations and does not modify AWS resources.
  Users should validate compliance findings against their specific regulatory
  requirements and consult qualified compliance professionals.

## License

Apache 2.0
