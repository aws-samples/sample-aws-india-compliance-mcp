# Adding a New Compliance Framework

This guide explains how to add a new regulatory compliance framework to the
AWS India Compliance MCP server. The plugin architecture lets you contribute
a framework by creating a single YAML file, with no Python code changes required.

## Prerequisites

Before you start, you will need:

- Python 3.10+ installed
- A clone of this repository
- Familiarity with the regulation you want to add (you must read the source text)
- Basic understanding of which AWS services address common security and privacy controls

You do not need deep Python knowledge. The framework definition is entirely YAML.

## Overview

Each compliance framework lives in a single file:

```
src/aws_india_compliance/frameworks/<id>.yaml
```

The server auto-discovers all YAML files in this directory at startup. No registration
code, no imports, no edits to other files.

## Step-by-Step Process

### Step 1: Generate the Skeleton (2 minutes)

Run the scaffold tool to create a starter file:

```bash
python scripts/scaffold_framework.py --new \
    --id gdpr \
    --name "EU General Data Protection Regulation" \
    --source-url "https://gdpr-info.eu"
```

You can also pre-populate regulatory search and update-detection metadata:

```bash
python scripts/scaffold_framework.py --new \
    --id gdpr \
    --name "EU General Data Protection Regulation" \
    --source-url "https://gdpr-info.eu" \
    --search-sources "https://gdpr-info.eu,https://edpb.europa.eu" \
    --circular-sources "https://edpb.europa.eu/our-work-tools/general-guidance" \
    --keywords "data protection,controller,processor"
```

| Option | Description |
|--------|-------------|
| `--search-sources` | Comma-separated URLs for regulatory text search |
| `--circular-sources` | Comma-separated URLs of circular listing pages for update detection |
| `--keywords` | Comma-separated keywords for filtering relevant circulars |

This creates `src/aws_india_compliance/frameworks/gdpr.yaml` with placeholder
content and inline instructions.

### Step 2: Research the Regulation (2 to 4 hours)

Read the regulation source text and identify:

1. **Control domains** (typically 5 to 15 themes the regulation addresses).
   For example, GDPR has themes like lawfulness, purpose limitation,
   data minimization, security measures, breach notification, etc.

2. **For each domain, determine:**
   - Official name from the regulation
   - Section or article reference
   - Whether it is "organizational" (requires human processes, policies, audits)
     or "technical" (can be validated by checking AWS resource configurations)

3. **For technical domains, identify:**
   - Which AWS services address the requirement (for example KMS for encryption)
   - Which AWS Config rules validate compliance (for example `encrypted-volumes`)
   - Which Control Tower guardrails enforce it (for example `AWS-GR_ENCRYPTED_VOLUMES`)

**Tip:** Look at the existing framework YAMLs for patterns. If your regulation
requires "encryption at rest," the same Config rules used by DPDP Domain 6 and
RBI Domain 4 will likely apply to your framework too.

### Step 3: Fill in the Domains

Edit your YAML file and populate each domain. Here is the structure:

```yaml
domains:
  1:
    name: "Lawfulness of Processing"
    section: "Article 6"
    type: organizational
    aws_controls:
      - "Cognito consent tracking"
      - "DynamoDB consent records"
    config_rules: []
    guardrails: []

  2:
    name: "Security of Processing"
    section: "Article 32"
    type: technical
    aws_controls:
      - "KMS encryption"
      - "S3 Block Public Access"
      - "IAM least privilege"
    config_rules:
      - "encrypted-volumes"
      - "rds-storage-encrypted"
      - "s3-bucket-server-side-encryption-enabled"
    guardrails:
      - "AWS-GR_ENCRYPTED_VOLUMES"
      - "AWS-GR_RDS_STORAGE_ENCRYPTED"
```

**Domain type guidance:**
- `organizational` = requires human processes, legal review, policies, or audits.
  Infrastructure scanning cannot validate these. Examples: consent management,
  privacy notices, governance boards, vendor agreements.
- `technical` = can be partially or fully validated by checking AWS resource
  configurations. Examples: encryption, access controls, logging, backup.

### Step 4: Add Declarative Assessment Checks (Optional but Recommended)

For technical domains, add a `checks:` section that tells the assessment
engine what to look for. Two types are supported:

**Resource-level checks** (run per matching AWS resource):

```yaml
checks:
  - match: "S3::Bucket"            # Resource type to match (substring)
    property: "encryption"          # Property name to inspect
    expect: "encrypted"             # Expected value (string, true, or false)
    domain: 2                       # Domain number this satisfies
    risk: high                      # Gap severity: critical, high, medium, low
    gap: "S3 bucket not encrypted"  # Human-readable gap description
    remediation: "Enable SSE-KMS"   # Fix recommendation
    reference: "Article 32(1)(a)"   # Regulatory citation
    confidence: high                # Check confidence: high, medium, low
```

**Architecture-level checks** (run once, check if a service exists):

```yaml
  - match_any: "guardduty"          # Substring to find in any component type
    domain: 3                       # Domain number
    risk: critical                  # Gap severity if NOT found
    gap: "No breach detection"      # Gap description
    remediation: "Enable GuardDuty" # Fix
    reference: "Article 33"         # Regulatory citation
    confidence: high
```

**Numeric minimum checks** (for retention periods, key rotation age, etc.):

```yaml
  - match: "Logs::LogGroup"
    property: "retention_days"
    expect_min: 365                 # Minimum acceptable value
    domain: 4
    risk: medium
    gap: "Log retention less than 1 year"
    remediation: "Set retention to 365 days"
    reference: "Article 30(1)"
    confidence: high
```

### Step 5: Fill in Monitoring Metadata

These fields enable the `admin check` command to detect when your regulation
source has been updated with new circulars or amendments:

```yaml
search_sources:
  - "https://gdpr-info.eu"

circular_sources:
  - "https://edpb.europa.eu/our-work-tools/general-guidance"

keywords:
  - "data protection"
  - "controller"
  - "processor"
  - "supervisory authority"
```

### Step 6: Suggest Checks (Optional)

```bash
python scripts/scaffold_framework.py --suggest-checks src/aws_india_compliance/frameworks/gdpr.yaml
```

This analyzes the domains and `config_rules` already defined in your YAML and
suggests additional declarative checks you may want to add for better coverage.

### Step 7: Validate

```bash
python scripts/scaffold_framework.py --validate src/aws_india_compliance/frameworks/gdpr.yaml
```

This checks:
- Required fields are present
- Framework id matches filename
- Domain types are valid
- Config rule names use correct format (lowercase, hyphens)
- Guardrail IDs use correct format (AWS-GR_UPPERCASE)
- Check definitions have all required fields

### Step 8: Rebuild the Manifest

```bash
python scripts/build_manifest.py
```

This regenerates `control_mappings.json` from all YAML files.

### Step 9: Run Tests

```bash
PYTHONPATH=src python -m pytest tests/ -v
```

All existing tests should still pass. Your new framework is additive.

### Step 10: Submit a Pull Request

```bash
git checkout -b add-framework-gdpr
git add src/aws_india_compliance/frameworks/gdpr.yaml
git add src/aws_india_compliance/control_mappings.json
git commit -m "feat: add GDPR compliance framework"
git push origin add-framework-gdpr
```

Then open a PR on GitHub. The CI workflow will automatically validate your
YAML against the schema.

## Framework YAML Reference

### Top-Level Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Lowercase identifier, 2 to 31 chars, letters/digits/underscores |
| `name` | Yes | Full human-readable framework name |
| `version` | Yes | Regulation version or circular date |
| `source_url` | Yes | Primary authoritative URL |
| `last_verified` | No | ISO date when mappings were last checked |
| `source_domains` | No | Allowed domains for regulatory text fetch |
| `activation` | No | "always" or "opt_in" (default: opt_in) |
| `activation_param` | No | Parameter name for opt-in activation |
| `search_sources` | No | URLs for regulatory text search |
| `circular_sources` | No | URLs for new circular detection |
| `keywords` | No | Keywords to filter relevant circulars |
| `penalty_default` | No | Default penalty text shown on gaps |
| `penalty_overrides` | No | Per-domain penalty overrides |
| `config_rule_params` | No | Config rule parameter overrides |
| `domains` | Yes | Control domain definitions (at least 1) |
| `checks` | No | Declarative assessment checks |

### Domain Fields

| Field | Required | Values |
|-------|----------|--------|
| `name` | Yes | Domain name from the regulation |
| `section` | Yes | Article or section reference |
| `type` | Yes | "organizational" or "technical" |
| `aws_controls` | No | List of AWS services that address this |
| `config_rules` | No | List of AWS Config rule names |
| `guardrails` | No | List of Control Tower guardrail IDs |
| `nist_csf` | No | NIST CSF cross-reference |
| `notes` | No | Additional notes about this domain |

### Check Fields

| Field | Required | Description |
|-------|----------|-------------|
| `match` | Yes (resource) | Resource type substring to match |
| `match_any` | Yes (architecture) | Component type substring to find |
| `property` | Yes (resource) | Property name to inspect |
| `expect` | Conditional | Expected value (string, true, false) |
| `expect_min` | Conditional | Minimum numeric value |
| `domain` | Yes | Domain number this check relates to |
| `risk` | Yes | critical, high, medium, or low |
| `gap` | Yes | Gap description if check fails |
| `remediation` | Yes | Fix recommendation |
| `reference` | Yes | Regulatory section citation |
| `confidence` | No | high, medium, low (default: medium) |

Either `expect` or `expect_min` is required for resource checks. Neither is
needed for architecture checks (they check for presence/absence).

## Available AWS Config Rule Names

For the full list of AWS-managed Config rules, see:
https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html

Common rules used across frameworks:

| Rule Name | What It Checks |
|-----------|----------------|
| `encrypted-volumes` | EBS volumes are encrypted |
| `rds-storage-encrypted` | RDS storage is encrypted |
| `s3-bucket-server-side-encryption-enabled` | S3 has SSE enabled |
| `s3-bucket-public-read-prohibited` | S3 not publicly readable |
| `guardduty-enabled-centralized` | GuardDuty is enabled |
| `securityhub-enabled` | Security Hub is enabled |
| `cloudtrail-enabled` | CloudTrail is enabled |
| `vpc-flow-logs-enabled` | VPC Flow Logs are on |
| `iam-policy-no-statements-with-admin-access` | No admin wildcard policies |
| `mfa-enabled-for-iam-console-access` | MFA on console users |
| `cw-loggroup-retention-period-check` | Log retention meets minimum |
| `db-instance-backup-enabled` | RDS backups are on |

## Available Resource Properties

The assessment engine inspects these properties per resource type:

| Resource Type | Properties Available |
|---------------|---------------------|
| S3::Bucket | encryption, public_access_blocked, lifecycle_policy, versioning, access_logging, object_lock |
| RDS::DB | encryption, public, multi_az, audit_logging, ssl_enforcement |
| DynamoDB::Table | encryption, pitr |
| EC2::Instance | public_ip, imdsv2_required, ebs_encrypted |
| Lambda::Function | public, dlq_configured, env_secrets |
| EKS::Cluster | secrets_encrypted, endpoint_public, logging_enabled |
| CloudTrail::Trail | log_file_validation, encryption, multi_region |
| Logs::LogGroup | retention_days, encrypted |
| KMS::Key | rotation_enabled, key_manager |

## Learning from Existing Frameworks

The best way to learn is to read the existing YAML files:

- `frameworks/dpdp.yaml` (10 domains, 17 checks, most comprehensive example)
- `frameworks/rbi.yaml` (7 domains, 16 checks, mixed org/technical)
- `frameworks/sebi.yaml` (6 domains, 10 checks, NIST CSF cross-references)
- `frameworks/certin.yaml` (8 domains, 6 checks, mostly architecture-level)

## How the MCP Server Uses Your Framework

Once your YAML is in place:

1. `list_control_domains("your_id")` returns your domains
2. `generate_conformance_pack("your_id")` generates a Config pack from your config_rules
3. `search_regulatory_text(query, "your_id")` searches your source URLs
4. `scan_aws_account(...)` evaluates your declarative checks
5. `admin check` monitors your circular_sources for updates

No Python code changes needed for any of this.

## Getting Help

- Open an issue on GitHub for questions
- Look at existing frameworks as working examples
- Use `python scripts/scaffold_framework.py --validate` early and often
- Run `python scripts/build_manifest.py` to regenerate the JSON after changes
