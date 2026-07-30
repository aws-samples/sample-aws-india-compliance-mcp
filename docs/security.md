# Security

This server performs read-only operations. It does not modify AWS resources.

## Input Validation

- AWS region format validated via regex (`^[a-z]{2}(-[a-z]+-\d+)?$`)
- Config Aggregator name validated (`^[a-zA-Z0-9_-]{1,256}$`)
- Report file paths constrained to `reports/` directory (path traversal blocked)
- `top_k` parameter capped at 50
- Error messages sanitized to avoid leaking filesystem paths

## Transport

- `stdio` by default (local process, no network exposure)
- For remote deployment over HTTP, set `MCP_API_KEY` and use OAuth 2.1 or equivalent authentication

## Credentials

Use IAM roles or SSO profiles. Do not hardcode credentials in config files or source code.

## Data Handling

- Scan results cached in memory for drill-down via `get_compliance_gaps` and discarded on process exit
- Large scan reports saved to `reports/` (gitignored) only when `save_to_file=True`
- `submit_feedback` appends to `~/.aws-india-compliance/feedback.log` (local) and optionally posts to a public GitHub issue via `gh` CLI
- No telemetry collected
- Logs (stderr, INFO level) contain resource ARNs and type identifiers but not credential material

## XML Parsing

draw.io templates are parsed with `defusedxml`, which blocks XXE, DTD processing, and entity expansion.

## Outbound Network

- HTTPS-only calls to regulatory sites (dpdpact.in, rbi.org.in, sebi.gov.in, cert-in.org.in)
- Domain allowlist enforced (loaded from framework YAML `source_domains` fields)
- Response size capped at 5 MB
- Rate-limited to 10 requests/minute per domain
- 30-second timeout

## Minimum IAM Policy

Least-privilege policy covering org-wide Config queries, Control Tower enumeration, and fallback service detection checks.

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
        "config:DescribeConfigurationAggregators"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecurityServiceDetection",
      "Effect": "Allow",
      "Action": [
        "securityhub:DescribeHub",
        "guardduty:ListDetectors",
        "cloudtrail:DescribeTrails",
        "wafv2:ListWebACLs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "BackupAssessment",
      "Effect": "Allow",
      "Action": [
        "backup:ListBackupPlans",
        "backup:ListBackupVaults"
      ],
      "Resource": "*"
    },
    {
      "Sid": "InspectorAndShield",
      "Effect": "Allow",
      "Action": [
        "inspector2:BatchGetAccountStatus",
        "shield:DescribeSubscription"
      ],
      "Resource": "*"
    },
    {
      "Sid": "NetworkSecurityDetection",
      "Effect": "Allow",
      "Action": [
        "network-firewall:ListFirewalls"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DataProtectionDetection",
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ListAnalyzers",
        "macie2:GetMacieSession"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdentityCaller",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ControlTowerScan",
      "Effect": "Allow",
      "Action": [
        "controltower:ListLandingZones",
        "controltower:GetLandingZone",
        "controltower:ListEnabledControls"
      ],
      "Resource": "*"
    },
    {
      "Sid": "OrganizationsReadOnly",
      "Effect": "Allow",
      "Action": [
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyDestructiveActions",
      "Effect": "Deny",
      "Action": [
        "config:Delete*",
        "config:Stop*",
        "config:Put*",
        "controltower:Delete*",
        "controltower:Disable*",
        "organizations:Delete*",
        "organizations:Remove*",
        "guardduty:Delete*",
        "securityhub:Disable*",
        "cloudtrail:Delete*",
        "cloudtrail:Stop*",
        "inspector2:Disable*",
        "backup:Delete*",
        "macie2:Disable*"
      ],
      "Resource": "*"
    }
  ]
}
```

**20 Allow actions** (vs ~12,000 in `ReadOnlyAccess`). The Deny statement prevents destructive operations even if this role is used alongside broader policies.

For org-wide scans, this policy must be attached in the **management account** (or delegated admin) where the Config Aggregator resides.
