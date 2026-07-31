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
- `streamable-http` available for remote deployment (set `MCP_TRANSPORT=streamable-http`)
- No built-in authentication. For remote deployments, place behind a reverse proxy with authentication (for example API Gateway, ALB with OIDC, or VPN)
- Binds to `127.0.0.1` by default (configurable via `MCP_HOST`). Do not bind to `0.0.0.0` without authentication in front

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

- HTTPS-only calls to regulatory sites
- Domain allowlist enforced dynamically from framework YAML `source_domains` fields (currently: meity.gov.in, egazette.gov.in, rbi.org.in, sebi.gov.in, cert-in.org.in, irdai.gov.in)
- Response size capped at 5 MB
- Rate-limited to 10 requests/minute per domain
- 30-second timeout
- No outbound calls are made during normal scanning (scanning uses AWS APIs only). Outbound HTTPS is only used by `search_regulatory_text` and `admin check`

## Minimum IAM Policy

Least-privilege policy covering org-wide Config queries, Control Tower enumeration, and fallback service detection checks. Only 20 Allow actions (vs approximately 12,000 in the AWS-managed `ReadOnlyAccess` policy). Includes an explicit Deny statement that blocks destructive operations even if this role is used alongside broader policies.

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

For org-wide scans, this policy must be attached in the **management account** (or delegated admin) where the Config Aggregator resides.
