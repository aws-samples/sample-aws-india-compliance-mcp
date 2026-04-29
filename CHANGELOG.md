# Changelog

## 0.1.0 — 2026-04-29

Initial release.

### Tools
- `scan_aws_account` — AWS Config-based resource scan with DPDP + RBI assessment
- `scan_control_tower_tool` — Control Tower governance controls assessment
- `parse_architecture` — CloudFormation, Terraform, draw.io parser
- `assess_compliance` — Per-resource compliance checks (13 resource types)
- `generate_report` — Full report with posture scores and remediation timeline
- `search_regulatory_text` — Live search from official government sources
- `list_control_domains` — DPDP (10) and RBI (7) control domain reference

### Regulatory mappings
- DPDP Act 2023 (as enacted August 11, 2023) — 10 control domains
- RBI Master Direction DoS.CO.CSITE.SEC.3/31.01.015/2023-24 (April 7, 2023) — 7 control domains
- 27 Control Tower controls mapped to DPDP/RBI domains

### Security
- XXE protection for XML parsing (DTD/entity declarations rejected)
- Template input size limited to 10 MB
- HTTPS-only outbound requests with TLS 1.2+
- Response size capped at 5 MB with content-type validation
- Rate limiting: 10 requests/minute per regulatory domain
- Configurable cache TTL via REGULATORY_CACHE_TTL environment variable
- LOG_LEVEL environment variable for log verbosity control
- No persistence — all data held in memory, discarded on exit
