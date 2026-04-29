# Changelog

## 0.3.0 — 2026-04-29

### SEBI CSCRF framework support
- Added SEBI Cybersecurity and Cyber Resilience Framework (CSCRF) as third regulatory framework
- 6 SEBI control domains: Governance, Identification, Protection, Detection, Response, Recovery
- SEBI Cloud Framework requirements mapped to AWS controls and guardrails
- `is_sebi_regulated` parameter added to scan and assessment tools

### Versioned control mappings manifest
- Created `control_mappings.json` with detailed regulatory-to-AWS control mappings
- Each domain includes: section references, AWS services, Config rules, and CT guardrails
- Manifest tracks version, last_verified date, and source URLs per framework
- DPDP Act: 10 domains with AWS Config rules and Control Tower guardrails mapped
- RBI Master Direction: 7 domains mapped to AWS Config conformance pack rules
- SEBI CSCRF: 6 domains mapped to AWS controls from SEBI Cloud Framework

### New tool: check_regulatory_updates
- Returns manifest metadata with last verified dates per framework
- Lists regulatory source URLs for checking new circulars and amendments
- Enables operators to identify when control mappings need updating

### Expanded regulatory sources
- Added sebi.gov.in to domain allowlist and search sources
- Added cert-in.org.in to domain allowlist
- `search_regulatory_text` now supports "sebi" framework filter
- `list_control_domains` now supports "sebi" framework

## 0.2.0 — 2026-04-29

### New assessment checks (from STRIDE threat model)
- Data residency check: flags resources outside Indian regions for RBI-regulated entities
- S3 Object Lock check: flags audit/CloudTrail buckets without immutable retention
- CloudWatch Log Group retention: flags groups with < 180 days retention (CERT-In)
- CloudTrail CloudWatch Logs integration: flags trails not forwarding to CloudWatch
- IAM role overly broad permissions: flags AdministratorAccess, IAMFullAccess, PowerUserAccess

### Security hardening
- Tool schema integrity: SHA-256 manifest logged at startup for tool poisoning detection
- Domain allowlist enforcement in knowledge.py: outbound requests restricted to ALLOWED_SOURCE_DOMAINS
- Explicit deny IAM policy documented in README for destructive operations
- Deployment security guidance added to README (IMDSv2, network isolation, immutable containers)

### New resource types scanned
- AWS::Logs::LogGroup (CloudWatch Log Groups)
- AWS::IAM::Role (attached policy analysis)

## 0.1.1 — 2026-04-29

### Security
- Replaced stdlib `xml.etree.ElementTree` with `defusedxml` for draw.io XML parsing.
  Resolves high-severity finding: native Python XML library is vulnerable to XXE attacks.
  `defusedxml` blocks external entities, DTD processing, and entity expansion at the parser level.
- Fixed B310 (Bandit): `urllib.request.urlopen` now validates URL scheme via `urlparse`
  before opening, rejecting `file:/`, `ftp:/`, `data:`, and plain `http://` schemes.
- Fixed B104 (Bandit): MCP server now binds to `127.0.0.1` by default instead of `0.0.0.0`.
  Use `MCP_HOST=0.0.0.0` environment variable to bind to all interfaces when needed.
- Fixed URL formatting in README that caused scanner false positives on URL validation.
- Softened prescriptive language in README security guidance per inclusive language assessment.

### Dependencies
- Added `defusedxml>=0.7.1`.

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
