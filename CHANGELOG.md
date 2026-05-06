# Changelog

## [0.2.0] - 2026-05-05

### Added
- CERT-In expanded from 4 to 8 domains: DDoS/Bot Protection, Network Security/DNS, Endpoint/Malware Protection, Data Leakage Prevention
- NIST CSF cross-references on all SEBI CSCRF domains (ID.GV, ID.RA, PR.AC, DE.AE, RS.RP, RC.RP)
- DPDP Rules 2025 Rule 6 sub-clause references (6.1.a-g) on security safeguard gaps
- DPDP Rules 2025 Rule 7 breach notification checklist (7.1.a-e) on breach notification gaps
- Penalty exposure field on every gap (INR 200Cr for children's data, INR 150Cr for SDF, INR 50Cr for other DPDP)
- AWS Shield Advanced detection (fallback API check)
- AWS Network Firewall detection (fallback API check)
- Amazon Macie detection for DLP assessment
- Production-grade DOCX report generator with color-coded risk levels and posture scores
- format_report MCP tool now supports output_format="docx"
- IAM Access Analyzer detection and assessment (RBI 2016 Section 8.5 - unused permissions)
- Amazon Macie enablement check (RBI 2016 Section 1.2 - data classification)
- responsibility_type field on every gap ("shared" or "customer" per AWS shared responsibility model)
- Fallback API checks for Access Analyzer and Macie

### Changed
- CERT-In posture score now calculated against 8 domains (was 4)
- SEBI domains in control_mappings.json now include nist_csf field
- DPDP domain 5 section reference updated with Rule 7 breach notification requirements
- DPDP domain 6 section reference updated with Rule 6.1.a-g security safeguard sub-clauses
- control_mappings.json manifest_version updated to 1.2.0
- RBI gaps now reference specific 2016 Cyber Security Framework sections where applicable
- Gap output enriched with responsibility_type for shared responsibility clarity

### Fixed
- SecurityGroup ipRanges parsing (handles string and dict formats from AWS Config)
- S3 bucket policy TLS extraction (handles string bucketPolicy field)
- MCP response size management for large org scans (>100 gaps saved to reports/ dir)
- disabledTools in MCP config was blocking all tool calls

## [0.1.0] - 2026-04-15

### Added
- Initial release with DPDP Act 2023, RBI Master Direction, SEBI CSCRF assessment
- AWS Config-based resource scanning (30+ resource types)
- Control Tower guardrail mapping
- CloudFormation/Terraform/draw.io template parsing
- Regulatory text search with live source fallback
- Regulatory update monitoring (staleness, content hashing, circular detection)
- LLM-assisted mapping update workflow (propose + apply)
