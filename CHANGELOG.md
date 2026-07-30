# Changelog

## [0.3.0] - 2026-07-30

### Added
- Plugin-based framework architecture: each compliance framework is defined in a single YAML file under `src/aws_india_compliance/frameworks/`
- `framework_registry.py`: auto-discovers and loads all framework YAML files at startup
- `scripts/scaffold_framework.py`: generates skeleton YAML for new frameworks (`--new`) and validates existing ones (`--validate`, `--validate-all`)
- `scripts/build_manifest.py`: compiles all framework YAMLs into `control_mappings.json`
- Declarative assessment checks in YAML (49 checks across 4 frameworks) with generic rule evaluator
- `CONTRIBUTING_FRAMEWORKS.md`: full contributor guide for adding new compliance frameworks
- `.github/workflows/framework-validation.yml`: CI workflow validates framework YAMLs on PR
- `pyyaml` dependency for YAML parsing

### Changed
- `domains.py` now reads domain definitions from the framework registry instead of hardcoded dicts
- `knowledge.py` reads search_sources, circular_sources, and keywords from the framework registry
- `conformance_pack.py` reads framework names, domains, and parameter overrides from the registry
- `control_tower.py` builds recommended guardrail lists from the registry
- `server.py` `list_control_domains` now dynamically supports any registered framework
- `admin.py` reads and writes framework YAML files directly instead of the JSON manifest
- `control_mappings.json` is now auto-generated from framework YAMLs (manifest_version 2.0.0)

### How to add a new framework
Drop a YAML file in `src/aws_india_compliance/frameworks/` and the server picks it up automatically. See `CONTRIBUTING_FRAMEWORKS.md` for details.

## [0.2.3] - 2026-07-30

### Fixed
- MCP SDK v2+ compatibility: added fallback import for `mcp.server.mcpserver.MCPServer` while retaining v1 `mcp.server.fastmcp.FastMCP` support
- Synced `__version__` in `__init__.py` with `pyproject.toml`

## [0.2.1] - 2026-07-24

### Changed
- Version bump for patch release

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
- control_mappings.json manifest_version updated to 2.0.0
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
