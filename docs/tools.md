# Tools Reference

The server exposes 8 MCP tools following a **compact summary + drill-down** pattern: `scan_aws_account` returns a compact summary, and `get_compliance_gaps` provides paginated access to full gap details.

Maintainer tools (regulatory updates, mapping management) are CLI-only and not exposed via MCP.

## MCP Tools (User-Facing)

### scan_aws_account

Discover resources via AWS Config and assess against all active frameworks.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `region` | string | `ap-south-1` | AWS region to scan |
| `is_significant_data_fiduciary` | bool | false | SDF under DPDP Act |
| `is_rbi_regulated` | bool | false | RBI-regulated entity |
| `is_sebi_regulated` | bool | false | SEBI-regulated entity |
| `is_irdai_regulated` | bool | false | IRDAI-regulated entity |
| `frameworks` | string | (empty) | Comma-separated framework IDs to assess (e.g. "dpdp,rbi,irdai"). Preferred way to activate frameworks. Overrides boolean flags for listed frameworks. |
| `aggregator_name` | string | (auto) | Config Aggregator name for org-wide scan |
| `sebi_entity_tier` | string | (none) | SEBI tier: "mii", "qualified_re", "other_re" |
| `exceptions` | string | (none) | JSON string of exception rules |
| `filter_tags` | string | (none) | JSON of {key: value} pairs, include only matching |
| `exclude_tags` | string | (none) | JSON of {key: value} pairs, exclude matching |
| `save_to_file` | bool | false | Save full report JSON to reports/ directory |

### scan_control_tower

Enumerate enabled guardrails across OUs and recommend missing controls per framework.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `region` | string | `ap-south-1` | AWS region where Control Tower is deployed |
| `is_significant_data_fiduciary` | bool | false | SDF flag |
| `is_rbi_regulated` | bool | false | RBI flag |
| `is_sebi_regulated` | bool | false | SEBI flag |

### get_compliance_gaps

Drill into compliance gaps from the most recent scan with filtering and pagination.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `framework` | string | (all) | Filter: "dpdp", "rbi", "sebi", "certin" |
| `risk` | string | (all) | Filter: "critical", "high", "medium", "low" |
| `domain` | string | (all) | Filter by domain name or number (partial match) |
| `page` | int | 1 | Page number (1-indexed) |
| `page_size` | int | 20 | Results per page (max 50) |

### list_control_domains

List the control domains for any registered framework.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `framework` | string | `dpdp` | Framework ID (any registered framework) |

### search_regulatory_text

Search regulatory text from government sources with automatic fallback to bundled mappings.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | (required) | Search terms |
| `framework` | string | (all) | Filter by framework ID |
| `top_k` | int | 5 | Number of results (max 50) |

### generate_conformance_pack

Generate a deployable AWS Config conformance pack YAML for any framework.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `framework` | string | `dpdp` | Framework ID |
| `include_domains` | string | (all) | Comma-separated domain numbers to include |
| `exclude_domains` | string | (none) | Comma-separated domain numbers to exclude |
| `pack_name_prefix` | string | (none) | Custom prefix for the pack name |

### format_report

Generate a production-grade DOCX or Markdown compliance report from scan results.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `report_json` | string | (none) | Inline JSON string of scan results |
| `report_path` | string | (none) | Path to a saved scan report JSON |
| `output_format` | string | `docx` | "docx" or "markdown" |
| `save_to_file` | bool | true | Save to reports/ directory |

### submit_feedback

Submit feedback about the tool (bugs, missing capabilities, suggestions).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `message` | string | (required) | Description (max 2000 chars) |
| `category` | string | `other` | "bug", "feature_request", "documentation", "missing_capability", "other" |
| `tool_name` | string | (none) | Which tool the feedback is about |
| `severity` | string | `medium` | "high", "medium", "low" |

## CLI-Only Tools (Maintainer)

These are not exposed via MCP. They are for package maintainers updating control mappings.

```bash
aws-india-compliance-admin check      # Check for regulatory updates/staleness
aws-india-compliance-admin propose    # Feed regulatory text for LLM analysis
aws-india-compliance-admin apply      # Apply proposed changes to framework YAML
```

## Sample Prompts

| What you want to do | Example prompt |
|---------------------|----------------|
| Scan a single account | "Scan my AWS account in ap-south-1 for DPDP and RBI compliance" |
| Scan your organization | "Scan my AWS organization for compliance" |
| Scan with SEBI | "Scan my AWS account as a SEBI MII entity" |
| Drill into gaps | "Show me all critical DPDP gaps" |
| Assess Control Tower | "Scan my Control Tower and check guardrail coverage" |
| Search regulatory text | "What does DPDP say about breach notification timelines?" |
| List domains | "List the SEBI CSCRF control domains" |
| Generate report | "Format my last scan as a Word document" |
| Generate conformance pack | "Generate an AWS Config conformance pack for RBI" |
| Filter by tags | "Scan only resources tagged Environment=Production" |
| Submit feedback | "Submit feedback: the scan doesn't check Neptune clusters" |
