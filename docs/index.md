# AWS India Compliance MCP Server

An MCP server that assesses AWS infrastructure against Indian regulatory compliance frameworks. Works with Kiro, Claude Desktop, Cursor, or any MCP-compatible client.

## What It Does

- Scans your AWS account via AWS Config and evaluates resources against regulatory control domains
- Generates compliance gap reports with risk levels, remediation steps, and regulatory citations
- Produces deployable AWS Config conformance packs for continuous monitoring
- Searches live regulatory text from government sources
- Monitors for new circulars and regulatory updates

## Supported Frameworks

| Framework | Domains | Activation |
|-----------|---------|------------|
| [DPDP Act 2023 + Rules 2025](frameworks/dpdp.md) | 10 | Always |
| [RBI Master Direction 2023](frameworks/rbi.md) | 7 | Opt-in |
| [SEBI CSCRF 2024](frameworks/sebi.md) | 6 | Opt-in |
| [CERT-In Directions 2022](frameworks/certin.md) | 8 | Always |

See [Frameworks](frameworks/index.md) for full details on each framework.

## Quick Start

```json
{
  "mcpServers": {
    "aws-india-compliance": {
      "command": "uvx",
      "args": ["aws-india-compliance@latest"]
    }
  }
}
```

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/) installed and AWS credentials configured.

## Documentation

- [Getting Started](getting-started.md) - Installation, credentials, verification
- [Tools Reference](tools.md) - All 8 MCP tools with parameters and examples
- [Frameworks](frameworks/index.md) - Supported regulatory frameworks
- [Architecture](architecture.md) - How scanning and assessment works
- [Security](security.md) - Transport, input validation, IAM policy
- [Contributing a Framework](contributing.md) - How to add a new compliance framework
