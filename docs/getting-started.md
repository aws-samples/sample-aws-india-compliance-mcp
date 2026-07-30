# Getting Started

## Installation

No installation required. Add to your MCP client config and `uvx` handles the rest:

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

If you use a named AWS profile, pass it explicitly:

```json
{
  "mcpServers": {
    "aws-india-compliance": {
      "command": "uvx",
      "args": ["aws-india-compliance@latest"],
      "env": {
        "AWS_PROFILE": "my-sso-profile"
      }
    }
  }
}
```

Add the config to your MCP client's settings file:

- **Kiro**: `.kiro/settings/mcp.json`
- **Claude Desktop**: `claude_desktop_config.json`
- **Claude Code**: `~/.claude/mcp.json`

**Requires [`uv`](https://docs.astral.sh/uv/getting-started/installation/) installed. On macOS: `brew install uv`**

## AWS Credentials

The server needs read-only AWS access. Use **AWS IAM Identity Center (SSO)** for teams.

**First-time SSO setup:**
```bash
aws configure sso
```

Follow the prompts:
- SSO session name: `my-sso` (any name)
- SSO start URL: your org's SSO URL
- SSO region: `us-east-1` (or wherever your Identity Center is)
- It opens a browser for sign-in and authorization
- Select the account and role (for example `ReadOnlyAccess`)
- CLI profile name: `my-sso-profile`

**Login before each session:**
```bash
aws sso login --profile my-sso-profile
```

**Verify it works:**
```bash
aws sts get-caller-identity --profile my-sso-profile
```

**Alternative: static credentials (not recommended for teams)**

If you have long-lived access keys in `~/.aws/credentials`, those work too, but SSO is preferred for security.

## Prerequisites

- Python 3.10+
- AWS Config recorder enabled in target accounts/regions
- IAM credentials with read-only access (see [Security](security.md) for the IAM policy)
- For org-wide scans: a Config Aggregator (auto-discovered, or pass name explicitly)

## Verification

Ask your MCP client:

> "List the DPDP control domains"

If it returns 10 domains, you are set. To scan your AWS account:

> "Scan my AWS account in ap-south-1 for DPDP and RBI compliance"

## Install from Source (Development)

```bash
git clone https://github.com/aws-samples/sample-aws-india-compliance-mcp.git
cd sample-aws-india-compliance-mcp
pip install -e .
```

Then configure your MCP client to use the local install:
```json
{
  "mcpServers": {
    "aws-india-compliance": {
      "command": "aws-india-compliance",
      "env": {
        "AWS_PROFILE": "my-sso-profile"
      }
    }
  }
}
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `AWS_PROFILE` | (none) | AWS SSO profile name |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `REGULATORY_CACHE_TTL` | `0` | Seconds to cache regulatory site responses. 0 = no caching. |
| `STALENESS_THRESHOLD_DAYS` | `30` | Days after last_verified before staleness warnings appear. |
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio` for local, `streamable-http` for remote |
| `MCP_HOST` | `127.0.0.1` | Host for HTTP transport |
| `MCP_PORT` | `8000` | Port for HTTP transport (validated 1-65535) |
| `REPORT_DIR` | `reports/` | Directory for persisted reports (only used when `save_to_file=True`). |
