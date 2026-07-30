# Contributing a New Framework

This project uses a plugin architecture. Each compliance framework is defined in a single YAML file. No Python code changes needed to add a new framework.

For the full step-by-step guide with field reference, examples, and validation instructions, see:

[CONTRIBUTING_FRAMEWORKS.md](https://github.com/aws-samples/sample-aws-india-compliance-mcp/blob/main/CONTRIBUTING_FRAMEWORKS.md)

## Quick Start

```bash
# Generate skeleton
python scripts/scaffold_framework.py --new --id gdpr --name "EU GDPR" --source-url "https://gdpr-info.eu"

# With optional search/update-detection metadata
python scripts/scaffold_framework.py --new --id gdpr --name "EU GDPR" \
    --source-url "https://gdpr-info.eu" \
    --search-sources "https://gdpr-info.eu" \
    --circular-sources "https://edpb.europa.eu/our-work-tools/general-guidance" \
    --keywords "data protection,controller"

# Fill in domains, then auto-suggest checks
python scripts/scaffold_framework.py --suggest-checks src/aws_india_compliance/frameworks/gdpr.yaml

# Validate
python scripts/scaffold_framework.py --validate src/aws_india_compliance/frameworks/gdpr.yaml

# Rebuild manifest
python scripts/build_manifest.py

# Run tests
PYTHONPATH=src python -m pytest tests/ -v
```

## What Happens Automatically

Once your YAML is in `src/aws_india_compliance/frameworks/`:

1. `list_control_domains("your_id")` returns your domains
2. `generate_conformance_pack("your_id")` generates a Config pack
3. `search_regulatory_text(query, "your_id")` searches your source URLs
4. `scan_aws_account(...)` evaluates your declarative checks
5. `admin check` monitors your circular_sources for updates
6. Framework docs are auto-generated via `scripts/generate_framework_docs.py`
