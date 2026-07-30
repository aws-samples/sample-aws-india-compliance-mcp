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

# Fill in domains (use your LLM to read the regulation and generate the YAML)

# Auto-suggest checks from config_rules you defined
python scripts/scaffold_framework.py --suggest-checks src/aws_india_compliance/frameworks/gdpr.yaml

# Validate
python scripts/scaffold_framework.py --validate src/aws_india_compliance/frameworks/gdpr.yaml

# Rebuild manifest
python scripts/build_manifest.py

# Run tests
PYTHONPATH=src python -m pytest tests/ -v

# Submit PR
git checkout -b add-framework-gdpr
git add src/aws_india_compliance/frameworks/gdpr.yaml
git commit -m "feat: add GDPR compliance framework"
git push origin add-framework-gdpr
```

## What Happens After You Submit a PR

1. **CI validates your YAML** automatically (schema, domain fields, check structure, Config rule formats)
2. **Maintainers review** the PR for domain accuracy, correct regulatory citations, and Config rule validity
3. **Once merged to main**, GitHub Actions automatically:
    - Validates all framework YAMLs
    - Rebuilds `control_mappings.json` from all YAMLs
    - Regenerates framework documentation pages
    - Updates the README "Supported Frameworks" list
    - Deploys updated documentation site
4. **Next PyPI release** includes your framework (maintainers handle version bumps and publishing)

You do not need to run any update scripts manually. All post-merge automation is handled by CI.

## What Works Automatically After Merge

Once your YAML is in `src/aws_india_compliance/frameworks/` on main:

1. `list_control_domains("your_id")` returns your domains
2. `generate_conformance_pack("your_id")` generates a Config pack
3. `search_regulatory_text(query, "your_id")` searches your source URLs
4. `scan_aws_account(...)` evaluates your declarative checks
5. `admin check` monitors your circular_sources for updates
6. Framework docs are live on the documentation site
7. README shows your framework in the supported list
