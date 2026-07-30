# Supported Compliance Frameworks

This project currently supports **5 regulatory frameworks**.
Each framework is defined in a single YAML file and auto-discovered at runtime.

## Framework Summary

| Framework | Domains | Checks | Type | Last Verified | Source |
|-----------|---------|--------|------|---------------|--------|
| [CERT-In Directions on Information Security Practices 2022](certin.md) | 8 | 6 | Always | 2026-06-30 | [Link](https://www.cert-in.org.in) |
| [Digital Personal Data Protection Act 2023 + Rules 2025](dpdp.md) | 10 | 16 | Always | 2026-07-30 | [Link](https://www.meity.gov.in/data-protection-framework) |
| [IRDAI Information and Cyber Security Guidelines 2023](irdai.md) | 12 | 27 | Opt-in | 2026-07-30 | [Link](https://irdai.gov.in) |
| [RBI Master Direction on IT Governance, Risk, Controls and Assurance Practices](rbi.md) | 7 | 16 | Opt-in | 2026-06-30 | [Link](https://rbi.org.in/Scripts/BS_ViewMasterDirections.aspx) |
| [SEBI Cybersecurity and Cyber Resilience Framework (CSCRF) / Cloud Framework](sebi.md) | 6 | 10 | Opt-in | 2026-06-30 | [Link](https://www.sebi.gov.in/legal/circulars/aug-2024/cybersecurity-and-cyber-resilience-framework-cscrf-_85964.html) |

## Framework Types

- **Always**: Assessed on every scan automatically (DPDP, CERT-In)
- **Opt-in**: Assessed only when the user passes the activation flag (RBI, SEBI)

## Adding a New Framework

See [CONTRIBUTING_FRAMEWORKS.md](https://github.com/aws-samples/sample-aws-india-compliance-mcp/blob/main/CONTRIBUTING_FRAMEWORKS.md) for the full guide.

Quick start:
```bash
python scripts/scaffold_framework.py --new --id myframework --name "My Framework" --source-url "https://example.com"
```

*Auto-generated on 2026-07-30 from framework YAML definitions.*
