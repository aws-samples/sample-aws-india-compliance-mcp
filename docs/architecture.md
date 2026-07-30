# Architecture

## How Scanning Works

1. **AWS Config Advanced Query** pulls resource configurations in a single API call. If no aggregator name is provided, the scanner auto-discovers organization-level aggregators for org-wide coverage.

2. **Property extraction** reads compliance-relevant fields per resource type (encryption, public access, logging, retention, key rotation, TLS enforcement, VPC flow logs, security group rules, secrets rotation, backup plans).

3. **Fallback API checks** cover Security Hub, GuardDuty, CloudTrail, WAF, AWS Backup, Shield, Network Firewall, Macie, Inspector, and IAM Access Analyzer.

4. **Assessment engine** evaluates each resource against applicable control domains from active frameworks.

5. **Compact summary** returned with posture scores, gap counts, top critical findings, and a remediation timeline. Full gap details cached in memory.

6. **Drill-down** via `get_compliance_gaps` with filtering by framework, risk level, or domain with pagination.

## Data Flow

```
MCP Client (Kiro / Claude / Cursor)
    |
    |  stdio or streamable-http
    v
server.py --- MCP tool registration, JSON serialization
    |
    +-- aws_scanner.py    -- AWS Config queries + fallback API calls
    +-- control_tower.py  -- Control Tower landing zone + guardrail enumeration
    +-- parsers.py        -- CloudFormation / Terraform / draw.io parsing
    +-- assessment.py     -- Rule engine: per-resource compliance checks + declarative evaluator
    +-- knowledge.py      -- Live regulatory text search + fallback
    +-- framework_registry.py -- Auto-discovers framework YAML definitions
    |       |
    |       +-- frameworks/dpdp.yaml, rbi.yaml, sebi.yaml, certin.yaml
    |
    +-- domains.py        -- Domain definitions + staleness check
    +-- control_mappings.json -- Compiled manifest (auto-generated from YAMLs)
```

## Plugin Architecture

Each compliance framework is defined in a single YAML file under `src/aws_india_compliance/frameworks/`. The `framework_registry.py` module auto-discovers all YAML files at startup and provides accessor functions used by all other modules.

Adding a new framework requires no Python code changes. Drop a YAML file and the server picks it up.

## Resource Checks

| Resource | What Gets Checked |
|----------|-------------------|
| S3 | Encryption at rest, lifecycle policies, Block Public Access, versioning, access logging, Object Lock, TLS enforcement |
| RDS | Storage encryption, public accessibility, Multi-AZ, audit logging, SSL enforcement |
| DynamoDB | KMS encryption, TTL, point-in-time recovery |
| Lambda | Secrets in environment variables, dead letter queue |
| EC2 | Public IP assignment, IMDSv2 enforcement, EBS encryption |
| EKS | Secrets envelope encryption, API server endpoint visibility, control plane logging |
| ECS | Container Insights |
| CloudTrail | Log file validation, KMS encryption, CloudWatch Logs integration |
| KMS | Automatic key rotation, BYOK verification (SEBI) |
| API Gateway | WAF association |
| CloudFront | WAF association, access logging |
| SQS/SNS | Encryption at rest |
| SageMaker | Direct internet access, KMS encryption, VPC configuration |
| IAM Roles | Overprivileged policies (AdministratorAccess, PowerUserAccess, IAMFullAccess) |
| VPC | Flow Logs enablement and destination |
| Security Groups | Open SSH (22) and RDP (3389) to 0.0.0.0/0 |
| Secrets Manager | Automatic rotation configuration |
| AWS Backup | Backup plan existence, Vault Lock status |
| Amazon Inspector | Enablement status (SEBI VAPT requirement) |

## Key Design Decisions

- **Mappings are static, not AI-generated.** Every compliance rule is hand-curated. Output is deterministic and auditable.
- **No vector database or embeddings.** Regulatory text search uses simple word overlap. Zero ML dependencies.
- **Binary domain scoring is intentionally simple.** The gap list provides granularity; the score provides the headline.
- **Organizational domains are auto-satisfied.** They require human assessment, not infrastructure checks.
- **Fallback-first resilience.** Live regulatory search falls back to bundled mappings when sites are unreachable.
- **Read-only by design.** All API calls are read operations. No AWS resources are modified.

## Confidence Scoring

Every compliance gap includes a confidence level:

- **High** -- Direct technical check verifiable from AWS Config (encryption disabled, public access enabled)
- **Medium** -- Interpretive mapping from regulatory requirement to AWS control (data localization)
- **Low** -- Organizational requirement where infrastructure is only a proxy (DPO appointment, consent tracking)

Each gap also carries `evidence` (triggering property values), `checked_at` (ISO 8601 timestamp), and `confidence_rationale`.
