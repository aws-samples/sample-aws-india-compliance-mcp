# Digital Personal Data Protection Act 2023 + Rules 2025

| Property | Value |
|----------|-------|
| **ID** | `dpdp` |
| **Version** | Act 2023 + Rules notified November 14, 2025 |
| **Source** | [https://www.meity.gov.in/data-protection-framework](https://www.meity.gov.in/data-protection-framework) |
| **Last Verified** | 2026-07-30 |
| **Activation** | always |
| **Domains** | 10 |
| **Declarative Checks** | 16 |
| **Default Penalty** | Up to INR 50 Crore |

## Control Domains

| # | Domain | Section | Type |
|---|--------|---------|------|
| 1 | Lawful Processing and Consent Management | Act Sections 4-6, Rules 4 | organizational |
| 2 | Data Minimization | Act Section 4(2) | organizational |
| 3 | Privacy Notices | Act Section 5, Rule 3 | organizational |
| 4 | Data Principal Rights | Act Sections 11-14, Rules 5, 9 | organizational |
| 5 | Breach Notification | DPDP Act Section 8(5), Rules 2025 Rule 7 (7.1.a-e: breach nature, risks, affected categories, mitigation measures, contact details) | technical |
| 6 | Reasonable Security Safeguards | DPDP Act Section 8(4), Rules 2025 Rule 6 (6.1.a-g: unauthorized access prevention, confidentiality, integrity, encryption, anonymization, access controls, monitoring) | technical |
| 7 | Data Retention Limits | Act Section 8(6), Rule 8 | technical |
| 8 | Cross-Border Data Transfer | Act Sections 16-17, Rules 14-15 | organizational |
| 9 | Children's Data Protection | Act Section 9, Rules 10-12 | organizational |
| 10 | Significant Data Fiduciary Obligations | Act Section 10, Rule 13 | organizational |

## AWS Controls by Domain

### Domain 1: Lawful Processing and Consent Management

**AWS Services:**
- Amazon Cognito consent tracking
- Custom consent management via DynamoDB/S3
- Consent Manager integration via API Gateway
- DynamoDB for 7-year consent record retention

### Domain 2: Data Minimization

**AWS Services:**
- S3 lifecycle policies
- DynamoDB TTL
- Data retention automation

### Domain 3: Privacy Notices

**AWS Services:**
- API Gateway for consent withdrawal endpoints
- Lambda for automated rights exercise

### Domain 4: Data Principal Rights

**AWS Services:**
- API Gateway for data subject requests
- Lambda for automated responses
- S3 for data portability exports
- Step Functions for rights request workflows

### Domain 5: Breach Notification

**AWS Services:**
- GuardDuty
- Security Hub
- CloudTrail
- EventBridge for automated alerting
- SNS for dual notification (DPB + Data Principals)
- Lambda for automated breach report generation

**Config Rules:**
- `guardduty-enabled-centralized`
- `securityhub-enabled`
- `cloud-trail-cloud-watch-logs-enabled`
- `cloudtrail-enabled`
- `cloud-trail-log-file-validation-enabled`
- `cloudwatch-log-group-encrypted`

**Control Tower Guardrails:**
- `AWS-GR_CLOUDTRAIL_ENABLED`
- `AWS-GR_CLOUDTRAIL_VALIDATION_ENABLED`
- `AWS-GR_AUDIT_BUCKET_LOGGING_ENABLED`
- `AWS-GR_LOG_GROUP_ENCRYPTED`

### Domain 6: Reasonable Security Safeguards

**AWS Services:**
- KMS encryption
- S3 Block Public Access
- IAM least privilege
- VPC network isolation
- WAF
- Shield
- CloudWatch Logs with 1-year retention for access logs
- AWS Backup for continuity measures
- Macie for data masking and classification

**Config Rules:**
- `encrypted-volumes`
- `rds-storage-encrypted`
- `s3-bucket-server-side-encryption-enabled`
- `s3-bucket-ssl-requests-only`
- `s3-bucket-public-read-prohibited`
- `s3-bucket-public-write-prohibited`
- `s3-account-level-public-access-blocks-periodic`
- `rds-instance-public-access-check`
- `ec2-instance-no-public-ip`
- `lambda-function-public-access-prohibited`
- `eks-secrets-encrypted`
- `eks-endpoint-no-public-access`
- `elasticsearch-encrypted-at-rest`
- `sns-encrypted-kms`
- `redshift-cluster-configuration-check`
- `cloud-trail-encryption-enabled`
- `cmk-backing-key-rotation-enabled`
- `ec2-imdsv2-check`
- `iam-policy-no-statements-with-admin-access`
- `iam-root-access-key-check`
- `mfa-enabled-for-iam-console-access`
- `root-account-mfa-enabled`
- `secretsmanager-rotation-enabled-check`
- `restricted-ssh`
- `vpc-flow-logs-enabled`
- `cw-loggroup-retention-period-check`
- `s3-bucket-logging-enabled`

**Control Tower Guardrails:**
- `AWS-GR_ENCRYPTED_VOLUMES`
- `AWS-GR_RDS_STORAGE_ENCRYPTED`
- `AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED`
- `AWS-GR_S3_BUCKET_PUBLIC_WRITE_PROHIBITED`
- `AWS-GR_RESTRICT_ROOT_USER`
- `AWS-GR_MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS`
- `AWS-GR_EC2_INSTANCE_NO_PUBLIC_IP`
- `AWS-GR_LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED`
- `AWS-GR_AUDIT_BUCKET_ENCRYPTION_ENABLED`
- `AWS-GR_S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC`

### Domain 7: Data Retention Limits

**AWS Services:**
- S3 lifecycle policies
- DynamoDB TTL
- Backup retention policies
- S3 Object Lock for mandatory log retention
- EventBridge + Lambda for 48-hour erasure warnings
- CloudWatch Logs 1-year minimum retention

**Config Rules:**
- `s3-lifecycle-policy-check`
- `dynamodb-table-encrypted-kms`
- `dynamodb-pitr-enabled`
- `s3-bucket-versioning-enabled`
- `db-instance-backup-enabled`
- `cw-loggroup-retention-period-check`

**Control Tower Guardrails:**
- `AWS-GR_AUDIT_BUCKET_RETENTION_POLICY`

### Domain 8: Cross-Border Data Transfer

**AWS Services:**
- Region deny SCPs
- S3 replication controls

**Config Rules:**
- `ebs-snapshot-public-restorable-check`
- `rds-snapshots-public-prohibited`

**Control Tower Guardrails:**
- `AWS-GR_REGION_DENY`
- `AWS-GR_DISALLOW_CROSS_REGION_NETWORKING`

### Domain 9: Children's Data Protection

**AWS Services:**
- Age verification via Cognito
- Parental consent workflows
- Virtual identity token verification
- Step Functions for parental consent orchestration

### Domain 10: Significant Data Fiduciary Obligations

**AWS Services:**
- Audit Manager for annual DPIA
- AWS Config for continuous compliance
- SageMaker model monitoring for algorithmic assessments
- Inspector for independent security audits

## Assessment Checks

This framework has **16 declarative checks** 
(13 resource-level, 3 architecture-level).

| Type | Match | Domain | Risk | Gap |
|------|-------|--------|------|-----|
| Resource | `S3::Bucket` | 6 | high | S3 bucket lacks encryption at rest |
| Resource | `S3::Bucket` | 6 | high | S3 public access not fully blocked |
| Resource | `S3::Bucket` | 7 | medium | S3 bucket lacks lifecycle or retention policy |
| Resource | `RDS::DB` | 6 | high | RDS instance not encrypted at rest |
| Resource | `RDS::DB` | 6 | critical | RDS instance is publicly accessible |
| Resource | `DynamoDB::Table` | 6 | high | DynamoDB table not encrypted with KMS |
| Resource | `EC2::Instance` | 6 | high | EC2 instance has a public IP address |
| Resource | `EC2::Instance` | 6 | high | EC2 instance does not enforce IMDSv2 |
| Resource | `Lambda::Function` | 6 | high | Lambda function has public access |
| Resource | `EKS::Cluster` | 6 | high | EKS cluster secrets not encrypted |
| Resource | `EKS::Cluster` | 6 | high | EKS cluster API endpoint is publicly accessible |
| Resource | `CloudTrail::Trail` | 5 | high | CloudTrail log file validation is disabled |
| Resource | `Logs::LogGroup` | 7 | medium | CloudWatch log group retention is less than 1 year |
| Architecture | `guardduty` | 5 | critical | No GuardDuty enabled for breach detection |
| Architecture | `securityhub` | 5 | critical | No Security Hub for centralized security findings |
| Architecture | `kms` | 6 | high | No KMS keys found for encryption key management |

## Regulatory Monitoring

**Search Sources:**
- https://www.meity.gov.in/data-protection-framework

**Monitoring Keywords:**
`data protection, personal data, dpdp, privacy, consent, data principal, data fiduciary, breach notification`

## Implementation Notes

**Domain 1 (Lawful Processing and Consent Management):** Rule 4 introduces Consent Manager framework: must be India-incorporated, INR 2Cr net worth, interoperable platform, 7-year consent record retention, no subcontracting. Registration with DPB required by Nov 2026.

**Domain 3 (Privacy Notices):** Rule 3 mandates standalone notices with: itemized list of personal data collected, specific processing purposes, direct links for consent withdrawal, rights exercise, and complaint filing. Effective May 2027.

**Domain 4 (Data Principal Rights):** Rules require specific mechanisms for Data Principals to withdraw consent, exercise rights, and file complaints. Must provide website link or app process.

**Domain 5 (Breach Notification):** Rule 7 is stricter than the Act alone: NO threshold for breach reporting (any breach must be reported). Dual notification required: (1) immediate notice to affected Data Principals with breach details, consequences, mitigation steps; (2) immediate intimation to DPB + detailed report within 72 hours. Penalties up to INR 200 crores.

**Domain 6 (Reasonable Security Safeguards):** Rule 6 makes safeguards PRESCRIPTIVE (not just reasonable): mandatory encryption, masking, obfuscation, tokenization. Mandatory access controls, activity logs, continuity measures (backups). ONE-YEAR mandatory retention of unauthorized access logs. Data Processor agreements must include mandatory security clauses. These are minimum standards.

**Domain 7 (Data Retention Limits):** Rule 8 adds prescriptive requirements: erasure when user disengages (per Third Schedule categories), 48-hour warning before erasure, 1-year minimum log retention. Large-scale Data Fiduciaries (e-commerce 20M+, gaming 5M+, social media 20M+ Indian users) must erase after 3 years except for account access or legal compliance.

**Domain 8 (Cross-Border Data Transfer):** Rules adopt blacklist approach (more lenient than GDPR): data may generally be transferred outside India. Restrictions only for government-designated blacklisted countries/entities. No blacklist published yet as of April 2026. SDFs may face additional data localization requirements per Rule 13.

**Domain 9 (Children's Data Protection):** Rules 10-12 require verifiable parental consent using: identity data, voluntarily provided details, or authorized virtual identity tokens. Schools, healthcare, and childcare services get targeted exemptions. Age threshold is 18 (not 16 as in GDPR).

**Domain 10 (Significant Data Fiduciary Obligations):** Rule 13 makes obligations prescriptive: mandatory annual DPIAs and independent audits. Algorithmic assessments required, must ensure technical measures (including algorithmic software) do not pose risk to Data Principal rights. Data localization for government-notified categories. Must submit reports to DPB. No SDFs designated yet as of April 2026.

*Auto-generated on 2026-07-30 from `frameworks/dpdp.yaml`.*
