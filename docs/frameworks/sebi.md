# SEBI Cybersecurity and Cyber Resilience Framework (CSCRF) / Cloud Framework

| Property | Value |
|----------|-------|
| **ID** | `sebi` |
| **Version** | Circular SEBI/HO/ITD/ITD-SEC-1/P/CIR/2024/113 (August 20, 2024) |
| **Source** | [https://www.sebi.gov.in/legal/circulars/aug-2024/cybersecurity-and-cyber-resilience-framework-cscrf-_85964.html](https://www.sebi.gov.in/legal/circulars/aug-2024/cybersecurity-and-cyber-resilience-framework-cscrf-_85964.html) |
| **Last Verified** | 2026-06-30 |
| **Activation** | opt_in |
| **Activation Param** | `is_sebi_regulated` |
| **Domains** | 6 |
| **Declarative Checks** | 10 |
| **Default Penalty** | As per SEBI adjudication guidelines |

## Control Domains

| # | Domain | Section | Type |
|---|--------|---------|------|
| 1 | Cyber Governance | Section 3.1 / Principle 1 | organizational |
| 2 | Cyber Risk Identification | Section 3.2 / Principle 2-3 | technical |
| 3 | Cyber Protection | Section 3.3 / Security IN the Cloud | technical |
| 4 | Cyber Detection | Section 3.4 / SOC Integration | technical |
| 5 | Cyber Response | Section 3.5 / Incident Management | technical |
| 6 | Cyber Recovery | Section 3.6 / BCP-DR | technical |

## AWS Controls by Domain

### Domain 1: Cyber Governance

**AWS Services:**
- AWS Organizations
- Control Tower
- Service Catalog
- Audit Manager

### Domain 2: Cyber Risk Identification

**AWS Services:**
- AWS Config
- Inspector
- Systems Manager
- Security Hub

**Config Rules:**
- `ec2-instance-managed-by-systems-manager`
- `ec2-stopped-instance`

### Domain 3: Cyber Protection

**AWS Services:**
- KMS (BYOK)
- IAM least privilege
- MFA
- Network segmentation
- WAF
- Shield
- VPC
- S3 encryption
- RDS encryption

**Config Rules:**
- `encrypted-volumes`
- `rds-storage-encrypted`
- `s3-bucket-server-side-encryption-enabled`
- `s3-bucket-public-read-prohibited`
- `iam-policy-no-statements-with-admin-access`
- `mfa-enabled-for-iam-console-access`
- `vpc-flow-logs-enabled`
- `restricted-ssh`

**Control Tower Guardrails:**
- `AWS-GR_ENCRYPTED_VOLUMES`
- `AWS-GR_RDS_STORAGE_ENCRYPTED`
- `AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED`
- `AWS-GR_S3_BUCKET_PUBLIC_WRITE_PROHIBITED`
- `AWS-GR_RESTRICT_ROOT_USER`
- `AWS-GR_MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS`
- `AWS-GR_EC2_INSTANCE_NO_PUBLIC_IP`

### Domain 4: Cyber Detection

**AWS Services:**
- GuardDuty
- Security Hub
- CloudWatch
- Detective
- SIEM integration

**Config Rules:**
- `guardduty-enabled-centralized`
- `securityhub-enabled`
- `cloudwatch-alarm-action-check`

### Domain 5: Cyber Response

**AWS Services:**
- EventBridge
- Lambda
- SNS
- Systems Manager Incident Manager

### Domain 6: Cyber Recovery

**AWS Services:**
- AWS Backup
- S3 versioning
- RDS Multi-AZ
- Cross-region replication
- DynamoDB PITR

**Config Rules:**
- `db-instance-backup-enabled`
- `dynamodb-pitr-enabled`
- `s3-bucket-versioning-enabled`

## Assessment Checks

This framework has **10 declarative checks** 
(8 resource-level, 2 architecture-level).

| Type | Match | Domain | Risk | Gap |
|------|-------|--------|------|-----|
| Resource | `S3::Bucket` | 3 | high | S3 bucket lacks encryption at rest |
| Resource | `S3::Bucket` | 3 | high | S3 public access not blocked |
| Resource | `RDS::DB` | 3 | high | RDS instance not encrypted at rest |
| Resource | `RDS::DB` | 3 | critical | RDS instance is publicly accessible |
| Resource | `EC2::Instance` | 3 | high | EC2 instance has a public IP address |
| Resource | `DynamoDB::Table` | 3 | high | DynamoDB table not encrypted with KMS |
| Resource | `DynamoDB::Table` | 6 | medium | DynamoDB table lacks point-in-time recovery |
| Resource | `Logs::LogGroup` | 4 | medium | CloudWatch log group retention is less than 1 year |
| Architecture | `guardduty` | 4 | critical | No GuardDuty enabled for cyber detection |
| Architecture | `securityhub` | 4 | critical | No Security Hub for centralized detection |

## Regulatory Monitoring

**Search Sources:**
- https://www.sebi.gov.in
- https://www.sebi.gov.in/sebiweb/home/HomeAction.do?doListing=yes&sid=3&ssid=27&smid=0

**Circular Sources:**
- https://www.sebi.gov.in/sebiweb/home/HomeAction.do?doListing=yes&sid=1&ssid=2&smid=0

**Monitoring Keywords:**
`cyber security, cyber resilience, cscrf, cloud framework, information security, soc, incident, data protection`

*Auto-generated on 2026-07-31 from `frameworks/sebi.yaml`.*
