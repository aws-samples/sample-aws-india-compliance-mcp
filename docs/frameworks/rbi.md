# RBI Master Direction on IT Governance, Risk, Controls and Assurance Practices

| Property | Value |
|----------|-------|
| **ID** | `rbi` |
| **Version** | DoS.CO.CSITE.SEC.3/31.01.015/2023-24 (April 7, 2023) |
| **Source** | [https://rbi.org.in/Scripts/BS_ViewMasterDirections.aspx](https://rbi.org.in/Scripts/BS_ViewMasterDirections.aspx) |
| **Last Verified** | 2026-06-30 |
| **Activation** | opt_in |
| **Activation Param** | `is_rbi_regulated` |
| **Domains** | 7 |
| **Declarative Checks** | 16 |
| **Default Penalty** | As per RBI enforcement framework |

## Control Domains

| # | Domain | Section | Type |
|---|--------|---------|------|
| 1 | IT Governance and Oversight | Chapter I | organizational |
| 2 | IT Infrastructure and Service Management | Chapter II | technical |
| 3 | IT Risk Management | Chapter III | organizational |
| 4 | Information Security | Chapter IV | technical |
| 5 | Cyber Security | Chapter V | technical |
| 6 | Business Continuity and Disaster Recovery | Chapter VI | technical |
| 7 | Information Systems Audit | Chapter VII | technical |

## AWS Controls by Domain

### Domain 1: IT Governance and Oversight

**AWS Services:**
- AWS Organizations
- Control Tower
- Service Catalog

### Domain 2: IT Infrastructure and Service Management

**AWS Services:**
- Systems Manager
- CloudWatch
- Auto Scaling
- Lambda DLQ

**Config Rules:**
- `ec2-instance-managed-by-systems-manager`
- `ec2-stopped-instance`
- `ec2-volume-inuse-check`

**Control Tower Guardrails:**
- `AWS-GR_EBS_OPTIMIZED_INSTANCE`

### Domain 3: IT Risk Management

**AWS Services:**
- AWS Config
- Security Hub
- Inspector
- Audit Manager

### Domain 4: Information Security

**AWS Services:**
- KMS
- IAM
- S3 Block Public Access
- RDS encryption
- EBS encryption

**Config Rules:**
- `access-keys-rotated`
- `iam-password-policy`
- `iam-policy-no-statements-with-admin-access`
- `iam-root-access-key-check`
- `iam-user-mfa-enabled`
- `encrypted-volumes`
- `rds-storage-encrypted`
- `s3-bucket-server-side-encryption-enabled`
- `s3-bucket-public-read-prohibited`
- `kms-cmk-not-scheduled-for-deletion`

**Control Tower Guardrails:**
- `AWS-GR_ENCRYPTED_VOLUMES`
- `AWS-GR_RDS_STORAGE_ENCRYPTED`
- `AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED`
- `AWS-GR_RESTRICT_ROOT_USER`
- `AWS-GR_MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS`
- `AWS-GR_EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK`

### Domain 5: Cyber Security

**AWS Services:**
- GuardDuty
- WAF
- Shield
- Network Firewall
- VPC Flow Logs

**Config Rules:**
- `guardduty-enabled-centralized`
- `vpc-flow-logs-enabled`
- `restricted-ssh`
- `ec2-instances-in-vpc`

**Control Tower Guardrails:**
- `AWS-GR_EC2_INSTANCE_NO_PUBLIC_IP`
- `AWS-GR_LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED`
- `AWS-GR_SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED`

### Domain 6: Business Continuity and Disaster Recovery

**AWS Services:**
- AWS Backup
- S3 versioning
- RDS Multi-AZ
- DynamoDB PITR
- Cross-region replication

**Config Rules:**
- `db-instance-backup-enabled`
- `dynamodb-pitr-enabled`
- `s3-bucket-versioning-enabled`
- `rds-multi-az-support`

### Domain 7: Information Systems Audit

**AWS Services:**
- CloudTrail
- CloudWatch Logs
- S3 access logging
- Audit Manager

**Config Rules:**
- `cloudtrail-enabled`
- `cloud-trail-log-file-validation-enabled`
- `cloud-trail-encryption-enabled`
- `cloudwatch-log-group-encrypted`
- `s3-bucket-logging-enabled`

**Control Tower Guardrails:**
- `AWS-GR_CLOUDTRAIL_ENABLED`
- `AWS-GR_CLOUDTRAIL_VALIDATION_ENABLED`
- `AWS-GR_AUDIT_BUCKET_LOGGING_ENABLED`
- `AWS-GR_LOG_GROUP_ENCRYPTED`

## Assessment Checks

This framework has **16 declarative checks** 
(13 resource-level, 3 architecture-level).

| Type | Match | Domain | Risk | Gap |
|------|-------|--------|------|-----|
| Resource | `S3::Bucket` | 4 | high | S3 bucket lacks encryption at rest |
| Resource | `S3::Bucket` | 4 | high | S3 public access not blocked |
| Resource | `S3::Bucket` | 6 | medium | S3 bucket lacks versioning for data recovery |
| Resource | `S3::Bucket` | 7 | medium | S3 bucket lacks access logging |
| Resource | `RDS::DB` | 4 | high | RDS instance not encrypted at rest |
| Resource | `RDS::DB` | 4 | critical | RDS instance is publicly accessible |
| Resource | `RDS::DB` | 6 | medium | RDS instance not configured for Multi-AZ |
| Resource | `EC2::Instance` | 5 | high | EC2 instance has a public IP address |
| Resource | `EC2::Instance` | 4 | high | EC2 instance does not enforce IMDSv2 |
| Resource | `DynamoDB::Table` | 4 | high | DynamoDB table not encrypted with KMS |
| Resource | `DynamoDB::Table` | 6 | medium | DynamoDB table lacks point-in-time recovery |
| Resource | `CloudTrail::Trail` | 7 | high | CloudTrail log file validation is disabled |
| Resource | `Logs::LogGroup` | 7 | medium | CloudWatch log group retention is less than 180 days |
| Architecture | `guardduty` | 5 | critical | No GuardDuty enabled for cyber threat detection |
| Architecture | `cloudtrail` | 7 | critical | No CloudTrail for audit logging |
| Architecture | `waf` | 5 | high | No WAF for web application protection |

## Regulatory Monitoring

**Search Sources:**
- https://rbi.org.in/Scripts/BS_ViewMasterDirections.aspx

**Circular Sources:**
- https://rbi.org.in/Scripts/BS_CircularIndexDisplay.aspx

**Monitoring Keywords:**
`it governance, cyber security, information security, it risk, outsourcing, cloud, data localization, digital payment, master direction, csite, information technology`

*Auto-generated on 2026-07-31 from `frameworks/rbi.yaml`.*
