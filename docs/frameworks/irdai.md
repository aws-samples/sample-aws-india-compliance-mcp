# IRDAI Information and Cyber Security Guidelines 2023

| Property | Value |
|----------|-------|
| **ID** | `irdai` |
| **Version** | IRDAI/GA&HR/GDL/MISC/88/04/2023 (April 24, 2023) |
| **Source** | [https://irdai.gov.in](https://irdai.gov.in) |
| **Last Verified** | 2026-07-30 |
| **Activation** | opt_in |
| **Activation Param** | `is_irdai_regulated` |
| **Domains** | 12 |
| **Declarative Checks** | 27 |
| **Default Penalty** | As per Insurance Act 1938 and IRDAI enforcement framework |

## Control Domains

| # | Domain | Section | Type |
|---|--------|---------|------|
| 1 | Information Security Governance | Chapter 1 - Governance Structure | organizational |
| 2 | Data Classification and Protection | Section 2.1 - Data Classification | technical |
| 3 | Asset Management | Section 2.2 - Asset Management | technical |
| 4 | Access Control | Section 2.3 - Access Control | technical |
| 5 | Human Resource Security | Section 2.4 - Human Resource Security | organizational |
| 6 | Information Systems Acquisition and Development | Section 2.5 - IS Acquisition and Development | technical |
| 7 | Information Systems Maintenance | Section 2.6 - IS Maintenance | technical |
| 8 | Mobile and BYOD Security | Sections 2.7-2.8 - Mobile Security and BYOD | organizational |
| 9 | Incident and Problem Management | Section 2.10 - Incident Management | technical |
| 10 | Network Security | Section 2.11 - Network Security | technical |
| 11 | Cryptographic Controls | Section 2.12 - Cryptographic Controls | technical |
| 12 | Audit and Compliance | Chapter 3 - Audit Requirements | technical |

## AWS Controls by Domain

### Domain 1: Information Security Governance

**AWS Services:**
- AWS Organizations
- Control Tower
- IAM Identity Center
- Audit Manager

### Domain 2: Data Classification and Protection

**AWS Services:**
- Macie for data discovery
- S3 Object Tagging
- KMS encryption
- S3 Block Public Access

**Config Rules:**
- `s3-bucket-server-side-encryption-enabled`
- `s3-bucket-public-read-prohibited`
- `s3-bucket-public-write-prohibited`
- `rds-storage-encrypted`
- `dynamodb-table-encrypted-kms`

**Control Tower Guardrails:**
- `AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED`
- `AWS-GR_S3_BUCKET_PUBLIC_WRITE_PROHIBITED`
- `AWS-GR_ENCRYPTED_VOLUMES`

### Domain 3: Asset Management

**AWS Services:**
- AWS Config
- Systems Manager Inventory
- Resource Groups
- Service Catalog

**Config Rules:**
- `ec2-instance-managed-by-systems-manager`
- `ec2-stopped-instance`
- `ec2-volume-inuse-check`

### Domain 4: Access Control

**AWS Services:**
- IAM
- IAM Identity Center
- MFA
- Secrets Manager
- KMS

**Config Rules:**
- `iam-policy-no-statements-with-admin-access`
- `iam-root-access-key-check`
- `mfa-enabled-for-iam-console-access`
- `root-account-mfa-enabled`
- `iam-user-mfa-enabled`
- `access-keys-rotated`
- `iam-password-policy`
- `secretsmanager-rotation-enabled-check`

**Control Tower Guardrails:**
- `AWS-GR_RESTRICT_ROOT_USER`
- `AWS-GR_MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS`
- `AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS`

### Domain 5: Human Resource Security

**AWS Services:**
- IAM Identity Center for lifecycle management
- CloudTrail for activity monitoring

### Domain 6: Information Systems Acquisition and Development

**AWS Services:**
- CodePipeline
- CodeBuild
- Inspector for vulnerability scanning
- ECR image scanning

**Config Rules:**
- `ec2-imdsv2-check`
- `eks-secrets-encrypted`
- `eks-endpoint-no-public-access`

**Control Tower Guardrails:**
- `AWS-GR_EC2_INSTANCE_NO_PUBLIC_IP`
- `AWS-GR_LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED`

### Domain 7: Information Systems Maintenance

**AWS Services:**
- Systems Manager Patch Manager
- Inspector
- AWS Backup

**Config Rules:**
- `ec2-instance-managed-by-systems-manager`
- `db-instance-backup-enabled`
- `s3-bucket-versioning-enabled`
- `rds-multi-az-support`

### Domain 8: Mobile and BYOD Security

**AWS Services:**
- AWS WorkSpaces
- Device Farm for testing

### Domain 9: Incident and Problem Management

**AWS Services:**
- GuardDuty
- Security Hub
- EventBridge
- SNS
- Lambda
- Systems Manager Incident Manager

**Config Rules:**
- `guardduty-enabled-centralized`
- `securityhub-enabled`
- `cloudwatch-alarm-action-check`

**Control Tower Guardrails:**
- `AWS-GR_CLOUDTRAIL_ENABLED`

### Domain 10: Network Security

**AWS Services:**
- VPC
- Security Groups
- Network Firewall
- WAF
- Shield
- VPC Flow Logs

**Config Rules:**
- `vpc-flow-logs-enabled`
- `restricted-ssh`
- `ec2-instances-in-vpc`
- `ec2-instance-no-public-ip`
- `lambda-function-public-access-prohibited`

**Control Tower Guardrails:**
- `AWS-GR_EC2_INSTANCE_NO_PUBLIC_IP`
- `AWS-GR_LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED`
- `AWS-GR_SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED`

### Domain 11: Cryptographic Controls

**AWS Services:**
- KMS
- ACM
- CloudHSM
- S3 SSE-KMS

**Config Rules:**
- `encrypted-volumes`
- `rds-storage-encrypted`
- `s3-bucket-server-side-encryption-enabled`
- `s3-bucket-ssl-requests-only`
- `cmk-backing-key-rotation-enabled`
- `kms-cmk-not-scheduled-for-deletion`

**Control Tower Guardrails:**
- `AWS-GR_ENCRYPTED_VOLUMES`
- `AWS-GR_RDS_STORAGE_ENCRYPTED`
- `AWS-GR_AUDIT_BUCKET_ENCRYPTION_ENABLED`

### Domain 12: Audit and Compliance

**AWS Services:**
- CloudTrail
- CloudWatch Logs
- S3 access logging
- Audit Manager
- Config

**Config Rules:**
- `cloudtrail-enabled`
- `cloud-trail-log-file-validation-enabled`
- `cloud-trail-encryption-enabled`
- `cloudwatch-log-group-encrypted`
- `s3-bucket-logging-enabled`
- `cw-loggroup-retention-period-check`

**Control Tower Guardrails:**
- `AWS-GR_CLOUDTRAIL_ENABLED`
- `AWS-GR_CLOUDTRAIL_VALIDATION_ENABLED`
- `AWS-GR_AUDIT_BUCKET_LOGGING_ENABLED`
- `AWS-GR_LOG_GROUP_ENCRYPTED`
- `AWS-GR_AUDIT_BUCKET_RETENTION_POLICY`

## Assessment Checks

This framework has **27 declarative checks** 
(23 resource-level, 4 architecture-level).

| Type | Match | Domain | Risk | Gap |
|------|-------|--------|------|-----|
| Resource | `S3::Bucket` | 2 | high | S3 bucket lacks encryption at rest |
| Resource | `S3::Bucket` | 2 | high | S3 bucket allows public read access |
| Resource | `RDS::DB` | 2 | high | RDS instance not encrypted at rest |
| Resource | `DynamoDB::Table` | 2 | high | DynamoDB table not encrypted with KMS |
| Resource | `IAM::Role` | 4 | critical | IAM role has admin-level access policy |
| Resource | `IAM::Role` | 4 | high | MFA not enabled for IAM console access |
| Resource | `SecretsManager::Secret` | 4 | medium | Secrets Manager secret rotation not configured |
| Resource | `EC2::Instance` | 6 | high | EC2 instance does not enforce IMDSv2 |
| Resource | `EKS::Cluster` | 6 | high | EKS cluster secrets not encrypted |
| Resource | `EKS::Cluster` | 6 | high | EKS cluster API endpoint is publicly accessible |
| Resource | `RDS::DB` | 7 | medium | RDS instance backups not enabled |
| Resource | `S3::Bucket` | 7 | medium | S3 bucket lacks versioning for data recovery |
| Resource | `RDS::DB` | 7 | medium | RDS instance not configured for Multi-AZ |
| Architecture | `guardduty` | 9 | critical | GuardDuty not enabled for threat detection |
| Architecture | `securityhub` | 9 | critical | Security Hub not enabled for centralized findings |
| Architecture | `vpc` | 10 | high | VPC Flow Logs not enabled |
| Resource | `EC2::SecurityGroup` | 10 | high | Security group allows SSH from 0.0.0.0/0 |
| Resource | `EC2::Instance` | 10 | high | EC2 instance has a public IP address |
| Resource | `Lambda::Function` | 10 | high | Lambda function has public access |
| Resource | `EC2::Instance` | 11 | high | EBS volumes not encrypted at rest |
| Resource | `S3::Bucket` | 11 | high | S3 bucket does not enforce TLS for requests |
| Resource | `KMS::Key` | 11 | medium | KMS customer-managed key automatic rotation not enabled |
| Architecture | `cloudtrail` | 12 | critical | CloudTrail is not enabled |
| Resource | `CloudTrail::Trail` | 12 | high | CloudTrail log file validation is disabled |
| Resource | `CloudTrail::Trail` | 12 | high | CloudTrail logs not encrypted with KMS |
| Resource | `S3::Bucket` | 12 | medium | S3 bucket lacks access logging |
| Resource | `Logs::LogGroup` | 12 | medium | CloudWatch log group retention below 180 days |

## Regulatory Monitoring

**Search Sources:**
- https://irdai.gov.in

**Circular Sources:**
- https://irdai.gov.in

**Monitoring Keywords:**
`information security, cyber security, data protection, insurance, CISO, incident reporting, VAPT, cryptographic, access control`

## Implementation Notes

**Domain 1 (Information Security Governance):** Requires Board of Directors oversight, Risk Management Committee, and Information Security Risk Management Committee (ISRMC) with CTO, CISO, CRO, CSO, and CHRO. Annual board-approved security policy.

**Domain 5 (Human Resource Security):** Covers pre-employment screening, security awareness training, role-based access provisioning, and termination procedures.

**Domain 7 (Information Systems Maintenance):** Covers patching, change management, backup and recovery procedures. Annual VAPT by external auditors is mandatory.

**Domain 8 (Mobile and BYOD Security):** Covers mobile device management, BYOD policies, containerization of corporate data on personal devices.

**Domain 9 (Incident and Problem Management):** Mandatory 6-hour cyber incident reporting to CERT-In with copy to IRDAI. Incident response plan must be tested annually.

**Domain 12 (Audit and Compliance):** Audit report must be submitted to IRDAI within 90 days of financial year end or 30 days of audit completion, whichever is earlier. Annual IS audit by CERT-In empanelled auditor is mandatory.

*Auto-generated on 2026-07-30 from `frameworks/irdai.yaml`.*
