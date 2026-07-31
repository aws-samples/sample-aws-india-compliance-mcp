# CERT-In Directions on Information Security Practices 2022

| Property | Value |
|----------|-------|
| **ID** | `certin` |
| **Version** | Directions dated April 28, 2022 |
| **Source** | [https://www.cert-in.org.in](https://www.cert-in.org.in) |
| **Last Verified** | 2026-06-30 |
| **Activation** | always |
| **Domains** | 8 |
| **Declarative Checks** | 6 |
| **Default Penalty** | As per IT Act Section 70B penalties |

## Control Domains

| # | Domain | Section | Type |
|---|--------|---------|------|
| 1 | Incident Reporting Readiness | Direction 1-3 | technical |
| 2 | Log Retention (180 days) | Direction 4 | technical |
| 3 | NTP Synchronization | Direction 5 | technical |
| 4 | Reportable Incident Awareness | Direction 6 | technical |
| 5 | DDoS and Bot Protection | CERT-In Directions 2022 - DDoS/Bot Attacks | technical |
| 6 | Network Security and DNS Protection | CERT-In Directions 2022 - Network Compromise | technical |
| 7 | Endpoint and Malware Protection | CERT-In Directions 2022 - Malware/Ransomware | technical |
| 8 | Data Leakage Prevention | CERT-In Directions 2022 - Data Breach/Leaks | technical |

## AWS Controls by Domain

### Domain 1: Incident Reporting Readiness

**AWS Services:**
- GuardDuty
- EventBridge
- SNS
- Lambda
- Security Hub

**Config Rules:**
- `guardduty-enabled-centralized`
- `securityhub-enabled`

**Control Tower Guardrails:**
- `AWS-GR_CLOUDTRAIL_ENABLED`

### Domain 2: Log Retention (180 days)

**AWS Services:**
- CloudWatch Logs
- S3 access logging
- CloudTrail

**Config Rules:**
- `cw-loggroup-retention-period-check`
- `cloudtrail-enabled`

**Control Tower Guardrails:**
- `AWS-GR_AUDIT_BUCKET_RETENTION_POLICY`

### Domain 3: NTP Synchronization

**AWS Services:**
- Amazon Time Sync Service (automatic on EC2/ECS/EKS)

### Domain 4: Reportable Incident Awareness

**AWS Services:**
- Security Hub
- GuardDuty
- Inspector
- Detective

**Config Rules:**
- `securityhub-enabled`
- `guardduty-enabled-centralized`

### Domain 5: DDoS and Bot Protection

**AWS Services:**
- AWS Shield Advanced
- AWS WAF Bot Control
- CloudFront

**Config Rules:**
- `shield-advanced-enabled-autorenew`

### Domain 6: Network Security and DNS Protection

**AWS Services:**
- AWS Network Firewall
- Route53 DNSSEC
- VPC Flow Logs

**Config Rules:**
- `vpc-flow-logs-enabled`
- `route53-dnssec-enabled`

### Domain 7: Endpoint and Malware Protection

**AWS Services:**
- GuardDuty Malware Protection
- Amazon Inspector
- SSM Patch Manager

**Config Rules:**
- `guardduty-malware-protection-enabled`

### Domain 8: Data Leakage Prevention

**AWS Services:**
- Macie
- S3 Block Public Access
- KMS Encryption
- CloudTrail Data Events

**Config Rules:**
- `s3-bucket-public-read-prohibited`
- `s3-bucket-public-write-prohibited`

**Control Tower Guardrails:**
- `AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED`
- `AWS-GR_S3_BUCKET_PUBLIC_WRITE_PROHIBITED`

## Assessment Checks

This framework has **6 declarative checks** 
(2 resource-level, 4 architecture-level).

| Type | Match | Domain | Risk | Gap |
|------|-------|--------|------|-----|
| Resource | `Logs::LogGroup` | 2 | high | CloudWatch log group retention is less than 180 days |
| Resource | `CloudTrail::Trail` | 1 | high | CloudTrail log file validation is disabled |
| Architecture | `guardduty` | 1 | critical | No GuardDuty for incident detection and reporting |
| Architecture | `securityhub` | 4 | high | No Security Hub for reportable incident awareness |
| Architecture | `shield` | 5 | high | No Shield Advanced for DDoS protection |
| Architecture | `networkfirewall` | 6 | high | No Network Firewall for network security |

## Regulatory Monitoring

**Circular Sources:**
- https://www.cert-in.org.in

**Monitoring Keywords:**
`cyber incident, incident reporting, log retention, ntp synchronization, data breach, malware, ransomware, ddos`

*Auto-generated on 2026-07-31 from `frameworks/certin.yaml`.*
