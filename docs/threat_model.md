# Threat Model (Lab)

## Goal
Detect common attacker activity in AWS IAM using CloudTrail management events.

## Assets
- AWS account control plane (IAM, CloudTrail configuration)
- Credentials (access keys, sessions)
- Audit logs (CloudTrail events)

## Threats in scope
### Privilege escalation / persistence
- Create new IAM users
- Attach high-privilege policies (e.g., AdministratorAccess)
- Create access keys for persistence

### Defense evasion
- Disable CloudTrail logging (`StopLogging`)

## Data sources
- CloudTrail Management Events delivered to CloudWatch Logs

## Detections (current)
### Atomic
- `CreateUser` (LOW)
- `CreateAccessKey` (MEDIUM)
- `AttachUserPolicy` with AdministratorAccess (HIGH)
- `StopLogging` (CRITICAL)

### Correlation
- **PrivEscChain** (CRITICAL)
  - `CreateUser` + `AttachUserPolicy(Admin)` + `CreateAccessKey` within 15 minutes for the same target user

## Improvements (future)
- Add allowlists (break-glass roles, CI/CD principals)
- Add more IAM events (CreateLoginProfile, UpdateAssumeRolePolicy, PutUserPolicy)
- Add geo/ASN enrichment for source IP
- Emit findings to a SIEM or SNS/SQS instead of local JSON
