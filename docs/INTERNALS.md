# DriftShield — Features & Internal Working

## What DriftShield Does

DriftShield is a CLI security tool that does two things:
1. Scans AWS resources (S3, EC2, IAM, CloudTrail, VPC, RDS) for misconfigurations
2. Detects when those configurations change from a known-good state (drift) and optionally auto-remediates them

---

## Architecture Overview

```
CLI (Cobra)  →  Handlers in main.go  →  scanner/ or baseline/  →  AWS SDK  →  alerts/
```

The entry point is `cmd/driftshield/main.go`, which wires up all Cobra subcommands and delegates to internal packages. All shared data structures live in `internal/types/types.go`.

### Package Responsibilities

| Package | Responsibility |
|---|---|
| `cmd/driftshield` | CLI entry point, command wiring, output formatting |
| `internal/types` | Shared structs used across all packages |
| `internal/config` | Static configuration (region, SES, Slack, baseline paths) |
| `internal/scanner` | Live AWS scanning for S3, EC2, IAM, CloudTrail, VPC, and RDS risks |
| `internal/baseline` | Snapshot, compare, and remediate configuration drift |
| `internal/ai` | Generate custom YAML compliance policies interactively via Groq LLaMA 3 |
| `internal/alerts` | Send findings via AWS SES email, SNS, and Slack webhook |
| `internal/display` | Banner printing and port description helpers |
| `internal/policy` | Declarative Policy-as-Code engine for custom YAML rule evaluation |
| `tests` | Centralized unit test suite covering all internal components |

---

## Core Features & Internal Mechanics

### 1. S3 Security Scanning

**Command:** `driftshield s3`

**File:** `internal/scanner/s3.go`

**How it works:**
- Calls `ListBuckets` to get all S3 buckets in the account
- For each bucket, calls `GetPublicAccessBlock` to retrieve the 4 public access flags
- A bucket is marked **SECURE** only if all 4 flags are `true`:
  - `BlockPublicAcls`
  - `IgnorePublicAcls`
  - `BlockPublicPolicy`
  - `RestrictPublicBuckets`
- If any flag is `false`, or the configuration doesn't exist at all (`NoSuchPublicAccessBlockConfiguration`), the bucket is marked **AT RISK**
- At-risk buckets trigger alerts via SES, SNS, and Slack

---

### 2. EC2 Security Scanning

**Command:** `driftshield ec2`

**File:** `internal/scanner/ec2.go`

**How it works:**
- Calls `DescribeSecurityGroups` to fetch all security groups in the configured region
- For each security group, iterates every inbound rule (`IpPermissions`)
- A rule is flagged as risky if **both** conditions are true:
  1. The source CIDR is `0.0.0.0/0` (IPv4) or `::/0` (IPv6) — open to the internet
  2. The port matches a known risky port, or all traffic / all ports are open

**Severity levels:**

| Condition | Severity |
|---|---|
| All traffic (`protocol: -1`) | CRITICAL |
| All ports (`0–65535`) | CRITICAL |
| SSH (22), RDP (3389) | CRITICAL |
| MySQL, PostgreSQL, MongoDB, Redis, etc. | HIGH |

**Risky ports watched:** 22, 3389, 3306, 5432, 1433, 1521, 27017, 6379, 9200, 5900, 23, 21, 445, 135

---

### 3. IAM Security Scanning

**Command:** `driftshield iam`

**File:** `internal/scanner/iam.go`

**How it works:**
- Calls `GetAccountSummary` to check root account MFA and active root access keys
- Calls `GetAccountPasswordPolicy` to evaluate password policy strength
- Calls `ListUsers` then for each user:
  - `GetLoginProfile` — checks if console access is enabled
  - `ListMFADevices` — checks if MFA is configured
  - `ListAttachedUserPolicies` — checks for `AdministratorAccess`
  - `ListUserPolicies` + `GetUserPolicy` — checks inline policies for wildcard `Action: *`
  - `ListAccessKeys` + `GetAccessKeyLastUsed` — checks for stale or never-used keys (90+ days)

**Checks and severities:**

| Check | Severity |
|---|---|
| Root MFA disabled | CRITICAL |
| Root account has active access keys | CRITICAL |
| IAM user with console access but no MFA | HIGH |
| No account password policy | HIGH |
| User has `AdministratorAccess` attached | HIGH |
| Inline policy with wildcard `Action: *` | HIGH |
| Password length below 14 characters | MEDIUM |
| Password complexity not fully enforced | MEDIUM |
| Passwords never expire | MEDIUM |
| Access key unused for 90+ days | MEDIUM |
| Access key never used | MEDIUM |
| Password reuse prevention not configured | LOW |

**Fix behavior:** `driftshield iam fix` prints a manual remediation guide only — no AWS API calls are made. IAM auto-remediation is intentionally avoided to prevent locking out users or breaking applications.

---

### 4. CloudTrail Security Scanning

**Command:** `driftshield cloudtrail`

**File:** `internal/scanner/cloudtrail.go`

**How it works:**
- Calls `DescribeTrails` to list all trails in the account
- For each trail, calls `GetTrailStatus` to check if logging is active
- Calls `GetEventSelectors` to check if read events are captured
- Checks for at least one multi-region trail
- Checks log file validation is enabled

**Checks and severities:**

| Check | Severity |
|---|---|
| No trails configured | CRITICAL |
| Trail exists but logging is disabled | CRITICAL |
| No multi-region trail configured | HIGH |
| Log file validation disabled | MEDIUM |
| Only write events logged (read events missed) | LOW |

**Auto-fix scope:** `driftshield cloudtrail fix` auto-remediates only:
- `LOGGING_STATUS_CHANGED` → `StartLogging` or `StopLogging`
- `LOG_VALIDATION_CHANGED` → `UpdateTrail`

Trail added/deleted, S3 bucket changed, and event selector changes are skipped (manual action required).

---

### 5. VPC Security Scanning

**Command:** `driftshield vpc`

**File:** `internal/scanner/vpc.go`

**How it works:**
- Calls `DescribeVpcs` to list all VPCs in the region
- Calls `DescribeFlowLogs` once to build a map of which VPCs have flow logs
- For each VPC:
  - Checks if it is the default VPC
  - Checks if flow logs are enabled (using the pre-built map)
  - Calls `DescribeNetworkAcls` filtered by VPC ID — checks for NACL rules that allow all inbound traffic (`protocol: -1`) from `0.0.0.0/0` or `::/0`
  - Calls `DescribeSubnets` filtered by VPC ID — checks each subnet for `MapPublicIpOnLaunch`

**Checks and severities:**

| Check | Severity |
|---|---|
| Default VPC is in use | MEDIUM |
| VPC has no flow logs enabled | HIGH |
| NACL allows all inbound traffic from internet | HIGH |
| Subnet auto-assigns public IPs on launch | MEDIUM |

**Auto-fix scope:** `driftshield vpc fix` auto-remediates only:
- `SUBNET_PUBLIC_IP_CHANGED` → `ModifySubnetAttribute` to restore baseline `MapPublicIpOnLaunch` value

VPC added/deleted and flow log changes are skipped (manual action required).

---

### 6. RDS Security Scanning

**Command:** `driftshield rds`

**File:** `internal/scanner/rds.go`

**How it works:**
- Calls `DescribeDBInstances` to list all RDS instances in the region
- For each instance checks 4 security properties directly from the `DBInstance` struct

**Checks and severities:**

| Check | Severity |
|---|---|
| Instance is publicly accessible (`PubliclyAccessible: true`) | HIGH |
| Storage is not encrypted (`StorageEncrypted: false`) | HIGH |
| Deletion protection is disabled (`DeletionProtection: false`) | MEDIUM |
| Master username matches a known default (`admin`, `root`, `master`, `postgres`, `mysql`, `oracle`, `sa`, `dbadmin`, `administrator`) | MEDIUM |

**Auto-fix scope:** `driftshield rds fix` auto-remediates via `ModifyDBInstance` with `ApplyImmediately: true`:
- `PUBLIC_ACCESS_CHANGED` → restores `PubliclyAccessible`
- `DELETION_PROTECTION_CHANGED` → restores `DeletionProtection`
- `AUTO_MINOR_UPGRADE_CHANGED` → restores `AutoMinorVersionUpgrade`

Encryption and Multi-AZ changes are skipped — encryption cannot be toggled on an existing instance (requires snapshot + restore).

---

### 7. Baseline System (Drift Detection)

This is the core of DriftShield. It works in two steps.

#### Step 1 — Create Baseline

**Commands:** `driftshield <service> baseline`

**Files:** `internal/baseline/common.go`, `s3.go`, `ec2.go`, `iam.go`, `cloudtrail.go`, `vpc.go`, `rds.go`, `internal/storage/state.go`

Each baseline command fetches the current live state from AWS and serializes it to JSON. 
This JSON is handed off to `internal/storage/state.go` which decides whether to save it locally in `baselines/` or push it directly to an AWS S3 bucket (if `DRIFTSHIELD_STATE_BUCKET` is configured in `.env`).

*Note: S3 bucket access is controlled entirely via AWS IAM. It is recommended to use an S3 Bucket Policy to restrict access exclusively to the DriftShield IAM user and AWS Root account to ensure state file integrity.*

| Service | Baseline JSON format | What is captured |
|---|---|---|
| S3 | `baselines/s3_baseline.json` | Public access flags, versioning, encryption per bucket |
| EC2 | `baselines/ec2_baseline.json` | All inbound rules per security group |
| IAM | `baselines/iam_baseline.json` | Password policy + per-user MFA, policies, access key IDs |
| CloudTrail | `baselines/cloudtrail_baseline.json` | Logging status, multi-region, log validation, S3 bucket, event selectors per trail |
| VPC | `baselines/vpc_baseline.json` | Flow logs status + per-subnet auto-assign public IP per VPC |
| RDS | `baselines/rds_baseline.json` | Publicly accessible, storage encrypted, deletion protection, Multi-AZ, auto minor upgrade per instance |

#### Step 2 — Compare Against Baseline

**Commands:** `driftshield <service> drift`

- Loads the saved JSON baseline using `internal/storage/state.go` (from S3 or local disk).
- Fetches the current live state from AWS.
- Diffs them field by field and reports changes.

**Nil-baseline detection:** IAM, CloudTrail, VPC, and RDS use a `([]Drift, bool, error)` return signature where the `bool` indicates whether a baseline file exists. This avoids the ambiguity of a nil slice (which could mean "no baseline" or "no drifts") that affects S3/EC2.

**S3 drift types:**

| Drift Type | Meaning |
|---|---|
| `PUBLIC_ACCESS_CHANGED` | One or more public access flags changed |
| `VERSIONING_CHANGED` | Versioning status changed |
| `ENCRYPTION_CHANGED` | Encryption algorithm changed |
| `NEW_BUCKET` | Bucket exists now but wasn't in baseline |
| `BUCKET_DELETED` | Bucket was in baseline but no longer exists |

**EC2 drift types:**

| Drift Type | Meaning |
|---|---|
| `RULES_CHANGED` | Inbound rules were added or removed |
| `NEW_SECURITY_GROUP` | Security group not present in baseline |
| `SECURITY_GROUP_DELETED` | Security group was deleted since baseline |

**IAM drift types:**

| Drift Type | Meaning |
|---|---|
| `USER_ADDED` | New IAM user since baseline |
| `USER_DELETED` | IAM user removed since baseline |
| `MFA_CHANGED` | User MFA enabled/disabled |
| `POLICY_ADDED` | Policy attached to user |
| `POLICY_REMOVED` | Policy detached from user |
| `ACCESS_KEY_ADDED` | New access key created |
| `ACCESS_KEY_REMOVED` | Access key deleted |
| `PASSWORD_POLICY_CHANGED` | Password policy setting changed |

**CloudTrail drift types:**

| Drift Type | Meaning |
|---|---|
| `LOGGING_STATUS_CHANGED` | Trail logging turned on or off |
| `LOG_VALIDATION_CHANGED` | Log file validation toggled |
| `MULTI_REGION_CHANGED` | Multi-region setting changed |
| `S3_BUCKET_CHANGED` | Trail S3 destination bucket changed |
| `EVENT_SELECTOR_CHANGED` | Read/write event selector changed |
| `TRAIL_ADDED` | New trail created since baseline |
| `TRAIL_DELETED` | Trail deleted since baseline |

**VPC drift types:**

| Drift Type | Meaning |
|---|---|
| `FLOW_LOGS_CHANGED` | Flow logs enabled or disabled |
| `SUBNET_PUBLIC_IP_CHANGED` | Subnet auto-assign public IP toggled |
| `SUBNET_ADDED` | New subnet created since baseline |
| `SUBNET_DELETED` | Subnet deleted since baseline |
| `VPC_ADDED` | New VPC created since baseline |
| `VPC_DELETED` | VPC deleted since baseline |

**RDS drift types:**

| Drift Type | Meaning |
|---|---|
| `PUBLIC_ACCESS_CHANGED` | Publicly accessible setting toggled |
| `ENCRYPTION_CHANGED` | Storage encryption changed |
| `DELETION_PROTECTION_CHANGED` | Deletion protection toggled |
| `MULTI_AZ_CHANGED` | Multi-AZ setting changed |
| `AUTO_MINOR_UPGRADE_CHANGED` | Auto minor version upgrade toggled |
| `INSTANCE_ADDED` | New RDS instance created since baseline |
| `INSTANCE_DELETED` | RDS instance deleted since baseline |

---

### 8. AI Baseline Designer

**Command:** `driftshield ai baseline`

**Files:** `internal/ai/client.go`, `conversation.go`, `generator.go`, `prompt.go`, `schema.go`

**How it works:**
The traditional `baseline` commands pull current AWS state. If the state is insecure, DriftShield enforces insecure state. The AI Designer flips this by generating a *secure-by-default* baseline from scratch.

1. **Context Gathering:** `survey/v2` prompts the user for context (e.g., Application Type, Environment, Public S3 needs, MFA requirements).
2. **Resource Snapshotting:** Before generating, DriftShield quietly scans the AWS environment to fetch the exact IDs and names of existing S3 Buckets, EC2 Security Groups, IAM Users, CloudTrails, VPCs, and RDS instances.
3. **LLM Invocation:** Calls the Groq API (LLaMA 3) via standard `net/http` to act as a Cloud Security Architect. The prompt receives the existing resource IDs so the AI perfectly applies its security recommendations to the user's actual infrastructure.
4. **Structured JSON Output:** The system prompt explicitly enforces a JSON schema that perfectly mirrors all 6 internal DriftShield `types` (`S3Baseline`, `EC2Baseline`, `IAMBaseline`, `CloudTrailBaseline`, `VPCBaseline`, `RDSBaseline`).
5. **Approval & Split:** The AI returns a unified baseline + recommendations. Upon user approval, `generator.go` splits the unified JSON into individual service files (`s3_baseline.json`, `ec2_baseline.json`, etc.) using `baseline.SaveBaseline()` and saves them into an isolated `ai-baselines/` directory for safe review.

**Important Design Principle:** The LLM is **never** used in the scanning or enforcement loop. It is strictly limited to generating the static configuration JSON upfront. This ensures DriftShield's actual security engine remains 100% deterministic, reliable, and fast.

---

### 9. Auto-Remediation

#### S3 Fix (`driftshield s3 fix`)
- `PUBLIC_ACCESS_CHANGED` → `PutPublicAccessBlock`
- `VERSIONING_CHANGED` → `PutBucketVersioning`
- `ENCRYPTION_CHANGED` → `PutBucketEncryption` or `DeleteBucketEncryption`
- `NEW_BUCKET`, `BUCKET_DELETED` → skipped

#### EC2 Fix (`driftshield ec2 fix`)
- Prompts for confirmation
- Calls `RevokeSecurityGroupIngress` for each rule open to `0.0.0.0/0` on risky ports
- Skips the `default` security group

#### IAM Fix (`driftshield iam fix`)
- No AWS API calls — prints a manual remediation guide only
- Intentional: disabling keys or detaching policies can break apps or lock out users

#### CloudTrail Fix (`driftshield cloudtrail fix`)
- Prompts for confirmation
- `LOGGING_STATUS_CHANGED` → `StartLogging` or `StopLogging`
- `LOG_VALIDATION_CHANGED` → `UpdateTrail`
- All other drift types → skipped

#### VPC Fix (`driftshield vpc fix`)
- Prompts for confirmation
- `SUBNET_PUBLIC_IP_CHANGED` → `ModifySubnetAttribute`
- All other drift types → skipped

#### RDS Fix (`driftshield rds fix`)
- Prompts for confirmation
- `PUBLIC_ACCESS_CHANGED` → `ModifyDBInstance` (ApplyImmediately)
- `DELETION_PROTECTION_CHANGED` → `ModifyDBInstance` (ApplyImmediately)
- `AUTO_MINOR_UPGRADE_CHANGED` → `ModifyDBInstance` (ApplyImmediately)
- `ENCRYPTION_CHANGED`, `MULTI_AZ_CHANGED`, `INSTANCE_ADDED/DELETED` → skipped (encryption requires snapshot + restore)

---

### 10. Alert System

Alerts are dispatched after every scan or drift check if issues are found. All three channels (SES, SNS, Slack) are called from the same `Send*` functions — each channel checks its own `Enabled` flag independently.

#### AWS SES Email (`internal/alerts/ses.go`)

- Creates an SES client using the region from `config.AWSSESConfig.Region`
- Sends both HTML and plain-text versions via `ses:SendEmail`
- Controlled by `config.AWSSESConfig.Enabled`

#### AWS SNS (`internal/alerts/sns.go`)

- Single `publishSNS(ctx, service, alertType, severity, subject, message)` helper
- Resolves topic ARN: checks `config.SNSConfig.ServiceTopics[service]` first, falls back to `config.SNSConfig.DefaultTopicARN`
- Attaches 3 message attributes to every publish enabling SNS filter policies:

| Attribute | Example values |
|---|---|
| `service` | `s3`, `ec2`, `iam`, `cloudtrail`, `vpc`, `rds` |
| `alertType` | `SCAN`, `DRIFT` |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM` |

- Controlled by `config.SNSConfig.Enabled`
- 12 public functions — one scan + one drift per service

| Function | Triggered by |
|---|---|
| `SNSPublishS3Alerts` | `driftshield s3` |
| `SNSPublishS3DriftAlerts` | `driftshield s3 drift` |
| `SNSPublishEC2Alerts` | `driftshield ec2` |
| `SNSPublishEC2DriftAlerts` | `driftshield ec2 drift` |
| `SNSPublishIAMAlerts` | `driftshield iam` |
| `SNSPublishIAMDriftAlerts` | `driftshield iam drift` |
| `SNSPublishCloudTrailAlerts` | `driftshield cloudtrail` |
| `SNSPublishCloudTrailDriftAlerts` | `driftshield cloudtrail drift` |
| `SNSPublishVPCAlerts` | `driftshield vpc` |
| `SNSPublishVPCDriftAlerts` | `driftshield vpc drift` |
| `SNSPublishRDSAlerts` | `driftshield rds` |
| `SNSPublishRDSDriftAlerts` | `driftshield rds drift` |

#### SES alert functions

| Function | Triggered by |
|---|---|
| `SendS3Alerts` | `driftshield s3` — at-risk buckets |
| `SendS3DriftAlerts` | `driftshield s3 drift` |
| `SendEC2Alerts` | `driftshield ec2` — risky security groups |
| `SendEC2DriftAlerts` | `driftshield ec2 drift` |
| `SendIAMAlerts` | `driftshield iam` — findings |
| `SendIAMDriftAlerts` | `driftshield iam drift` |
| `SendCloudTrailAlerts` | `driftshield cloudtrail` — findings |
| `SendCloudTrailDriftAlerts` | `driftshield cloudtrail drift` |
| `SendVPCAlerts` | `driftshield vpc` — findings |
| `SendVPCDriftAlerts` | `driftshield vpc drift` |
| `SendRDSAlerts` | `driftshield rds` — findings |
| `SendRDSDriftAlerts` | `driftshield rds drift` |

#### Slack Webhook (`internal/alerts/slack.go`)

- Posts Block Kit formatted messages to the configured webhook URL via HTTP POST
- Disabled by default — toggle via `config.SlackConfig.Enabled`

---

### 11. Configuration

**File:** `internal/config/config.go`

A static Go file — no environment variables or external config files. Edit it directly to change settings.

| Setting | Purpose |
|---|---|
| `AWSRegion` | Default AWS region used when `--region` flag is not provided |
| `CurrentRegion` | Set at runtime by the `--region` / `-r` flag; empty string when not provided |
| `AWSSESConfig` | SES sender email, recipient email, region, enabled toggle |
| `SNSConfig` | Default topic ARN, per-service topic ARNs map, region, enabled toggle |
| `SlackConfig` | Slack webhook URL, enabled toggle |
| `BaselineFile` | `baselines/s3_baseline.json` |
| `EC2BaselineFile` | `baselines/ec2_baseline.json` |
| `IAMBaselineFile` | `baselines/iam_baseline.json` |
| `CloudTrailBaselineFile` | `baselines/cloudtrail_baseline.json` |
| `VPCBaselineFile` | `baselines/vpc_baseline.json` |
| `RDSBaselineFile` | `baselines/rds_baseline.json` |

#### Global Flags

**Region Resolution (`--region` / `-r`)**
The `--region` flag is a Cobra persistent flag registered on the root command, so it applies to every subcommand. It sets `config.CurrentRegion` at parse time.

All AWS clients call `config.GetRegion()` when constructing their SDK config:

```go
func GetRegion() string {
    if CurrentRegion != "" {
        return CurrentRegion
    }
    return AWSRegion
}
```

| Client | File | Uses `GetRegion()` |
|---|---|---|
| EC2 | `scanner/ec2.go` | ✅ |
| S3 | `scanner/s3.go` | ✅ |
| IAM | `scanner/iam.go` | ✅ |
| CloudTrail | `scanner/cloudtrail.go` | ✅ |
| VPC | `scanner/vpc.go` | ✅ (via `NewEC2Client`) |
| RDS | `scanner/rds.go` | ✅ |
| S3 baseline | `baseline/s3.go` | ✅ |
| IAM baseline | `baseline/iam.go` | ✅ |

This means `--region` works uniformly across scan, baseline, drift, and fix operations for all services.

**Dry Run Mode (`--dry-run` / `-d`)**
The `--dry-run` flag is also a Cobra persistent flag registered on the root command, bound to a global `dryRun` boolean in `main.go`. When `driftshield <service> fix --dry-run` is invoked, `dryRun` is passed to the `Remediate*Drift` functions. If `dryRun` is `true`, these functions simulate execution by formatting the remediation message and returning it in the `Fixed` list without ever hitting the actual AWS APIs (like `PutPublicAccessBlock` or `RevokeSecurityGroupIngress`).

---

### 12. Scheduled Scanning

**File:** `scripts/scheduled_scan.sh`

A shell wrapper around the compiled binary, designed to be run by cron. It accepts `all`, `s3`, `ec2`, `iam`, `cloudtrail`, `vpc`, or `rds` as an argument and runs the corresponding scan + drift detection. Output is appended to `logs/cron.log`.

Example crontab entry to run every hour:
```
0 * * * * /path/to/DriftShield/scripts/scheduled_scan.sh all >> /path/to/DriftShield/logs/cron.log 2>&1
```

---

## Data Flow Examples

### `driftshield s3`
```
ListBuckets
  → for each bucket: GetPublicAccessBlock
  → classify as SECURE or AT RISK
  → if AT RISK: SendS3Alerts → SES email + SNS publish + Slack
```

### `driftshield iam`
```
GetAccountSummary → root MFA / root access keys
GetAccountPasswordPolicy → password policy checks
ListUsers → for each user:
  GetLoginProfile + ListMFADevices + ListAttachedUserPolicies
  ListUserPolicies + GetUserPolicy + ListAccessKeys + GetAccessKeyLastUsed
  → []IAMFinding
→ SendIAMAlerts → SES email + SNS publish
```

### `driftshield rds drift`
```
LoadRDSBaseline() → reads baselines/rds_baseline.json
GetRDSSnapshot() → DescribeDBInstances → map[instanceID]RDSInstanceSnapshot
CompareRDSWithBaseline() → diffs field by field → []RDSDrift
→ SendRDSDriftAlerts() → SES email + SNS publish
```

### `driftshield vpc drift`
```
LoadVPCBaseline() → reads baselines/vpc_baseline.json
GetVPCSnapshot() →
  DescribeVpcs + DescribeFlowLogs + DescribeNetworkAcls + DescribeSubnets
  → map[vpcID]VPCSnapshot
CompareVPCWithBaseline() → diffs field by field → []VPCDrift
→ SendVPCDriftAlerts() → SES email
```

### `driftshield all drift`
```
runAllDrifts() in main.go
Mutes display banner
Calls runS3Drift(), runEC2Drift(), runIAMDrift(), runCloudTrailDrift(), runRDSDrift(), runVPCDrift()
Unmutes display banner
If any drift is detected across any service, sets global `exitWithFailure = true` and eventually exits with `os.Exit(1)` (CI/CD integration)
```

### `driftshield cloudtrail fix`
```
CompareCloudTrailWithBaseline() → []CloudTrailDrift
Prompt for confirmation
for each drift:
  LOGGING_STATUS_CHANGED → StartLogging / StopLogging
  LOG_VALIDATION_CHANGED → UpdateTrail
  other → skip
→ report Fixed / Failed / Skipped
```

### `driftshield ec2 fix`
```
CompareEC2WithBaseline() → []EC2Drift
Prompt for confirmation
for each drift:
  RULES_CHANGED:
    → RevokeSecurityGroupIngress (for AddedRules)
    → AuthorizeSecurityGroupIngress (for RemovedRules)
  other → skip
→ report Fixed / Failed / Skipped
```

### `driftshield all`
```
runAllScans() in main.go
Calls ScanAllBuckets, ScanSecurityGroups, ScanIAM, ScanCloudTrail, ScanRDS, ScanVPC
Collects total risks across all 6 services
If total > 0:
  Sets global `exitWithFailure = true` (CI/CD failure)
  SendS3Alerts, SendEC2Alerts, SendIAMAlerts, SendCloudTrailAlerts, SendRDSAlerts, SendVPCAlerts
```

---

## Key Data Structures (`internal/types/types.go`)

| Struct | Purpose |
|---|---|
| `S3BucketConfig` | Public access flags, versioning, encryption for one bucket |
| `SGConfig` | Security group ID, name, VPC, and all inbound rules |
| `InboundRule` | Protocol, from/to port, source CIDRs for one rule |
| `Risk` | Type, severity, port, message for one detected risk |
| `S3Drift` | Bucket name, drift type, before/after values |
| `EC2Drift` | Security group, drift type, added/removed rules |
| `S3Baseline` | Timestamp + map of bucket name → S3BucketConfig |
| `EC2Baseline` | Timestamp + region + map of SG ID → SGConfig |
| `IAMFinding` | Type, severity, resource, message for one IAM issue |
| `IAMBaseline` | Timestamp + password policy snapshot + map of username → IAMUserSnapshot |
| `IAMDrift` | Type, resource, message, old/new value |
| `CloudTrailFinding` | Type, severity, trail name, message |
| `CloudTrailBaseline` | Timestamp + map of trail name → CloudTrailTrailSnapshot |
| `CloudTrailDrift` | Type, trail name, message, old/new value |
| `VPCFinding` | Type, severity, VPC ID, resource, message |
| `VPCBaseline` | Timestamp + map of VPC ID → VPCSnapshot |
| `VPCSnapshot` | VPC ID, default flag, flow logs status, map of subnet ID → VPCSubnetSnapshot |
| `VPCDrift` | Type, VPC ID, resource, message, old/new value |
| `RDSFinding` | Type, severity, instance ID, message |
| `RDSBaseline` | Timestamp + map of instance ID → RDSInstanceSnapshot |
| `RDSInstanceSnapshot` | Instance ID, engine, publicly accessible, encrypted, deletion protection, Multi-AZ, auto minor upgrade |
| `RDSDrift` | Type, instance ID, message, old/new value |
| `RemediationResults` | Fixed, Failed, Skipped lists of RemediationItem |
