# DriftShield — Features & Internal Working

## What DriftShield Does

DriftShield is a CLI security tool that does two things:
1. Scans AWS resources (S3 buckets and EC2 security groups) for misconfigurations
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
| `internal/scanner` | Live AWS scanning for S3 and EC2 risks |
| `internal/baseline` | Snapshot, compare, and remediate configuration drift |
| `internal/alerts` | Send findings via AWS SES email and Slack webhook |
| `internal/display` | Banner printing and port description helpers |

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
- At-risk buckets trigger alerts via SES and Slack

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

### 3. Baseline System (Drift Detection)

This is the core of DriftShield. It works in two steps.

#### Step 1 — Create Baseline

**Commands:** `driftshield s3 baseline` / `driftshield ec2 baseline`

**Files:** `internal/baseline/s3.go`, `internal/baseline/ec2.go`

- Fetches the current live state of all S3 buckets or EC2 security groups from AWS
- For S3, captures per bucket:
  - Public access block settings (all 4 flags)
  - Versioning status (`Enabled`, `Suspended`, `Disabled`)
  - Encryption algorithm (e.g. `AES256`, `aws:kms`, or `None`)
- For EC2, captures per security group:
  - All inbound rules: protocol, from/to port, and source CIDRs
- Serializes the snapshot to a local JSON file:
  - S3 → `baseline.json`
  - EC2 → `ec2_baseline.json`

#### Step 2 — Compare Against Baseline

**Commands:** `driftshield s3 drift` / `driftshield ec2 drift`

- Loads the saved JSON baseline from disk
- Fetches the current live state from AWS again
- Diffs them and reports changes

**S3 drift types detected:**

| Drift Type | Meaning |
|---|---|
| `PUBLIC_ACCESS_CHANGED` | One or more public access flags changed |
| `VERSIONING_CHANGED` | Versioning status changed |
| `ENCRYPTION_CHANGED` | Encryption algorithm changed |
| `NEW_BUCKET` | Bucket exists now but wasn't in baseline |
| `BUCKET_DELETED` | Bucket was in baseline but no longer exists |

**EC2 drift types detected:**

| Drift Type | Meaning |
|---|---|
| `RULES_CHANGED` | Inbound rules were added or removed |
| `NEW_SECURITY_GROUP` | Security group not present in baseline |
| `SECURITY_GROUP_DELETED` | Security group was deleted since baseline |

EC2 rule comparison uses a string key `protocol|fromPort|toPort|sources` to identify each rule uniquely, making it easy to diff added vs removed rules.

---

### 4. Auto-Remediation

#### S3 Fix

**Command:** `driftshield s3 fix`

**File:** `internal/baseline/s3.go`

- Runs drift detection first to find all drifted buckets
- For each drift, calls the appropriate AWS API to restore the baseline value:
  - `PUBLIC_ACCESS_CHANGED` → `PutPublicAccessBlock` with baseline flag values
  - `VERSIONING_CHANGED` → `PutBucketVersioning` with baseline status
  - `ENCRYPTION_CHANGED` → `PutBucketEncryption` (or `DeleteBucketEncryption` if baseline had none)
- Skips `NEW_BUCKET` and `BUCKET_DELETED` — these require manual action
- Reports Fixed / Failed / Skipped counts

#### EC2 Fix

**Command:** `driftshield ec2 fix`

**File:** `internal/scanner/ec2.go`

- Prompts for confirmation before making any changes
- Iterates all security groups, finds rules open to `0.0.0.0/0` or `::/0` on risky ports
- Calls `RevokeSecurityGroupIngress` to remove each risky rule
- Skips the `default` security group (flags it for manual review)
- Handles both IPv4 (`IpRanges`) and IPv6 (`Ipv6Ranges`) rules separately
- Reports Fixed / Failed / Skipped counts

---

### 5. Alert System

Alerts are dispatched after every scan or drift check if issues are found.

#### AWS SES Email (`internal/alerts/ses.go`)

- Creates an SES client using the region from `config.AWSSESConfig.Region`
- Sends both HTML and plain-text versions of the email via `ses:SendEmail`
- S3 scan alerts list at-risk bucket names
- S3 drift alerts include a formatted table: Bucket | Change Type | Details
- EC2 scan alerts list risky security groups with per-risk severity and message
- EC2 drift alerts include a table: Name | Security Group | Change | Details
- Controlled by `config.AWSSESConfig.Enabled`

#### Slack Webhook (`internal/alerts/slack.go`)

- Posts Block Kit formatted messages to the configured webhook URL via HTTP POST
- Uses header + section blocks for structured output
- Disabled by default — toggle via `config.SlackConfig.Enabled`
- S3 alerts show bucket count and list
- EC2 alerts show per-group risk summaries with severity labels

Both channels are called together from unified functions like `SendS3Alerts` and `SendEC2Alerts`.

---

### 6. Configuration

**File:** `internal/config/config.go`

A static Go file — no environment variables or external config files. Edit it directly to change settings.

| Setting | Purpose |
|---|---|
| `AWSRegion` | Default AWS region (overridable with `--region` flag) |
| `AWSSESConfig` | SES sender email, recipient email, region, enabled toggle |
| `SlackConfig` | Slack webhook URL, enabled toggle |
| `BaselineFile` | Path to S3 baseline JSON (`baseline.json`) |
| `EC2BaselineFile` | Path to EC2 baseline JSON (`ec2_baseline.json`) |

The `--region` / `-r` flag sets `CurrentRegion` at runtime. `GetRegion()` returns `CurrentRegion` if set, otherwise falls back to `AWSRegion`.

---

### 7. Scheduled Scanning

**File:** `scripts/scheduled_scan.sh`

A shell wrapper around the compiled binary, designed to be run by cron. It accepts `all`, `s3`, or `ec2` as an argument and runs the corresponding scan + drift detection. Output is appended to `logs/cron.log`.

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
  → if AT RISK: SendS3Alerts → SES email + Slack
```

### `driftshield s3 drift`
```
LoadS3Baseline() → reads baseline.json
  → ListBuckets + GetBucketConfig() → fetches live state
  → CompareS3WithBaseline() → diffs field by field → []S3Drift
  → SendS3DriftAlerts() → SES email
```

### `driftshield ec2 fix`
```
Prompt for confirmation
  → DescribeSecurityGroups
  → for each SG: for each rule open to 0.0.0.0/0 on risky port
    → RevokeSecurityGroupIngress
  → report Fixed / Failed / Skipped
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
| `RemediationResults` | Fixed, Failed, Skipped lists of RemediationItem |
