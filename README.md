# DriftShield

A cloud security tool that detects S3, EC2, IAM, CloudTrail, VPC, and RDS misconfigurations by monitoring settings against a secure baseline. It identifies risky changes in real-time and alerts administrators before security incidents occur.

Built in Go for fast, single-binary distribution with zero runtime dependencies.

## Features

- **S3 Security Scanning**: Detects S3 buckets with public access risks
- **EC2 Security Scanning**: Detects risky security group configurations (open SSH, RDP, database ports)
- **IAM Security Scanning**: Detects root account misconfigurations, missing MFA, admin policy abuse, and stale access keys
- **CloudTrail Security Scanning**: Detects disabled logging, missing multi-region trails, and log validation issues
- **VPC Security Scanning**: Detects default VPC usage, missing flow logs, open NACLs, and subnets with auto-assign public IP
- **RDS Security Scanning**: Detects publicly accessible instances, unencrypted storage, missing deletion protection, and default master usernames
- **AI Baseline Designer**: Interactively generates secure-by-default baselines based on application context using Groq LLaMA 3
- **Drift Detection**: Monitors configuration changes against a known-good baseline
- **Auto-Remediation**: Automatically fixes drifted configs back to baseline
- **Email Alerts**: Sends notifications via AWS SES when risks are detected
- **SNS Alerts**: Publishes to AWS SNS with message attributes for filter-policy-based routing
- **Slack Integration**: Optional Slack webhook alerts
- **Scheduled Scanning**: Automated hourly scans via cron
- **Shell Autocompletion**: Built-in completion for bash, zsh, fish, and PowerShell

## Project Structure

```
DriftShield/
├── cmd/
│   └── driftshield/
│       └── main.go              # CLI entry point (cobra)
├── internal/
│   ├── types/types.go           # Shared data structures
│   ├── config/config.go         # Configuration settings
│   ├── display/display.go       # Banner and formatting
│   ├── scanner/
│   │   ├── s3.go                # S3 security scanning
│   │   ├── ec2.go               # EC2 security group scanning
│   │   ├── iam.go               # IAM security scanning
│   │   ├── cloudtrail.go        # CloudTrail security scanning
│   │   ├── vpc.go               # VPC security scanning
│   │   └── rds.go               # RDS security scanning
│   ├── baseline/
│   │   ├── s3.go                # S3 baseline management
│   │   ├── ec2.go               # EC2 baseline management
│   │   ├── iam.go               # IAM baseline management
│   │   ├── cloudtrail.go        # CloudTrail baseline management
│   │   ├── vpc.go               # VPC baseline management
│   │   └── rds.go               # RDS baseline management
│   ├── ai/
│   │   ├── client.go            # Groq API client
│   │   ├── conversation.go      # Interactive CLI prompts
│   │   ├── generator.go         # Baseline generation logic
│   │   └── prompt.go            # LLM prompt construction
│   └── alerts/
│       ├── ses.go               # AWS SES email alerts
│       ├── sns.go               # AWS SNS alerts
│       └── slack.go             # Slack webhook alerts
├── baselines/
│   ├── s3_baseline.json         # S3 baseline snapshot
│   ├── ec2_baseline.json        # EC2 baseline snapshot
│   ├── iam_baseline.json        # IAM baseline snapshot
│   ├── cloudtrail_baseline.json # CloudTrail baseline snapshot
│   ├── vpc_baseline.json        # VPC baseline snapshot
│   └── rds_baseline.json        # RDS baseline snapshot
├── scripts/
│   └── scheduled_scan.sh        # Cron job script
├── logs/
│   └── cron.log                 # Scheduled scan logs
├── go.mod                       # Go module definition
├── go.sum                       # Dependency checksums
└── Makefile                     # Build targets
```

## Installation

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/SuryaTK2007/DriftShield.git
   cd DriftShield
   ```

2. Build the binary:
   ```bash
   make build
   ```

   This produces a `driftshield` binary in the project root.

3. (Optional) Install system-wide:
   ```bash
   make install
   ```

### Prerequisites

- **Go 1.21+** (for building from source)
- **AWS CLI** configured with valid credentials:
  ```bash
  aws configure
  ```

4. Update configuration in `internal/config/config.go`

## Usage

### S3 Commands
```bash
driftshield s3                    # Run S3 security scan
driftshield s3 baseline           # Create S3 baseline
driftshield s3 drift              # Detect S3 configuration drift
driftshield s3 fix                # Fix drifted S3 configs
```

### EC2 Commands
```bash
driftshield ec2                   # Run EC2 security group scan
driftshield ec2 baseline          # Create EC2 baseline
driftshield ec2 drift             # Detect EC2 configuration drift
driftshield ec2 fix               # Remove risky inbound rules
driftshield ec2 -r us-east-1      # Scan specific region
```

### IAM Commands
```bash
driftshield iam                   # Run IAM security scan
driftshield iam baseline          # Create IAM baseline
driftshield iam drift             # Detect IAM configuration drift
driftshield iam fix               # Show manual remediation steps
driftshield iam -r us-east-1      # Run with specific region
```

### CloudTrail Commands
```bash
driftshield cloudtrail            # Run CloudTrail security scan
driftshield cloudtrail baseline   # Create CloudTrail baseline
driftshield cloudtrail drift      # Detect CloudTrail configuration drift
driftshield cloudtrail fix        # Fix drifted CloudTrail configurations
driftshield cloudtrail -r us-east-1  # Scan specific region
```

### VPC Commands
```bash
driftshield vpc                   # Run VPC security scan
driftshield vpc baseline          # Create VPC baseline
driftshield vpc drift             # Detect VPC configuration drift
driftshield vpc fix               # Fix drifted VPC configurations
driftshield vpc -r us-east-1      # Scan specific region
```

### RDS Commands
```bash
driftshield rds                   # Run RDS security scan
driftshield rds baseline          # Create RDS baseline
driftshield rds drift             # Detect RDS configuration drift
driftshield rds fix               # Fix drifted RDS configurations
driftshield rds -r us-east-1      # Scan specific region
```

### AI Commands
```bash
driftshield ai baseline           # Generate secure baseline interactively using AI
```

### Other Commands
```bash
driftshield all                   # Run S3, EC2, IAM, CloudTrail, VPC, and RDS scans
driftshield all baseline          # Create baselines for all 6 services
driftshield all drift             # Detect drift for all 6 services
driftshield all fix               # Fix drifted configurations across all services
driftshield all -r us-east-1      # Run all scans in a specific region
driftshield --help                # Show help message
driftshield --version             # Show version
driftshield completion bash       # Generate bash completion script
```

### Running Without Installing

You can also run directly with `go run`:
```bash
go run ./cmd/driftshield s3
go run ./cmd/driftshield ec2 drift
go run ./cmd/driftshield iam
go run ./cmd/driftshield cloudtrail
go run ./cmd/driftshield vpc
go run ./cmd/driftshield rds
go run ./cmd/driftshield all
```

### Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--region` | `-r` | Override AWS region for the scan (e.g., `us-east-1`). Falls back to `AWSRegion` in `config.go` if not set. |
| `--help` | `-h` | Show help |
| `--version` | `-v` | Show version |

The `--region` flag is a persistent flag — it applies to all subcommands. Every AWS client (S3, EC2, IAM, CloudTrail, VPC, RDS) respects it via `config.GetRegion()`, which returns the flag value when set and the configured default otherwise.

```bash
# Scan a non-default region
driftshield all -r eu-west-1
driftshield rds drift --region ap-southeast-1
driftshield ec2 fix -r us-west-2
```

## AI Baseline Designer

The `driftshield ai baseline` command launches an interactive session to generate a security baseline tailored to your application's context (e.g. REST API, Static Website). 

Instead of creating a baseline from your *current* AWS state (which might already be insecure), the AI acts as a virtual Cloud Security Architect and generates a **secure-by-default** JSON baseline enforcing best practices for your specific use case. It uses the Groq API (LLaMA 3) under the hood.

Before generating the baseline, DriftShield seamlessly scans your live AWS environment (all 6 services) and feeds the exact names of your existing S3 buckets, EC2 Security Groups, IAM Users, CloudTrails, VPCs, and RDS instances to the AI. This ensures the AI perfectly tailors the secure configurations to your actual infrastructure rather than hallucinating random resource names.

1. Ensure `GROQ_API_KEY` is set in your `.env` file or environment.
2. Run `driftshield ai baseline`.
3. Answer the interactive prompts.
4. Review the AI's recommendations.
5. Approve to generate and save the `ai-baselines/*.json` files.
6. Once reviewed, move them to `baselines/` to begin enforcing them with `driftshield all drift`.

## IAM Security Checks

The IAM scanner detects these issues:

| Check | Severity |
|-------|----------|
| Root account MFA disabled | CRITICAL |
| Root account has active access keys | CRITICAL |
| IAM user with console access but no MFA | HIGH |
| No account password policy set | HIGH |
| User has `AdministratorAccess` policy attached | HIGH |
| User has inline policy with wildcard `Action: *` | HIGH |
| Minimum password length below 14 characters | MEDIUM |
| Password complexity not fully enforced | MEDIUM |
| Passwords never expire | MEDIUM |
| Access key unused for 90+ days | MEDIUM |
| Access key that was never used | MEDIUM |
| Password reuse prevention not configured | LOW |

## CloudTrail Security Checks

The CloudTrail scanner detects these issues:

| Check | Severity |
|-------|----------|
| No trails configured | CRITICAL |
| Trail exists but logging is disabled | CRITICAL |
| No multi-region trail configured | HIGH |
| Log file validation disabled | MEDIUM |
| Only write events logged (read events missed) | LOW |

## VPC Security Checks

The VPC scanner detects these issues:

| Check | Severity |
|-------|----------|
| Default VPC is in use | MEDIUM |
| VPC has no flow logs enabled | HIGH |
| NACL allows all inbound traffic from internet | HIGH |
| Subnet auto-assigns public IPs on launch | MEDIUM |

## RDS Security Checks

The RDS scanner detects these issues:

| Check | Severity |
|-------|----------|
| Instance is publicly accessible | HIGH |
| Storage is not encrypted | HIGH |
| Deletion protection is disabled | MEDIUM |
| Default master username in use (`admin`, `root`, `master`, `postgres`, etc.) | MEDIUM |

## EC2 Security Checks

The EC2 scanner detects these risky configurations when open to `0.0.0.0/0`:

| Port | Service | Severity |
|------|---------|----------|
| 22 | SSH | CRITICAL |
| 3389 | RDP | CRITICAL |
| 23 | Telnet | HIGH |
| 21 | FTP | HIGH |
| 3306 | MySQL | HIGH |
| 5432 | PostgreSQL | HIGH |
| 1433 | MSSQL | HIGH |
| 27017 | MongoDB | HIGH |
| 6379 | Redis | HIGH |
| 9200 | Elasticsearch | HIGH |
| All ports (0-65535) | Any | CRITICAL |
| All traffic | Any | CRITICAL |

## Scheduled Scanning (Cron)

Set up automated scans to run every hour:

### 1. Build the binary
```bash
make build
```

### 2. Test the script manually
```bash
./scripts/scheduled_scan.sh all        # Run all scans + drift detection
./scripts/scheduled_scan.sh s3         # Run S3 scan + drift
./scripts/scheduled_scan.sh ec2        # Run EC2 scan + drift
```

### 3. Add to crontab
```bash
crontab -e
```

### 4. Add one of these lines:

Replace `/path/to/DriftShield` with your actual installation path.

**Run all scans and drift detection every hour:**
```
0 * * * * /path/to/DriftShield/scripts/scheduled_scan.sh all >> /path/to/DriftShield/logs/cron.log 2>&1
```

**Run S3 scan and drift detection every hour:**
```
0 * * * * /path/to/DriftShield/scripts/scheduled_scan.sh s3 >> /path/to/DriftShield/logs/cron.log 2>&1
```

**Run EC2 scan and drift detection every 30 minutes:**
```
*/30 * * * * /path/to/DriftShield/scripts/scheduled_scan.sh ec2 >> /path/to/DriftShield/logs/cron.log 2>&1
```

### 5. View logs
```bash
tail -f logs/cron.log
```

## AWS IAM Permissions Required

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketVersioning",
                "s3:GetEncryptionConfiguration",
                "s3:PutBucketPublicAccessBlock",
                "s3:PutBucketVersioning",
                "s3:PutBucketEncryption",
                "s3:DeleteBucketEncryption"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSecurityGroupRules",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DescribeVpcs",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeNetworkAcls",
                "ec2:DescribeSubnets",
                "ec2:ModifySubnetAttribute"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary",
                "iam:ListUsers",
                "iam:GetLoginProfile",
                "iam:ListMFADevices",
                "iam:ListAttachedUserPolicies",
                "iam:ListUserPolicies",
                "iam:GetUserPolicy",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "iam:GetAccountPasswordPolicy",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "rds:DescribeDBInstances",
                "rds:ModifyDBInstance"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": "arn:aws:sns:ap-south-1:YOUR_ACCOUNT_ID:driftshield-alerts"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ses:SendEmail",
                "ses:SendRawEmail"
            ],
            "Resource": "*"
        }
    ]
}
```

## Configuration

Edit `internal/config/config.go` to configure:

- **AWSSESConfig**: Email alert settings (sender, recipient, region)
- **SNSConfig**: SNS topic ARN, region, enabled toggle, optional per-service topic ARNs
- **SlackConfig**: Slack webhook settings
- **BaselineFile / EC2BaselineFile / IAMBaselineFile / CloudTrailBaselineFile / VPCBaselineFile / RDSBaselineFile**: Baseline storage locations (all under `baselines/`)
- **AWSRegion**: Default AWS region

## SNS Alerts Setup

### 1. Create the SNS topic
```bash
aws sns create-topic --name driftshield-alerts --region ap-south-1
```

### 2. Subscribe your email
```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:ap-south-1:YOUR_ACCOUNT_ID:driftshield-alerts \
  --protocol email \
  --notification-endpoint your@email.com \
  --region ap-south-1
```
Check your inbox and click the confirmation link.

### 3. Enable SNS in config
Edit `internal/config/config.go`:
```go
var SNSConfig = SNSSettings{
    Enabled:         true,
    Region:          "ap-south-1",
    DefaultTopicARN: "arn:aws:sns:ap-south-1:YOUR_ACCOUNT_ID:driftshield-alerts",
    ServiceTopics:   map[string]string{},
}
```

### 4. Optional — per-service topics
Route specific services to dedicated topics:
```go
ServiceTopics: map[string]string{
    "rds": "arn:aws:sns:ap-south-1:YOUR_ACCOUNT_ID:driftshield-rds-alerts",
    "iam": "arn:aws:sns:ap-south-1:YOUR_ACCOUNT_ID:driftshield-iam-alerts",
},
```

### 5. Optional — SNS filter policies
Every SNS message includes these attributes for subscriber-side filtering:

| Attribute | Values |
|-----------|--------|
| `service` | `s3`, `ec2`, `iam`, `cloudtrail`, `vpc`, `rds` |
| `alertType` | `SCAN`, `DRIFT` |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM` |

Example filter policy (only CRITICAL scan alerts):
```json
{
  "alertType": ["SCAN"],
  "severity": ["CRITICAL"]
}
```

## Build Targets

```bash
make build     # Build the driftshield binary
make run       # Run without building
make install   # Install to $GOPATH/bin
make tidy      # Run go mod tidy
make clean     # Remove built binary
```

## Tech Stack

- **Language**: Go 1.21+
- **CLI Framework**: [Cobra](https://github.com/spf13/cobra)
- **AWS SDK**: [aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2)

## License

MIT License

## Author

SuryaTK
