# DriftShield

A cloud security tool that detects S3, EC2, IAM, and CloudTrail misconfigurations by monitoring settings against a secure baseline. It identifies risky changes in real-time and alerts administrators before security incidents occur.

Built in Go for fast, single-binary distribution with zero runtime dependencies.

## Features

- **S3 Security Scanning**: Detects S3 buckets with public access risks
- **EC2 Security Scanning**: Detects risky security group configurations (open SSH, RDP, database ports)
- **IAM Security Scanning**: Detects root account misconfigurations, missing MFA, admin policy abuse, and stale access keys
- **CloudTrail Security Scanning**: Detects disabled logging, missing multi-region trails, and log validation issues
- **Drift Detection**: Monitors configuration changes against a known-good baseline
- **Auto-Remediation**: Automatically fixes drifted configs back to baseline
- **Email Alerts**: Sends notifications via AWS SES when risks are detected
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
│   │   └── cloudtrail.go        # CloudTrail security scanning
│   ├── baseline/
│   │   ├── s3.go                # S3 baseline management
│   │   ├── ec2.go               # EC2 baseline management
│   │   ├── iam.go               # IAM baseline management
│   │   └── cloudtrail.go        # CloudTrail baseline management
│   └── alerts/
│       ├── ses.go               # AWS SES email alerts
│       └── slack.go             # Slack webhook alerts
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
```

### CloudTrail Commands
```bash
driftshield cloudtrail            # Run CloudTrail security scan
driftshield cloudtrail baseline   # Create CloudTrail baseline
driftshield cloudtrail drift      # Detect CloudTrail configuration drift
driftshield cloudtrail fix        # Fix drifted CloudTrail configurations
```

### Other Commands
```bash
driftshield all                   # Run S3, EC2, IAM, and CloudTrail scans
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
go run ./cmd/driftshield all
```

### Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--region` | `-r` | Set AWS region (e.g., us-east-1) |
| `--help` | `-h` | Show help |
| `--version` | `-v` | Show version |

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
                "ec2:RevokeSecurityGroupIngress"
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
- **SlackConfig**: Slack webhook settings
- **BaselineFile / EC2BaselineFile**: Baseline storage locations
- **AWSRegion**: Default AWS region

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
