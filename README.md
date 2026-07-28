# DriftShield

A cloud security tool that detects S3, EC2, IAM, CloudTrail, VPC, and RDS misconfigurations by monitoring settings against a secure baseline. It identifies risky changes in real-time and alerts administrators before security incidents occur.

Built in Go for fast, single-binary distribution with zero runtime dependencies, extended with a **6-Agent Autonomous Fetch.ai `uAgents` Alliance**, **Groq LLaMA 3 70B AI Reasoning**, and a **Real-Time WebSocket DevSecOps Command Center Dashboard**.

## Features

- **Fetch.ai AgentVerse 6-Agent Alliance**: Autonomous multi-agent alliance running on `uagents.Bureau` (`Scanner`, `PolicyGuard`, `DriftSentinel`, `ArchitectAI`, `AutoFix`, `AlertRouter`)
- **Groq LLaMA 3 70B AI Reasoning Engine**: Live integration with `llama-3.3-70b-versatile` synthesizing step-by-step human remediation guides and custom YAML rules
- **Real-Time WebSockets DevSecOps Dashboard**: Interactive dark-mode dashboard (`http://localhost:8080`) featuring live agent health grid, uAgent event ticker stream, and instant scan trigger API
- **Human-in-the-Loop AI Safety Guardrail**: Zero direct AI AWS mutations; `AutoFixAgent` executes safe `--dry-run` simulations ONLY and signs digital audit proofs
- **Clean Markdown State Reporting**: Automatically persists human-readable Markdown reports (`agents_data/*_report.md`) with zero JSON clutter
- **S3 Security Scanning**: Detects S3 buckets with public access risks
- **EC2 Security Scanning**: Detects risky security group configurations (open SSH, RDP, database ports)
- **IAM Security Scanning**: Detects root account misconfigurations, missing MFA, admin policy abuse, and stale access keys
- **CloudTrail Security Scanning**: Detects disabled logging, missing multi-region trails, and log validation issues
- **VPC Security Scanning**: Detects default VPC usage, missing flow logs, open NACLs, and subnets with auto-assign public IP
- **RDS Security Scanning**: Detects publicly accessible instances, unencrypted storage, missing deletion protection, and default master usernames
- **Policy-as-Code Engine**: Evaluate live AWS resources against custom declarative YAML rules (`policies/*.yaml`)
- **AI Baseline Designer**: Interactively generates secure-by-default baselines based on application context using Groq LLaMA 3
- **Drift Detection**: Monitors configuration changes against a known-good baseline
- **Auto-Remediation**: Automatically fixes drifted configs back to baseline
- **Remote State Backend**: Store and fetch baseline states securely from AWS S3 (GitOps ready)
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
│   │   ├── conversation.go      # Interactive AI Policy CLI prompts
│   │   └── policy_generator.go  # AI policy rule generator
│   ├── policy/
│   │   ├── evaluator.go         # Condition evaluation engine
│   │   ├── loader.go            # YAML policy parser & defaults
│   │   └── schema.go            # PolicyRule schema definitions
│   ├── storage/
│   │   └── state.go             # S3 / local state backend
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
├── policies/                    # Policy-as-Code YAML rules
│   ├── s3_policies.yaml
│   ├── ec2_policies.yaml
│   ├── iam_policies.yaml
│   ├── rds_policies.yaml
│   ├── vpc_policies.yaml
│   ├── cloudtrail_policies.yaml
│   └── custom_policy.yaml
├── tests/                       # Unit test suite
│   ├── ai_test.go               # AI generator & schema unit tests
│   ├── alerts_test.go           # Alert dispatching unit tests
│   ├── baseline_test.go         # Baseline comparison & remediation unit tests
│   ├── config_test.go           # Configuration & environment unit tests
│   ├── display_test.go          # Display formatting unit tests
│   ├── policy_test.go           # Policy evaluation unit tests
│   ├── scanner_test.go          # Scanner rule evaluation unit tests
│   └── storage_test.go          # Storage backend unit tests
├── agents/                      # Fetch.ai AgentVerse uAgents Alliance
│   ├── run_agents.py            # Master Bureau Launcher & Dashboard Auto-Start
│   ├── scanner_agent.py         # Agent 1: Scanner (Port 8001)
│   ├── policy_agent.py          # Agent 2: Policy Guard (Port 8002)
│   ├── drift_agent.py           # Agent 3: Drift Sentinel (Port 8003)
│   ├── ai_agent.py              # Agent 4: Architect AI (Port 8004)
│   ├── autofix_agent.py         # Agent 5: Auto Fix Safety Auditor (Port 8005)
│   ├── alert_agent.py           # Agent 6: Alert Router (Port 8006)
│   ├── models.py                # Inter-Agent Message Schemas & Markdown Reporter
│   └── dashboard/               # Real-Time DevSecOps Web Dashboard
│       ├── dashboard_server.py  # Python aiohttp WebSocket Server (Port 8080)
│       ├── dashboard.html       # Real-Time Liquid Glass Web Dashboard UI
│       └── dashboard.css        # Liquid Glass CSS Design System
├── agents_data/                 # Generated Markdown Reports (Git Ignored)
│   ├── architect_ai_agent_report.md
│   ├── autofix_agent_report.md
│   ├── policy_guard_agent_report.md
│   ├── scanner_agent_report.md
│   ├── alert_router_agent_report.md
│   └── drift_sentinel_agent_report.md
├── docs/                        # Project & Alliance Documentation
│   └── AGENTS.md                # Multi-Agent Architecture Specification
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
- **Python 3.10+** (for running the Fetch.ai AgentVerse uAgents Alliance)
- **AWS CLI** configured with valid credentials:
  ```bash
  aws configure
  ```

4. Create a `.env` file (copy `.env.example` if available) and update your configurations.
5. Update configuration in `internal/config/config.go` if needed.

## 🤖 Fetch.ai AgentVerse Multi-Agent Alliance & Web Dashboard

DriftShield features a **6-Agent Autonomous Alliance** built on the **Fetch.ai `uAgents` framework**. The alliance decouples telemetry collection, compliance checking, drift detection, AI reasoning, safety auditing, and alerting into peer-to-peer communicating agents.

### 🚀 Running the Agent Alliance & Web Dashboard

```bash
python3 agents/run_agents.py
```

This master launcher starts:
1. All 6 Fetch.ai uAgents on the `uagents.Bureau` (`Scanner`, `PolicyGuard`, `DriftSentinel`, `ArchitectAI`, `AutoFix`, `AlertRouter`).
2. The Real-Time DevSecOps WebSocket Dashboard server at **`http://localhost:8080`**.

### 🌐 Dashboard Features (`http://localhost:8080`)
- **Live 6-Agent Health Grid:** Real-time online/offline badges for all uAgents.
- **Interactive Markdown Tabs:** Renders Groq LLaMA 3 AI remediation guides, dry-run audit proofs, and policy dossiers using `marked.js`.
- **Live Inter-Agent Event Stream:** Real-time scrolling uAgent message ticker with precise timestamps.
- **⚡ Trigger Instant Scan Button:** Interactive UI button calling `/api/scan` to launch an immediate AWS infrastructure scan.


## Remote State Backend (S3)

DriftShield natively supports centralized state storage in AWS S3 for CI/CD and GitOps workflows. 

By default, DriftShield saves baseline snapshots as local `.json` files in the `baselines/` directory. However, if you configure the following in your `.env` file:
```env
DRIFTSHIELD_STATE_BUCKET=my-security-bucket
DRIFTSHIELD_STATE_BUCKET_REGION=us-east-1
```
All subcommands (`drift`, `baseline`, and `fix`) will bypass the local filesystem and read/write the JSON baselines directly from the specified S3 bucket. This ensures an immutable, auditable source of truth.

### Recommended Bucket Policy

To secure your remote state bucket, we recommend attaching a bucket policy that grants read/write access to your designated DriftShield IAM user (e.g., `drift-shield-user`) and read-only access to the AWS Root account. Remember to replace the Account ID and ARNs with your own:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowDriftShieldUserFullAccess",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::<ACCOUNT_ID>:user/drift-shield-user"
            },
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::<BUCKET_NAME>",
                "arn:aws:s3:::<BUCKET_NAME>/*"
            ]
        },
        {
            "Sid": "AllowRootAccountReadAccess",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::<ACCOUNT_ID>:root"
            },
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::<BUCKET_NAME>",
                "arn:aws:s3:::<BUCKET_NAME>/*"
            ]
        }
    ]
}
```

## Usage

### Global Flags
DriftShield supports several global flags that can be applied to its commands:
- `-r, --region string` : Specify the AWS region (e.g., `us-east-1`). If not provided, it falls back to `.env` or standard AWS config.
- `-d, --dry-run` : Simulate the `fix` command without actually making any destructive changes to your AWS environment. Highly recommended for CI/CD pipelines!
### CI/CD Integration
DriftShield is built for automated security pipelines.
- **Exit Codes:** If DriftShield detects any misconfigurations during a `scan` or drifts during a `drift` check, it automatically terminates with an `Exit Code 1`. This safely fails your CI/CD pipeline, blocking insecure deployments.
- **Dry-Run Remediation:** Running `driftshield all fix --dry-run` will output exactly what AWS API calls *would* have been made, allowing you to preview remediation in a safe, non-destructive way in CI.

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

### Policy-as-Code Commands
```bash
driftshield policy scan           # Evaluate live AWS resources against YAML policy rules
driftshield policy list           # List all loaded policy rules and their severities
driftshield policy validate       # Validate YAML syntax of policy rules
driftshield policy scan -p custom # Use custom rules directory
```

### AI Commands
```bash
driftshield ai policy             # Generate custom YAML policy rules from security requirements using AI
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

## AI Policy Generator

The `driftshield ai policy` command launches an interactive session to generate declarative YAML compliance policy rules tailored to your organization's security guidelines (e.g. SOC2, HIPAA, PCI-DSS).

Instead of manually writing YAML rules, the AI acts as a virtual Cloud Security Architect and generates syntactically valid `PolicyRule` objects enforcing your compliance requirements. It uses the Groq API (LLaMA 3) under the hood.

1. Ensure `GROQ_API_KEY` is set in your `.env` file or environment.
2. Run `driftshield ai policy`.
3. Select your compliance framework and describe any custom security requirements.
4. Review the AI's generated policy rules in the terminal.
5. Approve to save the generated `policies/custom_policy.yaml` file.
6. Evaluate your AWS infrastructure against the generated rules using `driftshield policy scan`.

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
make test      # Run unit tests across all packages
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
