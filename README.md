# DriftShield

A cloud security tool that detects S3 and EC2 misconfigurations by monitoring settings against a secure baseline. It identifies risky changes in real-time and alerts administrators before security incidents occur.

## Features

- **S3 Security Scanning**: Detects S3 buckets with public access risks
- **EC2 Security Scanning**: Detects risky security group configurations (open SSH, RDP, database ports)
- **Drift Detection**: Monitors configuration changes against a known-good baseline
- **Auto-Remediation**: Automatically fixes drifted configs back to baseline
- **Email Alerts**: Sends notifications via AWS SES when risks are detected
- **Slack Integration**: Optional Slack webhook alerts
- **Scheduled Scanning**: Automated hourly scans via cron

## Project Structure

```
DriftShield/
├── main.py              # Entry point and CLI
├── requirements.txt     # Python dependencies
├── baseline.json        # Saved baseline configuration
├── src/
│   ├── __init__.py      # Package initialization
│   ├── config.py        # Configuration settings
│   ├── scanner.py       # S3 security scanning
│   ├── ec2_scanner.py   # EC2 security group scanning
│   ├── baseline.py      # Baseline management
│   └── alerts.py        # Email and Slack alerts
├── scripts/
│   └── scheduled_scan.sh  # Cron job script
└── logs/
    └── cron.log         # Scheduled scan logs
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/SuryaTK2007/DriftShield.git
   cd DriftShield
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure AWS credentials:
   ```bash
   aws configure
   ```

5. Update configuration in `src/config.py`

## Usage

### S3 Commands
```bash
python main.py --s3                  # Run S3 security scan
python main.py --s3 --baseline        # Create S3 baseline
python main.py --s3 --drift           # Detect S3 configuration drift
python main.py --s3 --fix             # Fix drifted S3 configs
```

### EC2 Commands
```bash
python main.py --ec2                  # Run EC2 security group scan
python main.py --ec2 --baseline       # Create EC2 baseline
python main.py --ec2 --drift          # Detect EC2 configuration drift
python main.py --ec2 --fix            # Remove risky inbound rules
python main.py --ec2 --region us-east-1  # Scan specific region
```

### Other Commands
```bash
python main.py --all                  # Run both S3 and EC2 scans
python main.py --help                 # Show help message
```

### Shortcuts
| Short | Full | Description |
|-------|------|-------------|
| `-s` | `--s3` | S3 commands |
| `-e` | `--ec2` | EC2 commands |
| `-a` | `--all` | All scans |
| `-b` | `--baseline` | Create baseline |
| `-d` | `--drift` | Drift detection |
| `-f` | `--fix` | Fix drifts |
| `-r` | `--region` | Set AWS region |

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

### 1. Test the script manually
```bash
./scripts/scheduled_scan.sh all        # Run all scans + drift detection
./scripts/scheduled_scan.sh s3         # Run S3 scan + drift
./scripts/scheduled_scan.sh ec2        # Run EC2 scan + drift
```

### 2. Add to crontab
```bash
crontab -e
```

### 3. Add one of these lines:

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

### 4. View logs
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
                "ses:SendEmail",
                "ses:SendRawEmail"
            ],
            "Resource": "*"
        }
    ]
}
```

## Configuration

Edit `src/config.py` to configure:

- **AWS_SES_CONFIG**: Email alert settings
- **SLACK_CONFIG**: Slack webhook settings
- **BASELINE_FILE**: Baseline storage location

## License

MIT License

## Author

SuryaTK
