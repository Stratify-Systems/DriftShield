# DriftShield

A cloud security tool that detects S3 misconfigurations by monitoring bucket settings against a secure baseline. It identifies risky changes in real-time and alerts administrators before data leaks occur.

## Features

- **Security Scanning**: Detects S3 buckets with public access risks
- **Drift Detection**: Monitors configuration changes against a known-good baseline
- **Email Alerts**: Sends notifications via AWS SES when risks are detected
- **Slack Integration**: Optional Slack webhook alerts

## Project Structure

```
DriftShield/
├── main.py              # Entry point and CLI
├── requirements.txt     # Python dependencies
├── baseline.json        # Saved baseline configuration
└── src/
    ├── __init__.py      # Package initialization
    ├── config.py        # Configuration settings
    ├── scanner.py       # S3 security scanning
    ├── baseline.py      # Baseline management
    └── alerts.py        # Email and Slack alerts
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

### Run Security Scan
```bash
python main.py
```

### Create Baseline
```bash
python main.py --baseline
```

### Check for Configuration Drift
```bash
python main.py --drift
```

### Show Help
```bash
python main.py --help
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
                "s3:GetEncryptionConfiguration"
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
