"""
DriftShield Configuration

Update these settings with your AWS credentials and preferences.
"""

# Default AWS Region (can be overridden with --region flag)
AWS_REGION = "ap-south-1"

# AWS SES Email Settings
AWS_SES_CONFIG = {
    "enabled": True,
    "region": "ap-south-1",
    "sender_email": "tksurya164@gmail.com",
    "recipient_email": "suryatk2007@gmail.com",
}

# Slack Settings (Optional)
SLACK_CONFIG = {
    "enabled": False,
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
}

# Baseline file location
BASELINE_FILE = "baseline.json"

# Runtime region (set by CLI, do not modify)
CURRENT_REGION = None
