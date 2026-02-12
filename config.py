# DriftShield Configuration
# Update these settings with your credentials

# AWS SES Email Settings
AWS_SES_CONFIG = {
    "enabled": True,
    "region": "ap-south-1",  # Your AWS region
    "sender_email": "tksurya164@gmail.com",  # Must be verified in SES
    "recipient_email": "suryatk2007@gmail.com",  # Must be verified in SES
}

# Slack Settings (Optional)
SLACK_CONFIG = {
    "enabled": False,
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
}
