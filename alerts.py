import json
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

try:
    import urllib.request
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

from config import AWS_SES_CONFIG, SLACK_CONFIG


def send_ses_alert(at_risk_buckets):
    """Send email alert using AWS SES"""
    if not AWS_SES_CONFIG["enabled"]:
        print("📧 AWS SES alerts disabled (enable in config.py)")
        return False
    
    try:
        print("📧 Connecting to AWS SES...")
        
        ses = boto3.client('ses', region_name=AWS_SES_CONFIG["region"])
        
        # Create email body
        bucket_list_html = "".join(f"<li>{bucket}</li>" for bucket in at_risk_buckets)
        bucket_list_text = "\n".join(f"  - {bucket}" for bucket in at_risk_buckets)
        
        html_body = f"""
        <html>
        <body>
        <h2>DriftShield Security Alert</h2>
        <p><strong>Time:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Issue:</strong> S3 buckets detected with public access risk</p>
        
        <h3>At-Risk Buckets:</h3>
        <ul>
        {bucket_list_html}
        </ul>
        
        <h3>Recommended Actions:</h3>
        <ol>
        <li>Review bucket permissions in AWS Console</li>
        <li>Enable "Block Public Access" settings</li>
        <li>Check for sensitive data exposure</li>
        </ol>
        
        <p>---<br>DriftShield - Cloud Security Monitoring</p>
        </body>
        </html>
        """
        
        text_body = f"""
DriftShield Security Alert
===========================

Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Issue: S3 buckets detected with public access risk

At-Risk Buckets:
{bucket_list_text}

Recommended Actions:
1. Review bucket permissions in AWS Console
2. Enable "Block Public Access" settings
3. Check for sensitive data exposure

---
DriftShield - Cloud Security Monitoring
        """
        
        print("📧 Sending email via AWS SES...")
        
        response = ses.send_email(
            Source=AWS_SES_CONFIG["sender_email"],
            Destination={
                'ToAddresses': [AWS_SES_CONFIG["recipient_email"]]
            },
            Message={
                'Subject': {
                    'Data': f"🚨 DriftShield Alert: {len(at_risk_buckets)} At-Risk S3 Bucket(s)",
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {
                        'Data': text_body,
                        'Charset': 'UTF-8'
                    },
                    'Html': {
                        'Data': html_body,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        
        print(f"📧 Email sent successfully! Message ID: {response['MessageId']}")
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        
        if error_code == 'MessageRejected':
            print(f"📧 Email rejected: {error_msg}")
            print("   → Make sure both sender and recipient emails are verified in SES")
        elif error_code == 'AccessDenied':
            print(f"📧 Access denied: {error_msg}")
            print("   → Add SES permissions to your IAM user")
        else:
            print(f"📧 AWS SES error ({error_code}): {error_msg}")
        return False
        
    except Exception as e:
        print(f"📧 Email alert failed: {e}")
        return False


def send_slack_alert(at_risk_buckets):
    """Send Slack alert for at-risk buckets"""
    if not SLACK_CONFIG["enabled"]:
        print("💬 Slack alerts disabled (enable in config.py)")
        return False
    
    if not HAS_URLLIB:
        print("💬 Slack alert failed: urllib not available")
        return False
    
    try:
        # Create Slack message
        bucket_list = "\n".join(f"• {bucket}" for bucket in at_risk_buckets)
        
        message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "DriftShield Security Alert!",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*At-Risk Buckets:*\n{len(at_risk_buckets)}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Time:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*⚠️ Buckets with public access risk:*\n{bucket_list}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Recommended Actions:*\n1. Review bucket permissions\n2. Enable Block Public Access\n3. Check for data exposure"
                    }
                }
            ]
        }
        
        # Send to Slack
        data = json.dumps(message).encode("utf-8")
        req = urllib.request.Request(
            SLACK_CONFIG["webhook_url"],
            data=data,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req)
        
        print("💬 Slack alert sent successfully!")
        return True
        
    except Exception as e:
        print(f"💬 Slack alert failed: {e}")
        return False


def send_alerts(at_risk_buckets):
    """Send all configured alerts"""
    if not at_risk_buckets:
        print("✅ No at-risk buckets - no alerts needed")
        return
    
    print(f"\n🔔 Sending alerts for {len(at_risk_buckets)} at-risk bucket(s)...\n")
    
    # Try AWS SES first (recommended)
    send_ses_alert(at_risk_buckets)
    
    # Also try Slack if enabled
    send_slack_alert(at_risk_buckets)


if __name__ == "__main__":
    # Test alerts
    test_buckets = ["test-bucket-1", "test-bucket-2"]
    send_alerts(test_buckets)
