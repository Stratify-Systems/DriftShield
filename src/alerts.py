"""
Alert Module

Handles sending security alerts via AWS SES and Slack.
"""

import json
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

try:
    import urllib.request
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

from .config import AWS_SES_CONFIG, SLACK_CONFIG


def send_ses_alert(at_risk_buckets):
    """
    Send email alert using AWS SES.
    
    Args:
        at_risk_buckets: List of bucket names that are at risk
        
    Returns:
        bool: True if email sent successfully
    """
    if not AWS_SES_CONFIG["enabled"]:
        print("[EMAIL] AWS SES alerts disabled (enable in config.py)")
        return False
    
    try:
        print("[EMAIL] Connecting to AWS SES...")
        
        ses = boto3.client('ses', region_name=AWS_SES_CONFIG["region"])
        
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
        
        print("[EMAIL] Sending email via AWS SES...")
        
        response = ses.send_email(
            Source=AWS_SES_CONFIG["sender_email"],
            Destination={
                'ToAddresses': [AWS_SES_CONFIG["recipient_email"]]
            },
            Message={
                'Subject': {
                    'Data': f"[ALERT] DriftShield: {len(at_risk_buckets)} At-Risk S3 Bucket(s)",
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {'Data': text_body, 'Charset': 'UTF-8'},
                    'Html': {'Data': html_body, 'Charset': 'UTF-8'}
                }
            }
        )
        
        print(f"[EMAIL] Sent successfully. Message ID: {response['MessageId']}")
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        
        if error_code == 'MessageRejected':
            print(f"[EMAIL] Rejected: {error_msg}")
            print("        Ensure both sender and recipient emails are verified in SES")
        elif error_code == 'AccessDenied':
            print(f"[EMAIL] Access denied: {error_msg}")
            print("        Add SES permissions to your IAM user")
        else:
            print(f"[EMAIL] AWS SES error ({error_code}): {error_msg}")
        return False
        
    except Exception as e:
        print(f"[EMAIL] Failed: {e}")
        return False


def send_slack_alert(at_risk_buckets):
    """
    Send Slack alert for at-risk buckets.
    
    Args:
        at_risk_buckets: List of bucket names that are at risk
        
    Returns:
        bool: True if alert sent successfully
    """
    if not SLACK_CONFIG["enabled"]:
        print("[SLACK] Alerts disabled (enable in config.py)")
        return False
    
    if not HAS_URLLIB:
        print("[SLACK] Failed: urllib not available")
        return False
    
    try:
        bucket_list = "\n".join(f"- {bucket}" for bucket in at_risk_buckets)
        
        message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "DriftShield Security Alert",
                        "emoji": False
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*At-Risk Buckets:*\n{len(at_risk_buckets)}"},
                        {"type": "mrkdwn", "text": f"*Time:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Buckets with public access risk:*\n{bucket_list}"}
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
        
        data = json.dumps(message).encode("utf-8")
        req = urllib.request.Request(
            SLACK_CONFIG["webhook_url"],
            data=data,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req)
        
        print("[SLACK] Alert sent successfully")
        return True
        
    except Exception as e:
        print(f"[SLACK] Failed: {e}")
        return False


def send_alerts(at_risk_buckets):
    """
    Send all configured alerts.
    
    Args:
        at_risk_buckets: List of bucket names that are at risk
    """
    if not at_risk_buckets:
        print("[INFO] No at-risk buckets - no alerts needed")
        return
    
    print(f"\n[ALERT] Sending alerts for {len(at_risk_buckets)} at-risk bucket(s)...\n")
    
    send_ses_alert(at_risk_buckets)
    send_slack_alert(at_risk_buckets)


def send_drift_alerts(drifts):
    """
    Send alerts for configuration drift.
    
    Args:
        drifts: List of drift objects
        
    Returns:
        bool: True if alert sent successfully
    """
    if not drifts:
        print("[INFO] No drift detected - no alerts needed")
        return
    
    if not AWS_SES_CONFIG["enabled"]:
        print("[EMAIL] AWS SES alerts disabled")
        return
    
    try:
        print(f"\n[ALERT] Sending drift alerts...\n")
        print("[EMAIL] Connecting to AWS SES...")
        
        ses = boto3.client('ses', region_name=AWS_SES_CONFIG["region"])
        
        # Build drift details HTML
        drift_rows = ""
        for drift in drifts:
            drift_type = drift.get("type", "UNKNOWN")
            bucket = drift.get("bucket", "Unknown")
            message = drift.get("message", "")
            details = drift.get("details", [])
            
            details_html = "<br>".join(details) if details else message
            
            drift_rows += f"""
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd;">{bucket}</td>
                <td style="padding: 8px; border: 1px solid #ddd;">{drift_type}</td>
                <td style="padding: 8px; border: 1px solid #ddd;">{details_html}</td>
            </tr>
            """
        
        html_body = f"""
        <html>
        <body>
        <h2>DriftShield - Configuration Drift Detected</h2>
        <p><strong>Time:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Issue:</strong> S3 bucket configurations have drifted from baseline</p>
        
        <h3>Drift Summary ({len(drifts)} change(s)):</h3>
        <table style="border-collapse: collapse; width: 100%;">
            <tr style="background-color: #f2f2f2;">
                <th style="padding: 8px; border: 1px solid #ddd;">Bucket</th>
                <th style="padding: 8px; border: 1px solid #ddd;">Change Type</th>
                <th style="padding: 8px; border: 1px solid #ddd;">Details</th>
            </tr>
            {drift_rows}
        </table>
        
        <h3>Recommended Actions:</h3>
        <ol>
        <li>Review the configuration changes</li>
        <li>If changes are intentional, update baseline: <code>python main.py --baseline</code></li>
        <li>If unauthorized, revert the changes immediately</li>
        </ol>
        
        <p>---<br>DriftShield - Cloud Security Monitoring</p>
        </body>
        </html>
        """
        
        drift_text = "\n".join([
            f"  - {d['bucket']}: {d.get('message', d.get('type', 'Unknown'))}"
            for d in drifts
        ])
        
        text_body = f"""
DriftShield - Configuration Drift Detected
===========================================

Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Issue: S3 bucket configurations have drifted from baseline

Drifts Detected ({len(drifts)}):
{drift_text}

Recommended Actions:
1. Review the configuration changes
2. If intentional, update baseline: python main.py --baseline
3. If unauthorized, revert changes immediately

---
DriftShield - Cloud Security Monitoring
        """
        
        print("[EMAIL] Sending drift alert...")
        
        response = ses.send_email(
            Source=AWS_SES_CONFIG["sender_email"],
            Destination={
                'ToAddresses': [AWS_SES_CONFIG["recipient_email"]]
            },
            Message={
                'Subject': {
                    'Data': f"[DRIFT] DriftShield: {len(drifts)} Configuration Change(s) Detected",
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {'Data': text_body, 'Charset': 'UTF-8'},
                    'Html': {'Data': html_body, 'Charset': 'UTF-8'}
                }
            }
        )
        
        print(f"[EMAIL] Drift alert sent. Message ID: {response['MessageId']}")
        return True
        
    except Exception as e:
        print(f"[EMAIL] Drift alert failed: {e}")
        return False


def send_ec2_alerts(at_risk_groups, details):
    """
    Send alerts for EC2 security group risks.
    
    Args:
        at_risk_groups: List of security group IDs that are at risk
        details: Dict with security group details and risks
    """
    if not at_risk_groups:
        return
    
    print()
    print("[ALERT] Sending EC2 security alerts...")
    
    # Send email alert
    if AWS_SES_CONFIG["enabled"]:
        send_ec2_ses_alert(at_risk_groups, details)
    
    # Send Slack alert
    if SLACK_CONFIG["enabled"]:
        send_ec2_slack_alert(at_risk_groups, details)


def send_ec2_ses_alert(at_risk_groups, details):
    """
    Send email alert for EC2 security group risks via AWS SES.
    
    Args:
        at_risk_groups: List of security group IDs that are at risk
        details: Dict with security group details and risks
        
    Returns:
        bool: True if email sent successfully
    """
    try:
        ses = boto3.client('ses', region_name=AWS_SES_CONFIG["region"])
        
        # Build HTML list of risky security groups
        groups_html = ""
        groups_text = ""
        
        for sg_id in at_risk_groups:
            sg_details = details.get(sg_id, {})
            config = sg_details.get("config", {})
            risks = sg_details.get("risks", [])
            
            sg_name = config.get("group_name", "Unknown")
            
            risks_html = "".join(f"<li><strong>{r['severity']}</strong>: {r['message']}</li>" for r in risks)
            risks_text = "\n".join(f"      - [{r['severity']}] {r['message']}" for r in risks)
            
            groups_html += f"""
            <li>
                <strong>{sg_name}</strong> ({sg_id})
                <ul>{risks_html}</ul>
            </li>
            """
            
            groups_text += f"\n  - {sg_name} ({sg_id}):\n{risks_text}"
        
        html_body = f"""
        <html>
        <body>
        <h2>DriftShield EC2 Security Alert</h2>
        <p><strong>Time:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Issue:</strong> Security groups with risky configurations detected</p>
        
        <h3>At-Risk Security Groups:</h3>
        <ul>
        {groups_html}
        </ul>
        
        <h3>Recommended Actions:</h3>
        <ol>
        <li>Review inbound rules in AWS Console</li>
        <li>Restrict SSH/RDP access to specific IPs</li>
        <li>Remove unnecessary open ports</li>
        <li>Use VPN or bastion hosts for remote access</li>
        </ol>
        
        <p>---<br>DriftShield - Cloud Security Monitoring</p>
        </body>
        </html>
        """
        
        text_body = f"""
DriftShield EC2 Security Alert
==============================

Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Issue: Security groups with risky configurations detected

At-Risk Security Groups:
{groups_text}

Recommended Actions:
1. Review inbound rules in AWS Console
2. Restrict SSH/RDP access to specific IPs
3. Remove unnecessary open ports
4. Use VPN or bastion hosts for remote access

---
DriftShield - Cloud Security Monitoring
        """
        
        print("[EMAIL] Sending EC2 security alert...")
        
        response = ses.send_email(
            Source=AWS_SES_CONFIG["sender_email"],
            Destination={
                'ToAddresses': [AWS_SES_CONFIG["recipient_email"]]
            },
            Message={
                'Subject': {
                    'Data': f"[ALERT] DriftShield: {len(at_risk_groups)} Risky EC2 Security Group(s)",
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {'Data': text_body, 'Charset': 'UTF-8'},
                    'Html': {'Data': html_body, 'Charset': 'UTF-8'}
                }
            }
        )
        
        print(f"[EMAIL] EC2 alert sent. Message ID: {response['MessageId']}")
        return True
        
    except Exception as e:
        print(f"[EMAIL] EC2 alert failed: {e}")
        return False


def send_ec2_slack_alert(at_risk_groups, details):
    """
    Send Slack alert for EC2 security group risks.
    
    Args:
        at_risk_groups: List of security group IDs
        details: Dict with security group details
        
    Returns:
        bool: True if alert sent successfully
    """
    if not HAS_URLLIB:
        print("[SLACK] urllib not available")
        return False
    
    try:
        # Build message
        blocks = []
        
        for sg_id in at_risk_groups:
            sg_details = details.get(sg_id, {})
            config = sg_details.get("config", {})
            risks = sg_details.get("risks", [])
            
            sg_name = config.get("group_name", "Unknown")
            risks_text = "\n".join(f"• [{r['severity']}] {r['message']}" for r in risks)
            
            blocks.append(f"*{sg_name}* (`{sg_id}`)\n{risks_text}")
        
        message = {
            "text": f"EC2 Security Alert: {len(at_risk_groups)} risky security group(s)",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "DriftShield EC2 Alert"}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "\n\n".join(blocks)}
                }
            ]
        }
        
        data = json.dumps(message).encode('utf-8')
        req = urllib.request.Request(
            SLACK_CONFIG["webhook_url"],
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                print("[SLACK] EC2 alert sent successfully")
                return True
        
        return False
        
    except Exception as e:
        print(f"[SLACK] EC2 alert failed: {e}")
        return False
