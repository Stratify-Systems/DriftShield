"""
EC2 Security Group Scanner Module

Detects risky security group configurations like open SSH, RDP, or database ports.
"""

import boto3
from botocore.exceptions import ClientError

from . import config as cfg


def get_ec2_client():
    """Get EC2 client with configured region."""
    region = cfg.CURRENT_REGION or cfg.AWS_REGION
    return boto3.client('ec2', region_name=region)


# Risky ports and their descriptions
RISKY_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    1521: "Oracle",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5900: "VNC",
    23: "Telnet",
    21: "FTP",
    445: "SMB",
    135: "RPC",
}

# CIDR ranges that mean "open to internet"
OPEN_CIDRS = ["0.0.0.0/0", "::/0"]


def get_security_group_risks(sg):
    """
    Analyze a security group for risky configurations.
    
    Args:
        sg: Security group dict from boto3
        
    Returns:
        list: List of risk findings
    """
    risks = []
    sg_id = sg['GroupId']
    sg_name = sg.get('GroupName', 'Unknown')
    
    for rule in sg.get('IpPermissions', []):
        protocol = rule.get('IpProtocol', '')
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 65535)
        
        # Get all CIDR ranges (IPv4 and IPv6)
        cidrs = [ip['CidrIp'] for ip in rule.get('IpRanges', [])]
        cidrs += [ip['CidrIpv6'] for ip in rule.get('Ipv6Ranges', [])]
        
        # Check if open to internet
        open_to_internet = any(cidr in OPEN_CIDRS for cidr in cidrs)
        
        if not open_to_internet:
            continue
        
        # Check for all traffic allowed
        if protocol == '-1':
            risks.append({
                "type": "ALL_TRAFFIC_OPEN",
                "severity": "CRITICAL",
                "message": "All traffic allowed from internet",
                "details": f"Protocol: ALL, Source: {cidrs}"
            })
            continue
        
        # Check for all ports open
        if from_port == 0 and to_port == 65535:
            risks.append({
                "type": "ALL_PORTS_OPEN",
                "severity": "CRITICAL",
                "message": f"All ports open to internet ({protocol.upper()})",
                "details": f"Ports: 0-65535, Source: {cidrs}"
            })
            continue
        
        # Check for risky ports
        for port, service in RISKY_PORTS.items():
            if from_port <= port <= to_port:
                severity = "CRITICAL" if port in [22, 3389] else "HIGH"
                risks.append({
                    "type": f"{service.upper()}_OPEN",
                    "severity": severity,
                    "port": port,
                    "message": f"{service} (port {port}) open to internet",
                    "details": f"Source: {cidrs}"
                })
    
    return risks


def get_security_group_config(sg):
    """
    Get configuration summary for a security group.
    
    Args:
        sg: Security group dict from boto3
        
    Returns:
        dict: Configuration summary
    """
    inbound_rules = []
    for rule in sg.get('IpPermissions', []):
        protocol = rule.get('IpProtocol', '-1')
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 65535)
        
        cidrs = [ip['CidrIp'] for ip in rule.get('IpRanges', [])]
        cidrs += [ip['CidrIpv6'] for ip in rule.get('Ipv6Ranges', [])]
        
        inbound_rules.append({
            "protocol": protocol,
            "from_port": from_port,
            "to_port": to_port,
            "sources": cidrs
        })
    
    return {
        "group_id": sg['GroupId'],
        "group_name": sg.get('GroupName', 'Unknown'),
        "description": sg.get('Description', ''),
        "vpc_id": sg.get('VpcId', 'EC2-Classic'),
        "inbound_rules": inbound_rules,
        "inbound_rule_count": len(inbound_rules)
    }


def scan_security_groups():
    """
    Scan all security groups for risky configurations.
    
    Returns:
        dict: Results with 'secure', 'at_risk' lists and 'details'
    """
    ec2 = get_ec2_client()
    region = cfg.CURRENT_REGION or cfg.AWS_REGION
    
    results = {
        "secure": [],
        "at_risk": [],
        "details": {}
    }
    
    try:
        response = ec2.describe_security_groups()
        security_groups = response.get('SecurityGroups', [])
    except ClientError as e:
        print(f"[ERROR] Failed to get security groups: {e}")
        return results
    
    print(f"Region: {region}")
    print(f"Found {len(security_groups)} security group(s)\n")
    
    for sg in security_groups:
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'Unknown')
        display_name = f"{sg_name} ({sg_id})"
        
        risks = get_security_group_risks(sg)
        config = get_security_group_config(sg)
        
        results["details"][sg_id] = {
            "config": config,
            "risks": risks
        }
        
        if risks:
            results["at_risk"].append(sg_id)
            
            # Find highest severity
            severities = [r["severity"] for r in risks]
            if "CRITICAL" in severities:
                severity = "CRITICAL"
            elif "HIGH" in severities:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
            
            print(f"[{severity}]  {display_name}")
            for risk in risks:
                print(f"           - {risk['message']}")
        else:
            results["secure"].append(sg_id)
            print(f"[SECURE]   {display_name}")
    
    return results


def get_all_security_group_configs():
    """
    Get configurations for all security groups (for baseline).
    
    Returns:
        dict: Security group ID -> config mapping
    """
    ec2 = get_ec2_client()
    configs = {}
    
    try:
        response = ec2.describe_security_groups()
        for sg in response.get('SecurityGroups', []):
            sg_id = sg['GroupId']
            configs[sg_id] = get_security_group_config(sg)
    except ClientError as e:
        print(f"[ERROR] Failed to get security groups: {e}")
    
    return configs
