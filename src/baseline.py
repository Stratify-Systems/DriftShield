"""
Baseline Management Module

Handles creation, storage, and comparison of S3 bucket configuration baselines.
"""

import json
import os
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

from .config import BASELINE_FILE


def get_bucket_config(bucket_name):
    """
    Get full configuration for a bucket.
    
    Args:
        bucket_name: Name of the S3 bucket
        
    Returns:
        dict: Bucket configuration including public access, versioning, encryption
    """
    s3 = boto3.client('s3')
    config = {
        "bucket_name": bucket_name,
        "public_access_block": None,
        "versioning": None,
        "encryption": None,
    }
    
    # Get public access block settings
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config["public_access_block"] = response['PublicAccessBlockConfiguration']
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            config["public_access_block"] = {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        else:
            config["public_access_block"] = None
    except Exception:
        config["public_access_block"] = None
    
    # Get versioning status
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', None)
        config["versioning"] = status if status else "Disabled"
    except Exception as e:
        print(f"  Warning: Could not get versioning for {bucket_name}: {e}")
        config["versioning"] = "Unknown"
    
    # Get encryption status
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        if rules:
            config["encryption"] = rules[0].get(
                'ApplyServerSideEncryptionByDefault', {}
            ).get('SSEAlgorithm', 'None')
        else:
            config["encryption"] = "None"
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            config["encryption"] = "None"
        else:
            config["encryption"] = "Unknown"
    except Exception:
        config["encryption"] = "Unknown"
    
    return config


def load_baseline():
    """Load baseline from file."""
    if not os.path.exists(BASELINE_FILE):
        return {}
    
    with open(BASELINE_FILE, 'r') as f:
        return json.load(f)


def save_baseline(baseline):
    """Save baseline to file."""
    with open(BASELINE_FILE, 'w') as f:
        json.dump(baseline, f, indent=2)


def create_baseline():
    """
    Create baseline from current bucket configurations.
    
    Returns:
        dict: The created baseline
    """
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    
    baseline = {
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "buckets": {}
    }
    
    print("Creating baseline from current configurations...\n")
    
    for bucket in buckets:
        name = bucket['Name']
        print(f"  Capturing: {name}")
        config = get_bucket_config(name)
        baseline["buckets"][name] = config
    
    save_baseline(baseline)
    print(f"\nBaseline saved to {BASELINE_FILE}")
    print(f"  {len(buckets)} bucket(s) captured")
    
    return baseline


def compare_with_baseline():
    """
    Compare current configs with baseline and detect drift.
    
    Returns:
        list: List of drift objects, None if no baseline exists
    """
    baseline = load_baseline()
    
    if not baseline:
        print("[WARNING] No baseline found. Run with --baseline flag first.")
        return None
    
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    
    drifts = []
    
    print("Comparing against baseline...\n")
    print(f"  Baseline created: {baseline.get('created_at', 'Unknown')}\n")
    
    for bucket in buckets:
        name = bucket['Name']
        current_config = get_bucket_config(name)
        baseline_config = baseline.get("buckets", {}).get(name)
        
        if not baseline_config:
            drifts.append({
                "bucket": name,
                "type": "NEW_BUCKET",
                "message": "Bucket not in baseline (newly created)",
                "current": current_config,
                "baseline": None
            })
            print(f"[NEW]      {name} (not in baseline)")
            continue
        
        # Compare public access block
        current_pab = current_config.get("public_access_block", {})
        baseline_pab = baseline_config.get("public_access_block", {})
        
        if current_pab != baseline_pab:
            drift_details = []
            for key in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]:
                current_val = current_pab.get(key, False)
                baseline_val = baseline_pab.get(key, False)
                if current_val != baseline_val:
                    drift_details.append(f"{key}: {baseline_val} -> {current_val}")
            
            drifts.append({
                "bucket": name,
                "type": "PUBLIC_ACCESS_CHANGED",
                "message": "Public access settings changed",
                "details": drift_details,
                "current": current_pab,
                "baseline": baseline_pab
            })
            print(f"[DRIFT]    {name}")
            for detail in drift_details:
                print(f"           - {detail}")
        
        # Compare versioning
        if current_config.get("versioning") != baseline_config.get("versioning"):
            drifts.append({
                "bucket": name,
                "type": "VERSIONING_CHANGED",
                "message": f"Versioning: {baseline_config.get('versioning')} -> {current_config.get('versioning')}",
                "current": current_config.get("versioning"),
                "baseline": baseline_config.get("versioning")
            })
            print(f"[DRIFT]    {name}")
            print(f"           - Versioning: {baseline_config.get('versioning')} -> {current_config.get('versioning')}")
        
        # Compare encryption
        if current_config.get("encryption") != baseline_config.get("encryption"):
            drifts.append({
                "bucket": name,
                "type": "ENCRYPTION_CHANGED",
                "message": f"Encryption: {baseline_config.get('encryption')} -> {current_config.get('encryption')}",
                "current": current_config.get("encryption"),
                "baseline": baseline_config.get("encryption")
            })
            print(f"[DRIFT]    {name}")
            print(f"           - Encryption: {baseline_config.get('encryption')} -> {current_config.get('encryption')}")
        
        # No drift
        if name not in [d["bucket"] for d in drifts]:
            print(f"[OK]       {name}")
    
    # Check for deleted buckets
    current_bucket_names = [b['Name'] for b in buckets]
    for baseline_bucket in baseline.get("buckets", {}).keys():
        if baseline_bucket not in current_bucket_names:
            drifts.append({
                "bucket": baseline_bucket,
                "type": "BUCKET_DELETED",
                "message": "Bucket was deleted",
                "current": None,
                "baseline": baseline.get("buckets", {}).get(baseline_bucket)
            })
            print(f"[DELETED]  {baseline_bucket}")
    
    return drifts
