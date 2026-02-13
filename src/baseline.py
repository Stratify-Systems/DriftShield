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


def remediate_drift(drifts):
    """
    Fix drifted configurations by restoring baseline settings.
    
    Args:
        drifts: List of drift objects from compare_with_baseline()
        
    Returns:
        dict: Results with fixed and failed lists
    """
    if not drifts:
        print("[INFO] No drifts to remediate.")
        return {"fixed": [], "failed": [], "skipped": []}
    
    s3 = boto3.client('s3')
    baseline = load_baseline()
    
    results = {
        "fixed": [],
        "failed": [],
        "skipped": []
    }
    
    print("Starting remediation...\n")
    
    for drift in drifts:
        bucket = drift["bucket"]
        drift_type = drift["type"]
        
        # Skip buckets that can't be remediated
        if drift_type in ["NEW_BUCKET", "BUCKET_DELETED"]:
            print(f"[SKIP]    {bucket} - {drift_type} (manual action required)")
            results["skipped"].append({
                "bucket": bucket,
                "type": drift_type,
                "reason": "Manual action required"
            })
            continue
        
        try:
            baseline_config = baseline.get("buckets", {}).get(bucket, {})
            
            if drift_type == "PUBLIC_ACCESS_CHANGED":
                baseline_pab = baseline_config.get("public_access_block", {})
                s3.put_public_access_block(
                    Bucket=bucket,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': baseline_pab.get('BlockPublicAcls', True),
                        'IgnorePublicAcls': baseline_pab.get('IgnorePublicAcls', True),
                        'BlockPublicPolicy': baseline_pab.get('BlockPublicPolicy', True),
                        'RestrictPublicBuckets': baseline_pab.get('RestrictPublicBuckets', True)
                    }
                )
                print(f"[FIXED]   {bucket} - Public access block restored")
                results["fixed"].append({"bucket": bucket, "type": drift_type})
            
            elif drift_type == "VERSIONING_CHANGED":
                baseline_versioning = baseline_config.get("versioning", "Disabled")
                if baseline_versioning == "Enabled":
                    s3.put_bucket_versioning(
                        Bucket=bucket,
                        VersioningConfiguration={'Status': 'Enabled'}
                    )
                elif baseline_versioning in ["Disabled", None]:
                    s3.put_bucket_versioning(
                        Bucket=bucket,
                        VersioningConfiguration={'Status': 'Suspended'}
                    )
                print(f"[FIXED]   {bucket} - Versioning restored to {baseline_versioning}")
                results["fixed"].append({"bucket": bucket, "type": drift_type})
            
            elif drift_type == "ENCRYPTION_CHANGED":
                baseline_encryption = baseline_config.get("encryption", "None")
                if baseline_encryption and baseline_encryption not in ["None", "Unknown"]:
                    s3.put_bucket_encryption(
                        Bucket=bucket,
                        ServerSideEncryptionConfiguration={
                            'Rules': [{
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': baseline_encryption
                                }
                            }]
                        }
                    )
                    print(f"[FIXED]   {bucket} - Encryption restored to {baseline_encryption}")
                else:
                    s3.delete_bucket_encryption(Bucket=bucket)
                    print(f"[FIXED]   {bucket} - Encryption removed (baseline had none)")
                results["fixed"].append({"bucket": bucket, "type": drift_type})
            
            else:
                print(f"[SKIP]    {bucket} - Unknown drift type: {drift_type}")
                results["skipped"].append({
                    "bucket": bucket,
                    "type": drift_type,
                    "reason": "Unknown drift type"
                })
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            print(f"[FAILED]  {bucket} - {error_code}: {error_msg}")
            results["failed"].append({
                "bucket": bucket,
                "type": drift_type,
                "error": f"{error_code}: {error_msg}"
            })
        except Exception as e:
            print(f"[FAILED]  {bucket} - {str(e)}")
            results["failed"].append({
                "bucket": bucket,
                "type": drift_type,
                "error": str(e)
            })
    
    return results
