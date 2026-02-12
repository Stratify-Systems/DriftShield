"""
S3 Security Scanner Module

Scans AWS S3 buckets for public access misconfigurations.
"""

import boto3
from botocore.exceptions import ClientError


def get_public_access_status(bucket_name):
    """
    Check if a bucket has public access blocked.
    
    Args:
        bucket_name: Name of the S3 bucket to check
        
    Returns:
        tuple: (is_secure: bool, config: dict or None)
    """
    s3 = boto3.client('s3')
    
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']
        
        is_secure = all([
            config.get('BlockPublicAcls', False),
            config.get('IgnorePublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('RestrictPublicBuckets', False)
        ])
        
        return is_secure, config
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return False, None
        raise
    except Exception:
        return False, None


def scan_all_buckets():
    """
    Scan all S3 buckets for public access risks.
    
    Returns:
        dict: Contains 'secure' and 'at_risk' bucket lists
    """
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    
    print(f"Found {len(buckets)} bucket(s)\n")
    
    at_risk = []
    secure = []
    
    for bucket in buckets:
        name = bucket['Name']
        is_secure, config = get_public_access_status(name)
        
        if is_secure:
            print(f"[SECURE]   {name}")
            secure.append(name)
        else:
            print(f"[AT RISK]  {name}")
            at_risk.append(name)
    
    return {'secure': secure, 'at_risk': at_risk}


if __name__ == "__main__":
    results = scan_all_buckets()
    print(f"\nSecure: {len(results['secure'])}, At-Risk: {len(results['at_risk'])}")
