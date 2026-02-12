import boto3


def get_public_access_status(bucket_name):
    """Check if a bucket has public access blocked"""
    s3 = boto3.client('s3')
    
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']
        
        # All four should be True for full protection
        is_secure = all([
            config.get('BlockPublicAcls', False),
            config.get('IgnorePublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('RestrictPublicBuckets', False)
        ])
        
        return is_secure, config
        
    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        # No block configured = potentially public
        return False, None


def scan_all_buckets():
    """Scan all S3 buckets for public access risks"""
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    
    print(f"Found {len(buckets)} bucket(s)\n")
    
    at_risk = []
    secure = []
    
    for bucket in buckets:
        name = bucket['Name']
        is_secure, config = get_public_access_status(name)
        
        if is_secure:
            print(f"SECURE    - {name}")
            secure.append(name)
        else:
            print(f"AT RISK  - {name}")
            at_risk.append(name)
    
    return {'secure': secure, 'at_risk': at_risk}


if __name__ == "__main__":
    print("=" * 50)
    print("DriftShield - S3 Security Scanner")
    print("=" * 50 + "\n")
    
    results = scan_all_buckets()
    
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"Secure buckets:  {len(results['secure'])}")
    print(f"At-risk buckets: {len(results['at_risk'])}")
    
    if results['at_risk']:
        print("\nACTION REQUIRED: Review these buckets:")
        for bucket in results['at_risk']:
            print(f"   - {bucket}")