from scanner import scan_all_buckets
from alerts import send_alerts


def main():
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
        
        # Send alerts
        send_alerts(results['at_risk'])
    else:
        print("\nAll buckets are secure!")


if __name__ == "__main__":
    main()