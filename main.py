from scanner import scan_all_buckets


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
        print("\n🚨 ACTION REQUIRED: Review these buckets:")
        for bucket in results['at_risk']:
            print(f"   - {bucket}")


if __name__ == "__main__":
    main()