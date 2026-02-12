import sys
from scanner import scan_all_buckets
from baseline import create_baseline, compare_with_baseline
from alerts import send_alerts, send_drift_alerts


def print_help():
    """Print usage help"""
    print("""
DriftShield - S3 Security Scanner

Usage:
    python main.py              Run security scan
    python main.py --baseline   Create baseline from current configs
    python main.py --drift      Check for configuration drift
    python main.py --help       Show this help
    """)


def main():
    # Handle command line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        
        if arg == "--help" or arg == "-h":
            print_help()
            return
        
        elif arg == "--baseline":
            print("=" * 50)
            print("🛡️  DriftShield - Create Baseline")
            print("=" * 50 + "\n")
            create_baseline()
            return
        
        elif arg == "--drift":
            print("=" * 50)
            print("🛡️  DriftShield - Drift Detection")
            print("=" * 50 + "\n")
            drifts = compare_with_baseline()
            
            if drifts is None:
                print("\n💡 Tip: Run 'python main.py --baseline' first")
            elif drifts:
                print("\n" + "=" * 50)
                print("SUMMARY")
                print("=" * 50)
                print(f"⚠️  Configuration drifts detected: {len(drifts)}")
                send_drift_alerts(drifts)
            else:
                print("\n✅ All configurations match baseline!")
            return
    
    # Default: Run security scan
    print("=" * 50)
    print("🛡️  DriftShield - S3 Security Scanner")
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
        
        # Send alerts
        send_alerts(results['at_risk'])
    else:
        print("\n✅ All buckets are secure!")


if __name__ == "__main__":
    main()