#!/usr/bin/env python3
"""
DriftShield - S3 Security Scanner and Configuration Drift Detection

A cloud security tool that monitors AWS S3 bucket configurations
for security risks and configuration drift.
"""

import sys
from datetime import datetime

from src.scanner import scan_all_buckets
from src.baseline import create_baseline, compare_with_baseline, remediate_drift
from src.alerts import send_alerts, send_drift_alerts

VERSION = "1.0.0"


def print_banner(title):
    """Print a formatted banner."""
    print()
    print("+" + "-" * 58 + "+")
    print("|" + " " * 58 + "|")
    print("|" + f"  DRIFTSHIELD - {title}".ljust(58) + "|")
    print("|" + f"  Version {VERSION}".ljust(58) + "|")
    print("|" + " " * 58 + "|")
    print("+" + "-" * 58 + "+")
    print()


def print_help():
    """Print usage help."""
    print()
    print("+" + "-" * 58 + "+")
    print("|" + " " * 58 + "|")
    print("|" + "  DRIFTSHIELD".ljust(58) + "|")
    print("|" + "  S3 Security Scanner & Drift Detection Tool".ljust(58) + "|")
    print("|" + f"  Version {VERSION}".ljust(58) + "|")
    print("|" + " " * 58 + "|")
    print("+" + "-" * 58 + "+")
    print()
    print("DESCRIPTION:")
    print("  A cloud security tool that detects S3 misconfigurations")
    print("  and monitors configuration drift against a secure baseline.")
    print()
    print("USAGE:")
    print("  driftshield [command]")
    print()
    print("COMMANDS:")
    print("  (none)        Run security scan (default)")
    print("  --baseline    Create baseline from current configurations")
    print("  --drift       Check for configuration drift")
    print("  --fix         Fix drifted configs back to baseline")
    print("  --help        Show this help message")
    print()
    print("SHORTCUTS:")
    print("  -b            Same as --baseline")
    print("  -d            Same as --drift")
    print("  -f            Same as --fix")
    print("  -h            Same as --help")
    print()
    print("EXAMPLES:")
    print("  python main.py                 # Run security scan")
    print("  python main.py --baseline      # Save current config as baseline")
    print("  python main.py --drift         # Detect config changes")
    print("  python main.py --fix           # Fix drifted configs to baseline")
    print()
    print("CONFIGURATION:")
    print("  Edit src/config.py to configure email alerts.")
    print()
    print("MORE INFO:")
    print("  https://github.com/SuryaTK2007/DriftShield")
    print()


def run_security_scan():
    """Run the security scan for public access risks."""
    print_banner("SECURITY SCAN")
    
    print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    results = scan_all_buckets()
    
    print()
    print("+" + "-" * 58 + "+")
    print("|  SCAN RESULTS".ljust(59) + "|")
    print("+" + "-" * 58 + "+")
    print(f"|  Secure buckets:    {len(results['secure'])}".ljust(59) + "|")
    print(f"|  At-risk buckets:   {len(results['at_risk'])}".ljust(59) + "|")
    print("+" + "-" * 58 + "+")
    
    if results['at_risk']:
        print()
        print("[!] ACTION REQUIRED - Review these buckets:")
        for bucket in results['at_risk']:
            print(f"    - {bucket}")
        
        send_alerts(results['at_risk'])
    else:
        print()
        print("[+] All buckets are secure. No action required.")


def run_baseline_creation():
    """Create a new baseline from current configurations."""
    print_banner("CREATE BASELINE")
    
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    create_baseline()


def run_drift_detection():
    """Check for configuration drift against baseline."""
    print_banner("DRIFT DETECTION")
    
    print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    drifts = compare_with_baseline()
    
    if drifts is None:
        print()
        print("[!] No baseline found.")
        print("    Run 'python main.py --baseline' first to create one.")
        return None
    elif drifts:
        print()
        print("+" + "-" * 58 + "+")
        print("|  DRIFT DETECTION RESULTS".ljust(59) + "|")
        print("+" + "-" * 58 + "+")
        print(f"|  Configuration drifts found: {len(drifts)}".ljust(59) + "|")
        print("+" + "-" * 58 + "+")
        send_drift_alerts(drifts)
        return drifts
    else:
        print()
        print("[+] All configurations match baseline. No drift detected.")
        return []


def run_fix_drifts():
    """Detect drift and fix configurations back to baseline."""
    print_banner("REMEDIATION")
    
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # First detect drifts
    drifts = compare_with_baseline()
    
    if drifts is None:
        print()
        print("[!] No baseline found.")
        print("    Run 'python main.py --baseline' first to create one.")
        return
    
    if not drifts:
        print()
        print("[+] No drifts detected. Nothing to fix.")
        return
    
    print()
    print(f"Found {len(drifts)} drift(s). Starting remediation...")
    print()
    
    results = remediate_drift(drifts)
    
    print()
    print("+" + "-" * 58 + "+")
    print("|  REMEDIATION RESULTS".ljust(59) + "|")
    print("+" + "-" * 58 + "+")
    print(f"|  Fixed:    {len(results['fixed'])}".ljust(59) + "|")
    print(f"|  Failed:   {len(results['failed'])}".ljust(59) + "|")
    print(f"|  Skipped:  {len(results['skipped'])}".ljust(59) + "|")
    print("+" + "-" * 58 + "+")
    
    if results['failed']:
        print()
        print("[!] Some remediations failed. Check IAM permissions:")
        print("    - s3:PutBucketPublicAccessBlock")
        print("    - s3:PutBucketVersioning")
        print("    - s3:PutBucketEncryption")
        print("    - s3:DeleteBucketEncryption")


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        
        if arg in ("--help", "-h", "help"):
            print_help()
            return 0
        
        elif arg in ("--baseline", "-b", "baseline"):
            run_baseline_creation()
            return 0
        
        elif arg in ("--drift", "-d", "drift"):
            run_drift_detection()
            return 0
        
        elif arg in ("--fix", "-f", "fix"):
            run_fix_drifts()
            return 0
        
        else:
            print(f"[ERROR] Unknown option: {arg}")
            print("        Run 'python main.py --help' for usage information.")
            return 1
    
    # Default: Run security scan
    run_security_scan()
    return 0


if __name__ == "__main__":
    sys.exit(main())
