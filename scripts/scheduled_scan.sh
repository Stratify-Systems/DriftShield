#!/bin/bash
#
# DriftShield Scheduled Scanner
# 
# This script runs DriftShield security scans and drift detection
# on a schedule via cron.
#
# Usage:
#   ./scripts/scheduled_scan.sh [s3|ec2|all]
#
# Options:
#   s3   - Run S3 scan and drift detection
#   ec2  - Run EC2 scan and drift detection
#   all  - Run all scans and drift detection (default)
#
# Setup cron (every hour):
#   crontab -e
#   0 * * * * /home/suryatk/DriftShield/scripts/scheduled_scan.sh all >> /home/suryatk/DriftShield/logs/cron.log 2>&1
#

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_PATH="$PROJECT_DIR/venv"
LOG_DIR="$PROJECT_DIR/logs"
PYTHON="$VENV_PATH/bin/python"

# Create logs directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Activate virtual environment
source "$VENV_PATH/bin/activate"

# Change to project directory
cd "$PROJECT_DIR"

# Determine scan type
SCAN_TYPE="${1:-all}"

# Log timestamp
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "========================================"
echo "[$TIMESTAMP] DriftShield Scheduled Scan"
echo "========================================"

case "$SCAN_TYPE" in
    s3)
        # S3 Security scan
        echo "[$TIMESTAMP] Running S3 security scan..."
        RESULT=$($PYTHON main.py --s3 2>&1)
        SECURE=$(echo "$RESULT" | grep -o "Secure buckets:.*[0-9]" | grep -o "[0-9]*")
        AT_RISK=$(echo "$RESULT" | grep -o "At-risk buckets:.*[0-9]" | grep -o "[0-9]*")
        echo "[$TIMESTAMP] S3 Scan complete - Secure: ${SECURE:-0}, At-Risk: ${AT_RISK:-0}"
        
        # S3 Drift detection
        echo "[$TIMESTAMP] Running S3 drift detection..."
        RESULT=$($PYTHON main.py --s3 --drift 2>&1)
        if echo "$RESULT" | grep -q "No drift detected"; then
            echo "[$TIMESTAMP] S3 Drift check complete - No drift detected"
        elif echo "$RESULT" | grep -q "drifts found"; then
            DRIFT_COUNT=$(echo "$RESULT" | grep -o "drifts found:.*[0-9]" | grep -o "[0-9]*")
            echo "[$TIMESTAMP] ALERT: ${DRIFT_COUNT:-1} S3 configuration drift(s) detected"
        else
            echo "[$TIMESTAMP] S3 Drift check complete"
        fi
        ;;
    ec2)
        # EC2 Security scan
        echo "[$TIMESTAMP] Running EC2 security scan..."
        RESULT=$($PYTHON main.py --ec2 2>&1)
        SECURE=$(echo "$RESULT" | grep -o "Secure:.*[0-9]" | grep -o "[0-9]*")
        AT_RISK=$(echo "$RESULT" | grep -o "At-risk:.*[0-9]" | grep -o "[0-9]*")
        echo "[$TIMESTAMP] EC2 Scan complete - Secure: ${SECURE:-0}, At-Risk: ${AT_RISK:-0}"
        
        # EC2 Drift detection
        echo "[$TIMESTAMP] Running EC2 drift detection..."
        RESULT=$($PYTHON main.py --ec2 --drift 2>&1)
        if echo "$RESULT" | grep -q "No drift detected"; then
            echo "[$TIMESTAMP] EC2 Drift check complete - No drift detected"
        elif echo "$RESULT" | grep -q "drifts found"; then
            DRIFT_COUNT=$(echo "$RESULT" | grep -o "drifts found:.*[0-9]" | grep -o "[0-9]*")
            echo "[$TIMESTAMP] ALERT: ${DRIFT_COUNT:-1} EC2 configuration drift(s) detected"
        else
            echo "[$TIMESTAMP] EC2 Drift check complete"
        fi
        ;;
    all)
        # S3 Security scan
        echo "[$TIMESTAMP] Running S3 security scan..."
        RESULT=$($PYTHON main.py --s3 2>&1)
        SECURE=$(echo "$RESULT" | grep -o "Secure buckets:.*[0-9]" | grep -o "[0-9]*")
        AT_RISK=$(echo "$RESULT" | grep -o "At-risk buckets:.*[0-9]" | grep -o "[0-9]*")
        echo "[$TIMESTAMP] S3 Scan complete - Secure: ${SECURE:-0}, At-Risk: ${AT_RISK:-0}"
        
        # S3 Drift detection
        echo "[$TIMESTAMP] Running S3 drift detection..."
        RESULT=$($PYTHON main.py --s3 --drift 2>&1)
        if echo "$RESULT" | grep -q "No drift detected"; then
            echo "[$TIMESTAMP] S3 Drift check complete - No drift detected"
        elif echo "$RESULT" | grep -q "drifts found"; then
            DRIFT_COUNT=$(echo "$RESULT" | grep -o "drifts found:.*[0-9]" | grep -o "[0-9]*")
            echo "[$TIMESTAMP] ALERT: ${DRIFT_COUNT:-1} S3 configuration drift(s) detected"
        else
            echo "[$TIMESTAMP] S3 Drift check complete"
        fi
        
        echo ""
        
        # EC2 Security scan
        echo "[$TIMESTAMP] Running EC2 security scan..."
        RESULT=$($PYTHON main.py --ec2 2>&1)
        SECURE=$(echo "$RESULT" | grep -o "Secure:.*[0-9]" | grep -o "[0-9]*")
        AT_RISK=$(echo "$RESULT" | grep -o "At-risk:.*[0-9]" | grep -o "[0-9]*")
        echo "[$TIMESTAMP] EC2 Scan complete - Secure: ${SECURE:-0}, At-Risk: ${AT_RISK:-0}"
        
        # EC2 Drift detection
        echo "[$TIMESTAMP] Running EC2 drift detection..."
        RESULT=$($PYTHON main.py --ec2 --drift 2>&1)
        if echo "$RESULT" | grep -q "No drift detected"; then
            echo "[$TIMESTAMP] EC2 Drift check complete - No drift detected"
        elif echo "$RESULT" | grep -q "drifts found"; then
            DRIFT_COUNT=$(echo "$RESULT" | grep -o "drifts found:.*[0-9]" | grep -o "[0-9]*")
            echo "[$TIMESTAMP] ALERT: ${DRIFT_COUNT:-1} EC2 configuration drift(s) detected"
        else
            echo "[$TIMESTAMP] EC2 Drift check complete"
        fi
        ;;
    *)
        echo "[$TIMESTAMP] Error: Unknown scan type '$SCAN_TYPE'"
        echo "Usage: $0 [s3|ec2|all]"
        exit 1
        ;;
esac

echo ""
echo "[$TIMESTAMP] Scheduled scan completed"
echo "========================================"
