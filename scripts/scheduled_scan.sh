#!/bin/bash
#
# DriftShield Scheduled Scanner
# 
# This script runs DriftShield security scans and drift detection
# on a schedule via cron.
#
# Usage:
#   ./scripts/scheduled_scan.sh [scan|drift|both]
#
# Setup cron (every hour):
#   crontab -e
#   0 * * * * /home/suryatk/DriftShield/scripts/scheduled_scan.sh both >> /home/suryatk/DriftShield/logs/cron.log 2>&1
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
SCAN_TYPE="${1:-both}"

# Log timestamp
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

case "$SCAN_TYPE" in
    scan)
        echo "[$TIMESTAMP] Running security scan..."
        RESULT=$($PYTHON main.py 2>&1)
        SECURE=$(echo "$RESULT" | grep -o "Secure buckets:.*[0-9]" | grep -o "[0-9]*")
        AT_RISK=$(echo "$RESULT" | grep -o "At-risk buckets:.*[0-9]" | grep -o "[0-9]*")
        echo "[$TIMESTAMP] Scan complete - Secure: ${SECURE:-0}, At-Risk: ${AT_RISK:-0}"
        ;;
    drift)
        echo "[$TIMESTAMP] Running drift detection..."
        RESULT=$($PYTHON main.py --drift 2>&1)
        if echo "$RESULT" | grep -q "No drift detected"; then
            echo "[$TIMESTAMP] Drift check complete - No drift detected"
        elif echo "$RESULT" | grep -q "drifts found"; then
            DRIFT_COUNT=$(echo "$RESULT" | grep -o "drifts found:.*[0-9]" | grep -o "[0-9]*")
            echo "[$TIMESTAMP] ALERT: ${DRIFT_COUNT:-1} configuration drift(s) detected"
        else
            echo "[$TIMESTAMP] Drift check complete"
        fi
        ;;
    both)
        # Security scan
        echo "[$TIMESTAMP] Running security scan..."
        RESULT=$($PYTHON main.py 2>&1)
        SECURE=$(echo "$RESULT" | grep -o "Secure buckets:.*[0-9]" | grep -o "[0-9]*")
        AT_RISK=$(echo "$RESULT" | grep -o "At-risk buckets:.*[0-9]" | grep -o "[0-9]*")
        echo "[$TIMESTAMP] Scan complete - Secure: ${SECURE:-0}, At-Risk: ${AT_RISK:-0}"
        
        # Drift detection
        echo "[$TIMESTAMP] Running drift detection..."
        RESULT=$($PYTHON main.py --drift 2>&1)
        if echo "$RESULT" | grep -q "No drift detected"; then
            echo "[$TIMESTAMP] Drift check complete - No drift detected"
        elif echo "$RESULT" | grep -q "drifts found"; then
            DRIFT_COUNT=$(echo "$RESULT" | grep -o "drifts found:.*[0-9]" | grep -o "[0-9]*")
            echo "[$TIMESTAMP] ALERT: ${DRIFT_COUNT:-1} configuration drift(s) detected"
        else
            echo "[$TIMESTAMP] Drift check complete"
        fi
        ;;
    *)
        echo "[$TIMESTAMP] Error: Unknown scan type '$SCAN_TYPE'"
        exit 1
        ;;
esac
