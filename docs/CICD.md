# DriftShield CI/CD Integration Guide

DriftShield is engineered from the ground up to operate flawlessly inside automated CI/CD pipelines. As a compiled Go binary, it is incredibly lightweight, requires zero runtime dependencies (no Node.js, no Python, no Go installation), and securely ingests configuration via OS-level environment variables.

This guide outlines the core mechanisms DriftShield uses for pipeline automation and provides templates for popular CI/CD platforms.

---

## Core CI/CD Mechanisms

### 1. Zero-Dependency Execution
You do **not** need to clone this repository, install Go, or create an `.env` file to run DriftShield in CI/CD. 
Instead, your pipeline should download the compiled `driftshield` binary (e.g., from an S3 bucket or GitHub Releases) and execute it directly. DriftShield natively reads from the pipeline's secure environment variables.

### 2. Pipeline Exit Codes
DriftShield uses standard POSIX exit codes to signal success or failure to the CI/CD runner:
* `Exit Code 0` (Success): No security misconfigurations or drifts were detected. The pipeline will proceed and show a green checkmark.
* `Exit Code 1` (Failure): DriftShield detected an active misconfiguration or baseline drift. The pipeline will immediately **fail/turn red**, effectively blocking insecure deployments from reaching production.

### 3. AWS Authentication
DriftShield uses the standard AWS SDK for Go (`awsconfig.LoadDefaultConfig`). This means it automatically authenticates to whichever AWS Account is defined in the runner's environment variables. 
You do **not** need to run `aws configure`. The SDK natively looks for:
* `AWS_ACCESS_KEY_ID`
* `AWS_SECRET_ACCESS_KEY`
* `AWS_REGION`

There are two ways to provide these to your pipeline:
1. **The Traditional Way (Static Secrets):** You manually generate long-lived AWS keys and store them in your CI/CD Secrets Manager (e.g., GitHub Secrets or GitLab CI/CD Variables). 
2. **The Modern Way (OIDC):** You configure AWS IAM to trust your CI/CD platform (e.g., GitHub Actions OIDC). The pipeline requests a temporary 1-hour session and AWS securely injects the temporary keys directly into the environment. No static secrets need to be stored! This is the method used in the GitHub Actions example below.

### 4. Dry-Run Remediation (`--dry-run`)
Applying destructive infrastructure fixes automatically in a pipeline is highly risky. DriftShield provides a `--dry-run` (`-d`) global flag specifically for GitOps workflows. 

Running `./driftshield all fix --dry-run` in your pipeline will:
1. Identify all drifts.
2. Simulate the remediation logic.
3. Output the exact AWS API calls that *would* have been made.
4. Exit cleanly without altering your AWS infrastructure.

---

## Example: GitHub Actions

This workflow runs on a schedule (e.g., every hour) to audit your AWS environment against your secure baselines stored in S3. It uses OIDC (OpenID Connect) to securely assume an AWS IAM Role, meaning no long-lived AWS keys are stored in GitHub.

```yaml
name: DriftShield Security Audit
on:
  schedule:
    - cron: '0 * * * *' # Run hourly
  workflow_dispatch: # Allow manual trigger

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/DriftShieldAuditRole
          aws-region: ap-south-1

      - name: Download DriftShield Binary
        run: |
          # Replace with the URL where your compiled binary is hosted
          wget https://internal-artifacts.example.com/driftshield -O driftshield
          chmod +x driftshield

      - name: Run Unit Tests
        run: |
          go test -v ./...

      - name: Run DriftShield Compliance & Drift Detection
        env:
          DRIFTSHIELD_STATE_BUCKET: my-security-state-bucket
          DRIFTSHIELD_STATE_BUCKET_REGION: ap-south-1
          DRIFTSHIELD_SLACK_ENABLED: true
          DRIFTSHIELD_SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
        run: |
          # Evaluate live infrastructure against custom enterprise YAML policy rules
          ./driftshield policy scan
          # Detect baseline drift against state bucket
          ./driftshield all drift
```

---

## Example: GitLab CI

This pipeline template integrates DriftShield into a GitLab CI/CD workflow, utilizing GitLab's native environment variables for configuration.

```yaml
stages:
  - security-audit

driftshield_scan:
  stage: security-audit
  image: alpine:latest
  variables:
    DRIFTSHIELD_STATE_BUCKET: my-security-state-bucket
    DRIFTSHIELD_STATE_BUCKET_REGION: ap-south-1
    DRIFTSHIELD_SLACK_ENABLED: "true"
    # Note: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and DRIFTSHIELD_SLACK_WEBHOOK_URL 
    # should be configured securely in GitLab Settings > CI/CD > Variables.
  before_script:
    - apk add --no-cache wget ca-certificates
    - wget https://internal-artifacts.example.com/driftshield -O driftshield
    - chmod +x driftshield
  script:
    - echo "Running full infrastructure scan..."
    - ./driftshield all scan
    - echo "Evaluating policy rules..."
    - ./driftshield policy scan
    - echo "Checking for baseline drifts..."
    - ./driftshield all drift
```

---

## Best Practices for CI/CD

1. **State Isolation**: Ensure your `DRIFTSHIELD_STATE_BUCKET` is heavily restricted. Only the CI/CD IAM Role should have read/write access to prevent unauthorized tampering of the baselines.
2. **Alert Routing**: Use the `.env` override system to route pipeline alerts to specific Slack channels (e.g., `#secops-alerts`) rather than generic developer channels.
3. **Scheduled vs. Push**: Run `driftshield all drift` on a CRON schedule (e.g., every 4 hours) to catch out-of-band manual changes made directly in the AWS Console, not just during infrastructure deployments.
