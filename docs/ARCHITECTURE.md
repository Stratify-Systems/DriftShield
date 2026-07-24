# DriftShield Architecture

DriftShield is a highly modular, enterprise-ready Cloud Security Posture Management (CSPM) and Drift Detection tool. It is written in **Go (Golang)** and designed to compile into a single, dependency-free binary for high-speed execution in CI/CD pipelines.

This document outlines the core architectural components, data flows, and design decisions of the project.

---

## 1. High-Level Architecture Diagram

```mermaid
graph TD
    User(["User / CI Pipeline"]) --> CLI["cmd/driftshield (Cobra CLI)"]
    
    subgraph Core Engine
        CLI --> Config["internal/config"]
        CLI --> Baseline["internal/baseline"]
        CLI --> Scanner["internal/scanner"]
        CLI --> AI["internal/ai"]
        CLI --> Policy["internal/policy"]
    end

    subgraph AWS Integration
        Scanner --> SDK["AWS SDK for Go v2"]
        Baseline --> SDK
        Policy --> Scanner
    end

    subgraph Persistence Layer
        Baseline <--> Storage["internal/storage"]
        Storage <--> S3Backend[("AWS S3 Remote State")]
        Policy <--> PolicyFiles[("policies/*.yaml Rules")]
    end

    subgraph Notification Layer
        Scanner --> Alerts["internal/alerts"]
        Baseline --> Alerts
        Alerts --> SES["AWS SES"]
        Alerts --> SNS["AWS SNS"]
        Alerts --> Slack["Slack Webhooks"]
    end

    subgraph AI Layer
        AI <--> Groq["Groq API / LLaMA 3"]
        AI --> PolicyFiles
    end
```

---

## 2. Directory Structure & Separation of Concerns

DriftShield follows standard Go project layout principles, isolating logic into highly cohesive internal packages.

### `cmd/driftshield/`
* **Purpose:** The entry point of the application.
* **Component:** Implements the `spf13/cobra` CLI framework.
* **Responsibilities:** Defines flags (e.g., `--region`, `--dry-run`, `--rules-dir`), parses arguments, initializes context, handles early exits (`os.Exit(1)`), and routes commands to the appropriate internal packages.

### `internal/scanner/`
* **Purpose:** The AWS ingestion layer.
* **Responsibilities:** Uses `aws-sdk-go-v2` to query the live state of AWS services (EC2, S3, IAM, CloudTrail, RDS, VPC). It is purely a read-only data extraction layer.

### `internal/baseline/`
* **Purpose:** The core business logic and diff engine.
* **Responsibilities:** 
  1. **Creation:** Takes output from `scanner` and formats it into a strict schema.
  2. **Diffing:** Compares the live `scanner` state against the stored baseline state to identify configuration drifts.
  3. **Remediation:** Executes AWS API calls (e.g., `RevokeSecurityGroupIngress`) to restore drifted infrastructure, intercepting these calls if `--dry-run` is active.

### `internal/storage/`
* **Purpose:** The persistence abstraction layer.
* **Responsibilities:** Implements a `StateBackend` interface. Currently powered by `S3Backend`, it handles saving and retrieving serialized JSON baseline files securely from a centralized S3 bucket.

### `internal/alerts/`
* **Purpose:** The outbound notification router.
* **Responsibilities:** Formats and routes vulnerability findings and drift reports to configured sinks (Slack, AWS SES, AWS SNS).

### `internal/ai/`
* **Purpose:** AI Policy Rule Generation.
* **Responsibilities:** Connects to the Groq API (LLaMA 3) to convert natural language security guidelines into validated, declarative YAML compliance rules for user review.

### `internal/policy/`
* **Purpose:** Declarative Policy-as-Code engine.
* **Responsibilities:** Loads custom YAML rule files (`policies/*.yaml`), parses conditions, and evaluates live AWS account configurations against enterprise compliance policies.

### `tests/`
* **Purpose:** Centralized unit testing suite.
* **Responsibilities:** Contains isolated unit tests for `ai`, `alerts`, `baseline`, `config`, `display`, `policy`, `scanner`, and `storage` packages without external network dependencies.

---

## 3. Core Execution Flows

### The `drift` Flow
1. **Initialize:** `cmd` invokes `runS3Drift()`.
2. **Fetch Live State:** `scanner.ScanS3()` fetches current AWS configurations.
3. **Fetch Baseline:** `storage.Load()` pulls the `s3_baseline.json` from the S3 Remote State Bucket.
4. **Compare:** `baseline.CompareS3WithBaseline()` performs a deep diff between the live state and the remote state.
5. **Alert:** If drifts are found, `alerts.SendS3DriftAlerts()` fires notifications to Slack/SES.
6. **Fail-Fast:** The CLI global `exitWithFailure` is set to `true`, eventually causing `os.Exit(1)`.

### The `policy scan` Flow
1. **Initialize:** `cmd` invokes `runPolicyScan()`.
2. **Load Rules:** `policy.LoadRulesFromDir("policies")` reads and validates all `.yaml` policy rules in the rules directory.
3. **Fetch Resource Snapshots:** `policy.EvaluatePolicyRules()` queries live AWS configurations via `scanner`.
4. **Evaluate Conditions:** Diffs live resource properties against rule condition trees (`all`, `any`, `none`, `none_rule`).
5. **Report & Exit:** Prints policy evaluation summary box; sets `exitWithFailure = true` if violations exist.

### The `ai policy` Flow
1. **Prompt User:** `ai.RunPolicyDesigner()` collects compliance framework and security guidelines in natural language.
2. **LLM Generation:** `ai.GeneratePolicyRules()` sends structured prompt to Groq LLaMA 3.
3. **Validate:** `policy.ValidateRule()` parses and validates the generated YAML against `PolicyRule` schema.
4. **User Review:** Displays proposed rules in terminal; asks for user approval (`survey.Confirm`).
5. **Persist:** Saves validated rules to `policies/custom_policy.yaml`.

### The `fix --dry-run` Flow
1. **Identify Drifts:** Identical to the `drift` flow.
2. **Pre-Flight Check:** `Remediate*Drift()` receives the `dryRun: true` parameter.
3. **Simulate:** Instead of invoking destructive AWS SDK methods (like `PutPublicAccessBlock`), the function skips the API call, formats a `[DRY-RUN]` message, and appends the simulated action to the `Fixed` array.
4. **Report:** Outputs the simulated changes to the terminal.

---

## 4. Design Decisions

### S3 Remote State vs. Local Files
DriftShield initially used local `.json` files for baselines. This was upgraded to an **S3 Remote State Backend** to support GitOps and CI/CD. By storing state centrally in S3 (secured via strict Bucket Policies), multiple CI/CD runners and engineers can query the exact same source of truth simultaneously.

### Global Error Propagation
Rather than having deep nested functions call `os.Exit(1)` (which disrupts unit testing and cross-service aggregation), DriftShield uses a global `exitWithFailure` flag inside `main.go`. This ensures all scheduled tasks (e.g., `driftshield all drift`) complete fully, firing all relevant alerts, before terminating the pipeline with a non-zero exit code.

### AWS Authentication Delegation
DriftShield relies completely on the `awsconfig.LoadDefaultConfig()` standard credential chain. It does not handle static keys directly. This allows it to inherit robust, temporary authentication via OIDC in GitHub Actions, ECS Task Roles, or EC2 Instance Profiles securely.
