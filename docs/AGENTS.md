# DriftShield AgentVerse Alliance — Architecture & Implementation

## Overview

DriftShield v2.0.0 integrates a **6-Agent Autonomous Alliance** built on the **Fetch.ai `uAgents` framework**. The multi-agent system decouples cloud telemetry collection, compliance evaluation, anti-tampering drift detection, AI reasoning, safety auditing, and notification routing into specialized, peer-to-peer communicating agents.

---

## Agent Alliance Architecture

```text
               1. 🕵️‍♂️ ScannerAgent (Port 8001)
               Scans AWS Telemetry ONCE
                           │
             ┌─────────────┴─────────────┐
             │ (Broadcast Telemetry)     │
             ▼                           ▼
 2. 🛡️ PolicyGuardAgent (Port 8002)   3. 🔍 DriftSentinelAgent (Port 8003)
 Runs ./driftshield policy scan       Runs ./driftshield all drift
 Evaluates YAML Compliance            Diffs against S3 Remote State
             │ (PolicyViolationAlert)                │ (DriftDetectedAlert)
             ▼                                       │
 4. 🧠 ArchitectAIAgent (Port 8004)                   │
 Groq LLaMA 3 Engine Synthesizes                     │
 Step-by-Step Human Remediation Plan                 │
             │ (RemediationProposal)                 │
             ▼                                       │
 5. ⚡ AutoFixAgent (Port 8005)                      │
 Peer-Review Risk (≥ 80% Confidence)                 │
 Runs Safe --dry-run Simulation ONLY                 │
             │ (RemediationProof)                    │
             └─────────────┬─────────────────────────┘
                           ▼
               6. 📢 AlertRouterAgent (Port 8006)
               Dispatches Multi-Channel Notifications
               (Slack, SES Email, SNS)
```

---

## Agent Catalog & Responsibilities

| Agent Name | Address / Seed | Port | Primary Responsibility |
| :--- | :--- | :--- | :--- |
| **🕵️‍♂️ ScannerAgent** | `agent1q2j3sxjx9zd0fl...` | `8001` | Periodically executes `./driftshield all` to capture live AWS state (S3, EC2, IAM, CloudTrail, VPC, RDS) and broadcasts `CloudStateTelemetry` to Agent 2 and Agent 3. |
| **🛡️ PolicyGuardAgent** | `agent1qvs9er6w78u606...` | `8002` | Listens for `CloudStateTelemetry`, evaluates rules in `policies/*.yaml` via `./driftshield policy scan`, and emits `PolicyViolationAlert` if non-compliant. |
| **🔍 DriftSentinelAgent** | `agent1qtp3c0576aqfqn...` | `8003` | Listens for `CloudStateTelemetry`, compares live state against S3 Remote State baselines via `./driftshield all drift`, and emits `DriftDetectedAlert` on anti-tampering detection. |
| **🧠 ArchitectAIAgent** | `agent1qghyly2etc8y4x...` | `8004` | Ingests `PolicyViolationAlert`, invokes Groq LLaMA 3 engine to synthesize a **Step-by-Step Human Remediation Guide**, and transmits `RemediationProposal`. |
| **⚡ AutoFixAgent** | `agent1qt043wu6g049vl...` | `8005` | Evaluates proposal risk ($\ge 80\%$ confidence threshold), executes safe `./driftshield all fix --dry-run` simulations ONLY (0 live AWS mutations), and signs `RemediationProof`. |
| **📢 AlertRouterAgent** | `agent1qw9lyclq7dap8a...` | `8006` | Aggregates violation, drift, and remediation audit reports to dispatch multi-channel alerts (Slack, AWS SES Email, AWS SNS). |

---

## uAgent Inter-Agent Message Protocols (`agents/models.py`)

1. **`CloudStateTelemetry`**: Raw JSON telemetry payload captured by `ScannerAgent`.
2. **`PolicyViolationAlert`**: Non-compliance details emitted by `PolicyGuardAgent`.
3. **`DriftDetectedAlert`**: Anti-tampering baseline diff details emitted by `DriftSentinelAgent`.
4. **`RemediationProposal`**: AI-generated step-by-step human guide, YAML rule, and confidence score.
5. **`RemediationProof`**: Audit proof signed by `AutoFixAgent` following dry-run simulation.

---

## Human-in-the-Loop Safety Principles

* **Zero Direct AI Mutations:** AI models never execute destructive AWS API mutations.
* **Step-by-Step Remediation Guides:** `ArchitectAIAgent` generates plain English, AWS Console, and CLI instructions for human DevOps engineers.
* **Dry-Run Auditing:** `AutoFixAgent` only executes `./driftshield all fix --dry-run` to preview structural changes safely.

---

## State Persistence & Cleanliness

Agent memory states are isolated in the `agents_data/` directory (`agents_data/agent1q*.json`) and automatically ignored in `.gitignore` to maintain clean source control.

---

## Execution Guide

### Launching All 6 Agents on the Bureau (Recommended)
```bash
python3 agents/run_agents.py
```

### Launching an Individual Agent Standalone
```bash
python3 agents/scanner_agent.py
python3 agents/policy_agent.py
python3 agents/drift_agent.py
python3 agents/ai_agent.py
python3 agents/autofix_agent.py
python3 agents/alert_agent.py
```
