# DriftShield AgentVerse Alliance — Architecture & Implementation

## Overview

DriftShield v2.0.0 integrates a **6-Agent Autonomous Alliance** built on the **Fetch.ai `uAgents` framework**. The multi-agent system decouples cloud telemetry collection, compliance evaluation, anti-tampering drift detection, Groq LLaMA 3 AI reasoning, safety auditing, and notification routing into specialized, peer-to-peer communicating agents.

---

## Agent Alliance Architecture

```text
                1. ScannerAgent (Port 8001)
             [Runs ./driftshield all every 5 mins]
                            │
              ┌─────────────┴─────────────┐
              │ (Broadcasts Telemetry)    │
              ▼                           ▼
  2. PolicyGuardAgent (Port 8002)     3. DriftSentinelAgent (Port 8003)
  Runs ./driftshield policy scan       Runs ./driftshield all drift
  Evaluates YAML Compliance            Diffs against S3 Remote State
              │ (PolicyViolationAlert)                │ (DriftDetectedAlert)
              ▼                                       │
  4. ArchitectAIAgent (Port 8004)                     │
  Groq LLaMA 3 Engine Synthesizes                     │
  Step-by-Step Human Remediation Plan                 │
              │ (RemediationProposal)                 │
              ▼                                       │
  5. RemediationAgent (Port 8005)                     │
  Runs ./driftshield all fix --dry-run               │
  Safe Simulation (0 Live AWS Mutations)              │
              │ (RemediationProof)                    │
              └─────────────┬─────────────────────────┘
                            ▼
                6. AlertRouterAgent (Port 8006)
                Dispatches Multi-Channel Notifications
                (Slack, SES Email, SNS)
```

---

## Agent Catalog & Responsibilities

| Agent Name | Port | Primary Responsibility |
| :--- | :--- | :--- |
| **ScannerAgent** | `8001` | Periodically executes `./driftshield all` (interval: 300s / 5 mins) to capture live AWS state and broadcasts `CloudStateTelemetry` to Agent 2 and Agent 3. |
| **PolicyGuardAgent** | `8002` | Listens for `CloudStateTelemetry`, evaluates rules in `policies/*.yaml` via `./driftshield policy scan`, and emits `PolicyViolationAlert` if non-compliant. |
| **DriftSentinelAgent** | `8003` | Listens for `CloudStateTelemetry`, compares live state against S3 Remote State baselines via `./driftshield all drift`, and emits `DriftDetectedAlert` on anti-tampering detection. |
| **ArchitectAIAgent** | `8004` | Dynamically parses live AWS violations or invokes Groq LLaMA 3 (`llama-3.3-70b-versatile`) to synthesize a **Step-by-Step Human Remediation Guide** and transmits `RemediationProposal`. |
| **RemediationAgent** | `8005` | Executes safe `./driftshield all fix --dry-run` simulations (0 live AWS modifications executed), signing `RemediationProof` with output audit logs. |
| **AlertRouterAgent** | `8006` | Aggregates violation, drift, and remediation audit reports to dispatch multi-channel alerts (Slack, AWS SES Email, AWS SNS) and updates `alert_router_agent_report.md`. |

---

## uAgent Inter-Agent Message Protocols (`agents/models.py`)

1. **`CloudStateTelemetry`**: Raw JSON telemetry payload captured by `ScannerAgent`.
2. **`PolicyViolationAlert`**: Non-compliance details emitted by `PolicyGuardAgent`.
3. **`DriftDetectedAlert`**: Anti-tampering baseline diff details emitted by `DriftSentinelAgent`.
4. **`RemediationProposal`**: AI-generated step-by-step human guide and YAML rule.
5. **`RemediationProof`**: Audit proof signed by `RemediationAgent`.

---

## Human-in-the-Loop Safety Principles

* **Zero Direct AI Mutations:** AI models never execute destructive AWS API mutations.
* **Step-by-Step Remediation Guides:** `ArchitectAIAgent` generates plain English, AWS Console, and CLI instructions for human DevOps engineers.
* **Human Remediation Verification:** `RemediationAgent` validates step-by-step human remediation guides with zero live AWS modifications.

---

## State Persistence & Human-Readable Markdown Reports

Agent state reports are persisted inside the **`agents_data/`** directory in **Human-Readable Markdown format (`*_report.md`)**:
- **`agents_data/scanner_agent_report.md`**: Live AWS telemetry snapshot.
- **`agents_data/policy_guard_agent_report.md`**: Policy violation dossier.
- **`agents_data/drift_sentinel_agent_report.md`**: Anti-tampering baseline diff report.
- **`agents_data/architect_ai_agent_report.md`**: Groq LLaMA 3 AI step-by-step human remediation guide.
- **`agents_data/remediation_agent_report.md`**: Human remediation audit report.
- **`agents_data/alert_router_agent_report.md`**: Consolidated DevSecOps audit summary.

To eliminate JSON clutter, `run_agents.py` automatically runs `cleanup_json_files()` on startup, leaving strictly clean `.md` Markdown reports inside `agents_data/`. All `agents_data/` files and `__pycache__` directories are excluded from git tracking via [.gitignore](file:///home/suryatk/DriftShield/.gitignore).

---

## Live WebSockets DevSecOps Dashboard (`agents/dashboard/dashboard_server.py`, `dashboard.html`, `dashboard.css`)

* **Directory:** Cleanly isolated inside `agents/dashboard/`.
* **Host & Port:** Running on `http://localhost:8080`.
* **WebSocket Endpoint:** `/ws` providing real-time uAgent status packets (`agent_status`), live Markdown report pushes (`report_update`), and terminal log events (`event_log`).
* **API Trigger Endpoint:** `POST /api/scan` allowing users to click **"Trigger Instant Scan"** on the UI to initiate an immediate AWS infrastructure scan.
* **Liquid Glass UI:** Built with Google Fonts (**Outfit** & **Inter**), live status grid for all 6 agents, interactive Markdown tab switcher (`marked.js`), Liquid Glass CSS design system (`dashboard.css`), and a scrolling cyber terminal event ticker.

---

## Execution Guide

### Launching All 6 Agents on the Bureau (Recommended)
```bash
python3 agents/run_agents.py
```
This launches all 6 agents on port `8000` alongside the DevSecOps WebSockets Dashboard server at `http://localhost:8080`.
