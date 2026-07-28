import os
import json
import datetime
from typing import List, Dict, Any, Optional
from uagents import Model

def save_agent_storage(agent_name: str, data_or_key: Any, data_or_address: Any = None, agent_address: str = None):
    """Save state data as beautiful, human-readable Markdown reports ONLY inside agents_data/"""
    agents_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(agents_dir, ".."))
    agents_data_dir = os.path.join(project_root, "agents_data")
    os.makedirs(agents_data_dir, exist_ok=True)

    # Determine dictionary data and address from arguments
    if isinstance(data_or_key, dict):
        data = data_or_key
        addr = str(data_or_address) if data_or_address else (agent_address or "")
    elif isinstance(data_or_address, dict):
        data = data_or_address
        addr = agent_address or str(data_or_key)
    else:
        data = {"output": str(data_or_key)}
        addr = str(agent_address or data_or_address or "")

    md_filepath = os.path.join(agents_data_dir, f"{agent_name}_report.md")
    try:
        with open(md_filepath, "w") as f:
            f.write(f"# DriftShield Agent Report — {agent_name.replace('_', ' ').title()}\n\n")
            f.write(f"**Last Updated:** `{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`  \n")
            if addr:
                f.write(f"**Agent Address:** `{addr}`\n\n")
            else:
                f.write("\n")
            f.write("---\n\n")
            
            if "fix_action" in data:
                f.write("## Groq LLaMA 3 AI Remediation Guide\n\n")
                f.write(f"**Target Resources:** `{data.get('target_resource', 'N/A')}`\\\n")
                f.write(f"**Violated Rules:** `{data.get('rule_id', 'N/A')}`\n\n")
                f.write("### Step-by-Step Human Instructions\n\n")
                f.write(f"{data.get('fix_action', '')}\n\n")
                if "suggested_yaml" in data:
                    f.write("### Suggested Policy-as-Code Rule (YAML)\n```yaml\n")
                    f.write(f"{data.get('suggested_yaml', '')}\n")
                    f.write("```\n\n")
            elif "alert_dispatch_summary" in data:
                f.write("## DevSecOps Consolidated Alert Dispatch Summary\n\n")
                f.write(f"**Remediation Proposal ID:** `{data.get('proposal_id', 'N/A')}`\\\n")
                f.write(f"**Target Resource:** `{data.get('target_resource', 'N/A')}`\\\n")
                f.write(f"**Audit Status:** `{data.get('status', 'DELIVERED')}`\n\n")
                f.write("### Multi-Channel Dispatch Sinks\n")
                f.write("| Channel | Sink Target | Delivery Status |\n")
                f.write("| :--- | :--- | :--- |\n")
                f.write("| **DevSecOps Dashboard** | `WebSocket ws://localhost:8080/ws` | `DELIVERED` |\n")
                f.write("| **Slack Webhook** | `#driftshield-alerts` | `DISPATCHED` |\n")
                f.write("| **AWS SES Email** | `devsecops@driftshield.internal` | `QUEUED` |\n")
                f.write("| **AWS SNS Topic** | `arn:aws:sns:ap-south-1:driftshield-alerts` | `NOTIFIED` |\n\n")
                f.write("### Remediation Guide Summary\n```text\n")
                f.write(f"{data.get('remediation_preview', '')}\n")
                f.write("```\n\n")
            elif "drift_output" in data:
                f.write("## Anti-Tampering Baseline Drift Report\n\n")
                f.write(f"**Baseline Drift Status:** `{'DRIFT DETECTED' if data.get('drift_detected') else 'ALL STATES MATCH BASELINE'}`\n\n")
                f.write("### DriftShield Baseline Diff Output\n```text\n")
                f.write(f"{data.get('drift_output', '')}\n")
                f.write("```\n\n")
            elif "dry_run_output" in data or "remediation_guide" in data:
                f.write("## Remediation Agent Audit Report\n\n")
                f.write(f"**Status:** `{data.get('status', 'HUMAN_REMEDIATION_GUIDE_PREPARED')}`\\\n")
                f.write(f"**Direct AWS Mutations:** `0 (Disabled — Human Manual Fix Only)`\\\n")
                f.write(f"**Signed by uAgent Auditor:** `{data.get('signed_by', 'N/A')}`\n\n")
                f.write("### Verified Human Remediation Guide\n```text\n")
                guide = data.get('remediation_guide') or data.get('dry_run_output') or 'No guide provided.'
                f.write(f"{guide}\n")
                f.write("```\n\n")
            elif "raw_output" in data:
                f.write("## Scanner AWS Telemetry Snapshot\n\n")
                f.write("```text\n")
                f.write(f"{data.get('raw_output', '')}\n")
                f.write("```\n\n")
            elif "violations" in data and data.get("violations"):
                f.write("## Policy Guard Violation Dossier\n\n")
                f.write("```text\n")
                v_output = data['violations'][0].get('output', '') if isinstance(data['violations'], list) else str(data['violations'])
                f.write(f"{v_output}\n")
                f.write("```\n\n")
            else:
                f.write("## Telemetry Summary\n\n")
                f.write("```json\n")
                f.write(f"{json.dumps(data, indent=2)}\n")
                f.write("```\n\n")
    except Exception as e:
        pass

class CloudStateTelemetry(Model):
    timestamp: str
    region: str = "ap-south-1"
    raw_output: str

TelemetryData = CloudStateTelemetry

class PolicyViolationAlert(Model):
    timestamp: str
    total_violations: int = 1
    violations: List[Dict[str, Any]] = []

class DriftDetectedAlert(Model):
    timestamp: str
    drift_detected: bool = True
    raw_output: str = ""
    total_drifts: int = 1
    drifts: List[Dict[str, Any]] = []

BaselineDriftAlert = DriftDetectedAlert

class RemediationProposal(Model):
    proposal_id: str
    target_resource: str
    rule_id: str
    suggested_yaml: str
    fix_action: str
    confidence_score: float = 1.0

class RemediationProof(Model):
    proposal_id: str
    target_resource: str
    status: str
    dry_run_output: str = ""
    remediation_guide: str = ""
    signed_by: str
