import os
import json
import datetime
from typing import List, Dict, Any, Optional
from uagents import Model

def save_agent_storage(agent_name: str, key: str, data: dict):
    """Save state data as beautiful, human-readable Markdown reports ONLY inside agents_data/"""
    agents_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(agents_dir, ".."))
    agents_data_dir = os.path.join(project_root, "agents_data")
    os.makedirs(agents_data_dir, exist_ok=True)

    # Human-Readable Markdown Report
    md_filepath = os.path.join(agents_data_dir, f"{agent_name}_report.md")
    try:
        with open(md_filepath, "w") as f:
            f.write(f"# 🛡️ DriftShield Agent Report — {agent_name.replace('_', ' ').title()}\n\n")
            f.write(f"**Last Updated:** `{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n\n")
            f.write("---\n\n")
            
            if "fix_action" in data:
                f.write("## 🧠 Groq LLaMA 3 AI Remediation Guide\n\n")
                f.write(f"**Target Resources:** `{data.get('target_resource', 'N/A')}`\\\n")
                f.write(f"**Violated Rules:** `{data.get('rule_id', 'N/A')}`\\\n")
                f.write(f"**AI Confidence Score:** `{float(data.get('confidence_score', 0))*100:.1f}%`\n\n")
                f.write("### Step-by-Step Human Instructions\n\n")
                f.write(f"{data.get('fix_action', '')}\n\n")
                if "suggested_yaml" in data:
                    f.write("### Suggested Policy-as-Code Rule (YAML)\n```yaml\n")
                    f.write(f"{data.get('suggested_yaml', '')}\n")
                    f.write("```\n\n")
            elif "dry_run_output" in data:
                f.write("## ⚡ AutoFix Dry-Run Simulation Proof\n\n")
                f.write(f"**Status:** `{data.get('status', 'N/A')}`\\\n")
                f.write(f"**Signed by uAgent:** `{data.get('signed_by', 'N/A')}`\n\n")
                f.write("### Simulation Output Preview\n```text\n")
                f.write(f"{data.get('dry_run_output', '')}\n")
                f.write("```\n\n")
            elif "raw_output" in data:
                f.write("## 🕵️‍♂️ Scanner AWS Telemetry Snapshot\n\n")
                f.write("```text\n")
                f.write(f"{data.get('raw_output', '')}\n")
                f.write("```\n\n")
            elif "violations" in data and data.get("violations"):
                f.write("## 🛡️ Policy Guard Violation Dossier\n\n")
                f.write("```text\n")
                f.write(f"{data['violations'][0].get('output', '')}\n")
                f.write("```\n\n")
    except Exception:
        pass

class CloudStateTelemetry(Model):
    timestamp: str
    region: str
    raw_output: str

class PolicyViolationAlert(Model):
    timestamp: str
    total_violations: int
    violations: List[Dict[str, Any]] = []

class DriftDetectedAlert(Model):
    timestamp: str
    total_drifts: int
    drifts: List[Dict[str, Any]] = []

class RemediationProposal(Model):
    proposal_id: str
    target_resource: str
    rule_id: str
    suggested_yaml: str
    fix_action: str
    confidence_score: float

class RemediationProof(Model):
    proposal_id: str
    target_resource: str
    status: str
    dry_run_output: str
    signed_by: str
