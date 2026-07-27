import os
import json
from typing import List, Dict, Any, Optional
from uagents import Model

def save_agent_storage(agent_name: str, key: str, data: dict):
    """Save state data into clean, human-readable JSON files inside agents_data/"""
    agents_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(agents_dir, ".."))
    agents_data_dir = os.path.join(project_root, "agents_data")
    os.makedirs(agents_data_dir, exist_ok=True)
    
    filepath = os.path.join(agents_data_dir, f"{agent_name}.json")
    existing_data = {}
    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                existing_data = json.load(f)
        except Exception:
            existing_data = {}
            
    existing_data[key] = data
    with open(filepath, "w") as f:
        json.dump(existing_data, f, indent=4)

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
