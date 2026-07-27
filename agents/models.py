from typing import List, Dict, Any, Optional
from uagents import Model

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
