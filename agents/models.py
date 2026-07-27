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
