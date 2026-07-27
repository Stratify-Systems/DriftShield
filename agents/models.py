from typing import List, Dict, Any, Optional
from uagents import Model

class CloudStateTelemetry(Model):
    timestamp: str
    region: str
    raw_output: str
