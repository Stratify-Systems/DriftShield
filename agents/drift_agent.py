import os
import sys
import subprocess
import datetime

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(AGENTS_DIR, ".."))

from uagents import Agent, Context
from models import TelemetryData, BaselineDriftAlert, save_agent_storage

ARCHITECT_AI_ADDRESS = "agent1qghyly2etc8y4xem7x62jexaw26lp7upte9kgpyktkuuk5jznfz4qk3lu7c"
ALERT_ROUTER_ADDRESS = "agent1qw9lyclq7dap8atgcx00du6l4nm909mg9dvsx45rqangqfagpvtgk37p5e4"

drift_sentinel = Agent(
    name="DriftSentinelAgent",
    seed="drift_agent_seed_driftshield_003",
    port=8003,
    endpoint=["http://127.0.0.1:8003/submit"]
)

@drift_sentinel.on_event("startup")
async def startup_drift(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("DRIFTSHIELD - AGENT 3: DRIFT SENTINEL AGENT ONLINE")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@drift_sentinel.on_message(model=TelemetryData)
async def handle_telemetry(ctx: Context, sender: str, msg: TelemetryData):
    ctx.logger.info(f"[DriftSentinelAgent] Received telemetry from ScannerAgent ({sender[:12]}...).")
    ctx.logger.info("[DriftSentinelAgent] Diffing live AWS state across S3, EC2, IAM, CloudTrail, VPC & RDS against Remote State baselines...")
    
    try:
        proc = subprocess.run(
            ["./driftshield", "all", "drift"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=120
        )
        drift_output = proc.stdout if proc.stdout else proc.stderr
    except Exception as e:
        drift_output = f"Failed to execute drift detection: {e}"
        
    has_drift = ("DRIFT DETECTED" in drift_output.upper() or "MISCONFIGURATION" in drift_output.upper() or "MODIFIED" in drift_output.upper())
    
    save_agent_storage("drift_sentinel_agent", {
        "drift_detected": has_drift,
        "drift_output": drift_output
    }, drift_sentinel.address)
    
    if has_drift:
        ctx.logger.warning("[DriftSentinelAgent] Baseline Drift Detected in live AWS resources!")
        drift_msg = BaselineDriftAlert(
            timestamp=datetime.datetime.now().isoformat(),
            drift_detected=True,
            raw_output=drift_output
        )
        await ctx.send(ARCHITECT_AI_ADDRESS, drift_msg)
        await ctx.send(ALERT_ROUTER_ADDRESS, drift_msg)
    else:
        ctx.logger.info("[DriftSentinelAgent] No baseline drift detected. All states match S3 state bucket.")

if __name__ == "__main__":
    drift_sentinel.run()
