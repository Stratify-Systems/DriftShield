import os
import sys
import subprocess
import datetime

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(AGENTS_DIR, ".."))

from uagents import Agent, Context
from models import CloudStateTelemetry, DriftDetectedAlert, save_agent_storage

drift_sentinel = Agent(
    name="DriftSentinelAgent",
    seed="drift_agent_seed_driftshield_003",
    port=8003,
    endpoint=["http://127.0.0.1:8003/submit"]
)

@drift_sentinel.on_event("startup")
async def startup_drift(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("🛡️  DRIFTSHIELD - AGENT 3: DRIFT SENTINEL AGENT ONLINE")
    ctx.logger.info(f"   Agent Address: {drift_sentinel.address}")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@drift_sentinel.on_message(model=CloudStateTelemetry)
async def handle_telemetry(ctx: Context, sender: str, msg: CloudStateTelemetry):
    ctx.logger.info(f"🔍 [DriftSentinelAgent] Received telemetry from ScannerAgent ({sender[:12]}...).")
    ctx.logger.info("🔍 [DriftSentinelAgent] Diffing live AWS state across S3, EC2, IAM, CloudTrail, VPC & RDS against Remote State baselines...")
    
    result = subprocess.run(
        ["./driftshield", "all", "drift"],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    output = result.stdout
    has_drift = (result.returncode != 0)
    
    if has_drift:
        ctx.logger.warning("🔍 [DriftSentinelAgent] ✖ Baseline Drift Detected in live AWS resources!")
        alert = DriftDetectedAlert(
            timestamp=datetime.datetime.now().isoformat(),
            total_drifts=1,
            drifts=[{"output": output}]
        )
        save_agent_storage("drift_sentinel_agent", "latest_drift", alert.dict())
    else:
        ctx.logger.info("🔍 [DriftSentinelAgent] ✔ No baseline drift detected. All states match S3 state bucket.")

if __name__ == "__main__":
    drift_sentinel.run()
