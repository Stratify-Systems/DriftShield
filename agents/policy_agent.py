import os
import sys
import subprocess
import datetime

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(AGENTS_DIR, ".."))

from uagents import Agent, Context
from models import CloudStateTelemetry, PolicyViolationAlert, save_agent_storage

ARCHITECT_AI_ADDRESS = "agent1qghyly2etc8y4xem7x62jexaw26lp7upte9kgpyktkuuk5jznfz4qk3lu7c"

policy_guard = Agent(
    name="PolicyGuardAgent",
    seed="policy_agent_seed_driftshield_002",
    port=8002,
    endpoint=["http://127.0.0.1:8002/submit"]
)

@policy_guard.on_event("startup")
async def startup_policy(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("DRIFTSHIELD - AGENT 2: POLICY GUARD AGENT ONLINE")
    ctx.logger.info(f"   Agent Address: {policy_guard.address}")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@policy_guard.on_message(model=CloudStateTelemetry)
async def handle_telemetry(ctx: Context, sender: str, msg: CloudStateTelemetry):
    ctx.logger.info(f"[PolicyGuardAgent] Received telemetry from ScannerAgent ({sender[:12]}...).")
    ctx.logger.info("[PolicyGuardAgent] Evaluating live AWS resources against YAML policy rules...")
    
    result = subprocess.run(
        ["./driftshield", "policy", "scan"],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    output = result.stdout
    is_violation = (result.returncode != 0)
    
    if is_violation:
        ctx.logger.warning("[PolicyGuardAgent] Policy Violations Detected in live AWS resources!")
        alert = PolicyViolationAlert(
            timestamp=datetime.datetime.now().isoformat(),
            total_violations=1,
            violations=[{"output": output}]
        )
        save_agent_storage("policy_guard_agent", "latest_violation", alert.dict())
        
        await ctx.send(ARCHITECT_AI_ADDRESS, alert)
    else:
        ctx.logger.info("[PolicyGuardAgent] 100% Policy Compliance verified. 0 violations.")

if __name__ == "__main__":
    policy_guard.run()
