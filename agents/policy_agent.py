import subprocess
import datetime
from uagents import Agent, Context, Protocol
from models import CloudStateTelemetry, PolicyViolationAlert

policy_guard = Agent(
    name="PolicyGuardAgent",
    seed="policy_agent_seed_driftshield_002",
    port=8002,
    endpoint=["http://127.0.0.1:8002/submit"]
)

@policy_guard.on_event("startup")
async def startup_policy(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("🛡️  DRIFTSHIELD - AGENT 2: POLICY GUARD AGENT ONLINE")
    ctx.logger.info(f"   Agent Address: {policy_guard.address}")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@policy_guard.on_message(model=CloudStateTelemetry)
async def handle_telemetry(ctx: Context, sender: str, msg: CloudStateTelemetry):
    ctx.logger.info(f"🛡️ [PolicyGuardAgent] Received telemetry from ScannerAgent ({sender[:12]}...).")
    ctx.logger.info("🛡️ [PolicyGuardAgent] Evaluating live AWS resources against YAML policy rules...")
    
    # Run policy scan using Go engine
    result = subprocess.run(
        ["./driftshield", "policy", "scan"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    output = result.stdout
    is_violation = (result.returncode != 0)
    
    if is_violation:
        ctx.logger.warning("🛡️ [PolicyGuardAgent] ⚠️ Policy Violations Detected in live AWS resources!")
        alert = PolicyViolationAlert(
            timestamp=datetime.datetime.now().isoformat(),
            total_violations=1,
            violations=[{"output": output}]
        )
        ctx.storage.set("latest_violation", alert.dict())
    else:
        ctx.logger.info("🛡️ [PolicyGuardAgent] ✅ 100% Policy Compliance verified. 0 violations.")

if __name__ == "__main__":
    policy_guard.run()
