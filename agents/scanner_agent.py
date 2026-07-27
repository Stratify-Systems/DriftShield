import subprocess
import datetime
from uagents import Agent, Context
from models import CloudStateTelemetry

POLICY_GUARD_ADDRESS = "agent1qvs9er6w78u606a6952zlf2ejng89a5nelq096xys0hvf8xtjmrwq5ljm2a"
DRIFT_SENTINEL_ADDRESS = "agent1qtp3c0576aqfqnpqr6m7j79m8txa88a4x2x2jjshdmlpytg0cm5r2cts6p7"

scanner = Agent(
    name="ScannerAgent",
    seed="scanner_agent_seed_driftshield_001",
    port=8001,
    endpoint=["http://127.0.0.1:8001/submit"]
)

@scanner.on_event("startup")
async def startup_scanner(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("🛡️  DRIFTSHIELD - AGENT 1: SCANNER AGENT ONLINE")
    ctx.logger.info(f"   Agent Address: {scanner.address}")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@scanner.on_interval(period=300.0)
async def periodic_scan(ctx: Context):
    ctx.logger.info("🕵️‍♂️ [ScannerAgent] Triggering live AWS infrastructure scan...")
    try:
        result = subprocess.run(
            ["./driftshield", "all"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        raw_output = result.stdout
        
        telemetry = CloudStateTelemetry(
            timestamp=datetime.datetime.now().isoformat(),
            region="ap-south-1",
            raw_output=raw_output
        )
        
        ctx.logger.info(f"🕵️‍♂️ [ScannerAgent] AWS telemetry captured ({len(raw_output)} bytes). Broadcasting to PolicyGuard & DriftSentinel...")
        ctx.storage.set("latest_telemetry", telemetry.dict())
        
        # Broadcast telemetry to Agent 2 (PolicyGuard) and Agent 3 (DriftSentinel) in parallel
        await ctx.send(POLICY_GUARD_ADDRESS, telemetry)
        await ctx.send(DRIFT_SENTINEL_ADDRESS, telemetry)
    except Exception as e:
        ctx.logger.error(f"❌ [ScannerAgent] Failed to execute scan: {e}")

if __name__ == "__main__":
    scanner.run()
