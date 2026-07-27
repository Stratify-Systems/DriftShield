import subprocess
import datetime
from uagents import Agent, Context
from models import CloudStateTelemetry

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
        
        ctx.logger.info(f"🕵️‍♂️ [ScannerAgent] AWS telemetry captured successfully ({len(raw_output)} bytes).")
        ctx.storage.set("latest_telemetry", telemetry.dict())
    except Exception as e:
        ctx.logger.error(f"❌ [ScannerAgent] Failed to execute scan: {e}")

if __name__ == "__main__":
    scanner.run()
