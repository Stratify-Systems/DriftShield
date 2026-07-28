import os
import sys
import subprocess
import datetime

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(AGENTS_DIR, ".."))

from uagents import Agent, Context
from models import TelemetryData, save_agent_storage

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
    ctx.logger.info("DRIFTSHIELD - AGENT 1: SCANNER AGENT ONLINE")
    ctx.logger.info(f"   Agent Address: {scanner.address}")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@scanner.on_interval(period=300.0)
async def periodic_scan(ctx: Context):
    ctx.logger.info("[ScannerAgent] Triggering live AWS infrastructure scan...")
    try:
        # Run `./driftshield all` to capture telemetry for all 6 AWS services
        proc = subprocess.run(
            ["./driftshield", "all"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=120
        )
        raw_output = proc.stdout if proc.stdout else proc.stderr
        
        ctx.logger.info(f"[ScannerAgent] AWS telemetry captured ({len(raw_output)} bytes). Broadcasting to PolicyGuard & DriftSentinel...")
        
        # Save telemetry report
        save_agent_storage("scanner_agent", {"raw_output": raw_output}, scanner.address)
        
        # Broadcast TelemetryData to PolicyGuard & DriftSentinel
        telemetry_msg = TelemetryData(timestamp=datetime.datetime.now().isoformat(), raw_output=raw_output)
        await ctx.send(POLICY_GUARD_ADDRESS, telemetry_msg)
        await ctx.send(DRIFT_SENTINEL_ADDRESS, telemetry_msg)
        
    except Exception as e:
        ctx.logger.error(f"[ScannerAgent] Failed to execute scan: {e}")

if __name__ == "__main__":
    scanner.run()
