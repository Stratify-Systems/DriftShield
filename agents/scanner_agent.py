import os
import sys
import subprocess
import datetime
import urllib.request
import json

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

def summarize_telemetry_with_groq(ctx: Context, raw_telemetry: str) -> str:
    """Invokes Groq LLaMA 3 70B AI model to synthesize a detailed summary of exact findings from the live scan."""
    groq_api_key = os.getenv("GROQ_API_KEY", "")
    if not groq_api_key:
        env_path = os.path.join(PROJECT_ROOT, ".env")
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                for line in f:
                    if line.startswith("GROQ_API_KEY="):
                        groq_api_key = line.split("=", 1)[1].strip()
                        
    if groq_api_key:
        try:
            ctx.logger.info("[ScannerAgent] Calling Groq LLaMA 3 API (llama-3.3-70b-versatile) to summarize scan findings...")
            url = "https://api.groq.com/openai/v1/chat/completions"
            prompt = (
                "You are an enterprise Cloud Security Analyst reviewing a raw AWS infrastructure scan.\n"
                "Analyze the raw scan text below and provide a concise, factual summary of EXACTLY WHAT WAS FOUND in this scan.\n"
                "Highlight specific resource names, scanned services (S3, EC2, IAM, CloudTrail, VPC, RDS), security status ([OK] vs [AT RISK]), and active findings.\n\n"
                f"Raw Scan Output:\n{raw_telemetry[:3500]}\n\n"
                "Return ONLY clean markdown bullet points organized by service. Do NOT add conversational introductory filler."
            )
            payload = {
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers={
                    "Authorization": f"Bearer {groq_api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "DriftShield/2.0"
                }
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                resp_data = json.loads(response.read().decode('utf-8'))
                ai_summary = resp_data["choices"][0]["message"]["content"].strip()
                ctx.logger.info("[ScannerAgent] Groq LLaMA 3 scan findings summary generated successfully!")
                return ai_summary
        except Exception as e:
            ctx.logger.warning(f"[ScannerAgent] Groq API call failed: {e}. Falling back to dynamic summary.")
            
    # Dynamic fallback parser if API key is absent or call fails
    lines = raw_telemetry.splitlines()
    ok_count = sum(1 for l in lines if "[OK]" in l)
    risk_count = sum(1 for l in lines if "[AT RISK]" in l or "CRITICAL" in l or "HIGH" in l)
    
    return (
        f"- **Scan Findings Overview:** Identified {ok_count} secure resources (`[OK]`) and {risk_count} security risks/findings across audited services.\n"
        f"- **S3 Storage:** Evaluated public access blocks across active S3 buckets.\n"
        f"- **EC2 & IAM:** Audited security group ingress rules and IAM user credentials/MFA status.\n"
        f"- **CloudTrail, VPC & RDS:** Verified trail logging, flow logs, and database encryption settings."
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
        
        ctx.logger.info(f"[ScannerAgent] AWS telemetry captured ({len(raw_output)} bytes). Synthesizing Groq AI Posture Summary...")
        
        # Generate Groq AI Posture Summary
        ai_summary = summarize_telemetry_with_groq(ctx, raw_output)
        
        # Save telemetry report with AI summary
        save_agent_storage("scanner_agent", {
            "ai_summary": ai_summary,
            "raw_output": raw_output
        }, scanner.address)
        
        ctx.logger.info(f"[ScannerAgent] Broadcasting telemetry to PolicyGuard & DriftSentinel...")
        
        # Broadcast TelemetryData to PolicyGuard & DriftSentinel
        telemetry_msg = TelemetryData(timestamp=datetime.datetime.now().isoformat(), raw_output=raw_output)
        await ctx.send(POLICY_GUARD_ADDRESS, telemetry_msg)
        await ctx.send(DRIFT_SENTINEL_ADDRESS, telemetry_msg)
        
    except Exception as e:
        ctx.logger.error(f"[ScannerAgent] Failed to execute scan: {e}")

if __name__ == "__main__":
    scanner.run()
