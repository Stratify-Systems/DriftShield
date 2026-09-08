import os
import sys
import subprocess
import datetime
import urllib.request
import json

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

def analyze_drift_with_groq(ctx: Context, drift_output: str) -> str:
    """Invokes Groq LLaMA 3 70B AI model to analyze anti-tampering drift root-causes and suspicious intent."""
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
            ctx.logger.info("[DriftSentinelAgent] Calling Groq LLaMA 3 API (llama-3.3-70b-versatile) for anti-tampering drift analysis...")
            url = "https://api.groq.com/openai/v1/chat/completions"
            prompt = (
                "You are an enterprise Anti-Tampering & Digital Forensics Specialist evaluating AWS baseline drift diffs.\n"
                "Analyze the drift diff below and provide a Root Cause & Anti-Tampering Suspicious Intent Analysis.\n"
                "Evaluate whether configuration changes look like unauthorized manual tampering, out-of-band admin overrides, or GitOps state divergence.\n\n"
                f"Baseline Drift Diff:\n{drift_output[:3000]}\n\n"
                "Return ONLY clean markdown bullet points. Do NOT add conversational introductory filler."
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
                ai_drift = resp_data["choices"][0]["message"]["content"].strip()
                ctx.logger.info("[DriftSentinelAgent] Groq LLaMA 3 anti-tampering drift analysis generated successfully!")
                return ai_drift
        except Exception as e:
            ctx.logger.warning(f"[DriftSentinelAgent] Groq API call failed: {e}. Falling back to default drift analysis.")
            
    return (
        "- **Anti-Tampering Evaluation:** Detected baseline drift indicates configuration changes occurred outside the approved GitOps state bucket.\n"
        "- **Root Cause Analysis:** Potential out-of-band manual modification via AWS Management Console or un-tracked CLI script.\n"
        "- **Recommended Action:** Revert unauthorized changes or update the remote S3 state baseline."
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
    
    ai_drift_analysis = analyze_drift_with_groq(ctx, drift_output)
    
    save_agent_storage("drift_sentinel_agent", {
        "drift_detected": has_drift,
        "ai_drift_analysis": ai_drift_analysis,
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
