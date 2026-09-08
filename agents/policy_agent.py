import os
import sys
import subprocess
import datetime
import urllib.request
import json

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

def analyze_threat_with_groq(ctx: Context, violation_output: str) -> str:
    """Invokes Groq LLaMA 3 70B AI model to analyze threat vector risks of detected policy violations."""
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
            ctx.logger.info("[PolicyGuardAgent] Calling Groq LLaMA 3 API (llama-3.3-70b-versatile) for threat vector analysis...")
            url = "https://api.groq.com/openai/v1/chat/completions"
            prompt = (
                "You are an enterprise Cyber Threat Intelligence Analyst evaluating live AWS Policy-as-Code violations.\n"
                "Analyze the violation report below and provide a concise Threat Vector & Risk Impact Analysis.\n"
                "Explain the potential attack vectors, exploit risks, and business severity.\n\n"
                f"Policy Violation Report:\n{violation_output[:3000]}\n\n"
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
                ai_threat = resp_data["choices"][0]["message"]["content"].strip()
                ctx.logger.info("[PolicyGuardAgent] Groq LLaMA 3 threat vector analysis generated successfully!")
                return ai_threat
        except Exception as e:
            ctx.logger.warning(f"[PolicyGuardAgent] Groq API call failed: {e}. Falling back to default risk analysis.")
            
    return (
        "- **Threat Vector Analysis:** Detected policy violations expose cloud infrastructure to potential unauthorized access or compliance failure.\n"
        "- **Exploit Risk:** Misconfigured security groups or unencrypted storage resources increase attack surface area.\n"
        "- **Recommended Action:** Review Groq AI Step-by-Step Remediation Plan and apply least-privilege policies."
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
    ctx.logger.info("[PolicyGuardAgent] Executing `./driftshield all policy` security scan...")
    
    result = subprocess.run(
        ["./driftshield", "all", "policy"],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    output = result.stdout if result.stdout else result.stderr
    is_violation = (result.returncode != 0)
    
    ctx.logger.info("[PolicyGuardAgent] Synthesizing Groq AI Threat Vector Analysis for scan output...")
    ai_threat = analyze_threat_with_groq(ctx, output)
    
    save_agent_storage("policy_guard_agent", {
        "ai_threat": ai_threat,
        "raw_output": output
    }, policy_guard.address)
    
    if is_violation:
        ctx.logger.warning("[PolicyGuardAgent] Policy Violations Detected in live AWS resources! Broadcasting to ArchitectAIAgent...")
        alert = PolicyViolationAlert(
            timestamp=datetime.datetime.now().isoformat(),
            total_violations=1,
            violations=[{"output": output}]
        )
        await ctx.send(ARCHITECT_AI_ADDRESS, alert)
    else:
        ctx.logger.info("[PolicyGuardAgent] 100% Policy Compliance verified. 0 violations.")

if __name__ == "__main__":
    policy_guard.run()
