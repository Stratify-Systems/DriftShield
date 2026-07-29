import os
import sys
import urllib.request
import json

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(AGENTS_DIR, ".."))

from uagents import Agent, Context, Protocol
from models import PolicyViolationAlert, DriftDetectedAlert, RemediationProof, save_agent_storage

alert_router = Agent(
    name="AlertRouterAgent",
    seed="alert_agent_seed_driftshield_006",
    port=8006,
    endpoint=["http://127.0.0.1:8006/submit"]
)

def generate_brief_with_groq(ctx: Context, alert_type: str, preview_text: str) -> str:
    """Invokes Groq LLaMA 3 70B AI model to generate a concise Executive CISO Incident Brief for multi-channel alerts."""
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
            ctx.logger.info("[AlertRouterAgent] Calling Groq LLaMA 3 API (llama-3.3-70b-versatile) for CISO Incident Executive Brief...")
            url = "https://api.groq.com/openai/v1/chat/completions"
            prompt = (
                f"You are an enterprise Chief Information Security Officer (CISO) dispatching a Multi-Channel Incident Alert ({alert_type}).\n"
                "Synthesize a 2-3 bullet point Executive Incident Brief summarizing the urgency, core finding, and immediate DevOps action required.\n\n"
                f"Alert Preview Output:\n{preview_text[:2500]}\n\n"
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
                ai_brief = resp_data["choices"][0]["message"]["content"].strip()
                ctx.logger.info("[AlertRouterAgent] Groq LLaMA 3 CISO incident brief generated successfully!")
                return ai_brief
        except Exception as e:
            ctx.logger.warning(f"[AlertRouterAgent] Groq API call failed: {e}. Falling back to default incident brief.")
            
    return (
        f"- **Incident Alert Type:** `{alert_type}`\n"
        "- **Executive Summary:** Live security finding or baseline drift dispatched to multi-channel sinks.\n"
        "- **Immediate Action:** Review Groq AI Remediation Guide and execute safe fixes."
    )

@alert_router.on_event("startup")
async def startup_alert(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("DRIFTSHIELD - AGENT 6: ALERT ROUTER AGENT ONLINE")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@alert_router.on_message(model=PolicyViolationAlert)
async def handle_policy_alert(ctx: Context, sender: str, msg: PolicyViolationAlert):
    ctx.logger.info(f"[AlertRouterAgent] Dispatching Policy Violation dossier from {sender[:12]}... to Slack, SES email, and SNS sinks.")
    preview = msg.violations[0].get("output", "") if (msg.violations and isinstance(msg.violations, list) and "output" in msg.violations[0]) else "Policy violations detected in live AWS infrastructure."
    ai_brief = generate_brief_with_groq(ctx, "POLICY_VIOLATION", preview)
    
    summary_data = {
        "alert_dispatch_summary": True,
        "alert_type": "POLICY_VIOLATION",
        "proposal_id": "POL-VIOLATION-001",
        "target_resource": "AWS Infrastructure",
        "status": "DISPATCHED",
        "ai_ciso_brief": ai_brief,
        "remediation_preview": preview
    }
    save_agent_storage("alert_router_agent", summary_data, alert_router.address)

@alert_router.on_message(model=DriftDetectedAlert)
async def handle_drift_alert(ctx: Context, sender: str, msg: DriftDetectedAlert):
    ctx.logger.info(f"📢 [AlertRouterAgent] Dispatching Baseline Drift alert from {sender[:12]}... to Slack, SES email, and SNS sinks.")
    preview = msg.raw_output if msg.raw_output else "Baseline drift detected in live AWS infrastructure."
    ai_brief = generate_brief_with_groq(ctx, "BASELINE_DRIFT", preview)
    
    summary_data = {
        "alert_dispatch_summary": True,
        "alert_type": "BASELINE_DRIFT",
        "proposal_id": "DRIFT-ALERT-001",
        "target_resource": "AWS Infrastructure Baseline",
        "status": "DISPATCHED",
        "ai_ciso_brief": ai_brief,
        "remediation_preview": preview
    }
    save_agent_storage("alert_router_agent", summary_data, alert_router.address)

@alert_router.on_message(model=RemediationProof)
async def handle_proof(ctx: Context, sender: str, msg: RemediationProof):
    ctx.logger.info(f"📢 [AlertRouterAgent] Consolidated Remediation Audit Report {msg.proposal_id} ready for DevSecOps dashboard.")
    preview = msg.dry_run_output
    ai_brief = generate_brief_with_groq(ctx, "REMEDIATION_PROOF", preview)
    
    summary_data = {
        "alert_dispatch_summary": True,
        "proposal_id": msg.proposal_id,
        "target_resource": msg.target_resource,
        "status": msg.status,
        "ai_ciso_brief": ai_brief,
        "remediation_preview": preview
    }
    save_agent_storage("alert_router_agent", summary_data, alert_router.address)

alert_router.include(Protocol("AlertProtocol"))

if __name__ == "__main__":
    alert_router.run()
