import os
import sys
import json
import uuid
import datetime
import urllib.request

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(AGENTS_DIR, ".."))

from uagents import Agent, Context, Protocol
from models import PolicyViolationAlert, RemediationProposal, save_agent_storage

AUTOFIX_ADDRESS = "agent1qt043wu6g049vljszuafr275zlwf88cz7pfxetxgq52lmr7z7putxqxvjwk"

ai_architect = Agent(
    name="ArchitectAIAgent",
    seed="ai_agent_seed_driftshield_004",
    port=8004,
    endpoint=["http://127.0.0.1:8004/submit"]
)

def parse_remediation_from_violations(violations_output: str) -> tuple:
    """Fallback parser to extract rule IDs, resources, and remediation steps from CLI output."""
    rule_ids = []
    resources = []
    remediation_steps = []
    
    lines = violations_output.splitlines()
    for line in lines:
        if "[FAIL]" in line:
            parts = line.split("[FAIL]")
            if len(parts) > 1:
                detail = parts[1].strip()
                if "[" in detail and "]" in detail:
                    rule_id = detail.split("[")[1].split("]")[0]
                    rule_ids.append(rule_id)
                if "Resource:" in detail:
                    res = detail.split("Resource:")[1].strip()
                    resources.append(res)
                    
        if "Remediation:" in line:
            rem = line.split("Remediation:")[1].strip()
            remediation_steps.append(rem)
            
    if not rule_ids:
        rule_ids = ["POL-AWS-001"]
    if not resources:
        resources = ["AWS Infrastructure"]
        
    rule_id_str = " / ".join(list(dict.fromkeys(rule_ids)))
    target_res_str = " / ".join(list(dict.fromkeys(resources)))
    
    formatted_steps = [f"{idx}. {step}" for idx, step in enumerate(remediation_steps, 1)]
    if not formatted_steps:
        formatted_steps = [
            "1. Review Policy-as-Code YAML rules in policies/ directory.",
            "2. Apply required security baseline configurations."
        ]
        
    steps_txt = "\n".join(formatted_steps)
    fix_action = f"STEP-BY-STEP HUMAN REMEDIATION GUIDE FOR {target_res_str}:\n{steps_txt}\n{len(formatted_steps)+1}. Re-run './driftshield policy scan' to verify 100% compliance."
    
    suggested_yaml = f"""- id: {rule_ids[0]}
  name: Enforce Security Compliance for {resources[0]}
  severity: HIGH
  conditions:
    all:
      - field: status
        operator: equals
        value: compliant"""
        
    confidence_score = round(min(0.99, max(0.70, 0.85 + (len(remediation_steps) * 0.04))), 2)
    return target_res_str, rule_id_str, suggested_yaml, fix_action, confidence_score

def generate_remediation_with_groq(ctx: Context, violations_output: str) -> tuple:
    """Invokes Groq LLaMA 3 AI model to synthesize step-by-step human remediation guide and YAML rules."""
    groq_api_key = os.getenv("GROQ_API_KEY", "")
    if not groq_api_key:
        env_file = os.path.join(PROJECT_ROOT, ".env")
        if os.path.exists(env_file):
            with open(env_file, "r") as f:
                for line in f:
                    if line.startswith("GROQ_API_KEY="):
                        groq_api_key = line.split("=", 1)[1].strip()
                        break

    if groq_api_key:
        try:
            ctx.logger.info("[ArchitectAIAgent] Calling Groq LLaMA 3 API (llama-3.3-70b-versatile)...")
            url = "https://api.groq.com/openai/v1/chat/completions"

            prompt = f"""You are an expert AWS DevSecOps Security Architect.
A security policy violation was detected in live AWS infrastructure.
Violation details:
{violations_output}

Generate a concise, step-by-step human remediation guide for DevOps engineers.
Return ONLY a JSON object with this EXACT structure:
{{
    "target_resource": "<Comma separated list of failing resource names/IDs>",
    "rule_id": "<Comma separated list of failing policy rule IDs>",
    "suggested_yaml": "<Valid Policy-as-Code YAML rule for enforcement>",
    "fix_action": "STEP-BY-STEP HUMAN REMEDIATION GUIDE:\n1. <Step 1>\n2. <Step 2>..."
}}"""

            json_data = json.dumps({
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "response_format": {"type": "json_object"}
            }).encode('utf-8')

            req = urllib.request.Request(
                url,
                data=json_data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {groq_api_key}",
                    "User-Agent": "DriftShield/2.0"
                }
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result_json = json.loads(resp.read().decode('utf-8'))
                raw_text = result_json["choices"][0]["message"]["content"]
                ctx.logger.info("[ArchitectAIAgent] Groq LLaMA 3 API response received successfully!")
                parsed = json.loads(raw_text)
                return (
                    parsed.get("target_resource", "AWS Infrastructure"),
                    parsed.get("rule_id", "POL-AWS-001"),
                    parsed.get("suggested_yaml", "# AI Policy Rule"),
                    parsed.get("fix_action", "Step-by-step guide")
                )

        except Exception as e:
            ctx.logger.warning(f"[ArchitectAIAgent] Groq API call failed: {e}. Falling back to local dynamic parser.")

    return parse_remediation_from_violations(violations_output)

@ai_architect.on_event("startup")
async def startup_ai(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("DRIFTSHIELD - AGENT 4: ARCHITECT AI AGENT ONLINE")
    ctx.logger.info(f"   Agent Address: {ai_architect.address}")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@ai_architect.on_message(model=PolicyViolationAlert)
async def handle_violation_alert(ctx: Context, sender: str, msg: PolicyViolationAlert):
    ctx.logger.info(f"[ArchitectAIAgent] Received violation alert from PolicyGuardAgent ({sender[:12]}...).")
    
    raw_output = ""
    if msg.violations and isinstance(msg.violations, list) and "output" in msg.violations[0]:
        raw_output = msg.violations[0]["output"]

    target_res, rule_id, suggested_yaml, fix_action = generate_remediation_with_groq(ctx, raw_output)
    
    proposal = RemediationProposal(
        proposal_id=str(uuid.uuid4())[:8],
        target_resource=target_res,
        rule_id=rule_id,
        suggested_yaml=suggested_yaml,
        fix_action=fix_action
    )
    
    ctx.logger.info(f"[ArchitectAIAgent] AI Remediation Guide {proposal.proposal_id} generated for {target_res}. Transmitting to AutoFixAgent...")
    save_agent_storage("architect_ai_agent", f"proposal_{proposal.proposal_id}", proposal.dict())
    
    await ctx.send(AUTOFIX_ADDRESS, proposal)

ai_architect.include(Protocol("AIProtocol"))

if __name__ == "__main__":
    ai_architect.run()
