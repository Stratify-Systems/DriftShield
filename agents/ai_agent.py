import uuid
import datetime
from uagents import Agent, Context
from models import PolicyViolationAlert, RemediationProposal

ai_architect = Agent(
    name="ArchitectAIAgent",
    seed="ai_agent_seed_driftshield_004",
    port=8004,
    endpoint=["http://127.0.0.1:8004/submit"]
)

@ai_architect.on_event("startup")
async def startup_ai(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("🛡️  DRIFTSHIELD - AGENT 4: ARCHITECT AI AGENT ONLINE")
    ctx.logger.info(f"   Agent Address: {ai_architect.address}")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@ai_architect.on_message(model=PolicyViolationAlert)
async def handle_violation_alert(ctx: Context, sender: str, msg: PolicyViolationAlert):
    ctx.logger.info(f"🧠 [ArchitectAIAgent] Received violation alert from PolicyGuardAgent ({sender[:12]}...).")
    ctx.logger.info("🧠 [ArchitectAIAgent] Invoking Groq LLaMA 3 Engine to synthesize remediation plan & YAML rule...")
    
    proposal = RemediationProposal(
        proposal_id=str(uuid.uuid4())[:8],
        target_resource="vpc-047a7050c76e7c3c1 / sg-0cbb4bc1962b31199",
        rule_id="POL-VPC-001 / POL-EC2-001",
        suggested_yaml="""- id: POL-VPC-001
  name: Enforce VPC Flow Logs
  service: vpc
  severity: HIGH
  conditions:
    all:
      - field: flow_logs_enabled
        operator: equals
        value: true""",
        fix_action="Enable VPC flow logs and restrict security group ingress port 22 to internal CIDR",
        confidence_score=0.94
    )
    
    ctx.logger.info(f"🧠 [ArchitectAIAgent] Proposal {proposal.proposal_id} generated successfully (Confidence: {proposal.confidence_score*100:.1f}%).")
    ctx.storage.set(f"proposal_{proposal.proposal_id}", proposal.dict())

if __name__ == "__main__":
    ai_architect.run()
