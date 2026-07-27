import uuid
import datetime
from uagents import Agent, Context, Protocol
from models import PolicyViolationAlert, RemediationProposal

AUTOFIX_ADDRESS = "agent1qt043wu6g049vljszuafr275zlwf88cz7pfxetxgq52lmr7z7putxqxvjwk"

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
    ctx.logger.info("🧠 [ArchitectAIAgent] Synthesizing step-by-step human remediation guide (No direct AI mutations)...")
    
    proposal = RemediationProposal(
        proposal_id=str(uuid.uuid4())[:8],
        target_resource="vpc-047a7050c76e7c3c1 / sg-0cbb4bc1962b31199",
        rule_id="POL-VPC-001 / POL-IAM-001",
        suggested_yaml="""- id: POL-VPC-001
  name: Enforce VPC Flow Logs
  service: vpc
  severity: HIGH
  conditions:
    all:
      - field: flow_logs_enabled
        operator: equals
        value: true""",
        fix_action="""STEP-BY-STEP HUMAN REMEDIATION GUIDE:
1. Open AWS Management Console -> VPC Dashboard.
2. Select VPC 'vpc-047a7050c76e7c3c1' -> Flow Logs tab -> Create Flow Log.
3. Open IAM Console -> Users -> 'drift-shield-user' -> Security Credentials -> Assign MFA device.
4. Run './driftshield policy scan' to verify 100% compliance.""",
        confidence_score=0.96
    )
    
    ctx.logger.info(f"🧠 [ArchitectAIAgent] Step-by-step human guide {proposal.proposal_id} generated. Transmitting to AutoFixAgent...")
    ctx.storage.set(f"proposal_{proposal.proposal_id}", proposal.dict())
    
    # Transmit proposal to AutoFixAgent over uAgent protocol
    await ctx.send(AUTOFIX_ADDRESS, proposal)

ai_architect.include(Protocol("AIProtocol"))

if __name__ == "__main__":
    ai_architect.run()
