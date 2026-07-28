import os
import sys

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(AGENTS_DIR, ".."))

from uagents import Agent, Context, Protocol
from models import RemediationProposal, RemediationProof, save_agent_storage

ALERT_ROUTER_ADDRESS = "agent1qw9lyclq7dap8atgcx00du6l4nm909mg9dvsx45rqangqfagpvtgk37p5e4"

remediation_agent = Agent(
    name="RemediationAgent",
    seed="autofix_agent_seed_driftshield_005",
    port=8005,
    endpoint=["http://127.0.0.1:8005/submit"]
)

@remediation_agent.on_event("startup")
async def startup_remediation(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("DRIFTSHIELD - AGENT 5: REMEDIATION AGENT ONLINE")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@remediation_agent.on_message(model=RemediationProposal)
async def handle_remediation_proposal(ctx: Context, sender: str, msg: RemediationProposal):
    ctx.logger.info(f"[RemediationAgent] Reviewing Remediation Proposal {msg.proposal_id} from ArchitectAIAgent ({sender[:12]}...).")
    ctx.logger.info("[RemediationAgent] Preparing Step-by-Step Human Remediation Guide (0 AWS API modifications executed)...")
    
    remediation_guide = (
        f"PROPOSAL ID: {msg.proposal_id}\n"
        f"TARGET RESOURCE: {msg.target_resource}\n"
        f"VIOLATED RULE: {msg.rule_id}\n\n"
        f"{msg.fix_action}\n\n"
        f"ENFORCEMENT POLICY (YAML):\n{msg.suggested_yaml}"
    )
    
    proof_data = {
        "status": "HUMAN_REMEDIATION_GUIDE_PREPARED",
        "proposal_id": msg.proposal_id,
        "target_resource": msg.target_resource,
        "remediation_guide": remediation_guide,
        "signed_by": remediation_agent.address
    }
    
    proof = RemediationProof(
        proposal_id=msg.proposal_id,
        target_resource=msg.target_resource,
        status="HUMAN_REMEDIATION_GUIDE_PREPARED",
        dry_run_output=remediation_guide,
        signed_by=remediation_agent.address
    )
    
    save_agent_storage("remediation_agent", proof_data, remediation_agent.address)
    ctx.logger.info(f"[RemediationAgent] Verified human remediation guide for proposal {msg.proposal_id}. Signed by uAgent auditor {remediation_agent.address[:12]}... Transmitting to AlertRouterAgent...")
    
    await ctx.send(ALERT_ROUTER_ADDRESS, proof)

remediation_agent.include(Protocol("RemediationProtocol"))

if __name__ == "__main__":
    remediation_agent.run()
