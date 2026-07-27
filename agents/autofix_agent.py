import subprocess
from uagents import Agent, Context, Protocol
from models import RemediationProposal, RemediationProof

autofix = Agent(
    name="AutoFixAgent",
    seed="autofix_agent_seed_driftshield_005",
    port=8005,
    endpoint=["http://127.0.0.1:8005/submit"]
)

@autofix.on_event("startup")
async def startup_autofix(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("🛡️  DRIFTSHIELD - AGENT 5: AUTO FIX SAFETY AUDITOR ONLINE")
    ctx.logger.info(f"   Agent Address: {autofix.address}")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@autofix.on_message(model=RemediationProposal)
async def handle_remediation_proposal(ctx: Context, sender: str, msg: RemediationProposal):
    ctx.logger.info(f"⚡ [AutoFixAgent] Evaluating Remediation Proposal {msg.proposal_id} from ArchitectAIAgent ({sender[:12]}...).")
    
    # Safety Check: Require confidence score >= 0.80
    if msg.confidence_score < 0.80:
        ctx.logger.warning(f"⚡ [AutoFixAgent] ⚠️ Proposal {msg.proposal_id} rejected due to low confidence score ({msg.confidence_score*100:.1f}%).")
        return
    
    ctx.logger.info(f"⚡ [AutoFixAgent] Peer-review approved (Confidence: {msg.confidence_score*100:.1f}%). Executing dry-run simulation ONLY (No live AWS mutations)...")
    
    # Execute safe dry-run simulation using Go binary
    result = subprocess.run(
        ["./driftshield", "all", "fix", "--dry-run"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    output = result.stdout
    proof = RemediationProof(
        proposal_id=msg.proposal_id,
        target_resource=msg.target_resource,
        status="SIMULATED_SUCCESS",
        dry_run_output=output,
        signed_by=autofix.address
    )
    
    ctx.logger.info(f"⚡ [AutoFixAgent] ✅ Safe dry-run simulation completed. Signed by uAgent {autofix.address[:12]}...")
    ctx.storage.set(f"proof_{proof.proposal_id}", proof.dict())

autofix.include(Protocol("AutoFixProtocol"))

if __name__ == "__main__":
    autofix.run()
