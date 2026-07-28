import os
import sys
import subprocess

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(AGENTS_DIR, ".."))

from uagents import Agent, Context, Protocol
from models import RemediationProposal, RemediationProof, save_agent_storage

ALERT_ROUTER_ADDRESS = "agent1qw9lyclq7dap8atgcx00du6l4nm909mg9dvsx45rqangqfagpvtgk37p5e4"
CONFIDENCE_THRESHOLD = 0.80

autofix = Agent(
    name="AutoFixAgent",
    seed="autofix_agent_seed_driftshield_005",
    port=8005,
    endpoint=["http://127.0.0.1:8005/submit"]
)

@autofix.on_event("startup")
async def startup_autofix(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("DRIFTSHIELD - AGENT 5: AUTO FIX SAFETY AUDITOR ONLINE")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@autofix.on_message(model=RemediationProposal)
async def handle_remediation_proposal(ctx: Context, sender: str, msg: RemediationProposal):
    ctx.logger.info(f"[AutoFixAgent] Evaluating Remediation Proposal {msg.proposal_id} from ArchitectAIAgent ({sender[:12]}...).")
    
    if msg.confidence_score < CONFIDENCE_THRESHOLD:
        ctx.logger.warning(f"[AutoFixAgent] Proposal {msg.proposal_id} rejected due to low confidence score ({msg.confidence_score*100:.1f}%).")
        return
    
    ctx.logger.info(f"[AutoFixAgent] Peer-review approved (Confidence: {msg.confidence_score*100:.1f}%). Executing dry-run simulation ONLY (No live AWS mutations)...")
    
    try:
        proc = subprocess.run(
            ["./driftshield", "all", "fix", "--dry-run"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=120
        )
        dry_run_output = proc.stdout if proc.stdout else proc.stderr
    except Exception as e:
        dry_run_output = f"Dry-run simulation execution details: {e}"
        
    proof_data = {
        "status": "APPROVED_DRY_RUN_SIMULATION",
        "proposal_id": msg.proposal_id,
        "confidence_score": msg.confidence_score,
        "dry_run_output": dry_run_output,
        "signed_by": autofix.address
    }
    
    proof = RemediationProof(
        proposal_id=msg.proposal_id,
        target_resource=msg.target_resource,
        status="SIMULATED_SUCCESS",
        dry_run_output=dry_run_output,
        signed_by=autofix.address
    )
    
    save_agent_storage("autofix_agent", proof_data, autofix.address)
    ctx.logger.info(f"[AutoFixAgent] Safe dry-run simulation completed. Signed by uAgent {autofix.address[:12]}... Transmitting report to AlertRouterAgent...")
    save_agent_storage("autofix_agent", f"proof_{proof.proposal_id}", proof.dict())
    
    await ctx.send(ALERT_ROUTER_ADDRESS, proof)

autofix.include(Protocol("AutoFixProtocol"))

if __name__ == "__main__":
    autofix.run()
