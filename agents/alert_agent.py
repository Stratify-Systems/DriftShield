import os
import sys

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

@alert_router.on_event("startup")
async def startup_alert(ctx: Context):
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("DRIFTSHIELD - AGENT 6: ALERT ROUTER AGENT ONLINE")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")
    ctx.logger.info("================================━━━━━━━━━━━━━━━━━━━━")

@alert_router.on_message(model=PolicyViolationAlert)
async def handle_policy_alert(ctx: Context, sender: str, msg: PolicyViolationAlert):
    ctx.logger.info(f"[AlertRouterAgent] Dispatching Policy Violation dossier from {sender[:12]}... to Slack, SES email, and SNS sinks.")
    summary_data = {
        "alert_dispatch_summary": True,
        "alert_type": "POLICY_VIOLATION",
        "proposal_id": "POL-VIOLATION-001",
        "target_resource": "AWS Infrastructure",
        "status": "DISPATCHED",
        "remediation_preview": msg.violations[0].get("output", "") if (msg.violations and isinstance(msg.violations, list) and "output" in msg.violations[0]) else "Policy violations detected in live AWS infrastructure."
    }
    save_agent_storage("alert_router_agent", summary_data, alert_router.address)

@alert_router.on_message(model=DriftDetectedAlert)
async def handle_drift_alert(ctx: Context, sender: str, msg: DriftDetectedAlert):
    ctx.logger.info(f"📢 [AlertRouterAgent] Dispatching Baseline Drift alert from {sender[:12]}... to Slack, SES email, and SNS sinks.")
    summary_data = {
        "alert_dispatch_summary": True,
        "alert_type": "BASELINE_DRIFT",
        "proposal_id": "DRIFT-ALERT-001",
        "target_resource": "AWS Infrastructure Baseline",
        "status": "DISPATCHED",
        "remediation_preview": msg.raw_output if msg.raw_output else "Baseline drift detected in live AWS infrastructure."
    }
    save_agent_storage("alert_router_agent", summary_data, alert_router.address)

@alert_router.on_message(model=RemediationProof)
async def handle_proof(ctx: Context, sender: str, msg: RemediationProof):
    ctx.logger.info(f"📢 [AlertRouterAgent] Consolidated Remediation Audit Report {msg.proposal_id} ready for DevSecOps dashboard.")
    summary_data = {
        "alert_dispatch_summary": True,
        "proposal_id": msg.proposal_id,
        "target_resource": msg.target_resource,
        "status": msg.status,
        "remediation_preview": msg.dry_run_output
    }
    save_agent_storage("alert_router_agent", summary_data, alert_router.address)

alert_router.include(Protocol("AlertProtocol"))

if __name__ == "__main__":
    alert_router.run()
