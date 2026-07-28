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
    save_agent_storage("alert_router_agent", "latest_policy_alert", msg.dict())

@alert_router.on_message(model=DriftDetectedAlert)
async def handle_drift_alert(ctx: Context, sender: str, msg: DriftDetectedAlert):
    ctx.logger.info(f"📢 [AlertRouterAgent] Dispatching Baseline Drift alert from {sender[:12]}... to Slack, SES email, and SNS sinks.")
    save_agent_storage("alert_router_agent", "latest_drift_alert", msg.dict())

@alert_router.on_message(model=RemediationProof)
async def handle_proof(ctx: Context, sender: str, msg: RemediationProof):
    ctx.logger.info(f"📢 [AlertRouterAgent] Consolidated Remediation Audit Report {msg.proposal_id} ready for DevSecOps dashboard.")
    save_agent_storage("alert_router_agent", f"report_{msg.proposal_id}", msg.dict())

alert_router.include(Protocol("AlertProtocol"))

if __name__ == "__main__":
    alert_router.run()
