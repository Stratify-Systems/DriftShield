#!/usr/bin/env python3
import sys
import os

# Add agents directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uagents import Bureau
from scanner_agent import scanner
from policy_agent import policy_guard
from drift_agent import drift_sentinel
from ai_agent import ai_architect
from autofix_agent import autofix
from alert_agent import alert_router

def main():
    print(r"""
    ____       _  __ __  _____ __    _      __    __
   / __ \_____(_)/ // /_/ ___// /_  (_)__  / /___/ /
  / / / / ___/ / / __/ /\__ \/ __ \/ / _ \/ / __  / 
 / /_/ / /  / / / /_  ___/ / / / / /  __/ / /_/ /  
/_____/_/  /_/_/_/ / //____/_/ /_/_/\___/_/\__,_/   

 🛡️  DRIFTSHIELD v2.0.0 - AGENTVERSE MULTI-AGENT ALLIANCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

    bureau = Bureau(port=8000, endpoint=["http://127.0.0.1:8000/submit"])
    
    # Add all 6 agents to the AgentVerse Bureau
    bureau.add(scanner)
    bureau.add(policy_guard)
    bureau.add(drift_sentinel)
    bureau.add(ai_architect)
    bureau.add(autofix)
    bureau.add(alert_router)
    
    print("🚀 Starting all 6 Fetch.ai AgentVerse Agents...")
    print(f"  1. 🕵️‍♂️ ScannerAgent       [{scanner.address}]")
    print(f"  2. 🛡️ PolicyGuardAgent   [{policy_guard.address}]")
    print(f"  3. 🔍 DriftSentinelAgent [{drift_sentinel.address}]")
    print(f"  4. 🧠 ArchitectAIAgent   [{ai_architect.address}]")
    print(f"  5. ⚡ AutoFixAgent        [{autofix.address}]")
    print(f"  6. 📢 AlertRouterAgent   [{alert_router.address}]\n")

    bureau.run()

if __name__ == "__main__":
    main()
