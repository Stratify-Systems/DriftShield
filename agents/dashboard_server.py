import os
import sys
import asyncio
import json
import socket
import datetime
import subprocess
from aiohttp import web, WSMsgType

AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(AGENTS_DIR, ".."))
AGENTS_DATA_DIR = os.path.join(PROJECT_ROOT, "agents_data")

ws_clients = set()
file_mtimes = {}

AGENT_FILES = {
    "ScannerAgent": "scanner_agent_report.md",
    "PolicyGuardAgent": "policy_guard_agent_report.md",
    "DriftSentinelAgent": "drift_sentinel_agent_report.md",
    "ArchitectAIAgent": "architect_ai_agent_report.md",
    "AutoFixAgent": "autofix_agent_report.md",
    "AlertRouterAgent": "alert_router_agent_report.md",
}

AGENT_PORTS = {
    "ScannerAgent": 8001,
    "PolicyGuardAgent": 8002,
    "DriftSentinelAgent": 8003,
    "ArchitectAIAgent": 8004,
    "AutoFixAgent": 8005,
    "AlertRouterAgent": 8006,
}

def check_port_open(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.15)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0

def get_agent_statuses() -> dict:
    bureau_active = check_port_open(8000)
    statuses = {}
    
    for name, report_file in AGENT_FILES.items():
        standalone_port = AGENT_PORTS[name]
        is_port_open = check_port_open(standalone_port)
        
        filepath = os.path.join(AGENTS_DATA_DIR, report_file)
        has_recent_report = False
        if os.path.exists(filepath):
            try:
                mtime = os.path.getmtime(filepath)
                if (datetime.datetime.now().timestamp() - mtime) < 600:
                    has_recent_report = True
            except Exception:
                pass
                
        is_online = bureau_active or is_port_open or has_recent_report
        statuses[name] = is_online
        
    return statuses

async def broadcast_event(event_type: str, data: dict):
    message = json.dumps({"type": event_type, "timestamp": datetime.datetime.now().strftime('%H:%M:%S'), **data})
    for ws in list(ws_clients):
        try:
            await ws.send_str(message)
        except Exception:
            ws_clients.discard(ws)

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    ws_clients.add(ws)
    
    # Send initial agent status snapshot
    status_data = {
        "type": "agent_status",
        "timestamp": datetime.datetime.now().strftime('%H:%M:%S'),
        "agents": get_agent_statuses()
    }
    await ws.send_str(json.dumps(status_data))
    
    # Send initial report file contents
    if os.path.exists(AGENTS_DATA_DIR):
        for f in os.listdir(AGENTS_DATA_DIR):
            if f.endswith("_report.md"):
                filepath = os.path.join(AGENTS_DATA_DIR, f)
                try:
                    with open(filepath, "r") as r:
                        content = r.read()
                    await ws.send_str(json.dumps({
                        "type": "report_update",
                        "file": f,
                        "content": content
                    }))
                except Exception:
                    pass

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                if msg.data == 'ping':
                    await ws.send_str(json.dumps({'type': 'pong'}))
            elif msg.type == WSMsgType.ERROR:
                pass
    finally:
        ws_clients.discard(ws)
    return ws

async def trigger_scan_handler(request):
    """API endpoint to trigger an instant AWS scan."""
    try:
        asyncio.create_task(run_scan_task())
        return web.json_response({"status": "success", "message": "Instant AWS scan triggered!"})
    except Exception as e:
        return web.json_response({"status": "error", "message": str(e)}, status=500)

async def run_scan_task():
    await broadcast_event("event_log", {"agent": "ScannerAgent", "text": "⚡ Manual scan trigger initiated by DevSecOps Dashboard..."})
    subprocess.Popen(["./driftshield", "all"], cwd=PROJECT_ROOT)

async def background_watcher():
    """Background watcher that polls agent health and file updates."""
    while True:
        await asyncio.sleep(1.0)
        if not ws_clients:
            continue
            
        status_packet = {
            "type": "agent_status",
            "timestamp": datetime.datetime.now().strftime('%H:%M:%S'),
            "agents": get_agent_statuses()
        }
        
        changed_reports = []
        if os.path.exists(AGENTS_DATA_DIR):
            for f in os.listdir(AGENTS_DATA_DIR):
                if f.endswith("_report.md"):
                    filepath = os.path.join(AGENTS_DATA_DIR, f)
                    try:
                        mtime = os.path.getmtime(filepath)
                        if file_mtimes.get(f) != mtime:
                            file_mtimes[f] = mtime
                            with open(filepath, "r") as r:
                                content = r.read()
                            changed_reports.append({"file": f, "content": content})
                    except Exception:
                        pass
                        
        for ws in list(ws_clients):
            try:
                await ws.send_str(json.dumps(status_packet))
                for report in changed_reports:
                    await ws.send_str(json.dumps({
                        "type": "report_update",
                        "file": report["file"],
                        "content": report["content"]
                    }))
                    agent_name = report["file"].replace("_report.md", "").replace("_", " ").title()
                    await ws.send_str(json.dumps({
                        "type": "event_log",
                        "timestamp": datetime.datetime.now().strftime('%H:%M:%S'),
                        "agent": agent_name,
                        "text": f"Updated report generated: {report['file']}"
                    }))
            except Exception:
                ws_clients.discard(ws)

async def index_handler(request):
    html_path = os.path.join(AGENTS_DIR, "dashboard.html")
    if os.path.exists(html_path):
        return web.FileResponse(html_path)
    return web.Response(text="<h1>DriftShield Dashboard HTML not found</h1>", content_type="text/html")

async def css_handler(request):
    css_path = os.path.join(AGENTS_DIR, "dashboard.css")
    if os.path.exists(css_path):
        return web.FileResponse(css_path)
    return web.Response(text="", content_type="text/css")

async def start_background_tasks(app):
    app['watcher'] = asyncio.create_task(background_watcher())

async def cleanup_background_tasks(app):
    app['watcher'].cancel()
    await app['watcher']

def create_app():
    app = web.Application()
    app.router.add_get('/', index_handler)
    app.router.add_get('/dashboard.css', css_handler)
    app.router.add_get('/ws', websocket_handler)
    app.router.add_post('/api/scan', trigger_scan_handler)
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)
    return app

if __name__ == "__main__":
    app = create_app()
    print("🌐 Starting DriftShield DevSecOps WebSocket Dashboard on http://127.0.0.1:8080...")
    web.run_app(app, host="0.0.0.0", port=8080)
