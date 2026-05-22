"""MiMo Adversarial Red Team Engine - Main Application."""
import asyncio
import json
import time
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .database import init_db, get_stats, get_targets, get_findings, get_attack_paths, get_reports, get_defenses, get_deceptions, get_campaigns
from .core.kernel import AgentKernel
from .core.metrics import metrics
from .core.mitre import MITREMapper
from .agents.recon_agent import ReconAgent
from .agents.vuln_agent import VulnAgent
from .agents.social_agent import SocialAgent
from .agents.exploit_agent import ExploitAgent
from .agents.defense_agent import DefenseAgent
from .agents.deception_agent import DeceptionAgent
from .agents.report_agent import ReportAgent
from .config import HOST, PORT

import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("redteam")


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        for ws in self.active[:]:
            try:
                await ws.send_json(message)
            except Exception:
                self.active.remove(ws)


manager = ConnectionManager()
kernel: AgentKernel = None
mitre_mapper = MITREMapper()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global kernel
    logger.info("Starting MiMo Adversarial Red Team Engine...")
    init_db()
    kernel = AgentKernel()
    kernel.register("recon", ReconAgent())
    kernel.register("vuln", VulnAgent())
    kernel.register("social", SocialAgent())
    kernel.register("exploit", ExploitAgent())
    kernel.register("defense", DefenseAgent())
    kernel.register("deception", DeceptionAgent())
    kernel.register("report", ReportAgent())
    await kernel.start_all()
    logger.info(f"Started {len(kernel.agents)} agents")
    yield
    await kernel.stop_all()
    logger.info("All agents stopped")


app = FastAPI(
    title="MiMo Adversarial Red Team Engine",
    description="AI-powered multi-agent penetration testing and red team automation",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with open("templates/index.html") as f:
        return HTMLResponse(f.read())


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "uptime": kernel.get_uptime() if kernel else 0,
        "agents": kernel.get_health() if kernel else {},
    }


@app.get("/api/stats")
async def stats():
    db_stats = get_stats()
    agent_health = kernel.get_health() if kernel else {}
    return {
        "engine": "MiMo Adversarial Red Team Engine",
        "version": "1.0.0",
        "uptime_seconds": round(kernel.get_uptime()) if kernel else 0,
        "database": db_stats,
        "metrics": metrics.get_all(),
        "agents": agent_health,
    }


@app.post("/api/recon")
async def recon(request: Request):
    body = await request.json()
    result = await kernel.dispatch("recon", body)
    await manager.broadcast({"type": "recon", "data": result})
    return result


@app.post("/api/vuln-scan")
async def vuln_scan(request: Request):
    body = await request.json()
    result = await kernel.dispatch("vuln", body)
    await manager.broadcast({"type": "vuln", "data": result})
    return result


@app.post("/api/social")
async def social(request: Request):
    body = await request.json()
    result = await kernel.dispatch("social", body)
    await manager.broadcast({"type": "social", "data": result})
    return result


@app.post("/api/attack-path")
async def attack_path(request: Request):
    body = await request.json()
    result = await kernel.dispatch("exploit", body)
    await manager.broadcast({"type": "exploit", "data": result})
    return result


@app.post("/api/defend")
async def defend(request: Request):
    body = await request.json()
    result = await kernel.dispatch("defense", body)
    await manager.broadcast({"type": "defense", "data": result})
    return result


@app.post("/api/deceive")
async def deceive(request: Request):
    body = await request.json()
    result = await kernel.dispatch("deception", body)
    await manager.broadcast({"type": "deception", "data": result})
    return result


@app.post("/api/report")
async def report(request: Request):
    body = await request.json()
    result = await kernel.dispatch("report", body)
    await manager.broadcast({"type": "report", "data": result})
    return result


@app.post("/api/full-scan")
async def full_scan(request: Request):
    body = await request.json()
    target = body.get("target", "")
    target_type = body.get("type", "domain")
    name = body.get("name", target)

    results = {"target": target, "stages": {}}

    recon_result = await kernel.dispatch("recon", {"target": target, "type": target_type, "name": name})
    target_id = recon_result.get("target_id")
    results["stages"]["recon"] = recon_result

    vuln_result = await kernel.dispatch("vuln", {"target_id": target_id, "target": target, "type": target_type})
    results["stages"]["vuln"] = vuln_result

    exploit_result = await kernel.dispatch("exploit", {"target_id": target_id, "target": target})
    results["stages"]["exploit"] = exploit_result

    defense_result = await kernel.dispatch("defense", {"target_id": target_id, "target": target})
    results["stages"]["defense"] = defense_result

    deception_result = await kernel.dispatch("deception", {"target_id": target_id, "target": target})
    results["stages"]["deception"] = deception_result

    report_result = await kernel.dispatch("report", {"target_id": target_id, "target": target})
    results["stages"]["report"] = report_result

    results["summary"] = {
        "target_id": target_id,
        "total_findings": report_result.get("total_findings", 0),
        "critical": report_result.get("critical", 0),
        "high": report_result.get("high", 0),
        "attack_paths": report_result.get("attack_paths", 0),
        "defenses": report_result.get("defenses", 0),
    }

    await manager.broadcast({"type": "full_scan", "data": results})
    return results


@app.get("/api/targets")
async def targets():
    return {"targets": get_targets()}


@app.get("/api/findings")
async def findings(target_id: int = None):
    return {"findings": get_findings(target_id)}


@app.get("/api/attack-paths")
async def attack_paths(target_id: int = None):
    return {"attack_paths": get_attack_paths(target_id)}


@app.get("/api/reports")
async def reports(target_id: int = None):
    return {"reports": get_reports(target_id)}


@app.get("/api/defenses")
async def defenses(target_id: int = None):
    return {"defenses": get_defenses(target_id)}


@app.get("/api/deceptions")
async def deceptions(target_id: int = None):
    return {"deceptions": get_deceptions(target_id)}


@app.get("/api/campaigns")
async def campaigns(target_id: int = None):
    return {"campaigns": get_campaigns(target_id)}


@app.get("/api/mitre")
async def mitre():
    findings = get_findings()
    mitre_ids = [f.get("mitre_id") for f in findings if f.get("mitre_id")]
    coverage = mitre_mapper.get_coverage(mitre_ids)
    matrix = mitre_mapper.get_matrix()
    return {"coverage": coverage, "matrix": matrix}


@app.get("/api/mitre/matrix")
async def mitre_matrix():
    return {"matrix": mitre_mapper.get_matrix()}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(ws)
