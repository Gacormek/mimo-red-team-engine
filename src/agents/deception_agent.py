"""DeceptionAgent - Honeypot and canary token deployment."""
import asyncio
import random
import hashlib
import time
from .base import BaseAgent
from ..core.llm import MiMoLLM
from ..core.metrics import metrics
from ..database import insert_deception, insert_finding
from ..config import DECEPTION_INTERVAL, HONEYPOT_TYPES, CANARY_TYPES


class DeceptionAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.llm = MiMoLLM()

    @property
    def interval(self):
        return DECEPTION_INTERVAL

    async def execute(self, payload: dict) -> dict:
        target_id = payload.get("target_id")
        target_value = payload.get("target", "")
        network_info = payload.get("network", {})

        metrics.increment("deception_deployments")

        honeypots = await self._deploy_honeypots(target_id, target_value, network_info)
        canaries = await self._deploy_canaries(target_id, target_value)
        deception_paths = await self._create_deception_paths(target_value)

        llm_analysis = await self.llm.analyze(
            "You are a deception technology expert. Analyze the deception deployment and suggest improvements.",
            f"Target: {target_value}\nHoneypots: {len(honeypots)}\nCanaries: {len(canaries)}\nDeception Paths: {len(deception_paths)}"
        )

        return {
            "target_id": target_id,
            "target": target_value,
            "honeypots": honeypots,
            "canaries": canaries,
            "deception_paths": deception_paths,
            "total_deployments": len(honeypots) + len(canaries),
            "ai_analysis": llm_analysis
        }

    async def _deploy_honeypots(self, target_id: int, target: str, network: dict) -> list:
        honeypots = []
        selected_types = random.sample(HONEYPOT_TYPES, min(4, len(HONEYPOT_TYPES)))

        for hp_type in selected_types:
            config = {
                "type": hp_type,
                "name": f"hp-{hp_type}-{hashlib.md5(target.encode()).hexdigest()[:6]}",
                "port": self._get_honeypot_port(hp_type),
                "services": self._get_honeypot_services(hp_type),
                "logging": True,
                "alert_on_connect": True,
                "fake_data": True,
            }

            insert_deception(target_id, f"honeypot_{hp_type}", config)

            fid = insert_finding(
                target_id, "DeceptionAgent", "deception",
                f"Honeypot deployed: {hp_type}",
                f"Honeypot {config['name']} configured on port {config['port']}",
                severity="info",
                mitre_id="T1491",
                mitre_tactic="Impact"
            )

            honeypots.append({
                "type": hp_type,
                "config": config,
                "status": "deployed",
                "finding_id": fid
            })
            metrics.increment("honeypots_deployed")

        return honeypots

    async def _deploy_canaries(self, target_id: int, target: str) -> list:
        canaries = []

        for canary_type in CANARY_TYPES:
            token = hashlib.sha256(f"{target}-{canary_type}-{time.time()}".encode()).hexdigest()[:16]
            config = {
                "type": canary_type,
                "token": token,
                "name": f"canary-{canary_type}-{token[:6]}",
                "trigger_action": "alert",
                "ttl_days": 90,
            }

            if canary_type == "file":
                config["filename"] = f"confidential-{token[:8]}.docx"
                config["location"] = "/shared/documents/"
            elif canary_type == "dns":
                config["subdomain"] = f"internal-{token[:8]}.{target}"
            elif canary_type == "web":
                config["url_path"] = f"/admin/secret-{token[:8]}"
            elif canary_type == "credential":
                config["username"] = f"svc-admin-{token[:8]}"
                config["description"] = "Fake service account credential"

            insert_deception(target_id, f"canary_{canary_type}", config)

            canaries.append({
                "type": canary_type,
                "config": config,
                "status": "active",
            })
            metrics.increment("canaries_deployed")

        return canaries

    async def _create_deception_paths(self, target: str) -> list:
        return [
            {
                "name": "Fake Admin Portal",
                "description": f"Decoy admin login at admin-staging.{target}",
                "realistic": True,
                "triggers_alert": True,
            },
            {
                "name": "Honey File Share",
                "description": "Network share with fake sensitive documents",
                "realistic": True,
                "triggers_alert": True,
            },
            {
                "name": "Fake Database",
                "description": "Decoy database with realistic fake data",
                "realistic": True,
                "triggers_alert": True,
            },
            {
                "name": "Breadcrumb Trail",
                "description": "Fake credentials leading to honeypots",
                "realistic": True,
                "triggers_alert": True,
            },
        ]

    def _get_honeypot_port(self, hp_type: str) -> int:
        ports = {"ssh": 2222, "http": 8888, "ftp": 2121, "smb": 4445, "rdp": 3390, "database": 3307}
        return ports.get(hp_type, 9999)

    def _get_honeypot_services(self, hp_type: str) -> list:
        services = {
            "ssh": ["OpenSSH 8.9", "password auth enabled"],
            "http": ["Apache 2.4", "PHP 8.1", "WordPress 6.4"],
            "ftp": ["vsftpd 3.0", "anonymous access enabled"],
            "smb": ["Samba 4.17", "shared folders exposed"],
            "rdp": ["Windows Server 2022", "NLA disabled"],
            "database": ["MySQL 8.0", "root remote access"],
        }
        return services.get(hp_type, ["generic service"])

    async def run_loop(self):
        await asyncio.sleep(self.interval)
