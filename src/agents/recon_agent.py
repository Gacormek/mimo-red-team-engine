"""ReconAgent - OSINT gathering and reconnaissance."""
import asyncio
import hashlib
import socket
import time
from .base import BaseAgent
from ..core.llm import MiMoLLM
from ..core.metrics import metrics
from ..database import insert_finding, insert_target, get_targets
from ..config import RECON_INTERVAL


class ReconAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.llm = MiMoLLM()
        self.scan_queue = []

    @property
    def interval(self):
        return RECON_INTERVAL

    async def execute(self, payload: dict) -> dict:
        target_value = payload.get("target", "")
        target_type = payload.get("type", "domain")
        target_name = payload.get("name", target_value)

        target_id = insert_target(target_name, target_type, target_value)
        metrics.increment("recon_scans")

        results = {
            "target_id": target_id,
            "target": target_value,
            "type": target_type,
            "findings": []
        }

        if target_type == "domain":
            dns_info = await self._dns_recon(target_value)
            results["dns"] = dns_info

            subdomains = await self._subdomain_enum(target_value)
            results["subdomains"] = subdomains

            tech_stack = await self._tech_detection(target_value)
            results["tech_stack"] = tech_stack

            emails = await self._email_harvest(target_value)
            results["emails"] = emails

            for sub in subdomains:
                fid = insert_finding(
                    target_id, "ReconAgent", "subdomain",
                    f"Subdomain discovered: {sub}",
                    f"Subdomain {sub} found for {target_value}",
                    severity="info",
                    mitre_id="T1590",
                    mitre_tactic="Reconnaissance"
                )
                results["findings"].append(fid)
                metrics.increment("findings_created")

            for tech in tech_stack:
                fid = insert_finding(
                    target_id, "ReconAgent", "tech_stack",
                    f"Technology detected: {tech}",
                    f"Technology {tech} identified on {target_value}",
                    severity="info",
                    mitre_id="T1592",
                    mitre_tactic="Reconnaissance"
                )
                results["findings"].append(fid)

        elif target_type == "ip":
            ports = await self._port_scan(target_value)
            results["open_ports"] = ports
            for port in ports:
                fid = insert_finding(
                    target_id, "ReconAgent", "open_port",
                    f"Open port: {port}",
                    f"Port {port} is open on {target_value}",
                    severity="medium" if port in [22, 3389, 445] else "info",
                    mitre_id="T1595",
                    mitre_tactic="Reconnaissance"
                )
                results["findings"].append(fid)
                metrics.increment("findings_created")

        llm_analysis = await self.llm.analyze(
            "You are a cybersecurity recon analyst. Analyze the reconnaissance data and identify key attack surface areas.",
            f"Target: {target_value} ({target_type})\nResults: {results}"
        )
        results["ai_analysis"] = llm_analysis
        return results

    async def _dns_recon(self, domain: str) -> dict:
        info = {}
        try:
            records = socket.getaddrinfo(domain, None)
            info["A"] = list(set(r[4][0] for r in records))
        except Exception:
            info["A"] = []
        try:
            info["MX"] = [str(socket.getaddrinfo(domain, None))]
        except Exception:
            info["MX"] = []
        return info

    async def _subdomain_enum(self, domain: str) -> list:
        common = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "blog", "shop", "app", "portal", "cdn", "static",
            "docs", "support", "status", "vpn", "remote", "git"
        ]
        found = []
        for sub in common:
            try:
                socket.getaddrinfo(f"{sub}.{domain}", None)
                found.append(f"{sub}.{domain}")
            except Exception:
                pass
        return found

    async def _tech_detection(self, domain: str) -> list:
        techs = []
        common_techs = {
            "www": "Web Server",
            "mail": "Mail Server",
            "api": "API Gateway",
            "cdn": "CDN",
            "admin": "Admin Panel",
        }
        for sub, tech in common_techs.items():
            try:
                socket.getaddrinfo(f"{sub}.{domain}", None)
                techs.append(tech)
            except Exception:
                pass
        return techs

    async def _email_harvest(self, domain: str) -> list:
        prefixes = ["admin", "info", "support", "contact", "hr", "sales", "dev"]
        return [f"{p}@{domain}" for p in prefixes]

    async def _port_scan(self, ip: str) -> list:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        for port in common_ports:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=1.0
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
            except Exception:
                pass
        return open_ports

    async def run_loop(self):
        await asyncio.sleep(self.interval)
