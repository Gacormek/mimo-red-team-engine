"""DefenseAgent - Auto-generate mitigations and hardening rules."""
import asyncio
from .base import BaseAgent
from ..core.llm import MiMoLLM
from ..core.metrics import metrics
from ..database import insert_defense, get_findings
from ..config import DEFENSE_INTERVAL


class DefenseAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.llm = MiMoLLM()

    @property
    def interval(self):
        return DEFENSE_INTERVAL

    async def execute(self, payload: dict) -> dict:
        target_id = payload.get("target_id")
        target_value = payload.get("target", "")
        findings = payload.get("findings", [])

        metrics.increment("defense_generations")

        if not findings:
            findings = get_findings(target_id)

        defenses = []
        for finding in findings:
            category = finding.get("category", "")
            severity = finding.get("severity", "info")
            title = finding.get("title", "")
            description = finding.get("description", "")

            rules = await self._generate_defense(category, title, description, severity, target_value)
            for rule in rules:
                insert_defense(
                    target_id, finding.get("id"),
                    rule["type"], rule["rule"], rule["priority"]
                )
                defenses.append(rule)
                metrics.increment("defenses_created")

        hardening = await self._generate_hardening(target_value, findings)

        llm_analysis = await self.llm.analyze(
            "You are a defensive security expert. Analyze the findings and provide comprehensive hardening recommendations.",
            f"Target: {target_value}\nFindings: {len(findings)}\nDefenses Generated: {len(defenses)}"
        )

        return {
            "target_id": target_id,
            "target": target_value,
            "defenses": defenses,
            "hardening_rules": hardening,
            "total_defenses": len(defenses),
            "ai_analysis": llm_analysis
        }

    async def _generate_defense(self, category: str, title: str, description: str,
                                 severity: str, target: str) -> list:
        rules = []

        if category == "vulnerability":
            rules.append({
                "type": "patch",
                "rule": f"Apply security patch for: {title}",
                "priority": "critical" if severity == "critical" else "high",
                "detection": f"Monitor for exploitation attempts of {title}",
            })
            rules.append({
                "type": "waf",
                "rule": f"Add WAF rule to block exploitation of {title}",
                "priority": "high",
                "detection": "Alert on WAF rule triggers",
            })

        elif category == "open_port":
            rules.append({
                "type": "firewall",
                "rule": f"Restrict access to port from {title}: allow only trusted IPs",
                "priority": "high",
                "detection": "Monitor connection attempts to restricted ports",
            })
            rules.append({
                "type": "network_segmentation",
                "rule": f"Move service behind network segmentation",
                "priority": "medium",
                "detection": "Monitor lateral movement attempts",
            })

        elif category == "misconfiguration":
            rules.append({
                "type": "hardening",
                "rule": f"Fix misconfiguration: {title}",
                "priority": "high",
                "detection": "Periodic configuration audit",
            })

        elif category == "social_engineering":
            rules.append({
                "type": "email_security",
                "rule": "Implement DMARC, DKIM, SPF for email domain",
                "priority": "high",
                "detection": "Monitor for spoofed emails",
            })
            rules.append({
                "type": "training",
                "rule": "Conduct security awareness training for all employees",
                "priority": "medium",
                "detection": "Track phishing simulation click rates",
            })

        elif category == "subdomain":
            rules.append({
                "type": "dns_security",
                "rule": f"Review DNS records for {title}, remove unnecessary subdomains",
                "priority": "low",
                "detection": "Monitor DNS changes",
            })

        return rules

    async def _generate_hardening(self, target: str, findings: list) -> list:
        return [
            {"area": "Network", "rule": "Implement zero-trust network architecture", "priority": "high"},
            {"area": "Authentication", "rule": "Enforce MFA on all external-facing services", "priority": "critical"},
            {"area": "Monitoring", "rule": "Deploy SIEM with real-time alerting", "priority": "high"},
            {"area": "Backup", "rule": "Implement 3-2-1 backup strategy with offline copies", "priority": "medium"},
            {"area": "Encryption", "rule": "Enforce TLS 1.3 on all services, disable older versions", "priority": "high"},
            {"area": "Access Control", "rule": "Implement least-privilege access model", "priority": "high"},
            {"area": "Logging", "rule": "Enable comprehensive audit logging with tamper protection", "priority": "medium"},
            {"area": "Incident Response", "rule": "Establish and test incident response playbook", "priority": "medium"},
        ]

    async def run_loop(self):
        await asyncio.sleep(self.interval)
