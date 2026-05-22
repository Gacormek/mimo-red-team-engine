"""SocialAgent - Phishing campaign generation and social engineering."""
import asyncio
import random
from .base import BaseAgent
from ..core.llm import MiMoLLM
from ..core.metrics import metrics
from ..database import insert_campaign, insert_finding, get_targets
from ..config import SOCIAL_INTERVAL, PHISHING_TEMPLATES


class SocialAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.llm = MiMoLLM()

    @property
    def interval(self):
        return SOCIAL_INTERVAL

    async def execute(self, payload: dict) -> dict:
        target_id = payload.get("target_id")
        target_value = payload.get("target", "")
        employees = payload.get("employees", [])
        campaign_type = payload.get("campaign_type", "credential_harvest")

        metrics.increment("social_campaigns")

        template = PHISHING_TEMPLATES.get(campaign_type, PHISHING_TEMPLATES["credential_harvest"])

        email_templates = await self._generate_templates(target_value, employees, template)
        pretext_scenarios = await self._generate_pretexts(target_value, employees)

        campaign_id = insert_campaign(
            target_id, "phishing",
            f"{template['name']} - {target_value}",
            {"emails": email_templates, "pretexts": pretext_scenarios}
        )

        fid = insert_finding(
            target_id, "SocialAgent", "social_engineering",
            f"Phishing campaign generated: {template['name']}",
            f"Campaign targeting {target_value} with {len(email_templates)} email templates",
            severity="high",
            mitre_id="T1566",
            mitre_tactic="Initial Access",
            recommendation="Implement email security awareness training and DMARC/DKIM/SPF"
        )
        metrics.increment("findings_created")

        llm_analysis = await self.llm.analyze(
            "You are a social engineering expert. Analyze the phishing campaign effectiveness and suggest improvements.",
            f"Target: {target_value}\nCampaign: {template['name']}\nTemplates: {len(email_templates)}\nEmployees: {len(employees)}"
        )

        return {
            "campaign_id": campaign_id,
            "target": target_value,
            "campaign_type": campaign_type,
            "template_name": template["name"],
            "email_count": len(email_templates),
            "emails": email_templates,
            "pretexts": pretext_scenarios,
            "finding_id": fid,
            "ai_analysis": llm_analysis
        }

    async def _generate_templates(self, target: str, employees: list, template: dict) -> list:
        templates = []
        personas = [
            {"name": "IT Support", "email": f"it-support@{target}", "style": "technical"},
            {"name": "HR Department", "email": f"hr@{target}", "style": "corporate"},
            {"name": "CEO Office", "email": f"ceo@{target}", "style": "executive"},
            {"name": "Security Team", "email": f"security@{target}", "style": "urgent"},
        ]

        for persona in personas:
            llm_result = await self.llm.analyze(
                f"You are a phishing email writer impersonating {persona['name']} at {target}. Generate a realistic phishing email.",
                f"Template type: {template['name']}\nSubject: {template['subject']}\nPersona: {persona['name']}\nStyle: {persona['style']}"
            )
            templates.append({
                "persona": persona["name"],
                "sender": persona["email"],
                "subject": template["subject"],
                "body": llm_result[:500],
                "template_type": template["name"],
                "success_probability": round(random.uniform(0.15, 0.65), 2),
            })
        return templates

    async def _generate_pretexts(self, target: str, employees: list) -> list:
        pretexts = [
            {
                "scenario": "Vendor impersonation",
                "description": f"Pose as a trusted vendor requesting urgent payment or credential update",
                "success_rate": round(random.uniform(0.2, 0.5), 2),
                "mitre_id": "T1566.002"
            },
            {
                "scenario": "IT support call",
                "description": "Call employees claiming to be IT support needing to verify credentials",
                "success_rate": round(random.uniform(0.25, 0.55), 2),
                "mitre_id": "T1566.004"
            },
            {
                "scenario": "Executive authority",
                "description": "Impersonate C-level executive requesting urgent confidential action",
                "success_rate": round(random.uniform(0.3, 0.6), 2),
                "mitre_id": "T1566.002"
            }
        ]
        return pretexts

    async def run_loop(self):
        await asyncio.sleep(self.interval)
