"""ReportAgent - Generate comprehensive pentest reports."""
import asyncio
import time
from datetime import datetime
from .base import BaseAgent
from ..core.llm import MiMoLLM
from ..core.mitre import MITREMapper
from ..core.metrics import metrics
from ..database import (
    insert_report, get_findings, get_attack_paths,
    get_defenses, get_deceptions, get_campaigns, get_targets
)
from ..config import REPORT_INTERVAL


class ReportAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.llm = MiMoLLM()
        self.mitre = MITREMapper()

    @property
    def interval(self):
        return REPORT_INTERVAL

    async def execute(self, payload: dict) -> dict:
        target_id = payload.get("target_id")
        target_value = payload.get("target", "")

        metrics.increment("reports_generated")

        findings = get_findings(target_id)
        attack_paths = get_attack_paths(target_id)
        defenses = get_defenses(target_id)
        deceptions = get_deceptions(target_id)
        campaigns = get_campaigns(target_id)

        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        high_count = sum(1 for f in findings if f.get("severity") == "high")
        medium_count = sum(1 for f in findings if f.get("severity") == "medium")
        low_count = sum(1 for f in findings if f.get("severity") == "low")

        mitre_ids = [f.get("mitre_id") for f in findings if f.get("mitre_id")]
        mitre_coverage = self.mitre.get_coverage(mitre_ids)

        executive_summary = await self._generate_executive_summary(
            target_value, findings, attack_paths, critical_count, high_count
        )

        detailed_findings = await self._organize_findings(findings)

        recommendations = await self._generate_recommendations(
            target_value, findings, defenses
        )

        report_content = self._build_report(
            target_value, findings, attack_paths, defenses,
            deceptions, campaigns, mitre_coverage,
            executive_summary, detailed_findings, recommendations,
            critical_count, high_count, medium_count, low_count
        )

        insert_report(
            target_id, report_content, executive_summary,
            len(findings), critical_count, high_count
        )

        return {
            "target_id": target_id,
            "target": target_value,
            "executive_summary": executive_summary,
            "total_findings": len(findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "attack_paths": len(attack_paths),
            "defenses": len(defenses),
            "deceptions": len(deceptions),
            "mitre_coverage": mitre_coverage,
            "recommendations": recommendations[:5],
            "report_length": len(report_content),
        }

    async def _generate_executive_summary(self, target: str, findings: list,
                                           paths: list, critical: int, high: int) -> str:
        return await self.llm.analyze(
            "You are a senior penetration tester. Write a concise executive summary for a pentest report.",
            f"Target: {target}\nTotal Findings: {len(findings)}\nCritical: {critical}\nHigh: {high}\nAttack Paths: {len(paths)}"
        )

    async def _organize_findings(self, findings: list) -> dict:
        organized = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in organized:
                organized[sev].append({
                    "title": f.get("title", ""),
                    "description": f.get("description", ""),
                    "cvss": f.get("cvss_score", 0),
                    "mitre": f.get("mitre_id", ""),
                    "recommendation": f.get("recommendation", ""),
                })
        return organized

    async def _generate_recommendations(self, target: str, findings: list, defenses: list) -> list:
        recs = [
            {"priority": "immediate", "action": "Patch all critical and high severity vulnerabilities",
             "effort": "high", "impact": "high"},
            {"priority": "immediate", "action": "Implement MFA on all external-facing services",
             "effort": "medium", "impact": "high"},
            {"priority": "short_term", "action": "Deploy network segmentation for sensitive systems",
             "effort": "high", "impact": "high"},
            {"priority": "short_term", "action": "Implement comprehensive logging and monitoring",
             "effort": "medium", "impact": "medium"},
            {"priority": "medium_term", "action": "Conduct security awareness training for all staff",
             "effort": "medium", "impact": "medium"},
            {"priority": "medium_term", "action": "Establish vulnerability management program",
             "effort": "medium", "impact": "high"},
            {"priority": "long_term", "action": "Implement zero-trust architecture",
             "effort": "high", "impact": "high"},
            {"priority": "long_term", "action": "Establish red team exercise program",
             "effort": "medium", "impact": "high"},
        ]
        return recs

    def _build_report(self, target, findings, paths, defenses, deceptions,
                      campaigns, mitre_coverage, exec_summary, detailed,
                      recommendations, critical, high, medium, low) -> str:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        report = f"""
# Penetration Test Report
## Target: {target}
## Date: {timestamp}
## Classification: CONFIDENTIAL

---

## 1. Executive Summary
{exec_summary}

## 2. Scope & Methodology
- Target: {target}
- Methodology: OWASP Testing Guide, PTES, MITRE ATT&CK Framework
- Tools: MiMo Red Team Engine (AI-powered multi-agent system)

## 3. Findings Summary
| Severity | Count |
|----------|-------|
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Low | {low} |
| Total | {len(findings)} |

## 4. Attack Paths Identified
Total attack paths: {len(paths)}

## 5. MITRE ATT&CK Coverage
- Techniques covered: {mitre_coverage.get('covered', 0)}/{mitre_coverage.get('total_techniques', 0)}
- Coverage: {mitre_coverage.get('coverage_pct', 0)}%

## 6. Defenses Generated
Total defensive rules: {len(defenses)}

## 7. Deception Deployments
Total deception assets: {len(deceptions)}

## 8. Recommendations
"""
        for i, rec in enumerate(recommendations, 1):
            report += f"{i}. [{rec['priority'].upper()}] {rec['action']}\n"

        report += f"""
## 9. Conclusion
This penetration test identified {len(findings)} security findings across {target}.
{critical} critical and {high} high severity issues require immediate attention.
{len(paths)} viable attack paths were identified and mapped to the MITRE ATT&CK framework.

---
Generated by MiMo Red Team Engine - AI-Powered Penetration Testing
"""
        return report

    async def run_loop(self):
        await asyncio.sleep(self.interval)
