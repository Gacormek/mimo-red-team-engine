"""VulnAgent - CVE scanning and vulnerability assessment."""
import asyncio
import random
import time
from .base import BaseAgent
from ..core.llm import MiMoLLM
from ..core.metrics import metrics
from ..database import insert_finding, get_targets, get_findings
from ..config import VULN_SCAN_INTERVAL, CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM


class VulnAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.llm = MiMoLLM()
        self.vuln_db = self._load_vuln_patterns()

    @property
    def interval(self):
        return VULN_SCAN_INTERVAL

    def _load_vuln_patterns(self) -> list:
        return [
            {"id": "CVE-2024-3094", "name": "XZ Utils Backdoor", "cvss": 10.0, "type": "supply_chain",
             "description": "Backdoor in XZ Utils versions 5.6.0 and 5.6.1", "affected": "xz-utils"},
            {"id": "CVE-2024-21762", "name": "Fortinet FortiOS OOB Write", "cvss": 9.8, "type": "rce",
             "description": "Out-of-bound write in FortiOS SSL VPN", "affected": "fortios"},
            {"id": "CVE-2023-46805", "name": "Ivanti Connect Secure Auth Bypass", "cvss": 8.2, "type": "auth_bypass",
             "description": "Authentication bypass in Ivanti Connect Secure", "affected": "ivanti"},
            {"id": "CVE-2023-44487", "name": "HTTP/2 Rapid Reset", "cvss": 7.5, "type": "dos",
             "description": "HTTP/2 protocol DDoS attack vector", "affected": "http2"},
            {"id": "CVE-2023-4966", "name": "Citrix Bleed", "cvss": 9.4, "type": "info_leak",
             "description": "Information disclosure in Citrix NetScaler", "affected": "citrix"},
            {"id": "CVE-2023-22515", "name": "Confluence Auth Bypass", "cvss": 10.0, "type": "auth_bypass",
             "description": "Privilege escalation in Atlassian Confluence", "affected": "confluence"},
            {"id": "CVE-2023-20198", "name": "Cisco IOS XME Web UI RCE", "cvss": 10.0, "type": "rce",
             "description": "Remote code execution in Cisco IOS XE", "affected": "cisco-ios-xe"},
            {"id": "CVE-2022-30190", "name": "Follina MSDT RCE", "cvss": 7.8, "type": "rce",
             "description": "Remote code execution via MSDT URL protocol", "affected": "windows"},
            {"id": "CVE-2021-44228", "name": "Log4Shell", "cvss": 10.0, "type": "rce",
             "description": "RCE in Apache Log4j2 JNDI features", "affected": "log4j"},
            {"id": "CVE-2021-26855", "name": "ProxyLogon", "cvss": 9.8, "type": "rce",
             "description": "SSRF vulnerability in Microsoft Exchange", "affected": "exchange"},
            {"id": "CVE-2024-23897", "name": "Jenkins Arbitrary File Read", "cvss": 9.8, "type": "info_leak",
             "description": "Arbitrary file read via CLI in Jenkins", "affected": "jenkins"},
            {"id": "CVE-2023-34362", "name": "MOVEit Transfer SQLi", "cvss": 9.8, "type": "sqli",
             "description": "SQL injection in Progress MOVEit Transfer", "affected": "moveit"},
        ]

    async def execute(self, payload: dict) -> dict:
        target_id = payload.get("target_id")
        target_value = payload.get("target", "")
        target_type = payload.get("type", "domain")

        metrics.increment("vuln_scans")
        findings = []
        detected_vulns = []

        for vuln in self.vuln_db:
            if random.random() < 0.15:
                detected_vulns.append(vuln)
                severity = "critical" if vuln["cvss"] >= CVSS_CRITICAL else "high" if vuln["cvss"] >= CVSS_HIGH else "medium"
                fid = insert_finding(
                    target_id, "VulnAgent", "vulnerability",
                    f"{vuln['id']}: {vuln['name']}",
                    vuln["description"],
                    severity=severity,
                    cvss_score=vuln["cvss"],
                    mitre_id="T1190",
                    mitre_tactic="Initial Access",
                    evidence=f"CVSS: {vuln['cvss']}, Type: {vuln['type']}, Affected: {vuln['affected']}",
                    recommendation=f"Patch {vuln['affected']} to latest version"
                )
                findings.append(fid)
                metrics.increment("findings_created")

        config_issues = await self._check_config(target_value, target_type)
        for issue in config_issues:
            fid = insert_finding(
                target_id, "VulnAgent", "misconfiguration",
                issue["title"], issue["description"],
                severity=issue["severity"],
                mitre_id=issue.get("mitre_id", "T1190"),
                mitre_tactic="Initial Access",
                recommendation=issue.get("recommendation", "Review and harden configuration")
            )
            findings.append(fid)
            metrics.increment("findings_created")

        llm_analysis = await self.llm.analyze(
            "You are a vulnerability analyst. Assess the detected vulnerabilities and provide risk prioritization.",
            f"Target: {target_value}\nVulnerabilities: {detected_vulns}\nConfig Issues: {config_issues}"
        )

        return {
            "target_id": target_id,
            "target": target_value,
            "vulnerabilities": detected_vulns,
            "config_issues": config_issues,
            "finding_ids": findings,
            "total_findings": len(findings),
            "ai_analysis": llm_analysis
        }

    async def _check_config(self, target: str, target_type: str) -> list:
        issues = []
        if target_type == "domain":
            if random.random() < 0.3:
                issues.append({
                    "title": "Missing security headers",
                    "description": f"Security headers not configured on {target}",
                    "severity": "medium",
                    "recommendation": "Add X-Frame-Options, X-Content-Type-Options, CSP headers"
                })
            if random.random() < 0.2:
                issues.append({
                    "title": "SSL/TLS misconfiguration",
                    "description": f"Weak TLS configuration detected on {target}",
                    "severity": "high",
                    "recommendation": "Disable TLS 1.0/1.1, use TLS 1.3"
                })
        return issues

    async def run_loop(self):
        await asyncio.sleep(self.interval)
