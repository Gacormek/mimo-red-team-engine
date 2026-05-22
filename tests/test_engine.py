"""Test suite for MiMo Red Team Engine."""
import pytest
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_config():
    from src.config import HOST, PORT, DB_PATH, MIMO_API_URL, MITRE_TECHNIQUES
    assert HOST == "0.0.0.0"
    assert PORT == 80
    assert "redteam.db" in DB_PATH
    assert MIMO_API_URL
    assert len(MITRE_TECHNIQUES) > 20


def test_database_init():
    from src.database import init_db, get_stats, get_connection
    init_db()
    stats = get_stats()
    assert "targets" in stats
    assert "findings" in stats
    assert stats["targets"] == 0


def test_database_operations():
    from src.database import (
        init_db, insert_target, insert_finding, insert_attack_path,
        insert_campaign, insert_defense, insert_deception,
        get_targets, get_findings, get_stats
    )
    init_db()
    tid = insert_target("test.com", "domain", "test.com")
    assert tid > 0
    fid = insert_finding(tid, "TestAgent", "vulnerability", "Test Vuln", "Description", "critical", 9.5)
    assert fid > 0
    insert_attack_path(tid, "Test Path", [{"step": 1}], 0.5, 0.3, ["T1190"])
    insert_campaign(tid, "phishing", "Test Campaign", {"emails": []})
    insert_defense(tid, fid, "patch", "Apply patch", "high")
    insert_deception(tid, "honeypot_ssh", {"port": 2222})
    targets = get_targets()
    assert len(targets) >= 1
    findings = get_findings(tid)
    assert len(findings) >= 1
    stats = get_stats()
    assert stats["targets"] >= 1
    assert stats["findings"] >= 1


def test_kernel():
    from src.core.kernel import AgentKernel, AgentState
    kernel = AgentKernel()
    assert kernel.agents == {}
    assert kernel.get_uptime() > 0
    health = kernel.get_health()
    assert health == {}


def test_metrics():
    from src.core.metrics import MetricsCollector
    m = MetricsCollector()
    m.increment("test")
    m.increment("test", 5)
    m.set_gauge("cpu", 50.0)
    all_m = m.get_all()
    assert all_m["counters"]["test"] == 6
    assert all_m["gauges"]["cpu"] == 50.0


def test_mitre_mapper():
    from src.core.mitre import MITREMapper
    mapper = MITREMapper()
    tech = mapper.get_technique("T1190")
    assert tech["name"] == "Exploit Public-Facing Application"
    assert tech["tactic"] == "Initial Access"
    tactics = mapper.get_all_tactics()
    assert "Initial Access" in tactics
    recon = mapper.get_by_tactic("Reconnaissance")
    assert len(recon) > 0
    coverage = mapper.get_coverage(["T1190", "T1566"])
    assert coverage["covered"] == 2
    matrix = mapper.get_matrix()
    assert len(matrix) > 0


def test_attack_graph():
    from src.core.attack_graph import AttackGraph, AttackStep
    graph = AttackGraph()
    s1 = AttackStep(1, "Recon", "Active Scanning", "T1595", "Reconnaissance", "Scan target", success_rate=0.95)
    s2 = AttackStep(2, "Exploit", "Exploit App", "T1190", "Initial Access", "Exploit vuln", prerequisites=[1], success_rate=0.6)
    s3 = AttackStep(3, "Escalate", "Privesc", "T1068", "Privilege Escalation", "Escalate", prerequisites=[2], success_rate=0.5)
    graph.add_step(s1)
    graph.add_step(s2)
    graph.add_step(s3)
    path = graph.build_path("p1", "Full Chain", [1, 2, 3])
    assert len(path.steps) == 3
    assert path.success_probability > 0
    paths = graph.get_paths()
    assert len(paths) == 1
    dot = graph.to_dot()
    assert "digraph" in dot


def test_llm_client():
    from src.core.llm import MiMoLLM
    llm = MiMoLLM()
    assert llm.api_url
    assert llm.model


def test_agents_import():
    from src.agents.recon_agent import ReconAgent
    from src.agents.vuln_agent import VulnAgent
    from src.agents.social_agent import SocialAgent
    from src.agents.exploit_agent import ExploitAgent
    from src.agents.defense_agent import DefenseAgent
    from src.agents.deception_agent import DeceptionAgent
    from src.agents.report_agent import ReportAgent
    agents = [ReconAgent(), VulnAgent(), SocialAgent(), ExploitAgent(), DefenseAgent(), DeceptionAgent(), ReportAgent()]
    assert len(agents) == 7


@pytest.mark.asyncio
async def test_recon_agent():
    from src.agents.recon_agent import ReconAgent
    from src.database import init_db
    init_db()
    agent = ReconAgent()
    result = await agent.execute({"target": "example.com", "type": "domain", "name": "Example"})
    assert "target_id" in result
    assert "subdomains" in result
    assert "tech_stack" in result


@pytest.mark.asyncio
async def test_vuln_agent():
    from src.agents.vuln_agent import VulnAgent
    from src.database import init_db
    init_db()
    agent = VulnAgent()
    result = await agent.execute({"target": "example.com", "target_id": 1, "type": "domain"})
    assert "vulnerabilities" in result
    assert "finding_ids" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
