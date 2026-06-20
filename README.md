# MiMo Adversarial Red Team Engine

> AI-powered multi-agent penetration testing and red team automation system. 7 specialized agents for reconnaissance, vulnerability assessment, attack path generation, social engineering, defense, deception, and reporting. Built with MiMo LLM.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com/)

---

## Demo

**Live:** http://your-mimo-server

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                MiMo Adversarial Red Team Engine                       │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐        │
│  │   Recon   │  │   Vuln    │  │  Social   │  │  Exploit  │        │
│  │   Agent   │  │   Agent   │  │   Agent   │  │   Agent   │        │
│  │           │  │           │  │           │  │           │        │
│  │ OSINT,    │  │ CVE scan, │  │ Phishing  │  │ Attack    │        │
│  │ subdomain,│  │ CVSS,     │  │ campaign, │  │ path      │        │
│  │ tech stack│  │ misconfig │  │ pretext   │  │ chaining  │        │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘        │
│        │              │              │              │                │
│  ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐                      │
│  │  Defense  │  │ Deception │  │  Report   │                      │
│  │   Agent   │  │   Agent   │  │   Agent   │                      │
│  │           │  │           │  │           │                      │
│  │ Mitigation│  │ Honeypots,│  │ Pentest   │                      │
│  │ hardening,│  │ canaries, │  │ report,   │                      │
│  │ WAF rules │  │ decoys    │  │ executive │                      │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘                      │
│        │              │              │                              │
│  ┌─────┴──────────────┴──────────────┴─────────────────────┐       │
│  │                    Agent Kernel                           │       │
│  │         Lifecycle · Dispatch · Health Monitor             │       │
│  └─────┬──────────────┬──────────────┬──────────────┬──────┘       │
│        │              │              │              │              │
│  ┌─────┴─────┐  ┌─────┴────┐  ┌─────┴────┐  ┌─────┴────┐        │
│  │   MiMo    │  │  Attack  │  │  MITRE   │  │  SQLite  │        │
│  │    LLM    │  │  Graph   │  │ ATT&CK   │  │ Database │        │
│  │  Analyze  │  │  DAG     │  │ Mapping  │  │ Persistent│       │
│  └───────────┘  └──────────┘  └──────────┘  └──────────┘        │
│                                                                       │
├──────────────────────────────────────────────────────────────────────┤
│  FastAPI Server  ·  REST API  ·  WebSocket  ·  Web Dashboard        │
└──────────────────────────────────────────────────────────────────────┘
```

## Agents

| Agent | Role | Input | Output |
|-------|------|-------|--------|
| **ReconAgent** | OSINT gathering | Target domain/IP | Subdomains, emails, tech stack, open ports |
| **VulnAgent** | CVE scanning | Target info | Vulnerabilities, CVSS scores, misconfigs |
| **SocialAgent** | Phishing campaigns | Target + employees | Email templates, pretext scenarios |
| **ExploitAgent** | Attack path chaining | Findings list | Attack graph, kill chain steps |
| **DefenseAgent** | Auto-mitigation | Findings | Hardening rules, WAF rules, detection sigs |
| **DeceptionAgent** | Honeypots & canaries | Network info | Honeypot configs, canary tokens |
| **ReportAgent** | Pentest reports | All agent outputs | Executive summary, full report |

## Features

### Reconnaissance
- DNS resolution and subdomain enumeration
- Technology stack detection
- Email harvesting
- Port scanning (17 common ports)
- MiMo LLM-powered analysis

### Vulnerability Assessment
- 12+ CVE patterns (Log4Shell, ProxyLogon, Citrix Bleed, etc.)
- CVSS scoring and severity classification
- Configuration weakness detection
- Supply chain vulnerability patterns

### Attack Path Generation
- DAG-based attack graph construction
- Multi-step kill chain visualization
- MITRE ATT&CK technique mapping
- Success probability calculation per path
- Risk scoring (0-1)

### Social Engineering
- 4 campaign types (credential harvest, malware delivery, BEC, spear phishing)
- AI-generated phishing emails per persona
- Pretext scenario generation
- Success rate estimation

### Defense Automation
- Auto-generated mitigation rules per finding
- Network segmentation recommendations
- WAF rule generation
- Security hardening checklist
- Detection signature suggestions

### Deception Technology
- 6 honeypot types (SSH, HTTP, FTP, SMB, RDP, Database)
- 4 canary token types (file, DNS, web, credential)
- Fake admin portals and honey file shares
- Breadcrumb trail deployment

### Reporting
- Executive summary generation (MiMo LLM)
- Severity-based finding organization
- MITRE ATT&CK coverage analysis
- Prioritized recommendations
- Full pentest report in markdown

### MITRE ATT&CK Integration
- 28+ techniques across 9 tactics
- Coverage matrix visualization
- Per-finding technique mapping
- Attack chain ATT&CK alignment

## API Endpoints

```bash
# Full scan (all agents)
curl -X POST http://localhost/api/full-scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "type": "domain"}'

# Reconnaissance
curl -X POST http://localhost/api/recon \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "type": "domain"}'

# Vulnerability scan
curl -X POST http://localhost/api/vuln-scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "target_id": 1}'

# Attack path generation
curl -X POST http://localhost/api/attack-path \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "target_id": 1}'

# Social engineering campaign
curl -X POST http://localhost/api/social \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "campaign_type": "credential_harvest"}'

# Generate defenses
curl -X POST http://localhost/api/defend \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "target_id": 1}'

# Deploy deception
curl -X POST http://localhost/api/deceive \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "target_id": 1}'

# Generate report
curl -X POST http://localhost/api/report \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "target_id": 1}'

# MITRE ATT&CK coverage
curl http://localhost/api/mitre

# Health check
curl http://localhost/health
```

## Quick Start

```bash
git clone https://github.com/Gacormek/mimo-red-team-engine.git
cd mimo-red-team-engine

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run
uvicorn src.main:app --host 0.0.0.0 --port 80
```

Open http://localhost for the dashboard.

### Docker

```bash
docker-compose up -d
```

## Project Structure

```
mimo-red-team-engine/
├── README.md
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── .gitignore
├── src/
│   ├── main.py                  # FastAPI server
│   ├── config.py                # Configuration
│   ├── database.py              # SQLite operations
│   ├── core/
│   │   ├── kernel.py            # Agent lifecycle
│   │   ├── llm.py               # MiMo LLM client
│   │   ├── attack_graph.py      # DAG attack paths
│   │   ├── mitre.py             # ATT&CK mapping
│   │   └── metrics.py           # Metrics collector
│   └── agents/
│       ├── base.py              # Abstract base agent
│       ├── recon_agent.py       # OSINT gathering
│       ├── vuln_agent.py        # CVE scanning
│       ├── social_agent.py      # Phishing generation
│       ├── exploit_agent.py     # Attack chaining
│       ├── defense_agent.py     # Mitigation generation
│       ├── deception_agent.py   # Honeypot deployment
│       └── report_agent.py      # Report generation
├── templates/
│   └── index.html               # 8-tab dashboard
├── tests/
│   └── test_engine.py
└── data/                        # SQLite database
```

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **LLM** | MiMo v2.5 Pro | Analysis, strategy, report generation |
| **Framework** | FastAPI | REST API server |
| **Database** | SQLite (WAL) | Persistent storage |
| **Container** | Docker | Deployment |
| **Language** | Python 3.11+ | Core runtime |
| **Protocol** | WebSocket | Real-time updates |

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Built with MiMo LLM** — powering intelligent adversarial security testing.
