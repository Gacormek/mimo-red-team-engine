"""Configuration for MiMo Adversarial Red Team Engine."""

# ── Server ─────────────────────────────────────────────────────
HOST = "0.0.0.0"
PORT = 80

# ── Database ───────────────────────────────────────────────────
DB_PATH = "/root/mimo-red-team-engine/data/redteam.db"

# ── MiMo LLM ──────────────────────────────────────────────────
MIMO_API_URL = os.getenv("MIMO_API_URL")
MIMO_MODEL = "xmtp/mimo-v2.5-pro"
MIMO_MAX_TOKENS = 2000

# ── Agent Timing ───────────────────────────────────────────────
RECON_INTERVAL = 10
VULN_SCAN_INTERVAL = 15
SOCIAL_INTERVAL = 20
EXPLOIT_INTERVAL = 12
DEFENSE_INTERVAL = 15
DECEPTION_INTERVAL = 25
REPORT_INTERVAL = 30

# ── CVSS Thresholds ────────────────────────────────────────────
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0
CVSS_LOW = 0.1

# ── Attack Path ────────────────────────────────────────────────
MAX_ATTACK_DEPTH = 5
MAX_PATHS_PER_TARGET = 10

# ── MITRE ATT&CK ──────────────────────────────────────────────
MITRE_TECHNIQUES = {
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "Reconnaissance"},
    "T1590": {"name": "Gather Victim Network Information", "tactic": "Reconnaissance"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution"},
    "T1055": {"name": "Process Injection", "tactic": "Privilege Escalation"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1134": {"name": "Access Token Manipulation", "tactic": "Privilege Escalation"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1080": {"name": "Taint Shared Content", "tactic": "Lateral Movement"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1489": {"name": "Service Stop", "tactic": "Impact"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact"},
}

# ── Deception ──────────────────────────────────────────────────
HONEYPOT_TYPES = ["ssh", "http", "ftp", "smb", "rdp", "database"]
CANARY_TYPES = ["file", "dns", "web", "credential"]

# ── Phishing Templates ────────────────────────────────────────
PHISHING_TEMPLATES = {
    "credential_harvest": {
        "name": "Credential Harvest",
        "subject": "Urgent: Password Reset Required",
        "description": "Fake password reset email targeting corporate credentials"
    },
    "malware_delivery": {
        "name": "Malware Delivery",
        "subject": "Invoice Attached - Action Required",
        "description": "Malicious document attachment campaign"
    },
    "bec": {
        "name": "Business Email Compromise",
        "subject": "Wire Transfer Request - Confidential",
        "description": "Executive impersonation for financial fraud"
    },
    "spear_phish": {
        "name": "Spear Phishing",
        "subject": "Team Collaboration Tool Update",
        "description": "Targeted attack using personal information"
    }
}
