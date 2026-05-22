"""SQLite database operations for Red Team Engine."""
import sqlite3
import json
import time
from pathlib import Path
from .config import DB_PATH


def get_connection():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at REAL DEFAULT (strftime('%s','now')),
            updated_at REAL DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            agent TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            cvss_score REAL DEFAULT 0.0,
            title TEXT NOT NULL,
            description TEXT,
            mitre_id TEXT,
            mitre_tactic TEXT,
            evidence TEXT,
            recommendation TEXT,
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS attack_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            path_name TEXT NOT NULL,
            steps TEXT NOT NULL,
            total_risk REAL DEFAULT 0.0,
            success_probability REAL DEFAULT 0.0,
            mitre_chain TEXT,
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            campaign_type TEXT NOT NULL,
            name TEXT NOT NULL,
            templates TEXT,
            status TEXT DEFAULT 'draft',
            metrics TEXT,
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS defenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            finding_id INTEGER,
            defense_type TEXT NOT NULL,
            rule TEXT NOT NULL,
            priority TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'recommended',
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS deceptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            deception_type TEXT NOT NULL,
            config TEXT NOT NULL,
            status TEXT DEFAULT 'planned',
            triggers INTEGER DEFAULT 0,
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER,
            report_type TEXT DEFAULT 'full',
            content TEXT NOT NULL,
            executive_summary TEXT,
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (target_id) REFERENCES targets(id)
        );
        CREATE TABLE IF NOT EXISTS agent_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent TEXT NOT NULL,
            action TEXT NOT NULL,
            target_id INTEGER,
            details TEXT,
            duration_ms REAL,
            created_at REAL DEFAULT (strftime('%s','now'))
        );
    """)
    conn.close()


def insert_target(name, target_type, value):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO targets (name, type, value) VALUES (?, ?, ?)",
        (name, target_type, value)
    )
    target_id = cur.lastrowid
    conn.commit()
    conn.close()
    return target_id


def insert_finding(target_id, agent, category, title, description,
                   severity="info", cvss_score=0.0, mitre_id=None,
                   mitre_tactic=None, evidence=None, recommendation=None):
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO findings (target_id, agent, category, severity, cvss_score,
           title, description, mitre_id, mitre_tactic, evidence, recommendation)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (target_id, agent, category, severity, cvss_score, title, description,
         mitre_id, mitre_tactic, evidence, recommendation)
    )
    finding_id = cur.lastrowid
    conn.commit()
    conn.close()
    return finding_id


def insert_attack_path(target_id, path_name, steps, total_risk,
                       success_probability, mitre_chain):
    conn = get_connection()
    conn.execute(
        """INSERT INTO attack_paths (target_id, path_name, steps, total_risk,
           success_probability, mitre_chain) VALUES (?, ?, ?, ?, ?, ?)""",
        (target_id, path_name, json.dumps(steps), total_risk,
         success_probability, json.dumps(mitre_chain))
    )
    conn.commit()
    conn.close()


def insert_campaign(target_id, campaign_type, name, templates):
    conn = get_connection()
    conn.execute(
        """INSERT INTO campaigns (target_id, campaign_type, name, templates)
           VALUES (?, ?, ?, ?)""",
        (target_id, campaign_type, name, json.dumps(templates))
    )
    conn.commit()
    conn.close()


def insert_defense(target_id, finding_id, defense_type, rule, priority="medium"):
    conn = get_connection()
    conn.execute(
        """INSERT INTO defenses (target_id, finding_id, defense_type, rule, priority)
           VALUES (?, ?, ?, ?, ?)""",
        (target_id, finding_id, defense_type, rule, priority)
    )
    conn.commit()
    conn.close()


def insert_deception(target_id, deception_type, config):
    conn = get_connection()
    conn.execute(
        """INSERT INTO deceptions (target_id, deception_type, config)
           VALUES (?, ?, ?)""",
        (target_id, deception_type, json.dumps(config))
    )
    conn.commit()
    conn.close()


def insert_report(target_id, content, executive_summary,
                  total_findings, critical_count, high_count):
    conn = get_connection()
    conn.execute(
        """INSERT INTO reports (target_id, content, executive_summary,
           total_findings, critical_count, high_count)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (target_id, content, executive_summary,
         total_findings, critical_count, high_count)
    )
    conn.commit()
    conn.close()


def get_targets():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_findings(target_id=None):
    conn = get_connection()
    if target_id:
        rows = conn.execute(
            "SELECT * FROM findings WHERE target_id=? ORDER BY cvss_score DESC",
            (target_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY cvss_score DESC"
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_attack_paths(target_id=None):
    conn = get_connection()
    if target_id:
        rows = conn.execute(
            "SELECT * FROM attack_paths WHERE target_id=? ORDER BY total_risk DESC",
            (target_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM attack_paths ORDER BY total_risk DESC"
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_reports(target_id=None):
    conn = get_connection()
    if target_id:
        rows = conn.execute(
            "SELECT * FROM reports WHERE target_id=? ORDER BY created_at DESC",
            (target_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM reports ORDER BY created_at DESC"
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_defenses(target_id=None):
    conn = get_connection()
    if target_id:
        rows = conn.execute(
            "SELECT * FROM defenses WHERE target_id=? ORDER BY priority",
            (target_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM defenses ORDER BY priority"
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_deceptions(target_id=None):
    conn = get_connection()
    if target_id:
        rows = conn.execute(
            "SELECT * FROM deceptions WHERE target_id=?", (target_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM deceptions").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_campaigns(target_id=None):
    conn = get_connection()
    if target_id:
        rows = conn.execute(
            "SELECT * FROM campaigns WHERE target_id=?", (target_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM campaigns ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    conn = get_connection()
    stats = {
        "targets": conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0],
        "findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
        "critical": conn.execute("SELECT COUNT(*) FROM findings WHERE severity='critical'").fetchone()[0],
        "high": conn.execute("SELECT COUNT(*) FROM findings WHERE severity='high'").fetchone()[0],
        "medium": conn.execute("SELECT COUNT(*) FROM findings WHERE severity='medium'").fetchone()[0],
        "low": conn.execute("SELECT COUNT(*) FROM findings WHERE severity='low'").fetchone()[0],
        "attack_paths": conn.execute("SELECT COUNT(*) FROM attack_paths").fetchone()[0],
        "campaigns": conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0],
        "defenses": conn.execute("SELECT COUNT(*) FROM defenses").fetchone()[0],
        "deceptions": conn.execute("SELECT COUNT(*) FROM deceptions").fetchone()[0],
        "reports": conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
    }
    conn.close()
    return stats
