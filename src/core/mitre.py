"""MITRE ATT&CK mapping module."""
from ..config import MITRE_TECHNIQUES


class MITREMapper:
    def __init__(self):
        self.techniques = MITRE_TECHNIQUES

    def get_technique(self, technique_id: str) -> dict:
        return self.techniques.get(technique_id, {
            "name": "Unknown",
            "tactic": "Unknown"
        })

    def get_by_tactic(self, tactic: str) -> list:
        return [
            {"id": tid, **info}
            for tid, info in self.techniques.items()
            if info["tactic"] == tactic
        ]

    def get_all_tactics(self) -> list:
        return sorted(set(t["tactic"] for t in self.techniques.values()))

    def get_coverage(self, found_ids: list) -> dict:
        all_ids = set(self.techniques.keys())
        covered = set(found_ids) & all_ids
        tactics = {}
        for tid in covered:
            tactic = self.techniques[tid]["tactic"]
            if tactic not in tactics:
                tactics[tactic] = {"total": 0, "covered": 0, "techniques": []}
            tactics[tactic]["covered"] += 1
            tactics[tactic]["techniques"].append(tid)
        for tid, info in self.techniques.items():
            tactic = info["tactic"]
            if tactic not in tactics:
                tactics[tactic] = {"total": 0, "covered": 0, "techniques": []}
            tactics[tactic]["total"] += 1
        for t in tactics:
            if tactics[t]["total"] > 0:
                tactics[t]["coverage_pct"] = round(
                    tactics[t]["covered"] / tactics[t]["total"] * 100, 1
                )
            else:
                tactics[t]["coverage_pct"] = 0.0
        return {
            "total_techniques": len(all_ids),
            "covered": len(covered),
            "coverage_pct": round(len(covered) / len(all_ids) * 100, 1),
            "by_tactic": tactics
        }

    def get_matrix(self) -> list:
        tactics = {}
        for tid, info in self.techniques.items():
            t = info["tactic"]
            if t not in tactics:
                tactics[t] = []
            tactics[t].append({"id": tid, "name": info["name"]})
        return [{"tactic": t, "techniques": techs} for t, techs in tactics.items()]
