"""Attack Graph - DAG-based attack path analysis."""
import json
import logging
from typing import List, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger("redteam.attack_graph")


@dataclass
class AttackStep:
    step_id: int
    name: str
    technique: str
    mitre_id: str
    tactic: str
    description: str
    prerequisites: List[int] = field(default_factory=list)
    success_rate: float = 0.7
    impact: str = "medium"
    detection_difficulty: str = "medium"


@dataclass
class AttackPath:
    path_id: str
    name: str
    steps: List[AttackStep]
    total_risk: float = 0.0
    success_probability: float = 0.0
    mitre_chain: List[str] = field(default_factory=list)


class AttackGraph:
    def __init__(self):
        self.paths: List[AttackPath] = []
        self.nodes: Dict[int, AttackStep] = {}

    def add_step(self, step: AttackStep):
        self.nodes[step.step_id] = step

    def build_path(self, path_id: str, name: str, step_ids: List[int]) -> AttackPath:
        steps = [self.nodes[sid] for sid in step_ids if sid in self.nodes]
        success_prob = 1.0
        for s in steps:
            success_prob *= s.success_rate
        total_risk = sum(1.0 - s.success_rate for s in steps)
        mitre_chain = [f"{s.mitre_id}" for s in steps]
        path = AttackPath(
            path_id=path_id,
            name=name,
            steps=steps,
            total_risk=round(total_risk, 3),
            success_probability=round(success_prob, 3),
            mitre_chain=mitre_chain
        )
        self.paths.append(path)
        return path

    def get_paths(self) -> List[dict]:
        result = []
        for p in self.paths:
            result.append({
                "path_id": p.path_id,
                "name": p.name,
                "steps": [
                    {
                        "step_id": s.step_id,
                        "name": s.name,
                        "technique": s.technique,
                        "mitre_id": s.mitre_id,
                        "tactic": s.tactic,
                        "description": s.description,
                        "success_rate": s.success_rate,
                        "impact": s.impact,
                        "detection_difficulty": s.detection_difficulty,
                    }
                    for s in p.steps
                ],
                "total_risk": p.total_risk,
                "success_probability": p.success_probability,
                "mitre_chain": p.mitre_chain,
                "step_count": len(p.steps),
            })
        return result

    def to_dot(self) -> str:
        lines = ["digraph AttackGraph {", '  rankdir=LR;', '  node [shape=box];']
        for sid, step in self.nodes.items():
            color = {"critical": "red", "high": "orange", "medium": "yellow", "low": "green"}.get(step.impact, "gray")
            lines.append(f'  n{sid} [label="{step.name}\\n{step.mitre_id}" style=filled fillcolor={color}];')
        for path in self.paths:
            for i in range(len(path.steps) - 1):
                lines.append(f"  n{path.steps[i].step_id} -> n{path.steps[i+1].step_id};")
        lines.append("}")
        return "\n".join(lines)
