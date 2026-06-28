"""
core/rules.py — Máquina de Regras (DSL).

Permite definir assinaturas de vulnerabilidades em YAML, desacoplando
o conhecimento da detecção do código do motor.
"""

import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any
from .logger import logger

@dataclass
class DetectionRule:
    name: str
    description: str
    severity: str
    confidence: float
    conditions: Dict[str, Any]

class RuleEngine:
    """
    Carrega e avalia regras declarativas em YAML.
    """
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(exist_ok=True)
        self.rules: List[DetectionRule] = []
        self.load_rules()

    def load_rules(self):
        """Varre a pasta de regras e carrega os arquivos YAML."""
        for rule_file in self.rules_dir.glob("*.yaml"):
            try:
                with open(rule_file, "r") as f:
                    data = yaml.safe_load(f)
                    rule = DetectionRule(
                        name=data.get("name", "Unnamed Rule"),
                        description=data.get("description", ""),
                        severity=data.get("severity", "Info"),
                        confidence=data.get("confidence", 0.5),
                        conditions=data.get("when", {})
                    )
                    self.rules.append(rule)
            except Exception as e:
                logger.error(f"Erro ao carregar regra {rule_file}: {e}")

    def evaluate(self, response_text: str, status_code: int) -> List[DetectionRule]:
        """Avalia o texto da resposta contra todas as regras carregadas."""
        hits = []
        text_lower = response_text.lower()
        
        for rule in self.rules:
            # Avalia condições 'contains'
            if "contains" in rule.conditions:
                if any(c.lower() in text_lower for c in rule.conditions["contains"]):
                    hits.append(rule)
                    continue
            
            # Avalia condições 'status'
            if "status" in rule.conditions:
                if status_code == rule.conditions["status"]:
                    hits.append(rule)
                    continue
        
        return hits
