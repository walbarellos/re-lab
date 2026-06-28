"""
core/scoring.py — Motor de Severidade e Pontuação.

Implementa a escala 0-10 para vulnerabilidades e calcula o 'Risk Score'
total da sessão de pentest.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Any, List
from .models import Vulnerability

class Severity(Enum):
    INFO     = 0.0
    LOW      = 3.0
    MEDIUM   = 5.0
    HIGH     = 8.0
    CRITICAL = 10.0

class ScoringEngine:
    @staticmethod
    def calculate_vulnerability_score(v: Vulnerability) -> float:
        """
        Calcula o score individual baseado na severidade base e na confiança.
        Score = BaseSeverity * Confidence
        """
        base_map = {
            "Info": 0.0,
            "Low": 3.0,
            "Medium": 5.0,
            "High": 8.0,
            "Critical": 10.0
        }
        base_score = base_map.get(v.severity, 5.0)
        return round(base_score * v.confidence, 1)

    @staticmethod
    def calculate_exposure_level(endpoints: List[str], session: Any = None) -> float:
        """
        Calcula o Nível de Exposição baseado na superfície mapeada.
        (v6.1.1 — Predictive Risk)
        """
        if not endpoints:
            return 0.0
            
        score = 0.0
        # Peso por densidade
        score += len(endpoints) * 0.1
        
        # Peso por endpoints críticos
        hot_patterns = ["admin", "login", "api", "v1", "v2", "config", "backup", "db", "shell", "graphql"]
        for ep in endpoints:
            if any(p in ep.lower() for p in hot_patterns):
                score += 0.5
        
        # 🕵️ REGRAS DE SCORE v6.3 (User Requested)
        # Analisa o histórico de requisições para pontuar comportamentos
        if session:
            for rec in getattr(session, "history", []):
                if rec.status == 403:
                    score += 2.0  # +20 (escala 0-10 = +2.0)
                if rec.status == 302 and ("login" in rec.body.lower() or "login" in rec.url.lower()):
                    score += 4.0  # +40 (escala 0-10 = +4.0)
        
        return min(round(score, 1), 10.0)

    @staticmethod
    def calculate_session_score(vulnerabilities: List[Vulnerability], endpoints: List[str] = None, session: Any = None) -> dict:
        """
        Calcula o relatório de risco em dois níveis.
        """
        confirmed = 0.0
        if vulnerabilities:
            scores = [ScoringEngine.calculate_vulnerability_score(v) for v in vulnerabilities]
            max_score = max(scores)
            others_sum = sum(scores) - max_score
            confirmed = min(round(max_score + (others_sum * 0.1), 1), 10.0)
            
        exposure = ScoringEngine.calculate_exposure_level(endpoints or [], session)
        
        return {
            "confirmed_risk": confirmed,
            "exposure_level": exposure,
            "total_threat": round(max(confirmed, exposure * 0.7), 1)
        }
