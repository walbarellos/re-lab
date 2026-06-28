"""
domains/detection/sqli_scanner.py — Scanner de SQL Injection (v5.0).

Implementação baseada em BaseScanner que utiliza o RuleEngine e o
PayloadManager para detecção genérica e robusta.
"""

from typing import Iterable, Any
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core.payloads import PayloadManager
from ctflab.core.rules import RuleEngine
from ctflab.core import http as H

class SQLiScanner(BaseScanner):
    name = "sqli_detection"
    capabilities = ["http", "sqli", "detection"]
    
    def __init__(self, ctx, path: str, method: str = "POST", param: str = "username"):
        super().__init__(ctx)
        self.path = path
        self.method = method
        self.param = param
        self.payload_mgr = PayloadManager()
        self.rule_engine = RuleEngine()

    def get_payloads(self) -> Iterable[str]:
        """Carrega payloads do arquivo payloads/sqli.yaml."""
        return self.payload_mgr.load("sqli")

    def execute(self, payload: str) -> Any:
        """Executa a requisição contra o alvo."""
        body = {self.param: payload}
        # Injeta uma senha dummy para o campo password (comum em CTF)
        body["password"] = "baseline_pass_123"
        
        return H.request(self.ctx.session, self.method, self.path, payload=body)

    def analyze(self, payload: str, response: Any) -> ScanResult:
        """Analisa a resposta usando a Máquina de Regras."""
        hits = self.rule_engine.evaluate(response.text, response.status_code)
        
        if hits:
            # Pega a regra com maior confiança
            best_rule = max(hits, key=lambda r: r.confidence)
            return ScanResult(
                success=True, 
                confidence=best_rule.confidence,
                details=f"Hit via regra: {best_rule.name} - {best_rule.description}"
            )
            
        return ScanResult(success=False, confidence=0.0, details="Nenhum sinal detectado")
