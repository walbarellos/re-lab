"""
domains/detection/differential_sqli.py — Scanner de SQLi Diferencial (v6.2).

Detecta SQL Injection através de inferência lógica (Boolean/Time based)
comparando a resposta do alvo com uma Baseline, sem depender de erros visíveis.
"""

from typing import Iterable, Any
import time
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core import http as H

class DifferentialSQLiScanner(BaseScanner):
    name = "differential_sqli"
    capabilities = ["http", "sqli", "differential", "blind"]

    def __init__(self, ctx, path: str, method: str = "GET", param: str = "id"):
        super().__init__(ctx)
        self.path = path
        self.method = method
        self.param = param
        self._baseline_text = ""
        self._baseline_time = 0.0

    def get_payloads(self) -> Iterable[str]:
        # Payloads de inferência lógica e tempo (Nada de 'OR 1=1' barulhento)
        return [
            "1 AND 1=1",      # Booleano Verdadeiro
            "1 AND 1=2",      # Booleano Falso
            "1' AND '1'='1",  # Break-out Verdadeiro
            "1' AND '1'='2",  # Break-out Falso
            "1) AND 1=1--",   # Parenteses
            "SLEEP(5)",       # Time-based (MySQL)
            "pg_sleep(5)",    # Time-based (Postgres)
            "(SELECT 1 FROM (SELECT(SLEEP(5)))a)" # Time-based complexo
        ]

    def execute(self, payload: str) -> Any:
        start = time.perf_counter()
        params = {self.param: payload} if self.method == "GET" else None
        data = {self.param: payload} if self.method == "POST" else None
        
        r = H.request(self.ctx.session, self.method, self.path, params=params, payload=data, use_cache=False)
        r._elapsed_total = time.perf_counter() - start
        return r

    def run(self):
        # 1. Captura a Baseline (como o site se comporta normalmente)
        self.ctx.log_info(f"DAD: Capturando baseline para {self.path}...")
        baseline_resp = self.get_baseline()
        self._baseline_text = baseline_resp.text
        self._baseline_time = getattr(baseline_resp, "_elapsed_total", 0.1)
        
        return super().run()

    def analyze(self, payload: str, response: Any) -> ScanResult:
        current_time = getattr(response, "_elapsed_total", 0.0)
        
        # 🕵️ LÓGICA 1: TIME-BASED (Atraso significativo)
        if "SLEEP" in payload.upper() or "pg_sleep" in payload:
            if current_time > (self._baseline_time + 4.0):
                return ScanResult(
                    success=True, confidence=0.95, severity="High",
                    details=f"SQLi Time-based confirmado! (Baseline: {self._baseline_time:.2f}s, Atual: {current_time:.2f}s)"
                )

        # 🕵️ LÓGICA 2: BOOLEAN-BASED (Estrutura da página mudou entre TRUE/FALSE)
        # Se AND 1=1 é igual à baseline, mas AND 1=2 é diferente, temos um hit.
        if "1=1" in payload:
            if response.text == self._baseline_text:
                self.ctx.session.remember(f"sqli_bool_stable_{self.param}", "true")
        
        if "1=2" in payload:
            is_stable = self.ctx.session.recall(f"sqli_bool_stable_{self.param}")
            if is_stable and response.text != self._baseline_text:
                return ScanResult(
                    success=True, confidence=0.9, severity="High",
                    details=f"SQLi Boolean-based confirmado via inferência diferencial no parâmetro '{self.param}'"
                )

        return ScanResult(success=False, confidence=0.0, details="-")
