"""
domains/reconnaissance/waf_char_fuzzer.py — Mapeador de Filtros de Caracteres (WAF Character Fuzzer).

Envia caracteres especiais para um parâmetro do alvo para traçar o perfil de filtragem
do WAF ou de sanitização da aplicação.
"""

from __future__ import annotations

from typing import Iterable, Any
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core import http as H

class WafCharFuzzer(BaseScanner):
    name = "waf_char_fuzzer"
    capabilities = ["reconnaissance", "waf_profiling"]

    def __init__(self, ctx, path: str = "/", param: str = "q", method: str = "GET"):
        super().__init__(ctx)
        self.path = path
        self.param = param
        self.method = method.upper()
        self.baseline_status = 200
        self.baseline_len = 0
        
        # Carrega a resposta de baseline para comparação diferencial
        try:
            base_resp = self.get_baseline()
            if base_resp:
                self.baseline_status = base_resp.status_code
                self.baseline_len = len(base_resp.text)
        except Exception:
            pass

    def get_payloads(self) -> Iterable[str]:
        # Lista de caracteres especiais usados em injeções (SQLi, SSTI, RCE, XSS)
        return ["'", "\"", "(", ")", ";", "<", ">", "&", "|", "$", "`", "\\", "/", "{", "}", "[", "]", "%", "+", "="]

    def get_baseline(self) -> Any:
        # Envia requisição limpa para baseline
        if self.method == "GET":
            return H.get(self.ctx.session, self.path, params={self.param: "normal_test_string"})
        else:
            return H.post(self.ctx.session, self.path, payload={self.param: "normal_test_string"})

    def execute(self, payload: str) -> Any:
        char = str(payload)
        # Testa o comportamento da aplicação com o caractere específico
        if self.method == "GET":
            try:
                return H.get(self.ctx.session, self.path, params={self.param: char})
            except Exception:
                return None
        else:
            try:
                return H.post(self.ctx.session, self.path, payload={self.param: char})
            except Exception:
                return None

    def analyze(self, payload: str, response: Any) -> ScanResult:
        char = str(payload)
        if not response:
            # Erro de conexão: pode ser instabilidade, NÃO assumir bloqueio WAF
            return ScanResult(
                success=False, confidence=0.3, severity="Low",
                details=f"Caractere '{char}' causou erro de conexão (pode ser instabilidade, não assumido como bloqueio)"
            )

        # Se o status code mudar para códigos de bloqueio clássicos
        if response.status_code in (400, 403, 406, 429) and response.status_code != self.baseline_status:
            self.ctx.session.remember(f"blocked_char_{char}", True)
            return ScanResult(
                success=True, confidence=1.0, severity="Medium",
                details=f"Caractere '{char}' BLOQUEADO. Status HTTP: {response.status_code} (Baseline era {self.baseline_status})"
            )

        # Se houver uma alteração muito abrupta no tamanho do corpo (ex: página de erro de WAF reduzida)
        body_len = len(response.text)
        if self.baseline_len > 0:
            diff_ratio = abs(body_len - self.baseline_len) / self.baseline_len
            if diff_ratio > 0.5 or (diff_ratio > 0.3 and response.status_code != self.baseline_status):
                self.ctx.session.remember(f"blocked_char_{char}", True)
                return ScanResult(
                    success=True, confidence=0.9, severity="Low",
                    details=f"Caractere '{char}' causou resposta diferencial abrupta (Tamanho: {body_len} vs Baseline: {self.baseline_len})"
                )

        return ScanResult(success=False, confidence=0.0, details=f"Caractere '{char}' aceito sem restrições visíveis")

