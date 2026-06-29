"""
domains/reconnaissance/param_discovery.py — Fuzzer de Parâmetros Ocultos (Parameter Discovery).

Identifica parâmetros ocultos em endpoints HTTP (ex: ?debug=1 ou ?admin=true)
detectando variações diferenciais nas respostas de status ou tamanho de página.
"""

from __future__ import annotations

from typing import Iterable, Any
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core import http as H

class ParamDiscovery(BaseScanner):
    name = "param_discovery"
    capabilities = ["reconnaissance", "parameter_fuzzing"]

    def __init__(self, ctx, path: str = "/", method: str = "GET"):
        super().__init__(ctx)
        self.path = path
        self.method = method.upper()
        self.baseline_status = 200
        self.baseline_len = 0
        
        # Obtém o baseline sem parâmetros adicionais
        try:
            base_resp = self.get_baseline()
            if base_resp:
                self.baseline_status = base_resp.status_code
                self.baseline_len = len(base_resp.text)
        except Exception:
            pass

        # Lista de 30 parâmetros comuns de depuração, admin e LFI em CTFs
        self.param_wordlist = [
            "debug", "admin", "admin_mode", "test", "dev", "source", "file", "path",
            "page", "view", "read", "cfg", "config", "settings", "secret", "key",
            "token", "id", "user", "username", "pass", "password", "email", "role",
            "level", "cmd", "exec", "eval", "system", "url", "redirect", "dest"
        ]

    def get_payloads(self) -> Iterable[str]:
        return self.param_wordlist

    def get_baseline(self) -> Any:
        if self.method == "GET":
            return H.get(self.ctx.session, self.path)
        else:
            return H.post(self.ctx.session, self.path, payload={})

    def execute(self, payload: str) -> Any:
        param_name = str(payload)
        # Tenta injetar valores de teste comuns em CTFs (1, true, /etc/passwd)
        test_val = "1"
        if param_name in ("file", "path", "page", "view", "read"):
            test_val = "/etc/passwd"
        elif param_name in ("admin", "admin_mode", "debug", "dev", "test"):
            test_val = "true"

        try:
            if self.method == "GET":
                return H.get(self.ctx.session, self.path, params={param_name: test_val})
            else:
                return H.post(self.ctx.session, self.path, payload={param_name: test_val})
        except Exception:
            return None

    def analyze(self, payload: str, response: Any) -> ScanResult:
        param_name = str(payload)
        if not response:
            return ScanResult(success=False, confidence=0.0, details="-")

        status = response.status_code
        body_len = len(response.text)

        # 1. Se a resposta retornar um código HTTP diferente do baseline
        if status != self.baseline_status and status not in (400, 404, 405, 413, 414, 422, 500, 501, 502, 503):
            self.ctx.session.remember(f"hidden_param_{param_name}", True)
            self.ctx.session.note(f"Parâmetro oculto descoberto: '{param_name}' em {self.path} (HTTP {status})")
            return ScanResult(
                success=True,
                confidence=0.9,
                severity="Medium",
                details=f"Parâmetro oculto '{param_name}' causa alteração de status HTTP ({status} vs Baseline {self.baseline_status})"
            )

        # 2. Se o tamanho da resposta mudar significativamente (ex: > 10% de variação)
        if self.baseline_len > 0:
            diff_ratio = abs(body_len - self.baseline_len) / self.baseline_len
            if diff_ratio > 0.15: # Alteração maior que 15% indica comportamento diferenciado (reduz FPs de conteúdo dinâmico)
                self.ctx.session.remember(f"hidden_param_{param_name}", True)
                self.ctx.session.note(f"Parâmetro oculto descoberto por tamanho de resposta: '{param_name}' ({body_len} bytes vs Baseline {self.baseline_len})")
                return ScanResult(
                    success=True,
                    confidence=0.8,
                    severity="Low",
                    details=f"Parâmetro oculto '{param_name}' altera tamanho de página ({body_len} bytes vs Baseline {self.baseline_len})"
                )

        return ScanResult(success=False, confidence=0.0, details="-")
