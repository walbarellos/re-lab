"""
domains/detection/ssrf_scanner.py — Scanner de SSRF (v6).

Testa parâmetros que aceitam URLs para detectar Server-Side Request Forgery.
"""

from typing import Iterable, Any
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core import http as H

class SSRFScanner(BaseScanner):
    name = "ssrf_detection"
    capabilities = ["http", "ssrf", "detection"]
    
    # Payloads para detectar SSRF
    PAYLOADS = [
        "http://127.0.0.1:80",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/", # AWS Metadata
    ]

    def __init__(self, ctx, path: str = "/", param: str = "url"):
        super().__init__(ctx)
        self.path = path
        self.param = param

    def get_payloads(self) -> Iterable[str]:
        return self.PAYLOADS

    def execute(self, payload: str) -> Any:
        return H.get(self.ctx.session, self.path, params={self.param: payload})

    def analyze(self, payload: str, response: Any) -> ScanResult:
        # Detecta se a resposta mudou ou contém sinais de serviços internos
        if response.status_code == 200 and len(response.text) > 0:
            if "instance-id" in response.text or "ami-id" in response.text:
                return ScanResult(
                    success=True,
                    confidence=1.0,
                    details=f"SSRF CONFIRMADO (AWS Metadata) via {self.param}",
                    severity="Critical"
                )
            return ScanResult(
                success=True,
                confidence=0.7,
                details=f"Possível SSRF via {self.param} (Status 200)",
                severity="High"
            )
        return ScanResult(success=False, confidence=0.0, details="-")
