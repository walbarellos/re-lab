"""
domains/detection/ssti_scanner.py — Scanner de Server-Side Template Injection (SSTI).

Detecta SSTI e vulnerabilidades de injeção de template em múltiplos frameworks.
"""

from __future__ import annotations

from typing import Iterable, Any
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core.payloads import PayloadManager
from ctflab.core import http as H

class SSTIScanner(BaseScanner):
    name = "ssti"
    capabilities = ["http", "ssti", "detection"]

    def __init__(self, ctx, path: str = "/", method: str = "POST", param: str = "template"):
        super().__init__(ctx)
        self.path = path
        self.method = method
        self.param = param
        self.payload_mgr = PayloadManager()

    def get_payloads(self) -> Iterable[str]:
        """Carrega os payloads do arquivo payloads/ssti.yaml."""
        return self.payload_mgr.load("ssti")

    def execute(self, payload: str) -> Any:
        """Executa a requisição injetando o payload no parâmetro especificado."""
        if self.method.upper() == "GET":
            return H.get(self.ctx.session, self.path, params={self.param: payload}, use_cache=False)
        else:
            return H.post(self.ctx.session, self.path, payload={self.param: payload}, use_cache=False)

    def analyze(self, payload: str, response: Any) -> ScanResult:
        """Analisa a resposta HTTP para verificar se a injeção de template ocorreu."""
        text = response.text

        # 1. Verifica se houve vazamento de flags (CTF/FLAG{...})
        from ctflab.core.intel import _FLAG_RE
        flag_match = _FLAG_RE.search(text)
        if flag_match:
            return ScanResult(
                success=True,
                confidence=1.0,
                details=f"SSTI EXPLOITED - Flag encontrada: {flag_match.group()}",
                severity="Critical"
            )

        # 2. Verifica avaliação de expressões matemáticas (ex: 7*7)
        is_math_probe = "7*7" in payload or "7*'7'" in payload
        if is_math_probe:
            if "7*'7'" in payload:
                if "7777777" in text:
                    return ScanResult(
                        success=True,
                        confidence=0.95,
                        details="SSTI Jinja2 confirmado (multiplicação de string resultou em 7777777)",
                        severity="High"
                    )
                elif "49" in text:
                    return ScanResult(
                        success=True,
                        confidence=0.9,
                        details="SSTI Twig / Mako / Freemarker confirmado (avaliação de string resultou em 49)",
                        severity="High"
                    )
            else:
                if "49" in text:
                    return ScanResult(
                        success=True,
                        confidence=0.9,
                        details=f"SSTI detectado via expressão matemática '{payload}'",
                        severity="High"
                    )

        # 3. Verifica execução de comandos (ex: uid=, gid=, groups=)
        if "uid=" in text and "gid=" in text:
            return ScanResult(
                success=True,
                confidence=1.0,
                details=f"SSTI RCE CONFIRMADO - Comando id executado com sucesso",
                severity="Critical"
            )

        # 4. Verifica se houve vazamento de arquivos de sistema (ex: root:x:0:0)
        system_sigs = [
            "root:x:0:0",
            "daemon:x:1:1",
            "bin:x:2:2",
            "[boot loader]",
            "default=multi(0)",
            "127.0.0.1 localhost",
        ]
        if any(sig in text for sig in system_sigs):
            return ScanResult(
                success=True,
                confidence=1.0,
                details=f"SSTI LFI CONFIRMADO - Leitura de arquivo do sistema com sucesso",
                severity="Critical"
            )

        # 5. Verifica vazamento de informações de configuração (ex: Flask config)
        config_sigs = ["<Config", "SQLALCHEMY_DATABASE_URI", "SECRET_KEY", "JSONIFY_PRETTYPRINT_REGULAR"]
        if any(sig in text for sig in config_sigs):
            return ScanResult(
                success=True,
                confidence=0.95,
                details=f"SSTI Config Leak - Vazamento de dados de configuração sensíveis",
                severity="High"
            )

        return ScanResult(success=False, confidence=0.0, details="Nenhum sinal detectado")
