"""
domains/reconnaissance/subdomain_fuzzer.py — Enumerador de Subdomínios (v6.3).
"""

from typing import Iterable, Any
import httpx
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core import http as H

class SubdomainFuzzer(BaseScanner):
    name = "subdomain_fuzzer"
    capabilities = ["reconnaissance", "subdomains"]

    def __init__(self, ctx, wordlist: list[str] = None):
        super().__init__(ctx)
        self.wordlist = wordlist or ["admin", "gestao", "api", "dev", "test", "staging", "m", "blog"]
        self._target_domain = self.ctx.session.target.split("//")[-1].split("/")[0]

    def get_payloads(self) -> Iterable[str]:
        return self.wordlist

    def execute(self, payload: str) -> Any:
        # Tenta resolver o subdomínio
        sub = f"{payload}.{self._target_domain}"
        url = f"https://{sub}" if self.ctx.session.ssl else f"http://{sub}"
        
        try:
            # Faz um GET rápido no subdomínio
            with httpx.Client(verify=False, timeout=2.0) as client:
                r = client.get(url)
                return r
        except Exception:
            return None

    def analyze(self, payload: str, response: Any) -> ScanResult:
        if response and response.status_code != 404:
            sub = f"{payload}.{self._target_domain}"
            self.ctx.session.remember(f"subdomain_{sub}", sub)
            return ScanResult(
                success=True, confidence=0.9, severity="Low",
                details=f"Subdomínio descoberto: {sub} (Status: {response.status_code})"
            )
        return ScanResult(success=False, confidence=0.0, details="-")
