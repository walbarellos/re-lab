"""
domains/reconnaissance/fuzzer.py — Fuzzer de Parâmetros v5.4 (Dynamic Baseline).
"""

from typing import Iterable, Any
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core.payloads import PayloadManager
from ctflab.core import http as H

class ParameterFuzzer(BaseScanner):
    name = "reconnaissance_fuzzer"
    capabilities = ["http", "discovery", "reconnaissance"]

    def __init__(self, ctx, path: str = "/", mode: str = "get"):
        super().__init__(ctx)
        self.path = path
        self.mode = mode
        self.payload_mgr = PayloadManager()
        self._baseline_len = 0
        self._baseline_status = 0

    def run(self):
        """
        Sobrescreve run para fazer descoberta de API profunda e caminhos comuns.
        """
        from ctflab.cli.ui import console
        
        # 🚀 SUPER-WORDLIST v6.1.1 (Unificada: Comum + Deep API + CTF)
        api_wordlist = sorted(list(set([
            "api", "rest", "v1", "v2", "api/v1", "api/v2", "rest/admin", "rest/user", 
            "static", "assets", "main.js", "api/Users", "rest/products", "rest/user/login",
            "api/v1/users", "api/v1/login", "api/v1/register", "api/v1/products",
            "api/v2/users", "api/v2/auth", "api/v2/config", "rest/v1/admin",
            "rest/v1/user", "rest/v1/account", "api/health", "api/status",
            "api/debug", "api/admin/db", "api/v1/upload", "api/v1/download",
            "api/v1/profile", "api/v1/settings", "api/v1/search", "api/v1/logs",
            "ftp", "backup", "db", "admin", "config", "debug", "dev", "shell"
        ])))
        
        console.print(f"  [dim]→ iniciando Super-Varredura de Superfície ({len(api_wordlist)} rotas)...[/dim]")
        path_results = H.fuzz(self.ctx.session, api_wordlist)
        
        all_discovered = self.ctx.session.recall("_all_discovered_endpoints", set())
        if isinstance(all_discovered, list): all_discovered = set(all_discovered)
        
        found_count = 0
        for path, code, _, _ in path_results:
            # Qualquer código que não seja 404 é um sinal de vida da rota
            if code != 404:
                all_discovered.add(path)
                found_count += 1
        
        self.ctx.session.remember("_all_discovered_endpoints", list(all_discovered))
        if found_count:
            console.print(f"  [ok]Super-Discovery: {found_count} novos alvos identificados.[/ok]")

        # 2. Fuzzing de parâmetros
        return super().run()

    def get_payloads(self) -> Iterable[str]:
        params = self.payload_mgr.load("params")
        if not params:
            return ["debug", "admin", "test", "dev"]
        return params

    def execute(self, payload: str) -> Any:
        test_val = "fuzz_test_1337"

        if self.mode == "get":
            r = H.get(self.ctx.session, self.path, params={payload: test_val}, use_cache=False)
        else:
            r = H.post(self.ctx.session, self.path, payload={payload: test_val}, use_cache=False)

        if not self._baseline_status:
            self._baseline_len = len(r.text)
            self._baseline_status = r.status_code

        return r

    def analyze(self, payload: str, response: Any) -> ScanResult:
        delta = abs(len(response.text) - self._baseline_len)
        status_changed = response.status_code != self._baseline_status

        if status_changed or delta > 20:
            self.ctx.session.remember("hidden_param", payload)
            return ScanResult(
                success=True,
                confidence=0.85,
                details=f"param={payload} Δ={delta:+d} bytes",
                severity="Low"
            )

        return ScanResult(success=False, confidence=0.0, details="-")
