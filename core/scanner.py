"""
core/scanner.py — Motor de Varredura Base.

Define o contrato universal para todos os detectores e exploradores do CTFLab.
Reduz a duplicação de lógica de loops, tabelas e tratamento de erros.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Iterable

from .context import Context
from .models import ScanResult, Evidence, Vulnerability
from .events import VulnerabilityFound, EvidenceCreated, ScanStarted, ScanFinished

class BaseScanner(ABC):
    """
    Classe abstrata que orquestra o ciclo de vida de uma varredura.
    """
    name: str = "base_scanner"
    capabilities: list[str] = [] # ex: ["http", "sqli", "discovery"]
    
    def __init__(self, ctx: Context):
        self.ctx = ctx

    @abstractmethod
    def get_payloads(self) -> Iterable[Any]:
        """Retorna a lista de payloads a serem testados."""
        pass

    @abstractmethod
    def execute(self, payload: Any) -> Any:
        """Executa a requisição técnica com o payload."""
        pass

    @abstractmethod
    def analyze(self, payload: Any, response: Any) -> ScanResult:
        """Analisa a resposta para determinar se houve um hit."""
        pass

    def run(self) -> list[Vulnerability]:
        """
        Orquestra a varredura utilizando concorrência e políticas do perfil.
        """
        return asyncio.run(self._run_async())

    def get_baseline(self) -> Any:
        """
        Opcional: Captura uma resposta de referência sem payload.
        Útil para análise diferencial (v6.2).
        """
        return self.execute("")

    async def _run_async(self) -> list[Vulnerability]:
        self.ctx.publish(ScanStarted(module_name=self.name))
        self.ctx.metrics.start_module(self.name)

        profile = self.ctx.profiles.active_profile
        semaphore = asyncio.Semaphore(profile.threads)

        found_vulns = []
        payloads = list(self.get_payloads())
        requests_sent = 0
        errors_occurred = 0

        async def _worker(p):
            nonlocal requests_sent, errors_occurred
            if profile.delay > 0:
                await asyncio.sleep(profile.delay)

            async with semaphore:
                try:
                    requests_sent += 1
                    # Nota: execute() roda em thread para não bloquear o loop de eventos
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(None, self.execute, p)
                    result = self.analyze(p, response)

                    if result.success:
                        severity = getattr(result, "severity", "Medium")
                        evidence = Evidence(
                            module=self.name,
                            payload=str(p),
                            status=getattr(response, 'status_code', 0),
                            response_snippet=getattr(response, 'text', "")[:100],
                            confidence=result.confidence
                        )
                        vuln = Vulnerability(
                            severity=severity, 
                            confidence=result.confidence,
                            module=self.name,
                            name=f"Vulnerabilidade detectada via {self.name}",
                            payload=str(p),
                            evidence=[evidence]
                        )
                        self.ctx.session.add_vulnerability(vuln)
                        self.ctx.publish(EvidenceCreated(evidence=evidence))
                        self.ctx.publish(VulnerabilityFound(vulnerability=vuln))
                        return vuln
                except Exception as exc:
                    errors_occurred += 1
                    self.ctx.log_error(f"Erro em {self.name} com payload {p}: {exc}")
            return None

        # Dispara todas as tasks respeitando o semáforo
        tasks = [asyncio.create_task(_worker(p)) for p in payloads]
        results = await asyncio.gather(*tasks)
        found_vulns = [v for v in results if v is not None]

        self.ctx.metrics.stop_module(self.name, findings=len(found_vulns), requests=requests_sent, errors=errors_occurred)
        self.ctx.publish(ScanFinished(module_name=self.name, findings_count=len(found_vulns)))
        return found_vulns
