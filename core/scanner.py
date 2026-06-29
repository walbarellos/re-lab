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
        # Sincroniza configurações de tempo/retentativas do perfil com a sessão
        self.ctx.session.timeout = profile.timeout
        self.ctx.session.retries = profile.retries

        semaphore = asyncio.Semaphore(profile.threads)


        # Captura baseline para evitar falsos positivos
        baseline_triggered = False
        try:
            loop = asyncio.get_event_loop()
            base_resp = await loop.run_in_executor(None, self.get_baseline)
            if base_resp:
                # Reconstrói um dummy payload compatível com o tipo de get_payloads()
                first_payload = next(iter(self.get_payloads()), "")
                if isinstance(first_payload, tuple):
                    dummy_payload = tuple("" for _ in first_payload)
                elif isinstance(first_payload, list):
                    dummy_payload = list("" for _ in first_payload)
                elif isinstance(first_payload, dict):
                    dummy_payload = {k: "" for k in first_payload.keys()}
                elif isinstance(first_payload, int):
                    dummy_payload = 0
                elif isinstance(first_payload, float):
                    dummy_payload = 0.0
                else:
                    dummy_payload = ""

                base_res = self.analyze(dummy_payload, base_resp)
                if base_res.success:
                    baseline_triggered = True
                    self.ctx.log_info(f"Scanner {self.name}: Baseline disparou positivo — suprimindo falsos positivos (confidence={base_res.confidence})")
        except Exception as e:
            self.ctx.log_info(f"Falha ao obter baseline em {self.name}: {e}")

        found_vulns = []
        payloads = list(self.get_payloads())
        
        # Função auxiliar para extrair apenas as strings brutas de payloads complexos
        # Evita falso positivo de WAF blocks causados pela formatação do Python (como parênteses em tuplas)
        def _get_payload_strings(val: Any) -> list[str]:
            if isinstance(val, (str, int, float, bool)) or val is None:
                return [str(val)]
            elif isinstance(val, (list, tuple, set)):
                res = []
                for item in val:
                    res.extend(_get_payload_strings(item))
                return res
            elif isinstance(val, dict):
                res = []
                for k, v in val.items():
                    res.extend(_get_payload_strings(k))
                    res.extend(_get_payload_strings(v))
                return res
            return [str(val)]

        # Filtra payloads baseando-se em caracteres bloqueados na sessão (Evasão Adaptativa)
        filtered_payloads = []
        for p in payloads:
            p_strings = _get_payload_strings(p)
            blocked_in_payload = False
            for char in ["'", "\"", " ", "(", ")", ";", "{", "}", "[", "]", "<", ">"]:
                if self.ctx.session.recall(f"blocked_char_{char}", False):
                    # Verifica se o caractere realmente faz parte dos valores do payload
                    if any(char in s for s in p_strings):
                        blocked_in_payload = True
                        break
            if not blocked_in_payload:
                filtered_payloads.append(p)
            else:
                self.ctx.log_info(f"Scanner {self.name}: Payload omitido por conter caracteres proibidos pelo WAF.")
        
        payloads = filtered_payloads
        requests_sent = 0
        errors_occurred = 0
        _counter_lock = asyncio.Lock()

        async def _worker(p):
            nonlocal requests_sent, errors_occurred
            async with semaphore:
                if profile.delay > 0:
                    await asyncio.sleep(profile.delay)
                try:
                    async with _counter_lock:
                        requests_sent += 1
                    # Nota: execute() roda em thread para não bloquear o loop de eventos
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(None, self.execute, p)
                    result = self.analyze(p, response)

                    # Evita falsos positivos comparando com a assinatura da baseline
                    if result.success and not baseline_triggered:
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
                    async with _counter_lock:
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
