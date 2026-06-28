"""
core/metrics.py — Coletor de Métricas de Performance.

Monitora a eficiência metabólica da ferramenta (tempo, sucesso, volume de dados).
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class ModuleMetrics:
    start_time: float
    end_time: float = 0.0
    requests_count: int = 0
    findings_count: int = 0
    errors_count: int = 0

    @property
    def duration(self) -> float:
        return round(self.end_time - self.start_time, 3)

class MetricsCollector:
    def __init__(self):
        self.modules: Dict[str, ModuleMetrics] = {}
        self.global_start = time.perf_counter()

    def start_module(self, name: str):
        self.modules[name] = ModuleMetrics(start_time=time.perf_counter())

    def stop_module(self, name: str, findings: int = 0, requests: int = 0, errors: int = 0):
        if name in self.modules:
            m = self.modules[name]
            m.end_time = time.perf_counter()
            m.findings_count = findings
            m.requests_count = requests
            m.errors_count = errors

    def get_summary(self) -> dict:
        total_requests = sum(m.requests_count for m in self.modules.values())
        total_findings = sum(m.findings_count for m in self.modules.values())
        total_duration = round(time.perf_counter() - self.global_start, 3)
        
        return {
            "total_requests": total_requests,
            "total_findings": total_findings,
            "duration_seconds": total_duration,
            "modules_executed": list(self.modules.keys())
        }
