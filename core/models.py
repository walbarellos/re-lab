"""
core/models.py — Entidades de Domínio (DDD).

Contratos estritos para substituir o uso de dicionários genéricos,
garantindo type safety e previsibilidade estrutural.
"""

from dataclasses import dataclass, field
from typing import Any

@dataclass
class Target:
    base_url: str
    technologies: list[str] = field(default_factory=list)
    endpoints: list[str]    = field(default_factory=list)
    parameters: list[str]   = field(default_factory=list)

@dataclass
class Evidence:
    module: str
    payload: str
    status: int
    response_snippet: str
    confidence: float

@dataclass
class Finding:
    severity: str
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)

@dataclass
class Vulnerability(Finding):
    module: str = ""
    name: str = ""
    payload: str = ""

@dataclass
class ScanResult:
    success: bool
    confidence: float
    details: str
    severity: str = "Medium"
