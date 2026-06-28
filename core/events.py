"""
core/events.py — Catálogo de Eventos do Sistema.

Define os sinais que os componentes emitem durante a execução.
"""

from dataclasses import dataclass
from typing import Any
from .models import Vulnerability, Evidence, Target

@dataclass
class Event:
    """Classe base para todos os eventos."""
    pass

@dataclass
class TargetDiscovered(Event):
    target: Target

@dataclass
class VulnerabilityFound(Event):
    vulnerability: Vulnerability

@dataclass
class EvidenceCreated(Event):
    evidence: Evidence

@dataclass
class ScanStarted(Event):
    module_name: str

@dataclass
class ScanFinished(Event):
    module_name: str
    findings_count: int

@dataclass
class FlagCaptured(Event):
    flag: str
