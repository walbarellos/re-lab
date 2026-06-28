"""
core/intelligence.py — Serviço de Captura de Inteligência (v6).

Escuta eventos do barramento e alimenta o KnowledgeBase e o AttackGraph
automaticamente durante a execução.
"""

from .bus import MessageBus
from .events import VulnerabilityFound, EvidenceCreated, FlagCaptured
from .context import Context

class IntelligenceService:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self._setup_subscriptions()

    def _setup_subscriptions(self):
        """Inscreve os handlers no barramento de eventos."""
        self.ctx.bus.subscribe(VulnerabilityFound, self._on_vulnerability_found)
        self.ctx.bus.subscribe(EvidenceCreated, self._on_evidence_created)
        self.ctx.bus.subscribe(FlagCaptured, self._on_flag_captured)

    def _on_vulnerability_found(self, event: VulnerabilityFound):
        v = event.vulnerability
        self.ctx.log_debug(f"Intelligence: Registrando vulnerabilidade no KB: {v.name}")
        self.ctx.knowledge.remember("vulnerability", v.name)
        self.ctx.knowledge.remember(f"vuln_{v.module}", v.payload)
        
        # Conecta no Attack Graph
        self.ctx.attack_graph.add_node(v.module)
        self.ctx.attack_graph.add_edge("target", v.module, "is_vulnerable")

    def _on_evidence_created(self, event: EvidenceCreated):
        e = event.evidence
        self.ctx.log_debug(f"Intelligence: Capturando evidência: {e.module}")
        self.ctx.knowledge.remember("evidence", e.response_snippet)

    def _on_flag_captured(self, event: FlagCaptured):
        self.ctx.log_info(f"Intelligence: FLAG CAPTURADA REGISTRADA NO KB: {event.flag}")
        self.ctx.knowledge.remember("captured_flags", event.flag)
        self.ctx.attack_graph.add_edge("target", "pwned", "flag_captured")
