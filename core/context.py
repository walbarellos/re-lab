"""
core/context.py — Container de Injeção de Dependência.

Encapsula todas as ferramentas necessárias para a execução de um módulo,
evitando o uso de variáveis globais e facilitando testes unitários.
"""

from dataclasses import dataclass, field
from typing import Any

from .session import Session
from .bus import MessageBus
from .logger import logger
from .config import ConfigManager
from .cache import ResponseCache
from .metrics import MetricsCollector
from .profiles import ProfileManager
from .knowledge import KnowledgeBase
from .attack_graph import AttackGraph
from .correlation import CorrelationEngine

@dataclass
class Context:
    """
    O 'Cérebro' de execução. Injetado em todos os scanners e plugins.
    """
    session: Session
    bus: MessageBus
    config: ConfigManager
    cache: ResponseCache = field(default_factory=ResponseCache)
    metrics: MetricsCollector = field(default_factory=MetricsCollector)
    profiles: ProfileManager = field(default_factory=ProfileManager)
    knowledge: KnowledgeBase = field(default_factory=KnowledgeBase)
    attack_graph: AttackGraph = field(default_factory=AttackGraph)
    correlation: CorrelationEngine = field(default_factory=CorrelationEngine)

    def __post_init__(self):
        # Ponte para o HTTP core acessar o cache sem circular import
        self.session._cache = self.cache # type: ignore
        # Inicializa o perfil default
        self.profiles.load_profile("fast")
    
    def log_info(self, msg: str):
        logger.info(msg)

    def log_warn(self, msg: str):
        logger.warning(msg)

    def log_error(self, msg: str):
        logger.error(msg)

    def log_debug(self, msg: str):
        logger.debug(msg)

    def publish(self, event: Any):
        """Atalho para publicar eventos via barramento."""
        self.bus.publish(event)
