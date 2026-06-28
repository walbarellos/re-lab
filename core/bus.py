"""
core/bus.py — Barramento de Eventos (Message Bus).

Implementa o padrão Pub/Sub para desacoplar os módulos.
Permite que um scanner publique uma descoberta e outros componentes
(relatórios, dashboards, logs) reajam sem conhecimento mútuo.
"""

from typing import Any, Callable, Type, TypeVar

T = TypeVar("T")

class MessageBus:
    """
    Sistema simples de publicação e subscrição de eventos.
    """
    def __init__(self):
        self._subscribers: dict[Type, list[Callable]] = {}

    def subscribe(self, event_type: Type[T], handler: Callable[[T], None]):
        """Inscreve um handler para um tipo específico de evento."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

    def publish(self, event: Any):
        """Publica um evento para todos os inscritos interessados."""
        event_type = type(event)
        handlers = self._subscribers.get(event_type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                # Log de erro silencioso para não interromper o fluxo principal
                print(f"[fail] Erro no handler de evento {event_type.__name__}: {e}")
