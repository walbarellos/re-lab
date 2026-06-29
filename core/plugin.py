"""
core/plugin.py — loader de plugins dinâmicos.

Todo plugin é um módulo Python em plugins/ que expõe:

    PLUGIN_NAME: str          # nome exibido no menu
    PLUGIN_DESC: str          # descrição curta
    run(session, console)     # função principal

O loader varre plugins/ em runtime — sem registro manual.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Protocol, runtime_checkable

from rich.console import Console

from .bus import MessageBus
from .session import Session

_PLUGIN_DIR = Path(__file__).parent.parent / "plugins"


@runtime_checkable
class PluginProtocol(Protocol):
    PLUGIN_NAME: str
    PLUGIN_DESC: str

    def run(self, session: Session, console: Console) -> None: ...


@dataclass
class PluginCrashEvent:
    plugin_name: str
    error: str


def _load_module(path: Path) -> ModuleType | None:
    """Carrega um arquivo .py como módulo sem instalação."""
    try:
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[f"ctflab_plugin_{path.stem}"] = mod
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception as e:
        import logging
        logging.getLogger("ctflab.plugins").warning(f"Falha ao carregar plugin '{path.name}': {e}")
        return None


def discover() -> list[ModuleType]:
    """Retorna lista de módulos plugin válidos encontrados em plugins/."""
    plugins: list[ModuleType] = []
    if not _PLUGIN_DIR.exists():
        return plugins

    for pyfile in sorted(_PLUGIN_DIR.glob("*.py")):
        if pyfile.name.startswith("_"):
            continue
        mod = _load_module(pyfile)
        if mod is None:
            continue
        if (
            hasattr(mod, "PLUGIN_NAME")
            and hasattr(mod, "PLUGIN_DESC")
            and hasattr(mod, "run")
            and callable(mod.run)
        ):
            plugins.append(mod)

    return plugins


def run_plugin_safely(
    plugin: ModuleType,
    session: Session,
    console: Console,
    bus: MessageBus | None = None,
) -> None:
    """
    Executa um plugin dentro de uma sandbox — erros internos não
    derrubam o orquestrador.
    """
    name = getattr(plugin, "PLUGIN_NAME", "Unknown")
    try:
        plugin.run(session, console)
    except Exception as e:
        error_msg = f"Plugin {name} falhou: {e}"
        console.print(f"[fail]{error_msg}[/fail]")
        if bus:
            bus.publish(PluginCrashEvent(plugin_name=name, error=str(e)))
