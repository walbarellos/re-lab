"""
core/registry.py — Registro e Descoberta de Componentes.

Centraliza o catálogo de scanners e plugins disponíveis,
permitindo orquestração dinâmica baseada em capacidades.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
from pathlib import Path
from typing import Any, Type, Dict

from .scanner import BaseScanner
from .logger import logger


class Registry:
    """Gerenciador central de Scanners e Plugins."""

    def __init__(self):
        self.scanners: Dict[str, Type[BaseScanner]] = {}
        self.plugins: Dict[str, Any] = {}

    def register_scanner(self, scanner_cls: Type[BaseScanner]) -> None:
        """Registra um scanner manualmente."""
        self.scanners[scanner_cls.name] = scanner_cls

    def discover_components(self) -> None:
        """
        Varre todos os domínios e carrega scanners automaticamente.
        Garante que o prefixo 'ctflab' seja resolvido corretamente.
        """
        # 1. Garante que o pai da raiz do projeto está no path para resolver 'ctflab'
        core_dir = Path(__file__).parent.resolve()
        project_root = core_dir.parent
        parent_dir = project_root.parent
        
        if str(parent_dir) not in sys.path:
            sys.path.insert(0, str(parent_dir))

        # 2. Tenta importar o pacote de domínios (estritamente via ctflab prefix)
        try:
            import ctflab.domains as domains_pkg
        except ImportError:
            logger.warning("Pacote 'ctflab.domains' não encontrado — discovery ignorado.")
            return

        # 3. Discovery recursivo
        logger.info(f"Iniciando discovery em: {domains_pkg.__path__} ({domains_pkg.__name__})")
        for loader, module_name, is_pkg in pkgutil.walk_packages(
            domains_pkg.__path__, domains_pkg.__name__ + "."
        ):
            logger.info(f"Encontrado: {module_name} (pkg={is_pkg})")
            if is_pkg:
                continue
            try:
                module = importlib.import_module(module_name)
                for name, obj in inspect.getmembers(module):
                    # Compara nomes das classes para evitar falhas de identidade por import path
                    if (
                        inspect.isclass(obj)
                        and any(base.__name__ == "BaseScanner" for base in inspect.getmro(obj))
                        and obj.__name__ != "BaseScanner"
                    ):
                        self.register_scanner(obj)
                        logger.info(f"Scanner registrado: {obj.name} ({module_name})")
            except Exception as e:
                logger.error(f"Falha ao carregar {module_name}: {e}")

    def get_scanner(self, name: str) -> Type[BaseScanner] | None:
        return self.scanners.get(name)

    def list_scanners(self) -> list[str]:
        return list(self.scanners.keys())

    def get_by_capability(self, capability: str) -> list[Type[BaseScanner]]:
        return [s for s in self.scanners.values() if capability in s.capabilities]
