"""
core/payloads.py — Gerenciador de Armamento (YAML).

Carrega e gerencia payloads de arquivos YAML, permitindo a atualização
do arsenal sem modificação de código.
"""

import yaml
from pathlib import Path
from typing import Any, Dict, List
from .logger import logger

class PayloadManager:
    """
    Centraliza o carregamento de payloads estruturados.
    """
    def __init__(self, root_dir: str | Path | None = None):
        if root_dir is None:
            self.root_dir = Path(__file__).parent.parent / "payloads"
        else:
            self.root_dir = Path(root_dir)
        self.root_dir.mkdir(exist_ok=True)

    def load(self, category: str) -> List[str]:
        """
        Carrega payloads de um arquivo .yaml ou retorna lista vazia.
        Busca em payloads/<category>.yaml
        """
        file_path = self.root_dir / f"{category}.yaml"
        if not file_path.exists():
            logger.warning(f"Wordlist {category} não encontrada em {file_path}")
            return []

        try:
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict) and "payloads" in data:
                    return data["payloads"]
                if isinstance(data, list):
                    return data
                return []
        except Exception as e:
            logger.error(f"Erro ao carregar payloads de {file_path}: {e}")
            return []

    def save(self, category: str, payloads: List[str]):
        """Salva ou atualiza uma lista de payloads."""
        file_path = self.root_dir / f"{category}.yaml"
        with open(file_path, "w") as f:
            yaml.dump({"payloads": payloads}, f)


# ── shims de nível de módulo para retrocompatibilidade ────────

_mgr = PayloadManager()

def load(category: str) -> list[str]:
    return _mgr.load(category)

def save(category: str, payloads: list[str]) -> None:
    _mgr.save(category, payloads)

def list_available() -> list[str]:
    """Lista categorias disponíveis (nomes dos arquivos yaml)."""
    return [f.stem for f in _mgr.root_dir.glob("*.yaml")]
