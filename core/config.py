"""
core/config.py — Gerenciador de Configuração Centralizado.

Lê o arquivo ctflab.yaml e fornece acesso estruturado às configurações
do sistema, suportando defaults e sobrescritas.
"""

import yaml
from pathlib import Path
from typing import Any, Dict
from .logger import logger

class ConfigManager:
    def __init__(self, config_path: str = "ctflab.yaml"):
        self.config_path = Path(config_path)
        self.data: Dict[str, Any] = self._load_defaults()
        self.load_config()

    def _load_defaults(self) -> Dict[str, Any]:
        return {
            "timeout": 10.0,
            "retries": 2,
            "threads": 20,
            "ssl_verify": False,
            "reporting": {"format": "html", "output_dir": "reports"},
            "engine": {"auto_discover": True}
        }

    def load_config(self):
        if not self.config_path.exists():
            logger.info("Arquivo ctflab.yaml não encontrado. Usando defaults.")
            return

        try:
            with open(self.config_path, "r") as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    self._merge_dicts(self.data, user_config)
                    logger.info("Configurações carregadas de ctflab.yaml")
        except Exception as e:
            logger.error(f"Erro ao carregar ctflab.yaml: {e}")

    def _merge_dicts(self, base: Dict[str, Any], update: Dict[str, Any]):
        for k, v in update.items():
            if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                self._merge_dicts(base[k], v)
            else:
                base[k] = v

    def get(self, key: str, default: Any = None) -> Any:
        """Retorna valor usando notação de ponto (ex: 'reporting.format')."""
        parts = key.split(".")
        val = self.data
        for part in parts:
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                return default
        return val
