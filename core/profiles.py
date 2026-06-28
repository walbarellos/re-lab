"""
core/profiles.py — Gerenciador de Perfis de Execução.

Permite configurar a intensidade, timeouts e concorrência do CTFLab
através de perfis YAML, permitindo alternar entre scans rápidos ou furtivos.
"""

import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict
from .logger import logger

@dataclass
class ExecutionProfile:
    name: str
    threads: int = 10
    timeout: float = 5.0
    retries: int = 1
    delay: float = 0.0
    payload_set: str = "standard"  # small, standard, full

class ProfileManager:
    def __init__(self, profiles_dir: str | Path | None = None):
        if profiles_dir is None:
            self.profiles_dir = Path(__file__).parent.parent / "profiles"
        else:
            self.profiles_dir = Path(profiles_dir)
        self.profiles_dir.mkdir(exist_ok=True)
        self.active_profile = ExecutionProfile(name="default")

    def load_profile(self, name: str) -> ExecutionProfile:
        """Carrega um perfil YAML pelo nome."""
        file_path = self.profiles_dir / f"{name}.yaml"
        if not file_path.exists():
            logger.warning(f"Perfil '{name}' não encontrado. Usando defaults.")
            return self.active_profile

        try:
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
                self.active_profile = ExecutionProfile(
                    name=name,
                    threads=data.get("threads", 10),
                    timeout=data.get("timeout", 5.0),
                    retries=data.get("retries", 1),
                    delay=data.get("delay", 0.0),
                    payload_set=data.get("payload_set", "standard")
                )
                logger.info(f"Perfil de execução alterado para: {name.upper()}")
                return self.active_profile
        except Exception as e:
            logger.error(f"Erro ao carregar perfil {name}: {e}")
            return self.active_profile
