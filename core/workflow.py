"""
core/workflow.py — Motor de Workflows e Orquestração.

Permite a execução automatizada de cadeias de scanners baseada em 
arquivos YAML, resolvendo dependências entre domínios.
"""

import yaml
from pathlib import Path
from typing import List, Dict, Any
from .logger import logger
from .registry import Registry
from .context import Context

class WorkflowEngine:
    """
    Orquestra a execução de múltiplos scanners em sequência lógica.
    """
    def __init__(self, context: Context, registry: Registry):
        self.ctx = context
        self.registry = registry
        self.workflows_dir = Path("workflows")
        self.workflows_dir.mkdir(exist_ok=True)

    def run_workflow(self, workflow_name: str):
        """Carrega e executa um workflow pelo nome."""
        file_path = self.workflows_dir / f"{workflow_name}.yaml"
        if not file_path.exists():
            logger.error(f"Workflow '{workflow_name}' não encontrado.")
            return

        try:
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
                steps = data.get("steps", [])
                logger.info(f"Iniciando Workflow: {data.get('name', workflow_name)}")

                # 🧠 ORQUESTRAÇÃO INTELIGENTE: Ordena por dependência de domínio
                steps_tuples = [(s.get("scanner"), s.get("params", {})) for s in steps]
                steps_tuples = DependencyResolver.sort_by_dependency(steps_tuples)

                for scanner_name, params in steps_tuples:
                    scanner_cls = self.registry.get_scanner(scanner_name)
                    if not scanner_cls:
                        logger.warning(f"Scanner '{scanner_name}' não registrado. Pulando passo.")
                        continue

                    logger.info(f"Executando Passo: {scanner_name}")
                    # Instancia o scanner com o contexto e parâmetros dinâmicos
                    scanner = scanner_cls(self.ctx, **params)
                    scanner.run()

                logger.info("Workflow concluído com sucesso.")
                
        except Exception as e:
            logger.error(f"Falha na execução do workflow: {e}")

class DependencyResolver:
    """
    Garante que os scanners rodem na ordem logica de um pentest:
    Reconnaissance -> Detection -> Exploitation -> Reporting

    Dois mecanismos (mais especifico primeiro):
      1. SCANNER_PRIORITY -- mapa exato pelo nome registrado no Registry
      2. DOMAIN_PRIORITY  -- fallback por prefixo de dominio no nome
    """

    SCANNER_PRIORITY: dict = {
        # reconnaissance (0)
        "reconnaissance_fuzzer": 0,
        "recon": 0,
        "fuzzer": 0,
        "fuzz": 0,
        # detection (1)
        "sqli_detection": 1,
        "header_injection": 1,
        "sqli_scanner": 1,
        "idor": 1,
        "traversal": 1,
        "xss": 1,
        # exploitation (2)
        "forge": 2,
        "race": 2,
        # reporting (3)
        "report": 3,
        "reporter": 3,
    }

    DOMAIN_PRIORITY: dict = {
        "reconnaissance": 0,
        "detection": 1,
        "exploitation": 2,
        "reporting": 3,
    }

    @staticmethod
    def sort_by_dependency(scanners_to_run):
        def get_priority(scanner_tuple):
            name = scanner_tuple[0]
            # 1. lookup exato
            if name in DependencyResolver.SCANNER_PRIORITY:
                return DependencyResolver.SCANNER_PRIORITY[name]
            # 2. fallback por prefixo/substring de dominio
            for domain, priority in DependencyResolver.DOMAIN_PRIORITY.items():
                if name.startswith(domain) or domain in name:
                    return priority
            return 99  # desconhecido -- roda por ultimo

        return sorted(scanners_to_run, key=get_priority)
