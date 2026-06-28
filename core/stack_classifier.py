"""
core/stack_classifier.py — Classificador de Tecnologias baseado em Assinaturas.

Analisa a base de conhecimento e os endpoints descobertos para
identificar CMSs e frameworks específicos.
"""

from pathlib import Path
import yaml
from typing import List, Dict, Any
from .logger import logger

class StackClassifier:
    """
    Carrega assinaturas YAML e as confronta com o contexto da sessão.
    """
    _DEFAULT_SIGS_DIR = Path(__file__).parent.parent / "knowledge" / "signatures"

    def __init__(self, sigs_dir: str | None = None):
        self.sigs_dir = Path(sigs_dir) if sigs_dir else self._DEFAULT_SIGS_DIR
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> List[Dict[str, Any]]:
        sigs = []
        for file in self.sigs_dir.glob("*.yaml"):
            try:
                with open(file, "r") as f:
                    sigs.append(yaml.safe_load(f))
            except Exception as e:
                logger.error(f"Erro ao carregar assinatura {file}: {e}")
        return sigs

    def identify_stacks(self, session_ctx: Dict[str, Any], discovered_endpoints: List[str]) -> List[Dict[str, Any]]:
        """
        Retorna as stacks identificadas que possuem expansões de wordlist.
        """
        hits = []
        for sig in self.signatures:
            matched = False
            
            # 1. Match por caminhos descobertos
            for p in discovered_endpoints:
                if any(match_path in p for match_path in sig.get("match", {}).get("paths", [])):
                    matched = True
                    break
            
            # 2. Match por headers (Se implementado no ctx)
            if not matched:
                for match_h in sig.get("match", {}).get("headers", []):
                    # Verifica nas chaves do ctx que guardam headers interessantes
                    if any(match_h.lower() in str(v).lower() for v in session_ctx.values()):
                        matched = True
                        break
            
            if matched:
                hits.append(sig)
                logger.info(f"Sherlock Engine: Stack '{sig['name']}' identificada via DNA de caminhos.")
        
        return hits
