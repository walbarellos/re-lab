"""
core/fingerprint.py — Engine de Identificação de Stack.

Identifica tecnologias, frameworks e linguagens do alvo para
direcionar os scanners com precisão.
"""

from typing import Dict
import httpx
from .models import Target
from .logger import logger

class Fingerprinter:
    """
    Analisa headers e corpos de resposta para deduzir o 'TargetProfile'.
    """
    
    # Assinaturas comuns (Header -> Valor parcial -> Tecnologia)
    _HEADER_SIGS = {
        "server": {
            "Werkzeug": "Flask",
            "gunicorn": "Python/WSGI",
            "Apache": "Apache",
            "nginx": "Nginx",
            "Microsoft-IIS": "ASP.NET",
        },
        "x-powered-by": {
            "Express": "Node.js/Express",
            "PHP": "PHP",
            "Servlet": "Java/JEE",
        }
    }

    def analyze(self, response: httpx.Response, target: Target) -> Target:
        """Extrai tecnologias da resposta HTTP."""
        headers = response.headers
        
        # 1. Analisa Headers
        for header, sigs in self._HEADER_SIGS.items():
            val = headers.get(header, "")
            for pattern, tech in sigs.items():
                if pattern.lower() in val.lower():
                    if tech not in target.technologies:
                        target.technologies.append(tech)
                        logger.info(f"Tecnologia detectada via Header [{header}]: {tech}")

        # 2. Analisa Cookies (ex: session=Flask, PHPSESSID=PHP)
        cookies = response.cookies
        if "PHPSESSID" in cookies and "PHP" not in target.technologies:
            target.technologies.append("PHP")
            logger.info("Tecnologia detectada via Cookie: PHP")
        if "session" in cookies and "Flask" not in target.technologies:
            # Heurística fraca, mas comum em CTF
            target.technologies.append("Python/Flask")

        return target
