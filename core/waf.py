"""
core/waf.py — Detector de Web Application Firewall (WAF) e Evasão Adaptativa.

Identifica se as requisições estão sendo inspecionadas ou bloqueadas por WAFs
conhecidos e reconfigura as políticas de homeostase da sessão em tempo real.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from .logger import logger

if TYPE_CHECKING:
    from .session import Session

# Assinaturas comuns de WAFs baseados em headers e keywords no corpo de erro
_WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
        "body": [r"cloudflare", r"cloudflare-nginx", r"cf-browser-verification"],
    },
    "AWS WAF / Shield": {
        "headers": ["x-amz-cf-id", "x-amzn-requestid", "x-amzn-waf-action"],
        "body": [r"aws-waf", r"awselb"],
    },
    "ModSecurity / OWASP CRS": {
        "headers": ["x-denied-by-modsecurity", "server-y"],
        "body": [r"modsecurity", r"blocked by mod_security", r"owasp_crs", r"mod_security"],
    },
    "Sucuri CloudProxy": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body": [r"sucuri", r"cloudproxy", r"block.sucuri-id"],
    },
    "Incapsula / Imperva": {
        "headers": ["x-iinfo", "x-cdn", "visid_incap"],
        "body": [r"incapsula", r"visid_incap", r"imperva"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-http-error", "x-true-client-ip"],
        "body": [r"akamai", r"akamaigghost"],
    }
}

class WafDetector:
    @staticmethod
    def detect_and_adapt(session: Session, response_text: str, status_code: int, headers: dict) -> str | None:
        """
        Analisa a resposta HTTP em busca de WAFs e ajusta o mimetismo de rede.
        """
        detected_waf = None

        # 1. Analisa assinaturas em chaves e valores dos Headers
        headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
        for waf_name, sigs in _WAF_SIGNATURES.items():
            for h_pattern in sigs["headers"]:
                if h_pattern in headers_lower:
                    detected_waf = waf_name
                    break
                # Verifica se o padrão está presente no valor de algum cabeçalho
                for v in headers_lower.values():
                    if h_pattern in v:
                        detected_waf = waf_name
                        break
            if detected_waf:
                break

        # 2. Analisa o corpo da resposta em caso de bloqueio (403, 406, 429)
        if not detected_waf and status_code in (403, 406, 429) and response_text:
            body_lower = response_text.lower()
            for waf_name, sigs in _WAF_SIGNATURES.items():
                for b_pattern in sigs["body"]:
                    if re.search(b_pattern, body_lower):
                        detected_waf = waf_name
                        break
                if detected_waf:
                    break

        # 3. Homeostase Adaptativa se WAF for detectado
        if detected_waf:
            already_warned = session.recall(f"waf_warned_{detected_waf}", "")
            if not already_warned:
                session.remember(f"waf_warned_{detected_waf}", "1")
                session.note(f"WAF DETECTADO: {detected_waf}. Ativando Homeostase Adaptativa.")
                logger.warning(f"WafDetector: Alvo protegido por WAF '{detected_waf}'!")

                # Ativa o modo stealth para introduzir delays automáticos entre requisições
                session.stealth_mode = True

                # Adiciona o WAF à lista de tecnologias da sessão
                waf_label = f"WAF ({detected_waf})"
                if waf_label not in session._technologies:
                    session._technologies.append(waf_label)

        return detected_waf
