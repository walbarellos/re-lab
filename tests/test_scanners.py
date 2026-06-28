import sys
import threading
import time
from pathlib import Path

# 1. Configura o PYTHONPATH dinamicamente para importar o ctflab local
sys.path.insert(0, "/home/walbarellos/Aegis-Arsenal")
sys.path.insert(0, "/home/walbarellos/Aegis-Arsenal/ctflab/tests/vulnerable_apps/flask_app")

# 2. Inicializa o servidor vulnerável real (Flask) em background
from app import app as flask_app

def run_real_server():
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    flask_app.run(host="127.0.0.1", port=18888, debug=False, use_reloader=False)

def main():
    port = 18888
    server_thread = threading.Thread(target=run_real_server, daemon=True)
    server_thread.start()
    print(f"[TEST] Servidor real de alta fidelidade (Flask + SQLite) rodando em http://127.0.0.1:{port}")
    time.sleep(1.0)

    try:
        # 3. Inicializa componentes do CTFLab
        from ctflab.core.session import Session
        from ctflab.core.context import Context
        from ctflab.core.bus import MessageBus
        from ctflab.core.config import ConfigManager
        from ctflab.core.registry import Registry
        from ctflab.domains.detection.ssti_scanner import SSTIScanner
        from ctflab.reports.html import HTMLReportGenerator
        from ctflab.core import http as H

        print("[TEST] Inicializando motores e sessão do CTFLab...")
        session = Session(target=f"http://127.0.0.1:{port}")
        bus = MessageBus()
        config = ConfigManager()
        ctx = Context(session=session, bus=bus, config=config)


        # 4. Valida Fingerprinting e Assinaturas Passivas (Intel Engine)
        print("[TEST] Realizando baseline HTTP GET /...")
        H.get(session, "/")
        print(f"[TEST] Tecnologias detectadas ativamente (Fingerprint): {session._technologies}")
        assert any("Flask" in t for t in session._technologies), "Falha no fingerprint do Flask"

        print("[TEST] Realizando requisição em /wp-content para forçar assinatura passiva...")
        H.get(session, "/wp-content")
        print(f"[TEST] Tecnologias atualizadas com assinaturas passivas: {session._technologies}")
        assert "WordPress" in session._technologies, "Falha na detecção passiva de WordPress"
        
        # Verifica se os caminhos de expansão da stack foram alimentados na wordlist global
        all_eps = session.recall("_all_discovered_endpoints", [])
        print(f"[TEST] Caminhos passivos expandidos na wordlist global: {all_eps}")
        assert any("wp-admin" in ep for ep in all_eps), "Falha na expansão de caminhos passivos da assinatura"

        # 5. Executa SSTIScanner
        print("[TEST] Inicializando SSTIScanner no endpoint /ssti...")
        scanner = SSTIScanner(ctx, path="/ssti", method="GET", param="template")
        vulns = scanner.run()

        print(f"[TEST] Varredura concluída. Vulnerabilidades encontradas: {len(vulns)}")
        for v in vulns:
            print(f"  - [{v.severity}] {v.name} | Payload: {v.payload}")
        
        assert len(vulns) > 0, "Falha na detecção de SSTI pelo SSTIScanner"
        assert len(session.flags) > 0, "Falha na extração automática de flags do corpo da resposta"
        print(f"[TEST] Flags extraídas com sucesso: {session.flags}")

        # 6. Gera Relatório HTML Premium
        print("[TEST] Gerando relatório HTML consolidado...")
        report_gen = HTMLReportGenerator()
        report_path = report_gen.generate(session)
        print(f"[TEST] Relatório HTML salvo com sucesso em: {report_path.resolve()}")
        assert report_path.exists(), "Falha na geração física do relatório HTML"

        # 7. Testa a detecção ativa do WAF
        print("[TEST] Realizando requisição em /waf para disparar o WafDetector...")
        # Desliga o stealth_mode temporariamente para ver se o WafDetector o liga de volta
        session.stealth_mode = False
        H.get(session, "/waf")
        print(f"[TEST] Tecnologias atualizadas com WAF: {session._technologies}")
        assert any("WAF" in t for t in session._technologies), "WAF não foi detectado no _technologies!"
        assert session.stealth_mode is True, "Homeostase adaptativa falhou em ativar o stealth_mode!"

        # 8. Testa o PayloadObfuscator (Evasão WAF)
        print("[TEST] Validando PayloadObfuscator...")
        from ctflab.core.encoder import encode_all_formats
        raw_payload = "UNION SELECT"
        encoded = encode_all_formats(raw_payload)
        assert encoded["SQL Space Bypass"] == "UNION/**/SELECT", "SQL Space Bypass falhou!"
        assert encoded["Base64"] == "VU5JT04gU0VMRUNU", "Base64 encoding falhou!"
        print(f"[TEST] Codificações do PayloadObfuscator validadas com sucesso.")

        # 9. Testa o PortScanner (Recon de Infraestrutura)
        print("[TEST] Inicializando PortScanner...")
        from ctflab.domains.reconnaissance.port_scanner import PortScanner
        ps = PortScanner(ctx)
        # Vamos injetar a porta do mock server para testar sua detecção
        ps.get_payloads = lambda: [80, 443, 18888] 
        findings = ps.run()
        print(f"[TEST] PortScanner executado. Portas abertas encontradas: {len(findings)}")
        found_ports = [v.payload for v in findings]
        assert "18888" in found_ports, "PortScanner falhou em detectar a porta aberta do Mock Target!"
        print(f"[TEST] PortScanner validado com sucesso!")

        # 10. Testa o WafCharFuzzer
        print("[TEST] Inicializando WafCharFuzzer...")
        from ctflab.domains.reconnaissance.waf_char_fuzzer import WafCharFuzzer
        char_fuzzer = WafCharFuzzer(ctx, path="/waf_profile", param="q", method="GET")
        char_findings = char_fuzzer.run()
        print(f"[TEST] WafCharFuzzer executado. Bloqueios encontrados: {len(char_findings)}")
        blocked_chars = [v.payload for v in char_findings]
        # Espera-se que as aspas simples e duplas sejam detectadas como bloqueadas
        assert "'" in blocked_chars, "WafCharFuzzer falhou em identificar aspas simples bloqueadas!"
        print(f"[TEST] WafCharFuzzer validado com sucesso!")

        # 11. Testa o CredentialBruteforcer
        print("[TEST] Inicializando CredentialBruteforcer...")
        from ctflab.domains.exploitation.credential_bruteforcer import CredentialBruteforcer
        bf = CredentialBruteforcer(ctx, path="/login", user_field="username", pass_field="password")
        # Injeta uma credencial válida para teste rápido
        bf.credentials_list = [("user", "user"), ("admin", "admin123"), ("root", "toor")]
        bf_findings = bf.run()
        print(f"[TEST] CredentialBruteforcer executado. Credenciais válidas encontradas: {len(bf_findings)}")
        assert len(bf_findings) > 0, "CredentialBruteforcer falhou em quebrar a autenticação!"
        print(f"[TEST] CredentialBruteforcer validado com sucesso!")

        # 12. Testa o ParamDiscovery
        print("[TEST] Inicializando ParamDiscovery...")
        from ctflab.domains.reconnaissance.param_discovery import ParamDiscovery
        pd = ParamDiscovery(ctx, path="/", method="GET")
        pd_findings = pd.run()
        print(f"[TEST] ParamDiscovery executado. Parâmetros ocultos descobertos: {len(pd_findings)}")
        found_params = [v.payload for v in pd_findings]
        assert "debug" in found_params, "ParamDiscovery falhou em identificar o parâmetro oculto 'debug'!"
        print(f"[TEST] ParamDiscovery validado com sucesso!")

        print("\n" + "="*50)
        print(" 🎉 EXCELENTE! TODOS OS TESTES PASSARAM COM SUCESSO!")
        print("="*50 + "\n")





    except Exception as e:
        print(f"\n[FAIL] Erro durante a execução dos testes: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        pass


if __name__ == "__main__":
    main()
