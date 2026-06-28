"""
Verify Integrity v5.2 — Auditoria Rápida de Sincronização.

Valida se o Registry está detectando os domínios e se a infraestrutura
está operando com os novos contratos estritos.
"""

import sys
from pathlib import Path

# Setup do path
_root = Path(__file__).parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

# Tenta importar como 'core' ou 'ctflab.core'
try:
    from core.registry import Registry
    from core.bus import MessageBus
    from core.repository import SQLiteRepository
    from core.context import Context
    from core.session import Session
    from core.config import ConfigManager
except ImportError:
    from ctflab.core.registry import Registry
    from ctflab.core.bus import MessageBus
    from ctflab.core.repository import SQLiteRepository
    from ctflab.core.context import Context
    from ctflab.core.session import Session
    from ctflab.core.config import ConfigManager

def run_audit():
    print("\n" + "="*50)
    print("      AUDITORIA DE INTEGRIDADE CTFLab v5.2")
    print("="*50 + "\n")

    # 1. Teste de Infraestrutura
    print("[1/3] Inicializando Motores Core...")
    try:
        config = ConfigManager()
        bus = MessageBus()
        repo = SQLiteRepository("data/integrity_test.db")
        session = Session(target="http://integrity.test")
        ctx = Context(session=session, bus=bus, config=config)
        print("[OK] Motores Core: OK")
    except Exception as e:
        print(f"[FAIL] Falha no Core: {e}")
        return

    # 2. Teste de Registro e Descoberta
    print("[2/3] Varrendo Domínios (DDD Discovery)...")
    try:
        registry = Registry()
        registry.discover_components()
        scanners = registry.list_scanners()
        
        if not scanners:
            print("[WARN] Nenhum scanner encontrado! Verifique se a pasta 'domains' contém módulos válidos.")
        else:
            print(f"[OK] {len(scanners)} scanners registrados automaticamente:")
            for s in scanners:
                print(f"     - {s}")
    except Exception as e:
        print(f"[FAIL] Falha no Registry: {e}")
        import traceback
        traceback.print_exc()

    # 3. Teste de Persistência
    print("[3/3] Testando Escrita no Banco...")
    try:
        try:
            from core.models import Vulnerability
        except ImportError:
            from ctflab.core.models import Vulnerability
            
        v = Vulnerability(module="integrity_test", name="Audit Vuln", payload="<test>", severity="Info", confidence=1.0)
        session.add_vulnerability(v)
        repo.save_session(session)
        print("[OK] Persistência: OK")
    except Exception as e:
        print(f"[FAIL] Falha na Persistência: {e}")

    print("\n" + "="*50)
    print("      AUDITORIA CONCLUÍDA")
    print("="*50 + "\n")

if __name__ == "__main__":
    run_audit()
