"""
plugins/xss.py — plugin: XSS scanner.
"""

from __future__ import annotations

from rich.console import Console

from ctflab.core import http as H, payloads as P
from ctflab.core.session import Session
from ctflab.cli.ui import ask, askctx, scan_table

PLUGIN_NAME = "XSS Scanner"
PLUGIN_DESC = "Testa payloads de Cross-Site Scripting em parâmetros"


def run(session: Session, console: Console) -> None:
    console.rule("[head]XSS SCANNER (plugin)[/head]")

    path     = askctx(session, "path",  "path",              "/search")
    param    = askctx(session, "param", "parâmetro",         "q")
    use_get  = ask("método (get/post)", "get").lower() == "get"

    payloads = P.load("xss")
    table    = scan_table(
        f"XSS — {len(payloads)} payloads",
        ["payload", "status", "refletido?", "encoding?"],
    )

    hits = 0
    with H._make_client(session) as cl:
        for p in payloads:
            try:
                if use_get:
                    r = cl.get(path, params={param: p})
                else:
                    r = cl.post(path, json={param: p})

                # verifica reflexão direta e codificada (HTMLentities)
                reflected_raw     = p in r.text
                reflected_encoded = (
                    p.replace("<", "&lt;").replace(">", "&gt;") in r.text
                )
                style   = "ok" if reflected_raw else ("warn" if reflected_encoded else "fail")
                hit_str = (
                    "[ok]sim[/ok]"       if reflected_raw
                    else "[warn]encoded[/warn]" if reflected_encoded
                    else "[fail]não[/fail]"
                )
                enc_str = "[warn]sim (escape)[/warn]" if reflected_encoded and not reflected_raw else ""

                if reflected_raw:
                    hits += 1
                    session.note(f"XSS refletido: {p}")
                elif reflected_encoded:
                    session.note(f"XSS refletido (encoded): {p}")

            except Exception as exc:
                style, hit_str, enc_str = "fail", str(exc)[:30], ""

            table.add_row(
                p[:50],
                f"[{style}]{r.status_code if 'r' in dir() else 'ERR'}[/{style}]",
                hit_str,
                enc_str,
            )

    console.print(table)
    if hits:
        console.print(f"\n[ok]{hits} payload(s) refletidos sem encoding![/ok]")
    else:
        console.print("\n[fail]nenhum XSS refletido detectado[/fail]")
