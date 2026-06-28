"""
plugins/redirect.py — Scanner de Open Redirect e CRLF Injection.
"""

from __future__ import annotations

from rich.console import Console

from ctflab.core import http as H
from ctflab.core.session import Session
from ctflab.cli.ui import askctx, scan_table

PLUGIN_NAME = "Redirect / CRLF"
PLUGIN_DESC = "Testa Open Redirect e CRLF Injection em parâmetros de redirecionamento"

_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "javascript:alert(1)",
    "%0d%0aLocation: https://evil.com",
    "/%0d%0aSet-Cookie: test=1",
]


def run(s: Session, c: Console) -> None:
    path  = askctx(s, "path",        "path",             "/")
    param = askctx(s, "redir_param", "parâmetro alvo",   "next")

    c.print(f"\n[warn]testando {len(_REDIRECT_PAYLOADS)} payloads em {path}?{param}=...[/warn]\n")

    table = scan_table(
        "Redirect / CRLF Scan",
        ["payload", "status", "Location header", "hit?"],
    )

    hits = 0
    with H.make_client(s) as cl:
        for p in _REDIRECT_PAYLOADS:

            try:
                r   = cl.get(path, params={param: p}, follow_redirects=False)
                loc = r.headers.get("Location", "")

                is_redir = "evil.com" in loc or loc.startswith("javascript:")
                is_crlf  = "test=1" in r.headers.get("Set-Cookie", "")
                hit      = is_redir or is_crlf

                if hit:
                    hits += 1
                    s.note(f"Redirect hit: {p} -> {loc}")

                table.add_row(
                    p,
                    str(r.status_code),
                    f"[warn]{loc}[/warn]" if loc else "-",
                    "[ok]SIM[/ok]" if hit else "não",
                )
            except Exception as exc:
                table.add_row(p, "[fail]ERR[/fail]", str(exc)[:30], "-")

    c.print(table)
    if hits:
        c.print(f"\n[ok]{hits} redirect(s) detectado(s)![/ok]")
    else:
        c.print("\n[dim]nenhum redirect óbvio detectado[/dim]")
