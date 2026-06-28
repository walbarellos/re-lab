"""
cli/menu.py — decorator e runner de menus.

Elimina o padrão repetido:
    mostrar opções → ler input → despachar → tratar erro

Uso:

    @menu("NOME DO MÓDULO", {
        "1": ("descrição", handler_func),
        ...
    })
    def mod_sqli(session, console): ...

Ou manual via `run_menu(...)`.
"""

from __future__ import annotations

from typing import Any, Callable

from rich.console import Console
from rich.table import Table

from ctflab.core.session import Session
from .ui import ask, console as default_console

Handler = Callable[[Session, Console], None]
OptionMap = dict[str, tuple[str, Handler | None]]


def run_menu(
    title: str,
    options: OptionMap,
    session: Session,
    con: Console | None = None,
) -> None:
    """
    Exibe menu e despacha para o handler correto em um loop contínuo.
    O loop só termina quando o handler da opção for None (geralmente opção "0").
    """
    c = con or default_console

    while True:
        if title:
            c.rule(f"[head]{title}[/head]")

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="info")
        table.add_column()
        for key, (desc, _) in options.items():
            table.add_row(key, desc)
        c.print(table)
        c.print()

        op = ask("opção")
        entry = options.get(op)

        if entry is None:
            c.print("[fail]opção inválida[/fail]")
            continue

        desc, handler = entry
        if handler is None:
            return   # sair do loop / voltar

        try:
            handler(session, c)
        except KeyboardInterrupt:
            c.print("\n[warn]interrompido[/warn]")
        except Exception as exc:
            c.print(f"[fail]erro: {exc}[/fail]")
