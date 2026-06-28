"""
modules/fuzz.py — Módulo de Fuzzing de Parâmetros.

Descobre campos escondidos (GET params ou JSON keys) que não estão
documentados nos endpoints principais.
"""

from __future__ import annotations

import asyncio
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from ctflab.core import http as H, payloads as P
from ctflab.core.session import Session
from ctflab.cli.menu import run_menu
from ctflab.cli.ui import ask, askctx, scan_table

async def _gather_param_fuzz(
    session: Session,
    path: str,
    wordlist: list[str],
    mode: str = "get"
) -> list[tuple[str, int, int, str]]:
    """Executa o fuzzing de forma assíncrona."""
    results = []
    
    async with H.make_async_client(session) as c:
        tasks = []
        for param in wordlist:
            # Valor de teste único para detectar reflexão ou mudança de comportamento
            test_val = "fuzz_test_1337"
            if mode == "get":
                tasks.append(c.get(path, params={param: test_val}))
            else:
                tasks.append(c.post(path, json={param: test_val}))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    for param, r in zip(wordlist, responses):
        if isinstance(r, Exception):
            continue
        results.append((param, r.status_code, len(r.content), r.text[:50]))
    
    return results

def _param_fuzz(s: Session, c: Console) -> None:
    c.rule("[head]PARAMETER FUZZER[/head]")
    c.print("[dim]Procura por parâmetros ocultos (ex: debug, admin, dev, source).[/dim]\n")

    path = askctx(s, "path", "path para testar", "/")
    mode = ask("modo (get/json)", "get").lower()
    
    # Carrega wordlist de parâmetros (se não existir, usa uma base)
    params_to_test = P.load("params")
    if not params_to_test:
        params_to_test = ["debug", "admin", "test", "dev", "source", "config", "root", "shell", "exec", "cmd"]

    # Tira baseline
    c.print("[dim]tirando baseline com request limpo...[/dim]")
    try:
        r_base = H.get(s, path) if mode == "get" else H.post(s, path, json={})
        base_len = len(r_base.content)
        base_code = r_base.status_code
    except Exception:
        base_len, base_code = 0, 0

    c.print(f"[dim]baseline: {base_code} ({base_len} bytes) | testando {len(params_to_test)} nomes...[/dim]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=c,
    ) as progress:
        task = progress.add_task("fuzzing...", total=1)
        results = asyncio.run(_gather_param_fuzz(s, path, params_to_test, mode))
        progress.update(task, advance=1)

    table = scan_table("Resultados do Fuzzing", ["parâmetro", "status", "Δsize", "hit?", "snippet"])
    
    hits = 0
    for param, code, size, text in results:
        diff = size - base_len
        # Um hit é definido por mudança de status ou mudança significativa no tamanho
        is_hit = code != base_code or abs(diff) > 20
        
        if is_hit:
            hits += 1
            style = "ok"
            hit_str = "[ok]SIM[/ok]"
            s.note(f"Hidden param found: {param} ({mode}) at {path}")
            s.remember("hidden_param", param)
        else:
            style = "dim"
            hit_str = "-"

        if is_hit or code == 200:
            table.add_row(
                param,
                f"[{style}]{code}[/{style}]",
                f"{diff:+d}",
                hit_str,
                text.replace("\n", " ")
            )

    c.print(table)
    if hits:
        c.print(f"\n[ok]{hits} parâmetro(s) suspeito(s) encontrado(s)![/ok]")
    else:
        c.print("\n[dim]nenhum parâmetro oculto óbvio detectado.[/dim]")

_OPTIONS = {
    "1": ("fuzzing de parâmetros", _param_fuzz),
    "0": ("voltar",               None),
}

def run(session: Session, console: Console) -> None:
    run_menu("FUZZING", _OPTIONS, session, console)
