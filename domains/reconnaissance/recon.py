"""modules/recon.py"""

from __future__ import annotations

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from ctflab.core import http as H
from ctflab.core import payloads as P
from ctflab.core.session import Session
from ctflab.cli.menu import run_menu
from ctflab.cli.ui import (ask, ask_params, askctx, ask_json_interactive,
                            scan_table, show_response)

_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def _get_root(s: Session, c: Console) -> None:
    r = H.get(s, "/")
    show_response(r, s.history[-1].elapsed, s)


def _get_custom(s: Session, c: Console) -> None:
    path   = askctx(s, "path", "path", "/")
    params = ask_params()
    r      = H.get(s, path, params or None)
    show_response(r, s.history[-1].elapsed, s)


def _post_json(s: Session, c: Console) -> None:
    path    = askctx(s, "path", "path", "/")
    c.print("  [info]1[/info]. Construtor interativo (campo a campo)")
    c.print("  [info]2[/info]. Raw body (colar JSON completo ou string)")
    choice = ask("opção", "1")
    
    if choice == "1":
        payload = ask_json_interactive(c)
    else:
        from ctflab.cli.ui import ask_json
        payload = ask_json("body (JSON ou raw)")
        
    if payload is not None:
        r = H.post(s, path, payload)
        show_response(r, s.history[-1].elapsed, s)


def _post_form(s: Session, c: Console) -> None:
    path   = askctx(s, "path", "path", "/")
    params = ask_params("campos (ex: user=admin&pass=123)")
    r      = H.post(s, path, params, form=True)
    show_response(r, s.history[-1].elapsed, s)


def _custom_method(s: Session, c: Console) -> None:
    """Requisição com método HTTP arbitrário — GET/POST/PUT/PATCH/DELETE."""
    for i, m in enumerate(_HTTP_METHODS, 1):
        c.print(f"  [info]{i}[/info]. {m}")
    choice = ask("método (número ou nome)", "GET").upper()

    # aceita número ou nome direto
    if choice.isdigit():
        idx = int(choice) - 1
        method = _HTTP_METHODS[idx] if 0 <= idx < len(_HTTP_METHODS) else "GET"
    elif choice in _HTTP_METHODS:
        method = choice
    else:
        c.print("[fail]método inválido[/fail]")
        return

    path = askctx(s, "path", "path", "/")

    payload = None
    if method in ("POST", "PUT", "PATCH"):
        payload = ask_json_interactive(c)

    params = None
    if method == "GET":
        params = ask_params() or None

    r = H.request(s, method, path, payload=payload, params=params)
    show_response(r, s.history[-1].elapsed, s)


def _fuzz_dirs(s: Session, c: Console) -> None:
    wordlist  = P.load("paths")
    extra_raw = ask("wordlist extra separada por vírgula (enter = pular)", "")
    if extra_raw:
        for p in extra_raw.split(","):
            p = p.strip()
            if p and p not in wordlist:
                wordlist.append(p)

    c.print(f"\n[warn]preparando {len(wordlist)} requisições assíncronas...[/warn]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=c,
    ) as progress:
        task        = progress.add_task("fuzzing caminhos", total=1)
        results_raw = H.fuzz(s, wordlist)
        progress.update(task, advance=1, description="concluído")

    table = scan_table(
        "Directory Fuzzing Results",
        ["path", "status", "tamanho", "snippet"],
    )

    hits = 0
    for path, code, size, text in results_raw:
        snippet = text.replace("\n", " ")
        style = (
            "ok"   if code == 200 else
            "warn" if code in (301, 302, 307) else
            "info" if code == 403 else
            "fail" if code == 500 else "dim"
        )
        table.add_row(path, f"[{style}]{code}[/{style}]", str(size), snippet)
        hits += 1
        s.note(f"dir [{code}]: {path}")
        if code == 200:
            s.remember("path", path)

    c.print(table)
    c.print(f"\n[ok]{hits} caminho(s) interessante(s)[/ok]")


def _headers_inspect(s: Session, c: Console) -> None:
    path = askctx(s, "path", "path", "/")
    r    = H.get(s, path)

    c.print(f"\n[info]Headers de {path}:[/info]")
    for k, v in r.headers.items():
        c.print(f"  [warn]{k}[/warn]: {v}")

    server  = r.headers.get("server", "")
    powered = r.headers.get("x-powered-by", "")
    if server:
        c.print(f"\n[info]Stack detectado:[/info] [ok]{server}[/ok]")
    if powered:
        c.print(f"[info]Powered by:[/info] [ok]{powered}[/ok]")
    c.print()


_OPTIONS = {
    "1": ("GET / — explorar endpoints",    _get_root),
    "2": ("GET customizado",               _get_custom),
    "3": ("POST com JSON",                 _post_json),
    "4": ("POST como form-data",           _post_form),
    "5": ("qualquer método (PUT/PATCH/…)", _custom_method),
    "6": ("fuzz de diretórios",            _fuzz_dirs),
    "7": ("inspecionar headers",           _headers_inspect),
    "0": ("voltar",                        None),
}


def run(session: Session, console: Console) -> None:
    run_menu("RECONHECIMENTO", _OPTIONS, session, console)
