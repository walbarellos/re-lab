"""modules/utils.py"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import urllib.parse

from rich.console import Console

from ctflab.core.session import Session
from ctflab.cli.menu import run_menu
from ctflab.cli.ui import ask, history_table


# ── handlers ──────────────────────────────────────────────────

def _history(s: Session, c: Console) -> None:
    if not s.history:
        c.print("[dim]nenhuma requisição ainda[/dim]")
        return
    c.print(history_table(s))


def _notes(s: Session, c: Console) -> None:
    if not s.notes:
        c.print("[dim]nenhuma nota[/dim]")
        return
    for note in s.notes:
        c.print(f"  [warn]{note}[/warn]")


def _flags(s: Session, c: Console) -> None:
    if not s.flags:
        c.print("[dim]nenhuma flag capturada[/dim]")
        return
    for f in s.flags:
        c.print(f"  [flag] {f} [/flag]")


def _ctx(s: Session, c: Console) -> None:
    """Exibe todo o contexto salvo na sessão — útil para ver o que o intel captou."""
    if not s.ctx:
        c.print("[dim]contexto vazio[/dim]")
        return
    c.print("\n[info]contexto da sessão:[/info]")
    for k, v in s.ctx.items():
        c.print(f"  [warn]{k}[/warn]: {v}")
    c.print()


def _hashes(s: Session, c: Console) -> None:
    text = ask("texto")
    c.print(f"\n  [info]MD5[/info]    {hashlib.md5(text.encode()).hexdigest()}")
    c.print(f"  [info]SHA1[/info]   {hashlib.sha1(text.encode()).hexdigest()}")
    c.print(f"  [info]SHA256[/info] {hashlib.sha256(text.encode()).hexdigest()}")
    c.print(f"  [info]SHA512[/info] {hashlib.sha512(text.encode()).hexdigest()}")


def _md5_crack(s: Session, c: Console) -> None:
    target        = ask("hash MD5 alvo")
    wordlist_path = ask("wordlist (enter = senhas comuns)", "")

    if wordlist_path:
        from pathlib import Path
        try:
            words = Path(wordlist_path).read_text().splitlines()
        except Exception as exc:
            c.print(f"[fail]{exc}[/fail]")
            return
    else:
        from ctflab.core import payloads as P
        words = P.load("passwords")

    c.print(f"\n[warn]testando {len(words)} entradas...[/warn]")
    for word in words:
        if hashlib.md5(word.strip().encode()).hexdigest() == target:
            c.print(f"\n[ok]encontrado: {word.strip()}[/ok]")
            s.note(f"MD5 quebrado: {target} = {word.strip()}")
            return
    c.print("[fail]não encontrado[/fail]")


def _url_codec(s: Session, c: Console) -> None:
    mode = ask("(e)ncode ou (d)ecode", "e")
    text = ask("texto")
    if mode.startswith("e"):
        c.print(f"\n[ok]{urllib.parse.quote(text, safe='')}[/ok]")
    else:
        c.print(f"\n[ok]{urllib.parse.unquote(text)}[/ok]")


def _magic_decode(s: Session, c: Console) -> None:
    """
    Decodificador mágico — tenta múltiplos esquemas em cascata.

    Útil para strings encodadas em camadas (muito comum em CTF).
    Tenta: Base64, Hex, ROT13, URL, Binary, HTML entities, Morse.
    """
    text     = ask("texto para decodar")
    attempts = []

    # Base64
    for pad in ("", "=", "=="):
        try:
            dec = base64.b64decode(text + pad).decode("utf-8")
            attempts.append(("BASE64", dec))
            break
        except Exception:
            pass

    # Base64 URL-safe
    for pad in ("", "=", "=="):
        try:
            dec = base64.urlsafe_b64decode(text + pad).decode("utf-8")
            if dec not in [a[1] for a in attempts]:
                attempts.append(("BASE64url", dec))
            break
        except Exception:
            pass

    # Hex
    try:
        attempts.append(("HEX", bytes.fromhex(text).decode("utf-8")))
    except Exception:
        pass

    # ROT13
    try:
        attempts.append(("ROT13", codecs.decode(text, "rot_13")))
    except Exception:
        pass

    # URL decode
    decoded_url = urllib.parse.unquote(text)
    if decoded_url != text:
        attempts.append(("URL", decoded_url))

    # HTML entities
    try:
        import html
        decoded_html = html.unescape(text)
        if decoded_html != text:
            attempts.append(("HTML entities", decoded_html))
    except Exception:
        pass

    # Binary (espaços entre bytes)
    try:
        if all(c in "01 " for c in text) and " " in text:
            attempts.append(("BINARY", "".join(
                chr(int(b, 2)) for b in text.split()
            )))
    except Exception:
        pass

    # Octal
    try:
        parts = text.split()
        if all(all(c in "01234567" for c in p) for p in parts) and len(parts) > 1:
            attempts.append(("OCTAL", "".join(chr(int(b, 8)) for b in parts)))
    except Exception:
        pass

    if not attempts:
        c.print("[fail]nenhuma decodificação reconhecida[/fail]")
        return

    c.print(f"\n[info]{len(attempts)} decodificação(ões) encontrada(s):[/info]")
    for name, result in attempts:
        c.print(f"  [warn]{name:15s}[/warn] [ok]{result}[/ok]")

    if len(attempts) == 1:
        s.note(f"magic decode ({attempts[0][0]}): {attempts[0][1][:60]}")


def _set_target(s: Session, c: Console) -> None:
    s.target = ask("novo target", s.target)
    c.print(f"[ok]target: {s.target}[/ok]")


def _add_header(s: Session, c: Console) -> None:
    key   = ask("header (ex: Authorization)")
    value = ask("valor (ex: Bearer xyz)")
    s.set_header(key, value)
    c.print(f"[ok]{key}: {value}[/ok]")


def _remove_header(s: Session, c: Console) -> None:
    if not s.headers:
        c.print("[dim]nenhum header fixo[/dim]")
        return
    for k, v in s.headers.items():
        c.print(f"  [info]{k}[/info]: {v}")
    key = ask("header a remover")
    s.remove_header(key)
    c.print("[ok]removido[/ok]")


def _export(s: Session, c: Console) -> None:
    path = s.export()
    c.print(f"[ok]sessão exportada: {path.resolve()}[/ok]")


_OPTIONS = {
    "1": ("histórico de requisições",  _history),
    "2": ("notas da sessão",           _notes),
    "3": ("flags capturadas",          _flags),
    "4": ("contexto da sessão",        _ctx),
    "5": ("hashes (MD5/SHA1/256/512)", _hashes),
    "6": ("MD5 crack",                 _md5_crack),
    "7": ("encode/decode URL",         _url_codec),
    "8": ("magic decode (auto)",       _magic_decode),
    "9": ("mudar target",              _set_target),
    "a": ("adicionar header fixo",     _add_header),
    "b": ("remover header",            _remove_header),
    "e": ("exportar sessão JSON",      _export),
    "0": ("voltar",                    None),
}


def run(session: Session, console: Console) -> None:
    run_menu("UTILITÁRIOS", _OPTIONS, session, console)
