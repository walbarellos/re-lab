"""
cli/ui.py — tudo que é apresentação, separado de lógica.

Console compartilhado. Helpers de input. Formatação de respostas.
Detecção automática de flags. Sem lógica de negócio aqui.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.theme import Theme

from ctflab.core.session import Session
from ctflab.core import intel as Intel

# ── tema ──────────────────────────────────────────────────────

_THEME = Theme({
    "ok":   "bold green",
    "fail": "bold red",
    "warn": "bold yellow",
    "info": "bold cyan",
    "dim":  "dim white",
    "head": "bold blue",
    "flag": "bold magenta on black",
})

console = Console(theme=_THEME)


# ── helpers de input ──────────────────────────────────────────

def ask(prompt: str, default: str = "") -> str:
    return Prompt.ask(f"[info]{prompt}[/info]", default=default).strip()


def askctx(session: "Session", key: str, prompt: str, fallback: str = "") -> str:
    """
    ask com memória de sessão.

    Usa session.recall(key) como default — o que você digitou antes
    aparece como sugestão na próxima vez no mesmo campo.
    Após confirmado, salva de volta com session.remember(key).
    """
    default = session.recall(key, fallback)
    value   = ask(prompt, default)
    if value:
        session.remember(key, value)
    return value


def ask_int(prompt: str, default: int = 10) -> int:
    return IntPrompt.ask(f"[info]{prompt}[/info]", default=default)


def ask_json(prompt: str) -> dict | str | None:
    """
    Pede JSON em linha. Se não for JSON válido, retorna como string.
    """
    raw = ask(prompt)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        # Se falhar no JSON, retorna a string pura (útil para payloads)
        return raw


def ask_json_interactive(con: "Console | None" = None) -> dict | None:
    """
    Constrói payload campo a campo.
    Tenta inferir tipos (int, bool) via json.loads, mas mantém como string se falhar.
    """
    c = con or console
    c.print("\n[dim]construtor de payload — campo vazio para terminar[/dim]")
    payload: dict = {}
    while True:
        field = ask("  campo (enter = pronto)", "")
        if not field:
            break
        raw_val = ask(f"  valor de '{field}'", "")
        try:
            # Se for "true", "42", "{"a":1}", etc., converte.
            # Se for "{{7*7}}", o json.loads falha e cai no except.
            payload[field] = json.loads(raw_val)
        except Exception:
            payload[field] = raw_val
    if not payload:
        c.print("[fail]payload vazio[/fail]")
        return None
    c.print(f"\n[dim]payload construído:[/dim] [info]{json.dumps(payload)}[/info]")
    return payload


def ask_params(prompt: str = "query params (ex: name=foo&id=1)") -> dict:
    raw = ask(prompt, "")
    if not raw:
        return {}
    return dict(urllib.parse.parse_qsl(raw))


# ── formatação de resposta ────────────────────────────────────

def _flatten(obj: Any) -> list:
    out = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_flatten(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_flatten(v))
    else:
        out.append(obj)
    return out


def show_response(r: Any, elapsed: float, session: Session) -> None:
    """Mostra resposta HTTP formatada, detecta flags e extrai inteligência."""
    code  = r.status_code
    style = "ok" if code == 200 else ("warn" if code < 500 else "fail")

    console.print(f"\n[{style}][{code}][/{style}] [dim]{elapsed:.3f}s[/dim]")

    try:
        data   = r.json()
        pretty = json.dumps(data, indent=2, ensure_ascii=False)
        console.print(Syntax(pretty, "json", theme="monokai", word_wrap=True))

        for v in _flatten(data):
            if isinstance(v, str) and v.startswith("CTF{"):
                console.print(Panel(
                    f"[flag] {v} [/flag]",
                    title="🚩 FLAG ENCONTRADA",
                    border_style="magenta",
                ))
                session.flag(v)
    except Exception:
        console.print(r.text[:600])

    # extrai inteligência automaticamente e exibe o que foi descoberto
    found = Intel.analyze(session, r.text, code)
    if found:
        _show_intel(found)

    console.print()


def _show_intel(found: dict) -> None:
    """Exibe o que o intel extraiu da resposta, de forma compacta."""
    from rich.table import Table
    lines = []

    if "endpoints" in found:
        for ep in found["endpoints"]:
            fields_str = ", ".join(ep["fields"]) if ep["fields"] else "?"
            lines.append(f"[info]endpoint:[/info] [warn]{ep['method']} {ep['path']}[/warn]  campos: [dim]{fields_str}[/dim]")

    if "tokens" in found:
        for t in found["tokens"][:2]:
            lines.append(f"[info]token detectado:[/info] [dim]{t[:60]}[/dim]")

    if lines:
        console.print()
        console.print("[dim]── intel extraído ──────────────────────────────[/dim]")
        for line in lines:
            console.print(f"  {line}")
        console.print("[dim]  (defaults dos próximos módulos já atualizados)[/dim]")


# ── tabelas reutilizáveis ─────────────────────────────────────

def scan_table(title: str, cols: list[str]) -> Table:
    t = Table(title=title, show_lines=True)
    for col in cols:
        t.add_column(col)
    return t


def history_table(session: Session) -> Table:
    t = Table(title="histórico da sessão", show_lines=True)
    t.add_column("hora",   style="dim")
    t.add_column("método")
    t.add_column("url",    max_width=40)
    t.add_column("status")
    t.add_column("tempo")
    t.add_column("body",   max_width=45)

    for rec in session.history:
        style = "ok" if rec.status == 200 else "fail"
        t.add_row(
            rec.timestamp,
            rec.method,
            rec.url,
            f"[{style}]{rec.status}[/{style}]",
            f"{rec.elapsed:.3f}s",
            rec.body[:45],
        )
    return t


# ── banner ────────────────────────────────────────────────────

def banner(session: Session) -> None:
    flag_line = ""
    if session.flags:
        flag_line = "\n\n🚩 " + "  |  ".join(session.flags)
    console.print(Panel(
        f"[info]CTFLab v5.5[/info]\n"
        f"[dim]recon · sqli · forge · traversal · race · brute · crypto · plugins[/dim]\n\n"
        f"target: [warn]{session.target}[/warn]{flag_line}",
        border_style="cyan",
        padding=(1, 4),
    ))
