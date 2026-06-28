"""
core/autopilot.py — Loop AutoPilot Chain Engine (v6.3).
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING

from .classifier import ResponseClassifier, Candidate
from .stack_classifier import StackClassifier
from .logger import logger

if TYPE_CHECKING:
    from .context import Context
    from .registry import Registry


_NEEDS_TOKEN = {"idor_query_params", "mass_assignment", "race"}
# jwt_attack e forge fazem auto-login internamente — não precisam de token pré-existente
# Scanners que têm múltiplos paths-alvo e precisam rodar uma vez por path
_MULTI_PATH_SCANNERS = {"nosqli_detection"}
_ALWAYS_FIRST = {"sqli_detection", "path_traversal", "ssti"}

_SCANNER_ALIAS: dict[str, str] = {
    "ssti":              "ssti",
    "xxe":               "xxe",
    "xss":               "xss",
    "forge":             "jwt_attack",   # forge (interactive) → jwt_attack (BaseScanner)
    "race":              "race",
    "idor_query_params": "idor_query_params",
    "mass_assignment":   "mass_assignment",
    "sqli_detection":    "sqli_detection",
    "differential_sqli": "differential_sqli",
    "path_traversal":    "path_traversal",
    "ssrf_detection":    "ssrf_detection",
    "graphql_detection": "graphql_detection",
    "nosqli_detection":  "nosqli_detection",   # ← NOVO
    "jwt_attack":        "jwt_attack",            # ← JWT crack+forge
    "fuzzer":            "reconnaissance_fuzzer",
    "subdomains":        "subdomain_fuzzer",
}


class AutoPilot:
    def __init__(self, ctx: "Context", registry: "Registry"):
        self.ctx       = ctx
        self.registry  = registry
        self.clf       = ResponseClassifier()
        self.stack_clf = StackClassifier()
        self._ran: set[str] = set()

    def run(self, max_rounds: int = 3) -> list[str]:
        from ctflab.core import http as H

        console_print = self._print
        console_print("[bold cyan]◎ AutoPilot Chain Engine v6.3 iniciado[/bold cyan]")
        console_print(f"  alvo: {self.ctx.session.target}")

        body, headers, status = self._fingerprint_target()
        if not body:
            return []

        for _round in range(max_rounds):
            all_eps = self.ctx.session.recall("_all_discovered_endpoints", [])

            # Fase 1: Surface Expansion — apenas rodada 0
            if _round == 0 and "reconnaissance_fuzzer" not in self._ran:
                console_print("[warn]  Iniciando Expansão de Superfície (Super-Discovery)...[/warn]")
                self._run_candidate(Candidate(scanner="reconnaissance_fuzzer", score=1.0, reason="Cadeia de execução"))

                all_eps = self.ctx.session.recall("_all_discovered_endpoints", [])
                self._run_stack_aware_phase(all_eps, console_print)
                all_eps = self.ctx.session.recall("_all_discovered_endpoints", [])

            # Fase 2: Subdomain Enumeration — apenas rodada 1 E apenas em hosts reais  ← ALTERADO
            if _round == 1 and "subdomains" not in self._ran:
                if self._is_real_host():
                    self._run_subdomain_phase(console_print)
                    all_eps = self.ctx.session.recall("_all_discovered_endpoints", [])
                else:
                    logger.info("AutoPilot: subdomain fuzzer ignorado (localhost/IP direto)")

            # Fase 3: Classification & Attack
            spider_hints = "\n".join([f"GET {p}" for p in all_eps])
            classify_body = body + "\n" + spider_hints
            candidates = self.clf.classify(classify_body, headers, status)

            # FIX Bug 4d: expande nosqli_detection em dois runs separados:
            # (1) auth bypass em endpoints de login → obtém token
            # (2) data exfil em endpoints de busca → vaza dados com $regex
            # A ordem importa: auth PRIMEIRO, search DEPOIS (search requer token).
            expanded: list[Candidate] = []
            for c in candidates:
                alias = _SCANNER_ALIAS.get(c.scanner, c.scanner)
                if alias in _MULTI_PATH_SCANNERS:
                    # Auth endpoints: login/auth/signin → bypass para obter token
                    auth_eps = [
                        ep for ep in all_eps
                        if any(k in ep.lower() for k in ("login", "auth", "signin", "session"))
                    ]
                    # Search endpoints: search/filter/find (POST exclusivamente)
                    # NÃO inclui /entries nem /admin/entries — são GET-only
                    search_eps = [
                        ep for ep in all_eps
                        if any(k in ep.lower() for k in ("search", "filter", "find"))
                        and not any(k in ep.lower() for k in ("login", "auth", "signin"))
                    ]
                    # Fallback: usar o path do próprio candidato se nada foi descoberto
                    if not auth_eps and not search_eps:
                        auth_eps = [c.params.get("path", "/login")]

                    # Gera candidatos: auth primeiro, search depois
                    for mp_path in auth_eps:
                        p = dict(c.params)
                        p["path"] = mp_path
                        expanded.append(Candidate(
                            scanner=c.scanner,
                            score=c.score,
                            reason=c.reason + f" [auth:{mp_path}]",
                            params=p,
                        ))
                    for mp_path in search_eps:
                        p = dict(c.params)
                        p["path"] = mp_path
                        expanded.append(Candidate(
                            scanner=c.scanner,
                            score=c.score - 0.01,  # score ligeiramente menor → roda após auth
                            reason=c.reason + f" [search:{mp_path}]",
                            params=p,
                        ))
                else:
                    expanded.append(c)
            # Reordenar: maior score primeiro (auth antes de search)
            expanded.sort(key=lambda x: x.score, reverse=True)
            candidates = expanded

            if not candidates:
                console_print("[dim]  nenhum candidato encontrado — encerrando[/dim]")
                break

            console_print(f"\n[bold yellow]◈ Rodada {_round + 1} — {len(candidates)} candidato(s) | {len(all_eps)} endpoint(s):[/bold yellow]")
            if all_eps:
                console_print(f"  [dim]Targets: {', '.join(all_eps)}[/dim]")
            for c in candidates:
                console_print(f"  [{c.score:.0%}] {c.scanner:25s}  {c.reason}")

            ran_this_round = 0  # ← NOVO: contador por rodada
            for candidate in candidates:
                if self._should_skip(candidate):
                    continue
                flag_before = len(self.ctx.session.flags)
                self._run_candidate(candidate)
                ran_this_round += 1
                if len(self.ctx.session.flags) > flag_before:
                    for f in self.ctx.session.flags[flag_before:]:
                        console_print(f"\n[bold magenta on black]  🏁 FLAG: {f}[/bold magenta on black]")

            # ← NOVO: encerra se nada rodou (todos já executados ou sem token)
            if ran_this_round == 0:
                console_print("[dim]  todos os candidatos já rodaram — encerrando[/dim]")
                break

            # Correlação pós-rodada
            self.ctx.knowledge.sync_from_session(self.ctx.session)
            chains = self.ctx.correlation.correlate(self.ctx.knowledge, self.ctx)
            if chains:
                console_print(f"\n[bold magenta]⚡ Cadeias de Escalonamento de Privilégios:[/bold magenta]")
                for chain in chains:
                    console_print(f"  [warn]⚠ {chain['name']}[/warn]")

        return self.ctx.session.flags

    # ── fases ─────────────────────────────────────────────────────────────────

    def _run_stack_aware_phase(self, all_eps: list[str], print_fn) -> None:
        from ctflab.core import http as H

        stacks = self.stack_clf.identify_stacks(self.ctx.session.ctx, all_eps)
        if not stacks:
            return

        for stack in stacks:
            print_fn(f"  [bold blue] Sherlock Engine: Identificado {stack['name']} → Injetando {len(stack['expansion'])} rotas de elite...[/bold blue]")
            results = H.fuzz(self.ctx.session, stack["expansion"])

            discovered = self.ctx.session.recall("_all_discovered_endpoints", set())
            if isinstance(discovered, list):
                discovered = set(discovered)

            found = 0
            for path, code, _, _ in results:
                if code != 404:
                    discovered.add(path)
                    found += 1

            self.ctx.session.remember("_all_discovered_endpoints", list(discovered))
            if found:
                print_fn(f"  [ok]Sucesso: {found} endpoints de {stack['name']} encontrados![/ok]")

    def _run_subdomain_phase(self, print_fn) -> None:
        print_fn("\n[bold blue] Sherlock Engine: Iniciando Fase 2 — Enumeração de Subdomínios...[/bold blue]")
        self._run_candidate(Candidate(scanner="subdomains", score=1.0, reason="Cadeia de execução"))

    # ── helpers ───────────────────────────────────────────────────────────────

    def _is_real_host(self) -> bool:
        """Retorna False para localhost, 127.x e IPs diretos — evita subdomain fuzz inútil."""  # ← NOVO
        target = self.ctx.session.target
        host = target.split("//")[-1].split("/")[0].split(":")[0]
        if host in ("localhost", "127.0.0.1", "0.0.0.0"):
            return False
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            return False
        return True

    def _fingerprint_target(self) -> tuple[str, dict, int]:
        from ctflab.core import http as H
        for attempt in range(3):
            try:
                r = H.get(self.ctx.session, "/", use_cache=False)
                if r.status_code == 503:
                    time.sleep(2)
                    continue
                return r.text, dict(r.headers), r.status_code
            except Exception:
                time.sleep(2)
        return "", {}, 0

    def _should_skip(self, c: Candidate) -> bool:
        alias = _SCANNER_ALIAS.get(c.scanner, c.scanner)
        # FIX Bug 4b: scanners multi-path usam chave composta alias+path
        # para permitir rodar o mesmo scanner em endpoints distintos.
        if alias in _MULTI_PATH_SCANNERS:
            path_key = f"{alias}::{c.params.get('path', '')}"
            if path_key in self._ran:
                return True
        elif alias in self._ran:
            return True
        if c.scanner in _NEEDS_TOKEN and not self.ctx.session.recall("token"):
            return True
        return False

    def _run_candidate(self, c: Candidate) -> None:
        alias = _SCANNER_ALIAS.get(c.scanner, c.scanner)
        scanner_cls = self.registry.get_scanner(alias)
        if not scanner_cls:
            return

        # FIX Bug 4c: scanners multi-path registram chave composta
        if alias in _MULTI_PATH_SCANNERS:
            path_key = f"{alias}::{c.params.get('path', '')}"
            self._ran.add(path_key)
        else:
            self._ran.add(alias)

        self._print(f"\n  [cyan]→ rodando {alias}[/cyan]")

        if alias == "differential_sqli":
            all_discovered = self.ctx.session.recall("_all_discovered_endpoints", [])
            dynamic_targets = [ep for ep in all_discovered if "?" in ep or re.search(r"/\d+/?$", ep) or ep.count("/") >= 2]
            if dynamic_targets:
                for ep in dynamic_targets:
                    params = dict(c.params)
                    params["path"] = ep
                    try:
                        scanner_cls(self.ctx, **params).run()
                    except Exception:
                        pass
                return

        try:
            params = dict(c.params)
            if "path" not in params:
                params["path"] = self.ctx.session.recall("path", "/")
            scanner_cls(self.ctx, **params).run()
        except Exception:
            try:
                scanner_cls(self.ctx).run()
            except Exception:
                pass

    def _print(self, msg: str) -> None:
        from ctflab.cli.ui import console
        try:
            console.print(msg)
        except Exception:
            print(msg)
