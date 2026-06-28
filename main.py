#!/usr/bin/env python3
"""
CTFLab v5.0 — Framework de Domínio de Guerra (DDD & Event-Driven)

O Orquestrador Central unificado.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Garante que o pacote 'ctflab' seja importável
_root = Path(__file__).parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from ctflab.core.session import Session
from ctflab.core.context import Context
from ctflab.core.bus import MessageBus
from ctflab.core.registry import Registry
from ctflab.core.config import ConfigManager
from ctflab.core.workflow import WorkflowEngine
from ctflab.core.repository import SQLiteRepository
from ctflab.core.intelligence import IntelligenceService
from ctflab.core import plugin as plugin_loader
from ctflab.core.dashboard import run_dashboard
from ctflab.cli.ui import banner, console, ask

# Importação dos domínios (Legacy wrappers)
import ctflab.domains.reconnaissance.recon as recon
import ctflab.domains.detection.legacy_sqli as sqli
import ctflab.domains.exploitation.forge     as forge
import ctflab.domains.detection.traversal    as traversal
import ctflab.domains.exploitation.race      as race
import ctflab.domains.detection.idor         as idor
import ctflab.domains.reconnaissance.fuzz    as fuzz
import ctflab.domains.reporting.helper_utils as utils

def build_v5_menu() -> dict:
    return {
        "1": ("Reconhecimento",   recon.run),
        "2": ("SQL Injection",    sqli.run),
        "3": ("Forge de Token",   forge.run),
        "4": ("Path Traversal",   traversal.run),
        "5": ("Race / Brute",     race.run),
        "6": ("IDOR / Tampering", idor.run),
        "7": ("Fuzzing / Hidden", fuzz.run),
        "8": ("Utilitários",      utils.run),
        "d": ("Dashboard Web",    lambda s, c: run_dashboard()),
        "0": ("Sair",             None),
    }

def main_loop(ctx: Context):
    from rich.table import Table
    banner(ctx.session)
    
    registry = Registry()
    registry.discover_components()
    workflow_engine = WorkflowEngine(ctx, registry)

    while True:
        console.rule("[head]MENU PRINCIPAL v5.0[/head]")
        options = build_v5_menu()

        # Adiciona plugins dinâmicos ao menu
        plugins = plugin_loader.discover()
        for i, mod in enumerate(plugins, start=9):
            options[str(i)] = (
                f"{mod.PLUGIN_NAME} [dim](plugin)[/dim]",
                mod.run,
            )

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="info")
        table.add_column()
        for key, (desc, _) in options.items():
            table.add_row(key, desc)
        console.print(table)
        console.print()

        op = ask("comando / módulo")

        if op == "0":
            console.print("\n[dim]saindo...[/dim]\n")
            break
        
        # Atalho para rodar workflow
        if op.startswith("run "):
            wf_name = op.split(" ")[1]
            workflow_engine.run_workflow(wf_name)
            continue

        entry = options.get(op)
        if entry:
            _, handler = entry
            if handler:
                try:
                    # Se for um plugin dinâmico (índice >= 9), usa o runner seguro
                    if op.isdigit() and int(op) >= 9:
                        idx = int(op) - 9
                        plugin_loader.run_plugin_safely(plugins[idx], ctx.session, console, ctx.bus)
                    else:
                        handler(ctx.session, console)
                except Exception as e:
                    ctx.log_error(f"Erro no módulo: {e}")
        else:
            console.print("[fail]Opção inválida[/fail]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTFLab v5.0")
    parser.add_argument("--target", "-t", default="http://localhost:1337")
    parser.add_argument("--run", "-r", help="Executa um workflow YAML direto")
    parser.add_argument("--dashboard", action="store_true", help="Sobe o dashboard visual")
    parser.add_argument("--autopilot", "-a", action="store_true", help="Modo autônomo: fingerprint → classifica → ataca")
    args = parser.parse_args()

    # Inicialização da Arquitetura v5.0
    config = ConfigManager()
    bus = MessageBus()
    session = Session(target=args.target)
    repository = SQLiteRepository()
    
    ctx = Context(session=session, bus=bus, config=config)
    intel_service = IntelligenceService(ctx)
    
    if args.dashboard:
        run_dashboard()
    elif args.autopilot:
        from ctflab.core.autopilot import AutoPilot
        registry = Registry()
        registry.discover_components()
        pilot = AutoPilot(ctx, registry)
        flags = pilot.run()

        from ctflab.core.scoring import ScoringEngine
        # FIX: Usa o novo motor de Risco Preditivo (v6.1.1)
        all_eps = session.recall("_all_discovered_endpoints", [])
        risk_report = ScoringEngine.calculate_session_score(session.vulnerabilities, all_eps)
        
        summary = ctx.metrics.get_summary()
        console.rule("[head]RESUMO AUTOPILOT[/head]")
        console.print(f"  [info]Flags:[/info]      {flags or 'nenhuma'}")
        console.print(f"  [info]Risco Confirmado:[/info]  [bold red]{risk_report['confirmed_risk']}[/bold red] / 10.0")
        console.print(f"  [info]Nível Exposição:[/info]  [bold yellow]{risk_report['exposure_level']}[/bold yellow] / 10.0")
        console.print(f"  [info]Ameaça Total:[/info]     [bold magenta]{risk_report['total_threat']}[/bold magenta] / 10.0")
        console.print(f"  [info]Requisições:[/info]       {summary['total_requests']}")
        repository.save_session(session)

    elif args.run:
        registry = Registry()
        registry.discover_components()
        wf = WorkflowEngine(ctx, registry)
        wf.run_workflow(args.run)

        # 📊 EXIBIÇÃO DE RESULTADOS v5.5
        risk_report = ScoringEngine.calculate_session_score(session.vulnerabilities)
        risk = risk_report["total_threat"]
        summary = ctx.metrics.get_summary()
        console.rule("[head]RESUMO DA OPERAÇÃO[/head]")
        console.print(f"  [info]Risco Alvo:[/info]  [flag] {risk} / 10.0 [/flag]")

        console.print(f"  [info]Requisições:[/info] {summary['total_requests']}")
        console.print(f"  [info]Duração:[/info]      {summary['duration_seconds']}s")

        repository.save_session(session)

    else:
        try:
            main_loop(ctx)
            repository.save_session(session)
        except KeyboardInterrupt:
            console.print("\n[dim]Saindo e salvando sessão...[/dim]")
            repository.save_session(session)
