"""
domains/reconnaissance/port_scanner.py — Varredor de Portas (Port Scanner) de Infraestrutura.

Verifica de forma assíncrona/concorrente as portas abertas no host do alvo,
descobrindo outros serviços ativos e pontos potenciais de entrada de Red Team.
"""

from __future__ import annotations

import socket
from typing import Iterable, Any
from urllib.parse import urlparse

from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult

class PortScanner(BaseScanner):
    name = "port_scanner"
    capabilities = ["reconnaissance", "ports"]

    def __init__(self, ctx):
        super().__init__(ctx)
        target_url = self.ctx.session.target
        parsed = urlparse(target_url)
        # Extrai o hostname ou IP puro (remove portas se houver, ex: localhost:1337 -> localhost)
        if parsed.hostname:
            self.host = parsed.hostname
        else:
            # Caso não tenha esquema (ex: "127.0.0.1"), divide por dois pontos
            self.host = parsed.path.split(":")[0] if ":" in parsed.path else parsed.path

    def get_payloads(self) -> Iterable[int]:
        # Top 20 portas mais comuns e exploradas em ambientes de CTF e Red Team
        return [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            139,   # NetBIOS
            443,   # HTTPS
            445,   # SMB
            1433,  # MSSQL
            3306,  # MySQL
            3389,  # RDP
            5000,  # Flask / Docker / API
            6379,  # Redis
            8000,  # Web Dev / Alternativo
            8080,  # Apache Tomcat / Dev
            8443,  # HTTPS Alternativo
            9000,  # FastCGI / PHP-FPM
            27017  # MongoDB
        ]

    def execute(self, payload: int) -> bool:
        port = int(payload)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Timeout curto para manter o scan rápido
        s.settimeout(1.5)
        try:
            s.connect((self.host, port))
            s.close()
            return True
        except Exception:
            return False

    def analyze(self, payload: int, response: bool) -> ScanResult:
        port = int(payload)
        if response:
            service = self._get_service_name(port)
            self.ctx.session.remember(f"port_{port}_open", service)
            self.ctx.session.note(f"Serviço encontrado: Porta {port} ({service}) aberta em {self.host}")
            
            return ScanResult(
                success=True,
                confidence=1.0,
                severity="Low",
                details=f"Porta aberta encontrada: {port} ({service})"
            )
            
        return ScanResult(success=False, confidence=0.0, details="-")

    def _get_service_name(self, port: int) -> str:
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5000: "Flask / API",
            6379: "Redis",
            8000: "HTTP Dev",
            8080: "HTTP Proxy/Dev",
            8443: "HTTPS Alt",
            9000: "FastCGI / Web",
            27017: "MongoDB"
        }
        return services.get(port, "serviço desconhecido")
