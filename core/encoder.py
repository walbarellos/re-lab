"""
core/encoder.py — Codificador e Ofuscador de Payloads (WAF Evasion).

Fornece rotinas para codificação de strings e payloads, permitindo contornar
filtros de caracteres especiais em aplicações e firewalls.
"""

from __future__ import annotations

import base64
import urllib.parse

def url_encode(text: str, double: bool = False) -> str:
    """Codifica a string em formato URL (simples ou dupla)."""
    encoded = urllib.parse.quote(text)
    if double:
        encoded = urllib.parse.quote(encoded)
    return encoded

def hex_encode(text: str, prefix: str = "\\x") -> str:
    """Codifica a string em formato hexadecimal (ex: \\x41 ou 0x41)."""
    return "".join(f"{prefix}{ord(c):02x}" for c in text)

def unicode_encode(text: str) -> str:
    """Codifica a string usando representações JavaScript Unicode (\\uXXXX)."""
    return "".join(f"\\u{ord(c):04x}" for c in text)

def mixed_case(text: str) -> str:
    """Alterna maiúsculas e minúsculas para bypass de filtros case-sensitive."""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))

def sql_char_encode(text: str) -> str:
    """Codifica string usando CHAR() SQL para bypass de filtros de aspas."""
    return "CONCAT(" + ",".join(f"CHAR({ord(c)})" for c in text) + ")"

def json_unicode_encode(text: str) -> str:
    """Codifica string usando escapes JSON Unicode (\\u003c para <)."""
    return "".join(f"\\u{ord(c):04x}" for c in text)

def html_encode(text: str, decimal: bool = True) -> str:
    """Codifica a string em entidades HTML (decimal ou hexadecimal)."""
    if decimal:
        return "".join(f"&#{ord(c)};" for c in text)
    return "".join(f"&#x{ord(c):x};" for c in text)

def base64_encode(text: str) -> str:
    """Codifica a string em Base64."""
    return base64.b64encode(text.encode()).decode()

def sql_bypass_spaces(text: str) -> str:
    """Substitui espaços em branco por comentários SQL (/**/) para contornar filtros."""
    return text.replace(" ", "/**/")

def encode_all_formats(text: str) -> dict[str, str]:
    """Gera um dicionário com todas as codificações possíveis para uma determinada string."""
    return {
        "URL Simples": url_encode(text),
        "URL Dupla": url_encode(text, double=True),
        "Hex (\\x..)": hex_encode(text, prefix="\\x"),
        "Hex (0x..)": hex_encode(text, prefix="0x"),
        "Unicode (\\u..)": unicode_encode(text),
        "Entidade HTML": html_encode(text),
        "Base64": base64_encode(text),
        "SQL Space Bypass": sql_bypass_spaces(text),
        "Mixed Case": mixed_case(text),
        "SQL CHAR()": sql_char_encode(text),
        "JSON Unicode": json_unicode_encode(text),
    }

