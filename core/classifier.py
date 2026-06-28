"""
core/classifier.py — ResponseClassifier: heurísticas puras para decisão de ataque.

Lê body + headers de uma resposta HTTP e devolve uma lista ordenada de
candidatos de vulnerabilidade. Zero dependências externas — só regex e
conhecimento embutido do que CTFs costumam expor.
"""

from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from typing import Any


# ── sinais de detecção ────────────────────────────────────────────────────────

_BODY_SIGNALS: list[tuple[re.Pattern, str, float, dict]] = [
    # SSTI
    (re.compile(r'"(template|tpl|view|render|code|expr)\s*"', re.I),
     "ssti", 0.85, {"param": "template", "mode": "json"}),

    # JWT
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.', re.I),
     "forge", 0.9, {}),

    # XXE
    (re.compile(r'"(import|parse|upload|document|xml|invoice)"\s*:', re.I),
     "xxe", 0.75, {"path": "/parse"}),

    # IDOR / Advanced SQLi
    (re.compile(r'/(user|account|item|order|profile|ticket|exercises)/\d+', re.I),
     "differential_sqli", 0.95, {"param": "id"}),

    # SQLi
    (re.compile(r'"(username|user|login|email|search|query|q|id)\s*"', re.I),
     "differential_sqli", 0.8, {}),

    # NoSQLi — campos de busca com operadores ($gt/$ne/$regex típicos de MongoDB)  ← NOVO
    (re.compile(r'"(search|filter|find|entries|query)"\s*:', re.I),
     "nosqli_detection", 0.70, {"param": "username"}),

    # Mass Assignment
    (re.compile(r'PUT\s+/(me|profile|user|account)', re.I),
     "mass_assignment", 0.8, {"method": "PUT"}),

    # Path Traversal
    (re.compile(r'"(file|path|filename|template|page|include|doc)\s*"', re.I),
     "path_traversal", 0.7, {"param": "file"}),

    # Hidden params
    (re.compile(r'"status"\s*:\s*"(production|live|ok)"', re.I),
     "fuzzer", 0.6, {"mode": "params"}),

    # Race condition
    (re.compile(r'"(withdraw|transfer|buy|checkout|redeem|coupon)"\s*:', re.I),
     "race", 0.85, {}),

    # XSS
    (re.compile(r'"(message|comment|body|bio|name|description|content)"\s*:', re.I),
     "xss", 0.55, {}),

    # SSRF (v6.1)
    (re.compile(r'"(url|callback|redirect|webhook|endpoint|src|dest|target)"\s*:', re.I),
     "ssrf_detection", 0.75, {"param": "url"}),

    # GraphQL (v6.1)
    (re.compile(r'(graphql|__typename|__schema|"query"\s*:)', re.I),
     "graphql_detection", 0.85, {"path": "/graphql"}),
]

_CONTENT_TYPE_SIGNALS: list[tuple[str, str, float, dict]] = [
    ("application/xml", "xxe", 0.9, {}),
    ("text/xml",        "xxe", 0.9, {}),
]

_HEADER_SIGNALS: list[tuple[str, re.Pattern, str, float, dict]] = [
    ("x-powered-by", re.compile(r"php", re.I),       "sqli_detection", 0.3, {}),
    ("x-powered-by", re.compile(r"php", re.I),       "path_traversal",  0.3, {}),
    ("server",       re.compile(r"werkzeug|flask", re.I), "ssti",       0.4, {"param": "template", "mode": "json"}),
    ("www-authenticate", re.compile(r"bearer", re.I), "forge",          0.6, {}),
]

_ENDPOINT_SIGNALS: list[tuple[re.Pattern, str, float, dict]] = [
    (re.compile(r"POST\s+/login",      re.I), "sqli_detection",   0.6, {"path": "/login", "param": "username"}),
    (re.compile(r"POST\s+/login",      re.I), "mass_assignment",  0.5, {"path": "/login", "method": "POST"}),
    (re.compile(r"POST\s+/login",      re.I), "nosqli_detection", 0.65, {"path": "/login", "param": "username"}),  # ← NOVO
    (re.compile(r"POST\s+/(render|debug|preview|template)", re.I), "ssti", 0.9, {"param": "template", "mode": "json"}),
    (re.compile(r"POST\s+/(parse|import|upload)",           re.I), "xxe",  0.85, {}),
    (re.compile(r"GET\s+/flag",        re.I), "forge",            0.7, {}),
    (re.compile(r"GET\s+/flag",        re.I), "jwt_attack",        0.72, {}),  # ← jwt_attack direto
    (re.compile(r"PUT\s+/me",          re.I), "mass_assignment",  0.85, {"path": "/me", "method": "PUT"}),
    (re.compile(r"POST\s+/withdraw",   re.I), "race",             0.9, {}),
    (re.compile(r"(GET|POST)\s+/graphql", re.I), "graphql_detection", 0.9, {"path": "/graphql"}),
    (re.compile(r"POST\s+/(fetch|proxy|forward|request)", re.I), "ssrf_detection", 0.85, {"param": "url"}),
    (re.compile(r"POST\s+/(entries/search|search|filter)", re.I), "nosqli_detection", 0.75, {"path": "/entries/search", "param": "title"}),  # FIX Bug1: path explícito
]

@dataclass
class Candidate:
    scanner: str
    score:   float
    reason:  str
    params:  dict = field(default_factory=dict)

    def __lt__(self, other: "Candidate") -> bool:
        return self.score > other.score


class ResponseClassifier:
    THRESHOLD = 0.30

    def classify(
        self,
        body: str,
        headers: dict[str, str],
        status: int = 200,
    ) -> list[Candidate]:
        scores: dict[str, Candidate] = {}

        def _add(scanner: str, score: float, reason: str, params: dict) -> None:
            if scanner in scores:
                if score > scores[scanner].score:
                    # FIX Bug 1b: merge params — preserva chaves do candidato anterior
                    # que o novo não redefine (ex: 'path' do sinal de /login não é
                    # perdido quando sinal de /entries/search chega com score maior).
                    merged = dict(scores[scanner].params)
                    merged.update(params)
                    scores[scanner] = Candidate(scanner, score, reason, merged)
            else:
                scores[scanner] = Candidate(scanner, score, reason, params)

        for pattern, scanner, base_score, params in _BODY_SIGNALS:
            m = pattern.search(body)
            if m:
                _add(scanner, base_score, f"body contém '{m.group()}'", params)

        for pattern, scanner, base_score, params in _ENDPOINT_SIGNALS:
            if pattern.search(body):
                _add(scanner, base_score, f"endpoint '{pattern.pattern}' detectado", params)

        h_lower = {k.lower(): v for k, v in headers.items()}
        for header, pattern, scanner, bonus, params in _HEADER_SIGNALS:
            val = h_lower.get(header, "")
            if val and pattern.search(val):
                if scanner in scores:
                    scores[scanner] = Candidate(
                        scanner,
                        min(1.0, scores[scanner].score + bonus),
                        scores[scanner].reason + f" [+{header}]",
                        scores[scanner].params or params,
                    )
                else:
                    _add(scanner, bonus, f"header '{header}: {val}'", params)

        ct = h_lower.get("content-type", "")
        for ct_pat, scanner, base_score, params in _CONTENT_TYPE_SIGNALS:
            if ct_pat in ct:
                _add(scanner, base_score, f"Content-Type '{ct}'", params)

        self._analyze_json(body, scores, _add)

        result = [c for c in scores.values() if c.score >= self.THRESHOLD]
        result.sort()
        return result

    def _analyze_json(self, body: str, scores: dict[str, Candidate], add: Any) -> None:
        try:
            data = json.loads(body)
        except Exception:
            return

        endpoints = data.get("endpoints", {})
        if not endpoints:
            return

        all_paths = " ".join(str(v) for v in endpoints.values()) if isinstance(endpoints, dict) else ""

        if "xml" in all_paths.lower() or "Content-Type: application/xml" in all_paths:
            add("xxe", 0.85, "endpoint sugere XML", {})

        if "bearer" in all_paths.lower() or "Authorization" in all_paths:
            add("forge",      0.80, "endpoint exige Bearer token", {})
            add("jwt_attack", 0.82, "endpoint exige Bearer token", {})  # ← jwt_attack direto

        if re.search(r"/<\s*(id|user_id|account_id)\s*>", all_paths, re.I):
            add("idor_query_params", 0.85, "rota com parâmetro de ID numérico", {"param": "id", "start": 1, "end": 20})

        n_post = all_paths.count("POST")
        if n_post >= 2 and "sqli_detection" not in scores:
            add("sqli_detection", 0.40, f"{n_post} endpoints POST encontrados", {})

        # NoSQLi — endpoint de busca/filtro com POST  ← NOVO
        if re.search(r"POST\s+/(search|filter|entries/search|find)", all_paths, re.I):
            add("nosqli_detection", 0.70, "endpoint de busca POST detectado", {"param": "title"})
