"""
core/session.py — estado da sessão de pentest.

Session é injetada explicitamente em todo módulo e função.
Nunca existe como global.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Evidence, Vulnerability


@dataclass
class RequestRecord:
    """Registro imutável de uma requisição + resposta."""

    method:    str
    url:       str
    payload:   Any
    status:    int
    body:      str
    elapsed:   float
    timestamp: str = field(default_factory=lambda: time.strftime("%H:%M:%S"))

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "method":    self.method,
            "url":       self.url,
            "payload":   self.payload,
            "status":    self.status,
            "elapsed":   round(self.elapsed, 4),
            "body":      self.body[:2000],
        }


@dataclass
class Session:
    """
    Fonte única de verdade da sessão de pentest.
    Não é singleton — crie uma instância por contexto.
    """

    target:          str       = "http://localhost:1337"
    timeout:         float     = 10.0
    retries:         int       = 2
    ssl:             bool      = False
    proxy:           str | None = None
    waf_bypass:      bool      = False


    headers:         dict      = field(default_factory=dict)
    history:         list      = field(default_factory=list)   # list[RequestRecord]
    notes:           list[str] = field(default_factory=list)
    flags:           list[str] = field(default_factory=list)
    evidences:       list      = field(default_factory=list)   # list[Evidence]
    vulnerabilities: list      = field(default_factory=list)   # list[Vulnerability]
    ctx:             dict      = field(default_factory=dict)
    _visited_js:     set[str]  = field(default_factory=set)
    _technologies:   list[str] = field(default_factory=list)
    
    # 🕵️ Stealth Config (v6.1.1)
    stealth_mode:    bool      = True
    user_agent:      str       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    _bus:            Any       = field(default=None, init=False, repr=False)

    # ── mutações ──────────────────────────────────────────────

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        self.vulnerabilities.append(vuln)
        self.note(f"VULN [{vuln.severity}] {vuln.module} — {vuln.name}")

    def set_header(self, key: str, value: str) -> None:
        self.headers[key] = value

    def remove_header(self, key: str) -> None:
        self.headers.pop(key, None)

    def add_record(self, rec: RequestRecord) -> None:
        self.history.append(rec)

    def note(self, text: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.notes.append(f"[{ts}] {text}")

    def flag(self, value: str) -> None:
        if value not in self.flags:
            self.flags.append(value)
            self.note(f"FLAG: {value}")
            if self._bus:
                from .events import FlagCaptured
                self._bus.publish(FlagCaptured(flag=value))

    # ── contexto descoberto ───────────────────────────────────

    def remember(self, key: str, value: str) -> None:
        self.ctx[key] = value

    def recall(self, key: str, fallback: str = "") -> str:
        return self.ctx.get(key, fallback)

    # ── persistência ──────────────────────────────────────────

    def export(self, path: str | Path = "ctflab_session.json") -> Path:
        p = Path(path)
        data = {
            "target":  self.target,
            "timeout": self.timeout,
            "retries": self.retries,
            "proxy":   self.proxy,
            "waf_bypass": self.waf_bypass,
            "flags":   self.flags,
            "notes":   self.notes,
            "ctx":     self.ctx,
            "visited_js": list(self._visited_js),
            "technologies": self._technologies,
            "history": [r.to_dict() for r in self.history],
            "vulnerabilities": [
                {
                    "module": v.module,
                    "name": v.name,
                    "payload": v.payload,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "evidence": [
                        {
                            "module": e.module,
                            "payload": e.payload,
                            "status": e.status,
                            "snippet": e.response_snippet,
                            "confidence": e.confidence
                        } for e in v.evidence
                    ]
                } for v in self.vulnerabilities
            ]
        }
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return p

    @classmethod
    def load(cls, path: str | Path) -> "Session":
        from .models import Evidence
        data = json.loads(Path(path).read_text())
        s = cls(
            target=data.get("target", "http://localhost:1337"),
            timeout=data.get("timeout", 10.0),
            retries=data.get("retries", 2),
            proxy=data.get("proxy", None),
            waf_bypass=data.get("waf_bypass", False)
        )


        s.notes = data.get("notes", [])
        s.flags = data.get("flags", [])
        s.ctx   = data.get("ctx", {})
        s._visited_js = set(data.get("visited_js", []))
        s._technologies = data.get("technologies", [])
        
        for v_data in data.get("vulnerabilities", []):
            evidences = [
                Evidence(
                    module=e["module"],
                    payload=e["payload"],
                    status=e["status"],
                    response_snippet=e["snippet"],
                    confidence=e["confidence"]
                ) for e in v_data.get("evidence", [])
            ]
            s.vulnerabilities.append(Vulnerability(
                module=v_data["module"],
                name=v_data["name"],
                payload=v_data["payload"],
                severity=v_data["severity"],
                confidence=v_data["confidence"],
                evidence=evidences
            ))

        for r in data.get("history", []):
            s.history.append(RequestRecord(
                method=r["method"], url=r["url"],
                payload=r["payload"], status=r["status"],
                body=r["body"], elapsed=r["elapsed"],
                timestamp=r["timestamp"],
            ))
        return s
