"""
domains/detection/graphql_scanner.py — Scanner de GraphQL (v6).

Detecta endpoints GraphQL e tenta Introspecção para mapear o esquema.
"""

from typing import Iterable, Any
from ctflab.core.scanner import BaseScanner
from ctflab.core.models import ScanResult
from ctflab.core import http as H

class GraphQLScanner(BaseScanner):
    name = "graphql_detection"
    capabilities = ["http", "graphql", "detection"]
    
    # Payload de Introspecção Mestre
    INTROSPECTION_QUERY = {
        "query": "{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name}}}}}}}"
    }

    def __init__(self, ctx, path: str = "/graphql"):
        super().__init__(ctx)
        self.path = path

    def get_payloads(self) -> Iterable[dict]:
        return [self.INTROSPECTION_QUERY]

    def execute(self, payload: dict) -> Any:
        return H.post(self.ctx.session, self.path, payload=payload)

    def analyze(self, payload: dict, response: Any) -> ScanResult:
        if response.status_code == 200 and "__schema" in response.text:
            return ScanResult(
                success=True,
                confidence=1.0,
                details=f"Introspecção GraphQL habilitada em {self.path}",
                severity="Medium"
            )
        return ScanResult(success=False, confidence=0.0, details="-")
