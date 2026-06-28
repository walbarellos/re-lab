from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .session import Session


class KnowledgeBase:
    def __init__(self):
        self._facts = defaultdict(list)
        self._session = None

    def bind_session(self, session: "Session") -> None:
        self._session = session
        # Se a sessão já possui fatos salvos no ctx, restaura-os
        saved_facts = session.ctx.get("_kb_facts")
        if saved_facts:
            # Reconverte o dict simples para defaultdict(list)
            self._facts = defaultdict(list, saved_facts)
        else:
            session.ctx["_kb_facts"] = dict(self._facts)

    def remember(self, key, value):
        if value not in self._facts[key]:
            self._facts[key].append(value)
            if self._session:
                self._session.ctx["_kb_facts"] = dict(self._facts)

    def recall(self, key):
        if self._session and "_kb_facts" in self._session.ctx:
            self._facts = defaultdict(list, self._session.ctx["_kb_facts"])
        return list(self._facts.get(key, []))

    def export(self):
        if self._session and "_kb_facts" in self._session.ctx:
            return dict(self._session.ctx["_kb_facts"])
        return dict(self._facts)

    def sync_from_session(self, session: "Session") -> None:
        # token JWT → kb["jwt_secret"]
        token = session.recall("token", "")
        if token and token.count(".") == 2:
            self.remember("jwt_secret", token)

        # rotas descobertas → admin_endpoint + discovered_path
        for key, val in session.ctx.items():
            if key.startswith("js_hint_"):
                path = val
                if "admin" in path.lower():
                    self.remember("admin_endpoint", path)
                self.remember("discovered_path", path)

        # segredo vazado — session.recall retorna string, não lista  ← CORRIGIDO
        leaked = session.recall("leaked_secret", "")
        if leaked:
            self.remember("leaked_secret", leaked)

        # rotas admin descobertas pelo fuzzer → admin_endpoint  ← NOVO
        all_eps = session.recall("_all_discovered_endpoints", [])
        if isinstance(all_eps, list):
            for ep in all_eps:
                if "admin" in ep.lower():
                    self.remember("admin_endpoint", ep)
