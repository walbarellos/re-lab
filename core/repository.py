"""
core/repository.py — Camada de Persistência Abstrata.
"""

import sqlite3
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional, List

from .session import Session, RequestRecord
from .models import Vulnerability, Evidence


class Repository(ABC):

    @abstractmethod
    def save_session(self, session: Session) -> bool: ...

    @abstractmethod
    def load_session(self, session_id: str) -> Optional[Session]: ...

    @abstractmethod
    def add_vulnerability(self, session_id: str, vuln: Vulnerability): ...

    @abstractmethod
    def add_evidence(self, session_id: str, evidence: Evidence): ...

    @abstractmethod
    def list_sessions(self) -> List[dict]: ...


class SQLiteRepository(Repository):

    def __init__(self, db_path: str = "data/sessions.db"):
        self.db_path = db_path
        # garante que a pasta existe antes de abrir o arquivo
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    target TEXT,
                    notes TEXT,
                    flags TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    module TEXT,
                    name TEXT,
                    payload TEXT,
                    severity TEXT,
                    confidence REAL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    module TEXT,
                    payload TEXT,
                    status INTEGER,
                    snippet TEXT,
                    confidence REAL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                );
            """)

    def save_session(self, session: Session) -> bool:
        import uuid
        # usa target + timestamp como ID estável (não sobrescreve entre runs)
        session_id = getattr(session, "_id", None)
        if not session_id:
            session_id = str(uuid.uuid4())
            session._id = session_id  # type: ignore[attr-defined]

        with self._get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions (id, target, notes, flags) VALUES (?, ?, ?, ?)",
                (session_id, session.target, json.dumps(session.notes), json.dumps(session.flags)),
            )
            for v in session.vulnerabilities:
                self._add_vulnerability_with_conn(conn, session_id, v)
        return True

    def load_session(self, session_id: str) -> Optional[Session]:
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT target, notes, flags FROM sessions WHERE id = ?", (session_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            s = Session(target=row[0])
            s.notes = json.loads(row[1]) if row[1] else []
            s.flags = json.loads(row[2]) if row[2] else []
            
            v_cursor = conn.execute(
                "SELECT module, name, payload, severity, confidence "
                "FROM vulnerabilities WHERE session_id = ?",
                (session_id,),
            )
            for v_row in v_cursor.fetchall():
                s.vulnerabilities.append(Vulnerability(
                    module=v_row[0], name=v_row[1], payload=v_row[2],
                    severity=v_row[3], confidence=v_row[4],
                ))
            return s

    def _add_vulnerability_with_conn(self, conn, session_id: str, v: Vulnerability):
        conn.execute(
            "INSERT INTO vulnerabilities "
            "(session_id, module, name, payload, severity, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, v.module, v.name, v.payload, v.severity, v.confidence),
        )

    def add_vulnerability(self, session_id: str, v: Vulnerability):
        with self._get_conn() as conn:
            self._add_vulnerability_with_conn(conn, session_id, v)

    def add_evidence(self, session_id: str, e: Evidence):
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO evidence "
                "(session_id, module, payload, status, snippet, confidence) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, e.module, e.payload, e.status,
                 e.response_snippet, e.confidence),
            )

    def list_sessions(self) -> List[dict]:
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT id, target, created_at FROM sessions"
            )
            return [
                {"id": r[0], "target": r[1], "date": r[2]}
                for r in cursor.fetchall()
            ]
