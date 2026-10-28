"""SQLite persistence for JIT requests/grants, the audit log and the demo service inventory."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

audit_log = logging.getLogger("audit")

SCHEMA = """
CREATE TABLE IF NOT EXISTS jit_requests (
    id                 TEXT PRIMARY KEY,
    requester_oid      TEXT NOT NULL,
    requester_name     TEXT NOT NULL,
    requester_username TEXT NOT NULL,
    tool               TEXT NOT NULL,
    args_json          TEXT NOT NULL,
    bound_json         TEXT NOT NULL,
    fingerprint        TEXT NOT NULL,
    justification      TEXT NOT NULL DEFAULT '',
    ttl_seconds        INTEGER NOT NULL,
    single_use         INTEGER NOT NULL DEFAULT 0,
    status             TEXT NOT NULL,          -- pending|approved|denied|revoked|used|expired
    created_at         REAL NOT NULL,
    request_expires_at REAL NOT NULL,
    decided_at         REAL,
    decided_by_oid     TEXT,
    decided_by_name    TEXT,
    grant_expires_at   REAL,
    use_count          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_req_lookup ON jit_requests (requester_oid, tool, fingerprint, status);

CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    event      TEXT NOT NULL,
    actor_oid  TEXT,
    actor_name TEXT,
    request_id TEXT,
    tool       TEXT,
    detail     TEXT
);

CREATE TABLE IF NOT EXISTS services (
    name         TEXT NOT NULL,
    env          TEXT NOT NULL,
    status       TEXT NOT NULL,
    replicas     INTEGER NOT NULL,
    version      TEXT NOT NULL,
    secret_ver   INTEGER NOT NULL DEFAULT 1,
    last_change  REAL,
    last_actor   TEXT,
    last_action  TEXT,
    PRIMARY KEY (name, env)
);
"""

SEED_SERVICES = [
    ("payments", "dev", 1, "2.4.1"),
    ("payments", "prod", 4, "2.4.0"),
    ("orders", "dev", 1, "1.9.3"),
    ("orders", "prod", 3, "1.9.2"),
    ("inventory", "dev", 1, "3.1.0"),
    ("inventory", "prod", 2, "3.0.7"),
]


@dataclass
class JitRequest:
    id: str
    requester_oid: str
    requester_name: str
    requester_username: str
    tool: str
    args: dict[str, Any]
    bound: dict[str, Any]
    fingerprint: str
    justification: str
    ttl_seconds: int
    single_use: bool
    status: str
    created_at: float
    request_expires_at: float
    decided_at: float | None
    decided_by_oid: str | None
    decided_by_name: str | None
    grant_expires_at: float | None
    use_count: int

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "JitRequest":
        d = dict(row)
        d["args"] = json.loads(d.pop("args_json"))
        d["bound"] = json.loads(d.pop("bound_json"))
        d["single_use"] = bool(d["single_use"])
        return cls(**d)


class Store:
    def __init__(self, path: str, clock: Callable[[], float] = time.time):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._seed()

    # ---- low level ------------------------------------------------------
    def _exec(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, params)

    def _seed(self) -> None:
        if self._exec("SELECT COUNT(*) FROM services").fetchone()[0]:
            return
        for name, env, replicas, version in SEED_SERVICES:
            self._exec(
                "INSERT INTO services (name, env, status, replicas, version) VALUES (?, ?, 'running', ?, ?)",
                (name, env, replicas, version),
            )

    # ---- audit ----------------------------------------------------------
    def audit(self, event: str, *, actor_oid=None, actor_name=None, request_id=None, tool=None, **detail) -> None:
        ts = self.clock()
        self._exec(
            "INSERT INTO audit (ts, event, actor_oid, actor_name, request_id, tool, detail) VALUES (?,?,?,?,?,?,?)",
            (ts, event, actor_oid, actor_name, request_id, tool, json.dumps(detail, default=str)),
        )
        audit_log.info(
            json.dumps(
                {"ts": ts, "event": event, "actor": actor_name, "actor_oid": actor_oid,
                 "request_id": request_id, "tool": tool, **detail},
                default=str,
            )
        )

    def recent_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._exec("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"] or "{}")} for r in rows]

    # ---- JIT requests ---------------------------------------------------
    def insert_request(self, req: JitRequest) -> None:
        self._exec(
            """INSERT INTO jit_requests (id, requester_oid, requester_name, requester_username, tool, args_json,
               bound_json, fingerprint, justification, ttl_seconds, single_use, status, created_at,
               request_expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (req.id, req.requester_oid, req.requester_name, req.requester_username, req.tool,
             json.dumps(req.args, sort_keys=True), json.dumps(req.bound, sort_keys=True), req.fingerprint,
             req.justification, req.ttl_seconds, int(req.single_use), req.status, req.created_at,
             req.request_expires_at),
        )

    def get_request(self, request_id: str) -> JitRequest | None:
        row = self._exec("SELECT * FROM jit_requests WHERE id = ?", (request_id,)).fetchone()
        return JitRequest.from_row(row) if row else None

    def find(self, requester_oid: str, tool: str, fingerprint: str, status: str) -> JitRequest | None:
        row = self._exec(
            """SELECT * FROM jit_requests WHERE requester_oid=? AND tool=? AND fingerprint=? AND status=?
               ORDER BY created_at DESC LIMIT 1""",
            (requester_oid, tool, fingerprint, status),
        ).fetchone()
        return JitRequest.from_row(row) if row else None

    def update_request(self, request_id: str, **fields: Any) -> None:
        cols = ", ".join(f"{k} = :{k}" for k in fields)
        self._exec(f"UPDATE jit_requests SET {cols} WHERE id = :id", {**fields, "id": request_id})

    def list_requests(self, *, status: str | None = None, requester_oid: str | None = None,
                      limit: int = 100) -> list[JitRequest]:
        sql, params = "SELECT * FROM jit_requests WHERE 1=1", []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if requester_oid:
            sql += " AND requester_oid = ?"
            params.append(requester_oid)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [JitRequest.from_row(r) for r in self._exec(sql, tuple(params)).fetchall()]

    def due_for_expiry(self, now: float) -> list[JitRequest]:
        rows = self._exec(
            """SELECT * FROM jit_requests
               WHERE (status='pending' AND request_expires_at <= ?)
                  OR (status='approved' AND grant_expires_at <= ?)""",
            (now, now),
        ).fetchall()
        return [JitRequest.from_row(r) for r in rows]

    # ---- demo service inventory ----------------------------------------
    def services(self, env: str | None = None) -> list[dict[str, Any]]:
        if env:
            rows = self._exec("SELECT * FROM services WHERE env = ? ORDER BY name", (env,)).fetchall()
        else:
            rows = self._exec("SELECT * FROM services ORDER BY env, name").fetchall()
        return [dict(r) for r in rows]

    def service(self, name: str, env: str) -> dict[str, Any] | None:
        row = self._exec("SELECT * FROM services WHERE name = ? AND env = ?", (name, env)).fetchone()
        return dict(row) if row else None

    def update_service(self, name: str, env: str, **fields: Any) -> None:
        cols = ", ".join(f"{k} = :{k}" for k in fields)
        self._exec(f"UPDATE services SET {cols} WHERE name = :name AND env = :env", {**fields, "name": name, "env": env})
