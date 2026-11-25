"""Aegis Ledger — V1.

Append-only hash chain with payload_hash and event_hash.
"""
import hashlib
import json
import sqlite3
import time
from typing import Optional
from ..contracts.models import AuditEvent


def canonical_json(data: dict) -> str:
    """Produce canonical JSON: sorted keys, no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_payload_hash(payload: dict) -> str:
    """SHA-256 of canonical payload."""
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def compute_event_hash(event: AuditEvent, prev_hash: str) -> str:
    """SHA-256 of canonical event metadata + prev_hash + payload_hash."""
    data = {
        "event_id": event.event_id,
        "timestamp_utc": event.timestamp_utc,
        "actor": event.actor,
        "action": event.action,
        "verdict": event.verdict,
        "reason_code": event.reason_code,
        "constitution_version": event.constitution_version,
        "constitution_hash": event.constitution_hash,
        "payload_hash": event.payload_hash,
    }
    combined = canonical_json(data) + prev_hash
    return hashlib.sha256(combined.encode()).hexdigest()


class AegisLedger:
    """Append-only ledger backed by SQLite."""

    def __init__(self, db_path: str = "aegis_ledger.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp_utc TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason_code TEXT NOT NULL,
                constitution_version TEXT NOT NULL,
                constitution_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
        """)
        conn.commit()
        conn.close()

    def append(self, event: AuditEvent) -> str:
        """Append an event to the ledger. Returns event_hash."""
        prev_hash = self._get_last_hash()
        event.prev_hash = prev_hash
        event.event_hash = compute_event_hash(event, prev_hash)

        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO events (event_id, timestamp_utc, actor, action, verdict, reason_code, "
            "constitution_version, constitution_hash, prev_hash, payload_hash, event_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (event.event_id, event.timestamp_utc, event.actor, event.action,
             event.verdict, event.reason_code, event.constitution_version,
             event.constitution_hash, event.prev_hash, event.payload_hash,
             event.event_hash))
        conn.commit()
        conn.close()
        return event.event_hash

    def _get_last_hash(self) -> str:
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        conn.close()
        return row[0] if row else "0" * 64

    def verify(self) -> dict:
        """Verify the entire chain. Returns status dict."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
        conn.close()

        if not rows:
            return {"status": "EMPTY", "records": 0}

        prev_hash = "0" * 64
        for row in rows:
            (seq, event_id, timestamp, actor, action, verdict, reason_code,
             constitution_version, constitution_hash, stored_prev_hash,
             payload_hash, event_hash) = row

            if stored_prev_hash != prev_hash:
                return {"status": "INTEGRITY BROKEN", "broken_at": seq,
                        "expected_prev": prev_hash, "found_prev": stored_prev_hash}

            # Recompute event_hash
            event = AuditEvent(
                event_id=event_id, timestamp_utc=timestamp, actor=actor,
                action=action, verdict=verdict, reason_code=reason_code,
                constitution_version=constitution_version,
                constitution_hash=constitution_hash,
                prev_hash=stored_prev_hash, payload_hash=payload_hash)
            recomputed = compute_event_hash(event, stored_prev_hash)
            if recomputed != event_hash:
                return {"status": "INTEGRITY BROKEN", "broken_at": seq,
                        "expected_hash": recomputed, "found_hash": event_hash}

            prev_hash = event_hash

        return {"status": "VERIFIED", "records": len(rows)}

    def get_all(self) -> list[dict]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
        conn.close()
        return [dict(zip(["seq", "event_id", "timestamp_utc", "actor", "action",
                          "verdict", "reason_code", "constitution_version",
                          "constitution_hash", "prev_hash", "payload_hash",
                          "event_hash"], r)) for r in rows]

    def tamper(self, seq: int):
        """Tamper with an event (for demo only)."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE events SET verdict='TAMPERED' WHERE seq=?", (seq,))
        conn.commit()
        conn.close()