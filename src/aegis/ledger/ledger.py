"""Aegis Ledger — V1.6.

Append-only hash chain with payload_hash and event_hash.
V1.6: Signed checkpoint outside the DB for external integrity verification.
"""
import hashlib
import hmac
import json
import os
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
                event_hash TEXT NOT NULL,
                payload TEXT
            );

            CREATE TRIGGER IF NOT EXISTS prevent_update
            BEFORE UPDATE ON events
            BEGIN
                SELECT RAISE(ABORT, 'UPDATE on events table is not allowed');
            END;

            CREATE TRIGGER IF NOT EXISTS prevent_delete
            BEFORE DELETE ON events
            BEGIN
                SELECT RAISE(ABORT, 'DELETE on events table is not allowed');
            END;
        """)
        conn.commit()
        conn.close()

    def append(self, event: AuditEvent, payload: dict = None) -> str:
        """Append an event to the ledger. Returns event_hash."""
        prev_hash = self._get_last_hash()
        event.prev_hash = prev_hash
        event.event_hash = compute_event_hash(event, prev_hash)

        payload_json = json.dumps(payload, sort_keys=True) if payload else None

        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO events (event_id, timestamp_utc, actor, action, verdict, reason_code, "
            "constitution_version, constitution_hash, prev_hash, payload_hash, event_hash, payload) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (event.event_id, event.timestamp_utc, event.actor, event.action,
             event.verdict, event.reason_code, event.constitution_version,
             event.constitution_hash, event.prev_hash, event.payload_hash,
             event.event_hash, payload_json))
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
             payload_hash, event_hash, payload) = row

            if stored_prev_hash != prev_hash:
                return {"status": "INTEGRITY BROKEN", "broken_at": seq,
                        "expected_prev": prev_hash, "found_prev": stored_prev_hash}

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

            if payload is not None:
                try:
                    payload_dict = json.loads(payload)
                    expected_payload_hash = compute_payload_hash(payload_dict)
                except (json.JSONDecodeError, TypeError):
                    expected_payload_hash = compute_payload_hash(payload)
            else:
                expected_payload_hash = compute_payload_hash(None)
            if payload_hash != expected_payload_hash:
                return {"status": "INTEGRITY BROKEN", "broken_at": seq,
                        "expected_payload_hash": expected_payload_hash,
                        "found_payload_hash": payload_hash}

            prev_hash = event_hash

        return {"status": "VERIFIED", "records": len(rows)}

    def get_all(self) -> list[dict]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
        conn.close()
        keys = ["seq", "event_id", "timestamp_utc", "actor", "action",
                "verdict", "reason_code", "constitution_version",
                "constitution_hash", "prev_hash", "payload_hash",
                "event_hash"]
        return [dict(zip(keys, r)) for r in rows]

    def create_checkpoint(self, checkpoint_path: str) -> str:
        """Create a signed checkpoint of the ledger state (V1.6)."""
        last_hash = self._get_last_hash()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        key = os.environ.get("AEGIS_CHECKPOINT_KEY", None)
        if key is None:
            key_path = os.path.join(os.path.dirname(os.path.abspath(checkpoint_path)), ".checkpoint_key")
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    key = f.read().decode()
            else:
                key = "aegis-default-checkpoint-key"
        sig_key = key.encode() if isinstance(key, str) else key
        signature = hmac.new(sig_key, last_hash.encode(), hashlib.sha256).hexdigest()
        checkpoint = {
            "last_hash": last_hash,
            "timestamp_utc": timestamp,
            "signature": signature,
            "records": len(self.get_all()),
        }
        os.makedirs(os.path.dirname(os.path.abspath(checkpoint_path)), exist_ok=True)
        with open(checkpoint_path, "w") as f:
            json.dump(checkpoint, f)
        return checkpoint_path

    def verify_checkpoint(self, checkpoint_path: str) -> dict:
        """Verify a signed checkpoint against the live ledger state (V1.6)."""
        if not os.path.exists(checkpoint_path):
            return {"status": "CHECKPOINT_NOT_FOUND", "checkpoint_path": checkpoint_path}
        try:
            with open(checkpoint_path, "r") as f:
                checkpoint = json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"status": "CHECKPOINT_CORRUPT"}

        stored_last_hash = checkpoint.get("last_hash")
        signature = checkpoint.get("signature")
        if not stored_last_hash or not signature:
            return {"status": "CHECKPOINT_INVALID", "missing_fields": ["last_hash", "signature"]}

        live_last_hash = self._get_last_hash()
        key = os.environ.get("AEGIS_CHECKPOINT_KEY", None)
        if key is None:
            key_path = os.path.join(os.path.dirname(os.path.abspath(checkpoint_path)), ".checkpoint_key")
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    key = f.read().decode()
            else:
                key = "aegis-default-checkpoint-key"
        sig_key = key.encode() if isinstance(key, str) else key
        expected_sig = hmac.new(sig_key, stored_last_hash.encode(), hashlib.sha256).hexdigest()

        if signature == expected_sig and stored_last_hash == live_last_hash:
            return {"status": "VERIFIED", "last_hash": stored_last_hash, "records": checkpoint.get("records", 0)}
        if signature != expected_sig:
            return {"status": "SIGNATURE_INVALID", "stored_sig": signature, "expected_sig": expected_sig,
                    "last_hash": stored_last_hash, "live_last_hash": live_last_hash}
        return {"status": "INTEGRITY MISMATCH", "stored_last_hash": stored_last_hash,
                "live_last_hash": live_last_hash, "signature_valid": True}
