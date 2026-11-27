"""Aegis Attack Validation Suite — Ledger Attacks.

These tests verify that Aegis never returns ALLOW when ledger integrity
is compromised. Every attack must result in INTEGRITY BROKEN, VERIFY_FAILED,
or DENY — never ALLOW.
"""
import sys
import os
import json
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from aegis.contracts.models import MemoryFact, Verdict, ReasonCode, AuditEvent
from aegis.constitution.engine import ConstitutionEngine
from aegis.ledger.ledger import AegisLedger, compute_payload_hash
from aegis.demo.tamper import tamper_event_verdict, tamper_event_payload, truncate_tail


def _make_ledger_with_events(db_path, count=3):
    """Create a ledger with `count` ALLOW events and return it."""
    ledger = AegisLedger(db_path)
    for i in range(count):
        fact = MemoryFact(subject="USER", predicate="LANG", value=f"VALUE-{i}",
                          confidence=0.9, source="test")
        payload_hash = compute_payload_hash(fact.to_dict())
        event = AuditEvent(
            event_id=f"evt-{i:04d}",
            timestamp_utc=f"2026-11-25T00:00:{i:02d}Z",
            actor="test", action="MEMORY_WRITE", verdict="ALLOW",
            reason_code="NONE", constitution_version="v1.0.0",
            constitution_hash="sha256:test", prev_hash="",
            payload_hash=payload_hash)
        ledger.append(event, fact.to_dict())
    return ledger


def test_ledger_attack_payload_modification():
    """Tampering with a stored payload must yield INTEGRITY BROKEN."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    try:
        ledger = _make_ledger_with_events(db)
        tamper_event_payload(db, 1, '{"tampered": true}')
        status = ledger.verify()
        assert status["status"] == "INTEGRITY BROKEN", f"Expected INTEGRITY BROKEN, got {status['status']}"
    finally:
        os.unlink(db)


def test_ledger_attack_chain_rewrite():
    """Modifying an event's prev_hash breaks chain continuity → INTEGRITY BROKEN."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    try:
        ledger = _make_ledger_with_events(db)
        import sqlite3
        conn = sqlite3.connect(db)
        conn.execute("DROP TRIGGER IF EXISTS prevent_update")
        conn.execute("UPDATE events SET prev_hash=? WHERE seq=2", ("0" * 64,))
        conn.commit()
        conn.execute("""CREATE TRIGGER IF NOT EXISTS prevent_update
            BEFORE UPDATE ON events
            BEGIN
                SELECT RAISE(ABORT, 'UPDATE on events table is not allowed');
            END;""")
        conn.commit()
        conn.close()
        status = ledger.verify()
        assert status["status"] == "INTEGRITY BROKEN", f"Expected INTEGRITY BROKEN, got {status['status']}"
    finally:
        os.unlink(db)


def test_ledger_attack_tail_truncation():
    """Tail truncation is invisible to the pure hash chain, but the signed
    checkpoint (H-02) detects it. This test proves the checkpoint is the
    defense-in-depth layer that catches an internally-consistent truncation.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    checkpoint_path = db + ".checkpoint.json"
    try:
        ledger = _make_ledger_with_events(db, count=5)
        status_before = ledger.verify()
        assert status_before["status"] == "VERIFIED"
        # Anchor the full chain with a signed checkpoint BEFORE truncation
        ledger.create_checkpoint(checkpoint_path)
        # Truncate tail: keep only first event
        truncate_tail(db, keep=1)
        # The remaining records form a self-consistent sub-chain, so the pure
        # hash chain still verifies — this is the honest limitation.
        status_chain = ledger.verify()
        assert status_chain["status"] == "VERIFIED", \
            f"Pure hash chain cannot detect internally-consistent truncation: {status_chain}"
        # The signed checkpoint, however, detects the truncation.
        status_checkpoint = ledger.verify_checkpoint(checkpoint_path)
        assert status_checkpoint["status"] in ("INTEGRITY MISMATCH", "SIGNATURE_INVALID"), \
            f"Checkpoint must detect tail truncation, got {status_checkpoint['status']}"
    finally:
        for p in (db, checkpoint_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def test_ledger_attack_deleted_record():
    """Deleting a record via bypass must yield INTEGRITY BROKEN."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    try:
        ledger = _make_ledger_with_events(db)
        status_before = ledger.verify()
        assert status_before["status"] == "VERIFIED"
        import sqlite3
        conn = sqlite3.connect(db)
        conn.execute("DROP TRIGGER IF EXISTS prevent_delete")
        conn.execute("DELETE FROM events WHERE seq=2")
        conn.commit()
        conn.execute("""CREATE TRIGGER IF NOT EXISTS prevent_delete
            BEFORE DELETE ON events
            BEGIN
                SELECT RAISE(ABORT, 'DELETE on events table is not allowed');
            END;""")
        conn.commit()
        conn.close()
        status_after = ledger.verify()
        assert status_after["status"] == "INTEGRITY BROKEN", \
            f"Expected INTEGRITY BROKEN after delete, got {status_after['status']}"
    finally:
        os.unlink(db)


def test_ledger_attack_missing_checkpoint():
    """A missing external checkpoint must be VERIFY_FAILED, not VERIFIED."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    try:
        ledger = AegisLedger(db)
        fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                          confidence=0.9, source="test")
        payload_hash = compute_payload_hash(fact.to_dict())
        event = AuditEvent(
            event_id="evt-001", timestamp_utc="2026-11-25T00:00:00Z",
            actor="test", action="MEMORY_WRITE", verdict="ALLOW",
            reason_code="NONE", constitution_version="v1.0.0",
            constitution_hash="sha256:test", prev_hash="",
            payload_hash=payload_hash)
        ledger.append(event, fact.to_dict())
        checkpoint_path = db + ".checkpoint.json"
        if os.path.exists(checkpoint_path):
            os.unlink(checkpoint_path)
        result = ledger.verify_checkpoint(checkpoint_path)
        assert result["status"] == "CHECKPOINT_NOT_FOUND", \
            f"Expected CHECKPOINT_NOT_FOUND, got {result['status']}"
    finally:
        os.unlink(db)


def test_ledger_attack_invalid_signature():
    """A checkpoint with an invalid signature must be SIGNATURE_INVALID."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    try:
        ledger = AegisLedger(db)
        fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                          confidence=0.9, source="test")
        payload_hash = compute_payload_hash(fact.to_dict())
        event = AuditEvent(
            event_id="evt-001", timestamp_utc="2026-11-25T00:00:00Z",
            actor="test", action="MEMORY_WRITE", verdict="ALLOW",
            reason_code="NONE", constitution_version="v1.0.0",
            constitution_hash="sha256:test", prev_hash="",
            payload_hash=payload_hash)
        ledger.append(event, fact.to_dict())
        checkpoint_path = db + ".checkpoint.json"
        ledger.create_checkpoint(checkpoint_path)
        with open(checkpoint_path, "r") as cf:
            checkpoint = json.load(cf)
        checkpoint["signature"] = "deadbeef" * 8
        with open(checkpoint_path, "w") as cf:
            json.dump(checkpoint, cf)
        result = ledger.verify_checkpoint(checkpoint_path)
        assert result["status"] == "SIGNATURE_INVALID", \
            f"Expected SIGNATURE_INVALID, got {result['status']}"
    finally:
        os.unlink(db)


def test_engine_never_allows_on_broken_ledger():
    """Engine evaluation must not return ALLOW when ledger integrity broken."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
    try:
        ledger = _make_ledger_with_events(db)
        tamper_event_verdict(db, 1, "TAMPERED")
        status = ledger.verify()
        assert status["status"] == "INTEGRITY BROKEN"
        engine = ConstitutionEngine(confidence_threshold=0.8, ledger=ledger)
        fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                          confidence=0.9, source="test")
        verdict, reason = engine.evaluate(fact)
        assert verdict != Verdict.ALLOW, \
            f"Engine must not ALLOW on broken ledger integrity: {verdict}"
    finally:
        os.unlink(db)