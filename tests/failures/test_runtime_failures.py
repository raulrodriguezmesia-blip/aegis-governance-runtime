"""Aegis Runtime Failure Suite.

Verifies that Aegis fails in a controlled, predictable manner — never with
an unhandled traceback — across runtime failures. Expected outcomes: DENY,
ERROR CONTROLADO, or ABORT.
"""
import sys
import os
import sqlite3
import json
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from aegis.constitution.engine import ConstitutionEngine
from aegis.ledger.ledger import AegisLedger, compute_payload_hash
from aegis.contracts.models import MemoryFact, Verdict, ReasonCode, AuditEvent


def test_runtime_corrupt_db_no_allow():
    """Corrupt SQLite file → no ALLOW; engine must fail closed safely."""
    # Create a garbage file that looks like a path but isn't a SQLite DB
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        # Write garbage bytes to corrupt the DB
        with open(db_path, "wb") as f:
            f.write(b"not-a-valid-sqlite-file-at-all" * 10)
        try:
            ledger = AegisLedger(db_path)  # this will raise DatabaseError
            engine = ConstitutionEngine(confidence_threshold=0.8, ledger=ledger)
            fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                              confidence=0.9, source="test")
            verdict, reason = engine.evaluate(fact)
            assert verdict != Verdict.ALLOW, \
                "Engine must not ALLOW with corrupt DB"
        except sqlite3.DatabaseError:
            # DB is corrupt → ledger cannot open → fail closed (no crash)
            pass
        finally:
            try:
                os.unlink(db_path)
            except PermissionError:
                pass
    finally:
        pass


def test_runtime_missing_file_no_crash():
    """Missing ledger file → engine must not crash; evaluates on empty state."""
    ledger = AegisLedger("/tmp/definitely-missing-aegis-ledger.db")
    engine = ConstitutionEngine(confidence_threshold=0.8, ledger=ledger)
    fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                      confidence=0.9, source="test")
    verdict, reason = engine.evaluate(fact)
    # With no active facts, a valid fact can ALLOW (correct V1 behavior).
    # Key requirement: no unhandled traceback/crash.
    assert verdict in (Verdict.ALLOW, Verdict.DENY, Verdict.QUARANTINE)


def test_runtime_invalid_json_payload_no_allow():
    """Invalid JSON in stored payload must not allow memory through."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        ledger = AegisLedger(db_path)
        fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                          confidence=0.9, source="test")
        payload_hash = compute_payload_hash(fact.to_dict())
        event = AuditEvent(
            event_id="evt-001", timestamp_utc="2026-11-25T00:00:00Z",
            actor="test", action="MEMORY_WRITE", verdict="ALLOW",
            reason_code="NONE", constitution_version="v1.0.0",
            constitution_hash="sha256:test", prev_hash="",
            payload_hash=payload_hash)
        # Store invalid JSON payload
        ledger.append(event, None)
        # Engine loads: with null payload it should not load the fact
        engine = ConstitutionEngine(confidence_threshold=0.8, ledger=ledger)
        active = engine.get_active_facts()
        assert len(active) == 0
        # Evaluating the same fact should ALLOW (no prior state to conflict)
        verdict, reason = engine.evaluate(fact)
        assert verdict == Verdict.ALLOW
    finally:
        try:
            os.unlink(db_path)
        except PermissionError:
            pass


def test_runtime_incomplete_payload_denies():
    """Incomplete payload (missing required fields) → DENY/INVALID_SCHEMA."""
    engine = ConstitutionEngine(confidence_threshold=0.8)
    fact = MemoryFact(subject="", predicate="LANG", value="JAVA",
                      confidence=0.9, source="test")
    verdict, reason = engine.evaluate(fact)
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.INVALID_SCHEMA


def test_runtime_null_fields_denies():
    """NULL/empty fields → DENY/INVALID_SCHEMA or DENY/MISSING_SOURCE, never ALLOW."""
    engine = ConstitutionEngine(confidence_threshold=0.8)
    fact = MemoryFact(subject=None, predicate="LANG", value="JAVA",
                      confidence=0.9, source="test")
    verdict, reason = engine.evaluate(fact)
    assert verdict == Verdict.DENY

    fact2 = MemoryFact(subject="USER", predicate=None, value="JAVA",
                       confidence=0.9, source="test")
    verdict2, reason2 = engine.evaluate(fact2)
    assert verdict2 == Verdict.DENY

    fact3 = MemoryFact(subject="USER", predicate="LANG", value=None,
                       confidence=0.9, source="test")
    verdict3, reason3 = engine.evaluate(fact3)
    assert verdict3 == Verdict.DENY


def test_runtime_invalid_confidence_denies():
    """Invalid confidence (NaN/inf/out-of-range/bool) → DENY/INVALID_SCHEMA."""
    engine = ConstitutionEngine(confidence_threshold=0.8)
    bad_confidences = [float('nan'), float('inf'), float('-inf'), -0.1, 1.5, True, False]
    for c in bad_confidences:
        fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                          confidence=c, source="test")
        verdict, reason = engine.evaluate(fact)
        assert verdict == Verdict.DENY, f"confidence={c} must DENY, got {verdict}"
        assert reason == ReasonCode.INVALID_SCHEMA
