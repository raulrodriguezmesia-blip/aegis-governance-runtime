"""Tests for Aegis Governance Runtime V1."""
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.contracts.models import AuditEvent
from aegis.contracts.models import MemoryFact, Verdict, ReasonCode
from aegis.constitution.engine import ConstitutionEngine
from aegis.ledger.ledger import AegisLedger, compute_payload_hash, compute_event_hash


def test_valid_fact_allows():
    engine = ConstitutionEngine()
    fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                      confidence=0.9, source="test")
    verdict, reason = engine.evaluate(fact)
    assert verdict == Verdict.ALLOW
    assert reason == ReasonCode.NONE


def test_duplicate_denies():
    engine = ConstitutionEngine()
    f1 = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                    confidence=0.9, source="test")
    engine.evaluate(f1)
    engine.commit(f1)
    f2 = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                    confidence=0.9, source="test")
    verdict, reason = engine.evaluate(f2)
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.DUPLICATE


def test_contradiction_quarantines():
    engine = ConstitutionEngine()
    f1 = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                    confidence=0.9, source="test")
    engine.evaluate(f1)
    engine.commit(f1)
    f2 = MemoryFact(subject="USER", predicate="LANG", value="PYTHON",
                    confidence=0.9, source="test")
    verdict, reason = engine.evaluate(f2)
    assert verdict == Verdict.QUARANTINE
    assert reason == ReasonCode.CONTRADICTION


def test_missing_source_denies():
    engine = ConstitutionEngine()
    fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                      confidence=0.9, source="")
    verdict, reason = engine.evaluate(fact)
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.MISSING_SOURCE


def test_low_confidence_quarantines():
    engine = ConstitutionEngine()
    fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                      confidence=0.5, source="test")
    verdict, reason = engine.evaluate(fact)
    assert verdict == Verdict.QUARANTINE
    assert reason == ReasonCode.LOW_CONFIDENCE


def test_invalid_schema_denies():
    engine = ConstitutionEngine()
    fact = MemoryFact(subject="", predicate="LANG", value="JAVA",
                      confidence=0.9, source="test")
    verdict, reason = engine.evaluate(fact)
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.INVALID_SCHEMA


def test_ledger_chain_verifies():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
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
    status = ledger.verify()
    assert status["status"] == "VERIFIED"
    os.unlink(db)


def test_tamper_detected():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db = f.name
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
    from aegis.demo.tamper import tamper_event_verdict
    tamper_event_verdict(db, 1)
    status = ledger.verify()
    assert "BROKEN" in status["status"]
    os.unlink(db)


def test_determinism():
    """Same input must always produce same hash."""
    fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                      confidence=0.9, source="test")
    h1 = compute_payload_hash(fact.to_dict())
    h2 = compute_payload_hash(fact.to_dict())
    assert h1 == h2