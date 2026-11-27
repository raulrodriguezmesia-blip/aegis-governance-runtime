"""Tests for Aegis Governance Runtime V1.5/V1.6 features."""
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.constitution.engine import ConstitutionEngine
from aegis.ledger.ledger import AegisLedger, compute_payload_hash, compute_event_hash
from aegis.contracts.models import MemoryFact, Verdict, ReasonCode, AuditEvent


def test_engine_loads_active_facts_from_ledger():
    """Test that engine loads active facts from ledger on initialization."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    try:
        ledger = AegisLedger(db_path)
        
        # Create and commit a fact to the ledger
        fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                          confidence=0.9, source="test")
        payload_hash = compute_payload_hash(fact.to_dict())
        event = AuditEvent(
            event_id="evt-001", 
            timestamp_utc="2026-11-25T00:00:00Z",
            actor="test", 
            action="MEMORY_WRITE", 
            verdict="ALLOW", 
            reason_code="NONE", 
            constitution_version="v1.0.0",
            constitution_hash="sha256:test", 
            prev_hash="", 
            payload_hash=payload_hash)
        ledger.append(event, fact.to_dict())
        
        # Create engine with ledger - it should load the active fact
        engine = ConstitutionEngine(confidence_threshold=0.8, ledger=ledger)
        
        # Verify that the fact is in active facts
        active_facts = engine.get_active_facts()
        assert len(active_facts) == 1
        assert active_facts[0].subject == "USER"
        assert active_facts[0].predicate == "LANG"
        assert active_facts[0].value == "JAVA"
        assert active_facts[0].confidence == 0.9
        
        # Verify that evaluating the same fact returns DENY/DUPLICATE (not ALLOW)
        verdict, reason = engine.evaluate(fact)
        assert verdict == Verdict.DENY
        assert reason == ReasonCode.DUPLICATE
        
    finally:
        os.unlink(db_path)


def test_engine_rejects_duplicate_facts():
    """Test that engine properly rejects duplicate facts."""
    engine = ConstitutionEngine(confidence_threshold=0.8)
    
    # Create and commit a fact
    f1 = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                    confidence=0.9, source="test")
    engine.evaluate(f1)
    engine.commit(f1)
    
    # Try to evaluate the same fact again
    f2 = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                    confidence=0.9, source="test")
    verdict, reason = engine.evaluate(f2)
    
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.DUPLICATE


def test_engine_normalizes_value_comparison():
    """Test that value comparison is case-insensitive."""
    engine = ConstitutionEngine(confidence_threshold=0.8)
    
    # Create facts with different cases
    f1 = MemoryFact(subject="USER", predicate="LANG", value="JAVA", confidence=0.9, source="test")
    f2 = MemoryFact(subject="USER", predicate="LANG", value="java", confidence=0.9, source="test")
    
    # Evaluate first fact
    engine.evaluate(f1)
    engine.commit(f1)
    
    # Evaluate second fact - should be denied as duplicate
    verdict, reason = engine.evaluate(f2)
    
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.DUPLICATE


def test_engine_normalizes_source_comparison():
    """Test that source comparison is case-insensitive."""
    engine = ConstitutionEngine(confidence_threshold=0.8)
    
    # Create facts with different source cases
    f1 = MemoryFact(subject="USER", predicate="LANG", value="JAVA", confidence=0.9, source="Test")
    f2 = MemoryFact(subject="USER", predicate="LANG", value="JAVA", confidence=0.9, source="test")
    
    # Evaluate first fact
    engine.evaluate(f1)
    engine.commit(f1)
    
    # Evaluate second fact - should be denied as duplicate
    verdict, reason = engine.evaluate(f2)
    
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.DUPLICATE


def test_engine_rejects_bool_confidence():
    """Test that boolean confidence values are rejected (bool is subclass of int)."""
    engine = ConstitutionEngine(confidence_threshold=0.8)
    
    f1 = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                    confidence=True, source="test")  # bool
    verdict, reason = engine.evaluate(f1)
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.INVALID_SCHEMA
    
    f2 = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                    confidence=False, source="test")
    verdict, reason = engine.evaluate(f2)
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.INVALID_SCHEMA


def test_engine_rejects_nan_inf_confidence():
    """Test that NaN and Inf confidence values are rejected."""
    engine = ConstitutionEngine(confidence_threshold=0.8)
    
    import math
    f1 = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                    confidence=float('nan'), source="test")
    verdict, reason = engine.evaluate(f1)
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.INVALID_SCHEMA
    
    f2 = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                    confidence=float('inf'), source="test")
    verdict, reason = engine.evaluate(f2)
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.INVALID_SCHEMA
    
    f3 = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                    confidence=float('-inf'), source="test")
    verdict, reason = engine.evaluate(f3)
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.INVALID_SCHEMA


def test_engine_persistence_survives_restart():
    """Test that active facts persist across engine restarts via ledger."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    try:
        # First session: create ledger and commit a fact
        ledger1 = AegisLedger(db_path)
        fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                          confidence=0.9, source="test")
        payload_hash = compute_payload_hash(fact.to_dict())
        event = AuditEvent(
            event_id="evt-001", 
            timestamp_utc="2026-11-25T00:00:00Z",
            actor="test", 
            action="MEMORY_WRITE", 
            verdict="ALLOW", 
            reason_code="NONE", 
            constitution_version="v1.0.0",
            constitution_hash="sha256:test", 
            prev_hash="", 
            payload_hash=payload_hash)
        ledger1.append(event, fact.to_dict())
        
        # Second session: new engine with same ledger
        ledger2 = AegisLedger(db_path)
        engine = ConstitutionEngine(confidence_threshold=0.8, ledger=ledger2)
        
        # Fact should be in active memory
        active_facts = engine.get_active_facts()
        assert len(active_facts) == 1
        assert active_facts[0].subject == "USER"
        assert active_facts[0].predicate == "LANG"
        assert active_facts[0].value == "JAVA"
        
        # Duplicate should be rejected
        verdict, reason = engine.evaluate(fact)
        assert verdict == Verdict.DENY
        assert reason == ReasonCode.DUPLICATE
        
    finally:
        os.unlink(db_path)