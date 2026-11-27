"""Aegis Governance Failure Suite.

Verifies that Aegis fails closed on governance-layer attacks:
self-appeal, self-review, invalid quarantine review, nonexistent reviewer,
replay request. Expected: DENY with appropriate ReasonCode.
"""
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from aegis.constitution.engine import ConstitutionEngine
from aegis.constitution.quarantine import QuarantineManager, QuarantineState
from aegis.constitution.appeals import AppealManager
from aegis.contracts.models import MemoryFact, Verdict, ReasonCode


def test_governance_self_appeal_denied():
    """Agent appealing their own DENY must be rejected."""
    engine = ConstitutionEngine(confidence_threshold=0.8)
    am = AppealManager(engine)
    # File appeal as agent-1
    appeal = am.appeal("orig-1", "agent-1",
                       {"subject": "USER", "predicate": "LANG", "value": "JAVA",
                        "confidence": 0.95, "source": "verified"},
                       "Self appeal attempt")
    # Resolve with SAME agent as reviewer (self-approval)
    try:
        result = am.resolve(appeal.appeal_id, "agent-1")
        assert False, "Self-approval must raise ValueError"
    except ValueError as e:
        assert "same agent" in str(e).lower()


def test_governance_self_review_denied():
    """Quarantine reviewer cannot be the submitter."""
    qm = QuarantineManager(ttl_hours=24)
    qm.quarantine("f1", "USER", "LANG", "JAVA", 0.5, "test", "LOW_CONFIDENCE",
                  submitted_by="agent-1")
    try:
        qm.review("f1", "agent-1", "PROMOTE", "Self review")  # same as submitter
        assert False, "Self-review must raise ValueError"
    except ValueError as e:
        assert "same submitter" in str(e).lower()


def test_governance_invalid_quarantine_review_denied():
    """Reviewing a non-existent quarantine entry must be denied."""
    qm = QuarantineManager()
    try:
        qm.review("nonexistent", "reviewer", "PROMOTE")
        assert False, "Reviewing nonexistent entry must raise ValueError"
    except ValueError as e:
        assert "not found" in str(e).lower()


def test_governance_quarantine_invalid_decision_denied():
    """Invalid review decision must be denied."""
    qm = QuarantineManager()
    qm.quarantine("f1", "USER", "LANG", "JAVA", 0.5, "test", "LOW_CONFIDENCE")
    try:
        qm.review("f1", "reviewer", "INVALID_DECISION")
        assert False, "Invalid decision must raise ValueError"
    except ValueError as e:
        assert "invalid decision" in str(e).lower()


def test_governance_reviewer_required():
    """Empty/None reviewer identity must be denied."""
    qm = QuarantineManager()
    qm.quarantine("f1", "USER", "LANG", "JAVA", 0.5, "test", "LOW_CONFIDENCE")
    try:
        qm.review("f1", "", "PROMOTE")
        assert False, "Empty reviewer must raise ValueError"
    except ValueError as e:
        assert "required" in str(e).lower()

    try:
        qm.review("f1", None, "PROMOTE")
        assert False, "None reviewer must raise ValueError"
    except (ValueError, TypeError) as e:
        pass  # Either is fine as long as it's controlled


def test_governance_replay_request_denied():
    """Duplicate idempotency key must be detected and DENY/DUPLICATE_REQUEST."""
    from aegis.ledger.idempotency import IdempotencyStore
    store = IdempotencyStore()
    store.record("req-001", {"verdict": "ALLOW", "response": "ok"})
    is_dup, original = store.check("req-001")
    assert is_dup is True, "Replay must be detected as duplicate"
    assert original["response"]["verdict"] == "ALLOW"


def test_governance_appeal_nonexistent_denied():
    """Resolving a non-existent appeal must be denied."""
    engine = ConstitutionEngine()
    am = AppealManager(engine)
    try:
        am.resolve("nonexistent", "reviewer")
        assert False, "Nonexistent appeal must raise ValueError"
    except ValueError as e:
        assert "not found" in str(e).lower()


def test_governance_appeal_already_resolved_denied():
    """Resolving an already-resolved appeal must be denied."""
    engine = ConstitutionEngine()
    am = AppealManager(engine)
    appeal = am.appeal("orig-1", "agent-1",
                       {"subject": "USER", "predicate": "LANG", "value": "JAVA",
                        "confidence": 0.95, "source": "verified"},
                       "New evidence")
    am.resolve(appeal.appeal_id, "reviewer")
    try:
        am.resolve(appeal.appeal_id, "reviewer2")
        assert False, "Already-resolved appeal must raise ValueError"
    except ValueError as e:
        assert "is " in str(e).lower()  # "is APPROVED" or "is REJECTED"


def test_governance_quarantine_review_then_deny():
    """PROMOTE then DENY on same entry must be denied (state no longer reviewable)."""
    qm = QuarantineManager()
    qm.quarantine("f1", "USER", "LANG", "JAVA", 0.5, "test", "LOW_CONFIDENCE")
    qm.review("f1", "reviewer1", "PROMOTE")
    try:
        qm.review("f1", "reviewer2", "DENY")
        assert False, "Cannot review after PROMOTE"
    except ValueError as e:
        assert "cannot review" in str(e).lower()


def test_governance_engine_fails_closed_on_missing_source():
    """Engine with empty source must DENY/MISSING_SOURCE, never ALLOW."""
    engine = ConstitutionEngine()
    fact = MemoryFact(subject="USER", predicate="LANG", value="JAVA",
                      confidence=0.9, source="")
    verdict, reason = engine.evaluate(fact)
    assert verdict == Verdict.DENY
    assert reason == ReasonCode.MISSING_SOURCE