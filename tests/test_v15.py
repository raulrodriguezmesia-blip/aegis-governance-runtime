"""Tests for Aegis V1.5 features."""
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.constitution.quarantine import QuarantineManager, QuarantineState
from aegis.constitution.signing import ConstitutionSigner, generate_keypair
from aegis.constitution.appeals import AppealManager
from aegis.constitution.engine import ConstitutionEngine
from aegis.ledger.idempotency import IdempotencyStore
from aegis.contracts.models import MemoryFact


# --- Quarantine Lifecycle ---

def test_quarantine_pending():
    qm = QuarantineManager(ttl_hours=24)
    entry = qm.quarantine("f1", "USER", "LANG", "JAVA", 0.5, "test", "LOW_CONFIDENCE")
    assert entry.state == QuarantineState.PENDING
    assert len(qm.get_pending()) == 1


def test_quarantine_promote():
    qm = QuarantineManager()
    qm.quarantine("f1", "USER", "LANG", "JAVA", 0.5, "test", "LOW_CONFIDENCE")
    qm.review("f1", "auditor", "PROMOTE", "Evidence verified")
    entry = qm._entries["f1"]
    assert entry.state == QuarantineState.PROMOTED


def test_quarantine_deny():
    qm = QuarantineManager()
    qm.quarantine("f1", "USER", "LANG", "JAVA", 0.5, "test", "LOW_CONFIDENCE")
    qm.review("f1", "auditor", "DENY", "Insufficient evidence")
    entry = qm._entries["f1"]
    assert entry.state == QuarantineState.DENIED


def test_quarantine_expire():
    qm = QuarantineManager(ttl_hours=0.0000001)
    qm.quarantine("f1", "USER", "LANG", "JAVA", 0.5, "test", "LOW_CONFIDENCE")
    entry = qm._entries["f1"]
    entry.expires_at = "2020-01-01T00:00:00Z"
    expired = qm.expire_old()
    assert expired == 1
    assert entry.state == QuarantineState.EXPIRED


# --- Constitution Signing ---

def test_constitution_sign_verify():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("version: 1.0.0\nrules: []\n")
        path = f.name

    signer = ConstitutionSigner(path)
    priv, pub = generate_keypair()
    sig = signer.sign(priv)
    assert len(sig) > 0

    ok, msg = signer.verify_at_startup(pub)
    assert ok
    assert msg == "CONSTITUTION_VERIFIED"
    os.unlink(path)
    os.unlink(path + ".sig")
    os.unlink(path + ".sha256")


def test_constitution_tampered():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("version: 1.0.0\nrules: []\n")
        path = f.name

    signer = ConstitutionSigner(path)
    priv, pub = generate_keypair()
    signer.sign(priv)

    with open(path, "w") as f:
        f.write("version: 2.0.0\nrules: [EVIL]\n")

    ok, msg = signer.verify_at_startup(pub)
    assert not ok
    assert "COMPROMISED" in msg
    os.unlink(path)
    os.unlink(path + ".sig")
    os.unlink(path + ".sha256")


# --- Reverse Governance ---

def test_appeal_promote():
    engine = ConstitutionEngine()
    am = AppealManager(engine)
    appeal = am.appeal("orig-1", "agent-1", {
        "subject": "USER", "predicate": "LANG", "value": "JAVA",
        "confidence": 0.95, "source": "verified"
    }, "New evidence provided")
    result = am.resolve(appeal.appeal_id, "reviewer-1")
    assert result["status"] == "APPROVED"
    assert result["verdict"] == "ALLOW"


def test_appeal_reject():
    engine = ConstitutionEngine()
    am = AppealManager(engine)
    appeal = am.appeal("orig-1", "agent-1", {
        "subject": "USER", "predicate": "LANG", "value": "JAVA",
        "confidence": 0.3, "source": ""
    }, "Weak appeal")
    result = am.resolve(appeal.appeal_id, "reviewer-1")
    assert result["status"] == "REJECTED"


# --- Idempotency ---

def test_idempotency_duplicate():
    store = IdempotencyStore()
    is_dup, _ = store.check("req-001")
    assert not is_dup
    store.record("req-001", {"verdict": "ALLOW"})
    is_dup2, original = store.check("req-001")
    assert is_dup2
    assert original["response"]["verdict"] == "ALLOW"


def test_idempotency_fingerprint():
    store = IdempotencyStore()
    fp1 = store.fingerprint({"a": 1, "b": 2})
    fp2 = store.fingerprint({"b": 2, "a": 1})
    assert fp1 == fp2