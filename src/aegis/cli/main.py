"""Aegis CLI — V1.

Commands:
  aegis evaluate  — Evaluate a memory fact
  aegis verify    — Verify ledger integrity
  aegis demo      — Run 60-second demo (4 scenarios)
"""
import uuid
import hashlib
import os
import time
import sys
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aegis.contracts.models import MemoryFact, Verdict, ReasonCode, AuditEvent
from aegis.constitution.engine import ConstitutionEngine
from aegis.ledger.ledger import AegisLedger, compute_payload_hash

# Load constitution from YAML and compute real hash
CONSTITUTION_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "constitution", "charter_v1.yaml")
CONSTITUTION_HASH = "sha256:" + hashlib.sha256(open(CONSTITUTION_PATH, "rb").read()).hexdigest() if os.path.exists(CONSTITUTION_PATH) else "sha256:unknown"

# Load confidence threshold from YAML
CONFIDENCE_THRESHOLD = 0.8
try:
    import yaml as _yaml
    with open(CONSTITUTION_PATH) as f:
        charter = _yaml.safe_load(f)
    for rule in charter.get("rules", []):
        if rule.get("id") == "CONFIDENCE_THRESHOLD":
            CONFIDENCE_THRESHOLD = rule.get("threshold", 0.8)
    if "thresholds" in charter:
        CONFIDENCE_THRESHOLD = charter["thresholds"].get("confidence", CONFIDENCE_THRESHOLD)
except Exception:
    pass


def evaluate_fact(fact: MemoryFact, engine: ConstitutionEngine, ledger: AegisLedger) -> dict:
    """Evaluate a fact and record in ledger."""
    verdict, reason = engine.evaluate(fact)

    if verdict == Verdict.ALLOW:
        engine.commit(fact)

    payload_hash = compute_payload_hash(fact.to_dict())
    event = AuditEvent(
        event_id=f"evt-{uuid.uuid4()}",
        timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        actor=fact.source,
        action="MEMORY_WRITE",
        verdict=verdict.value,
        reason_code=reason.value,
        constitution_version="v1.0.0",
        constitution_hash=CONSTITUTION_HASH,
        prev_hash="",
        payload_hash=payload_hash)
    ledger.append(event, payload=fact.to_dict())

    return {"verdict": verdict.value, "reason_code": reason.value, "payload_hash": payload_hash[:16]}


def cmd_demo():
    """Run 60-second demo with 4 scenarios."""
    print("=" * 60)
    print("  AEGIS GOVERNANCE RUNTIME — DEMO (60s)")
    print("=" * 60)
    print()

    engine = ConstitutionEngine(confidence_threshold=CONFIDENCE_THRESHOLD)
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    ledger = AegisLedger(tmp.name)

    scenarios = [
        ("Scenario 1: Valid Memory (ALLOW)", MemoryFact(
            subject="USER", predicate="PRIMARY_LANGUAGE", value="JAVA",
            confidence=0.92, source="conversation",
            valid_from="2026-11-25T00:00:00Z")),
        ("Scenario 2: Duplicate Memory (DENY)", MemoryFact(
            subject="USER", predicate="PRIMARY_LANGUAGE", value="JAVA",
            confidence=0.95, source="conversation",
            valid_from="2026-11-25T01:00:00Z")),
        ("Scenario 3: Contradictory Memory (QUARANTINE)", MemoryFact(
            subject="USER", predicate="PRIMARY_LANGUAGE", value="PYTHON",
            confidence=0.85, source="conversation",
            valid_from="2026-11-25T02:00:00Z")),
        ("Scenario 4: Missing Source (DENY)", MemoryFact(
            subject="USER", predicate="COUNTRY", value="PERU",
            confidence=0.9, source="")),
    ]

    for title, fact in scenarios:
        print(f"[{title}]")
        result = evaluate_fact(fact, engine, ledger)
        icon = "[OK]" if result["verdict"] == "ALLOW" else "[NO]" if result["verdict"] == "DENY" else "[??]"
        print(f"  {icon} {result['verdict']} | {result['reason_code']} | hash={result['payload_hash']}...")
        print()

    # Verify chain
    print("[Verify Chain]")
    status = ledger.verify()
    icon = "[OK]" if status["status"] == "VERIFIED" else "[NO]"
    print(f"  {icon} {status['status']} ({status.get('records', 0)} records)")
    print()

    # Tamper simulation
    print("[Tamper Simulation — modify event #2]")
    ledger.tamper(2)
    status2 = ledger.verify()
    icon2 = "[!!]" if "BROKEN" in status2["status"] else "[OK]"
    print(f"  {icon2} {status2['status']} at seq={status2.get('broken_at', '?')}")
    print()
    print("=" * 60)
    print("  DEMO COMPLETE")
    print("=" * 60)


def cmd_evaluate(subject, predicate, value, confidence, source):
    """Evaluate a single fact."""
    engine = ConstitutionEngine()
    ledger = AegisLedger()
    fact = MemoryFact(
        subject=subject, predicate=predicate, value=value,
        confidence=float(confidence), source=source,
        valid_from=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    result = evaluate_fact(fact, engine, ledger)
    icon = "[OK]" if result["verdict"] == "ALLOW" else "[NO]" if result["verdict"] == "DENY" else "[??]"
    print(f"{icon} {result['verdict']} | {result['reason_code']}")


def cmd_verify():
    """Verify ledger integrity."""
    ledger = AegisLedger()
    status = ledger.verify()
    icon = "[OK]" if status["status"] == "VERIFIED" else "[NO]" if "BROKEN" in status["status"] else "[--]"
    print(f"{icon} {status['status']}" + (f" ({status['records']} records)" if "records" in status else ""))


def main():
    if len(sys.argv) < 2:
        print("Usage: aegis <command> [args]")
        print("Commands: demo, evaluate, verify")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "demo":
        cmd_demo()
    elif cmd == "evaluate":
        if len(sys.argv) < 7:
            print("Usage: aegis evaluate <subject> <predicate> <value> <confidence> <source>")
            sys.exit(1)
        cmd_evaluate(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    elif cmd == "verify":
        cmd_verify()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()