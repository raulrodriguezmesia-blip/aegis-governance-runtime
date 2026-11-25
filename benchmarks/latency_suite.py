"""Aegis Latency Benchmark — V1.

Measures p50/p95/p99 for:
  - Policy evaluation (Constitution Engine)
  - Ledger write (append + hash chain)
"""
import sys
import os
import time
import tempfile
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aegis.contracts.models import MemoryFact, AuditEvent
from aegis.constitution.engine import ConstitutionEngine
from aegis.ledger.ledger import AegisLedger, compute_payload_hash

ITERATIONS = 1000


def benchmark_evaluation():
    engine = ConstitutionEngine()
    latencies = []
    for i in range(ITERATIONS):
        fact = MemoryFact(
            subject=f"USER_{i}",
            predicate="LANG",
            value="JAVA",
            confidence=0.9,
            source="bench")
        start = time.perf_counter_ns()
        engine.evaluate(fact)
        end = time.perf_counter_ns()
        latencies.append(end - start)
    return latencies


def benchmark_ledger():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    ledger = AegisLedger(tmp.name)
    latencies = []
    for i in range(ITERATIONS):
        fact = MemoryFact(
            subject=f"USER_{i}",
            predicate="LANG",
            value="JAVA",
            confidence=0.9,
            source="bench")
        payload_hash = compute_payload_hash(fact.to_dict())
        event = AuditEvent(
            event_id=f"evt-{i:04d}",
            timestamp_utc="2026-11-25T00:00:00Z",
            actor="bench", action="MEMORY_WRITE",
            verdict="ALLOW", reason_code="NONE",
            constitution_version="v1.0.0",
            constitution_hash="sha256:bench",
            prev_hash="", payload_hash=payload_hash)
        start = time.perf_counter_ns()
        ledger.append(event)
        end = time.perf_counter_ns()
        latencies.append(end - start)
    os.unlink(tmp.name)
    return latencies


def print_stats(name, latencies):
    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    mean = statistics.mean(latencies)
    print(f"\n=== {name} ===")
    print(f"  Iterations: {len(latencies)}")
    print(f"  Mean:       {mean:.0f} ns")
    print(f"  p50:        {p50} ns")
    print(f"  p95:        {p95} ns")
    print(f"  p99:        {p99} ns")
    target = 100_000
    result = "PASS" if p99 < target else "FAIL"
    print(f"  Target:     < {target:,} ns (100 us)")
    print(f"  p99 result: {result}")


if __name__ == "__main__":
    print("=== Aegis Governance Runtime — Latency Benchmark ===")
    eval_lat = benchmark_evaluation()
    print_stats("Policy Evaluation", eval_lat)
    ledger_lat = benchmark_ledger()
    print_stats("Ledger Write", ledger_lat)