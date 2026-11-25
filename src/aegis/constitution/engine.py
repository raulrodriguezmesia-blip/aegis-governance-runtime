"""Aegis Memory Constitution Engine — V1.

Deterministic evaluation pipeline:
  Stage 1: Schema Validation
  Stage 2: Constitution Validation
  Stage 3: Conflict Analysis
  Stage 4: Risk Analysis
  Stage 5: Verdict Resolution
"""
import time
from typing import Optional
from ..contracts.models import MemoryFact, Verdict, ReasonCode


class ConstitutionEngine:
    """Evaluates memory facts against constitutional rules."""

    def __init__(self, confidence_threshold: float = 0.8):
        self.confidence_threshold = confidence_threshold
        self._active_facts: list[MemoryFact] = []

    def evaluate(self, fact: MemoryFact) -> tuple[Verdict, ReasonCode]:
        """Run the full evaluation pipeline. Returns (verdict, reason_code)."""

        # Stage 1: Schema Validation
        if not fact.subject or not fact.predicate or not fact.value:
            return (Verdict.DENY, ReasonCode.INVALID_SCHEMA)

        # Stage 2: Constitution Validation
        if not fact.source:
            return (Verdict.DENY, ReasonCode.MISSING_SOURCE)

        # Check for duplicates (same subject + predicate + value, both active)
        for existing in self._active_facts:
            if (existing.subject == fact.subject and
                existing.predicate == fact.predicate and
                existing.value == fact.value and
                existing.valid_to is None):
                return (Verdict.DENY, ReasonCode.DUPLICATE)

        # Stage 3: Conflict Analysis
        for existing in self._active_facts:
            if (existing.subject == fact.subject and
                existing.predicate == fact.predicate and
                existing.value != fact.value and
                existing.valid_to is None):
                return (Verdict.QUARANTINE, ReasonCode.CONTRADICTION)

        # Stage 4: Risk Analysis
        if fact.confidence < self.confidence_threshold:
            return (Verdict.QUARANTINE, ReasonCode.LOW_CONFIDENCE)

        # Stage 5: Verdict Resolution
        return (Verdict.ALLOW, ReasonCode.NONE)

    def commit(self, fact: MemoryFact):
        """Add an approved fact to active memory."""
        fact.valid_from = fact.valid_from or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._active_facts.append(fact)

    def get_active_facts(self) -> list[MemoryFact]:
        return [f for f in self._active_facts if f.valid_to is None]

    def supersede(self, subject: str, predicate: str):
        """Mark matching active facts as superseded."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for f in self._active_facts:
            if f.subject == subject and f.predicate == predicate and f.valid_to is None:
                f.valid_to = now