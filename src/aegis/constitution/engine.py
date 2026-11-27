"""Aegis Memory Constitution Engine — V1.6.

Deterministic evaluation pipeline:
  Stage 1: Schema Validation
  Stage 2: Constitution Validation
  Stage 3: Conflict Analysis
  Stage 4: Risk Analysis
  Stage 5: Verdict Resolution

V1.6: Real memory persistence — active facts are reconstructed from the
ledger on startup, so governance state survives process restarts.
"""

import json
import math
import sqlite3
import time
from typing import Optional

from ..contracts.models import MemoryFact, Verdict, ReasonCode
from ..ledger.ledger import AegisLedger


class ConstitutionEngine:
    """Evaluates memory facts against constitutional rules."""

    def __init__(self, confidence_threshold: float = 0.8, ledger: Optional[AegisLedger] = None):
        self.confidence_threshold = confidence_threshold
        self._active_facts: list[MemoryFact] = []
        self.ledger = ledger
        if ledger is not None:
            self._load_active_facts_from_ledger(ledger)

    def _load_active_facts_from_ledger(self, ledger: AegisLedger):
        """Rebuild active memory from the ledger.

        Reads every ALLOW event that persisted a memory fact payload and
        reconstructs the corresponding MemoryFact. Facts whose JSON payload is
        corrupt are skipped (fail-safe: never resurrect unverifiable state).
        """
        try:
            conn = sqlite3.connect(ledger.db_path)
            rows = conn.execute(
                "SELECT payload FROM events WHERE verdict = 'ALLOW' ORDER BY seq ASC"
            ).fetchall()
            conn.close()
        except sqlite3.Error:
            # A corrupt/missing DB must not crash the engine; it starts empty.
            return

        for (payload_json,) in rows:
            if not payload_json:
                continue
            try:
                data = json.loads(payload_json)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(data, dict):
                continue
            required = ("subject", "predicate", "value")
            if not all(data.get(k) for k in required):
                continue
            try:
                fact = MemoryFact(
                    subject=data["subject"],
                    predicate=data["predicate"],
                    value=data["value"],
                    confidence=float(data.get("confidence", 0.5)),
                    source=data.get("source", ""),
                    valid_from=data.get("valid_from", ""),
                    valid_to=data.get("valid_to"),
                )
            except (TypeError, ValueError):
                continue
            self._active_facts.append(fact)

    def evaluate(self, fact: MemoryFact) -> tuple[Verdict, ReasonCode]:
        """Run the full evaluation pipeline. Returns (verdict, reason_code)."""

        # Stage 1: Schema Validation
        if not fact.subject or not fact.predicate or not fact.value:
            return (Verdict.DENY, ReasonCode.INVALID_SCHEMA)

        if not isinstance(fact.confidence, (int, float)) or isinstance(fact.confidence, bool):
            return (Verdict.DENY, ReasonCode.INVALID_SCHEMA)

        if math.isnan(fact.confidence) or math.isinf(fact.confidence):
            return (Verdict.DENY, ReasonCode.INVALID_SCHEMA)

        if fact.confidence < 0.0 or fact.confidence > 1.0:
            return (Verdict.DENY, ReasonCode.INVALID_SCHEMA)

        # Stage 2: Constitution Validation
        if not fact.source or not fact.source.strip():
            return (Verdict.DENY, ReasonCode.MISSING_SOURCE)

        # Normalize for comparison (case-insensitive value/source)
        subject = fact.subject.strip().upper()
        predicate = fact.predicate.strip().upper()
        value = fact.value.strip().lower()

        # Check for duplicates (case-insensitive)
        for existing in self._active_facts:
            if (existing.subject.strip().upper() == subject and
                existing.predicate.strip().upper() == predicate and
                existing.value.strip().lower() == value and
                existing.valid_to is None):
                return (Verdict.DENY, ReasonCode.DUPLICATE)

        # Stage 3: Conflict Analysis
        for existing in self._active_facts:
            if (existing.subject.strip().upper() == subject and
                existing.predicate.strip().upper() == predicate and
                existing.value.strip().lower() != value and
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
            if f.subject.strip().upper() == subject.strip().upper() and \
               f.predicate.strip().upper() == predicate.strip().upper() and \
               f.valid_to is None:
                f.valid_to = now
