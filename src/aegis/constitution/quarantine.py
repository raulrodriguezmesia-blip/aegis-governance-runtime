"""Aegis Quarantine Lifecycle — V1.5.

QUARANTINE is not a terminal state. It is a governance queue:
  PENDING → UNDER_REVIEW → PROMOTED | DENIED | EXPIRED
"""
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class QuarantineState(str, Enum):
    PENDING = "PENDING"
    UNDER_REVIEW = "UNDER_REVIEW"
    PROMOTED = "PROMOTED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


@dataclass
class QuarantineEntry:
    fact_id: str
    subject: str
    predicate: str
    value: str
    confidence: float
    source: str
    reason_code: str
    state: QuarantineState = QuarantineState.PENDING
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    expires_at: str = ""
    reviewed_by: str = ""
    review_note: str = ""


class QuarantineManager:
    """Manages the quarantine lifecycle."""

    def __init__(self, ttl_hours: float = 24.0):
        self.ttl_hours = ttl_hours
        self._entries: dict[str, QuarantineEntry] = {}

    def quarantine(self, fact_id: str, subject: str, predicate: str,
                   value: str, confidence: float, source: str,
                   reason_code: str) -> QuarantineEntry:
        """Add a fact to quarantine."""
        created = time.time()
        expires = created + (self.ttl_hours * 3600)
        entry = QuarantineEntry(
            fact_id=fact_id, subject=subject, predicate=predicate,
            value=value, confidence=confidence, source=source,
            reason_code=reason_code,
            expires_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires)))
        self._entries[fact_id] = entry
        return entry

    def review(self, fact_id: str, reviewer: str, decision: str, note: str = ""):
        """Review a quarantined entry. decision: PROMOTE or DENY."""
        entry = self._entries.get(fact_id)
        if not entry:
            raise ValueError(f"Quarantine entry {fact_id} not found")
        if entry.state not in (QuarantineState.PENDING, QuarantineState.UNDER_REVIEW):
            raise ValueError(f"Entry {fact_id} is {entry.state}, cannot review")

        entry.state = QuarantineState.UNDER_REVIEW
        entry.reviewed_by = reviewer
        entry.review_note = note

        if decision.upper() == "PROMOTE":
            entry.state = QuarantineState.PROMOTED
        elif decision.upper() == "DENY":
            entry.state = QuarantineState.DENIED
        else:
            raise ValueError(f"Invalid decision: {decision}")

    def expire_old(self) -> int:
        """Expire entries past their TTL. Returns count expired."""
        now = time.time()
        expired = 0
        for entry in self._entries.values():
            if entry.state in (QuarantineState.PENDING, QuarantineState.UNDER_REVIEW):
                expires = time.mktime(time.strptime(entry.expires_at, "%Y-%m-%dT%H:%M:%SZ"))
                if now > expires:
                    entry.state = QuarantineState.EXPIRED
                    expired += 1
        return expired

    def get_pending(self) -> list[QuarantineEntry]:
        return [e for e in self._entries.values()
                if e.state in (QuarantineState.PENDING, QuarantineState.UNDER_REVIEW)]

    def get_stats(self) -> dict:
        total = len(self._entries)
        by_state = {}
        for e in self._entries.values():
            by_state[e.state.value] = by_state.get(e.state.value, 0) + 1
        return {"total": total, "by_state": by_state}