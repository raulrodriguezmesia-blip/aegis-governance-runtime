"""Aegis Reverse Governance — V1.5.

Agents can appeal a DENY with new evidence.
  DENY → Appeal → Re-evaluation → PROMOTE or DENY
"""
import time
from dataclasses import dataclass, field
from typing import Optional
from ..contracts.models import MemoryFact, Verdict, ReasonCode
from .engine import ConstitutionEngine


@dataclass
class Appeal:
    appeal_id: str
    original_fact_id: str
    agent_id: str
    new_evidence: list[dict]
    reason: str
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    resolved_at: Optional[str] = None
    final_verdict: Optional[str] = None


class AppealManager:
    """Manages agent appeals against DENY verdicts."""

    def __init__(self, engine: ConstitutionEngine):
        self.engine = engine
        self._appeals: dict[str, Appeal] = {}

    def appeal(self, original_fact_id: str, agent_id: str,
               new_evidence: list[dict], reason: str) -> Appeal:
        """File an appeal against a DENY."""
        appeal = Appeal(
            appeal_id=f"apl-{len(self._appeals)+1:04d}",
            original_fact_id=original_fact_id,
            agent_id=agent_id,
            new_evidence=new_evidence,
            reason=reason)
        self._appeals[appeal.appeal_id] = appeal
        return appeal

    def resolve(self, appeal_id: str) -> dict:
        """Re-evaluate the original fact with new evidence."""
        appeal = self._appeals.get(appeal_id)
        if not appeal:
            raise ValueError(f"Appeal {appeal_id} not found")
        if appeal.status != "PENDING":
            raise ValueError(f"Appeal {appeal_id} is {appeal.status}")

        # Reconstruct the fact with new evidence
        # The new_evidence should contain the missing fields
        fact = MemoryFact(
            subject=appeal.new_evidence.get("subject", ""),
            predicate=appeal.new_evidence.get("predicate", ""),
            value=appeal.new_evidence.get("value", ""),
            confidence=appeal.new_evidence.get("confidence", 0.5),
            source=appeal.new_evidence.get("source", ""))

        verdict, reason = self.engine.evaluate(fact)

        appeal.status = "APPROVED" if verdict == Verdict.ALLOW else "REJECTED"
        appeal.final_verdict = verdict.value
        appeal.resolved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if verdict == Verdict.ALLOW:
            self.engine.commit(fact)

        return {
            "appeal_id": appeal_id,
            "status": appeal.status,
            "verdict": verdict.value,
            "reason_code": reason.value,
            "resolved_at": appeal.resolved_at,
        }

    def get_pending(self) -> list[Appeal]:
        return [a for a in self._appeals.values() if a.status == "PENDING"]

    def get_stats(self) -> dict:
        total = len(self._appeals)
        approved = sum(1 for a in self._appeals.values() if a.status == "APPROVED")
        rejected = sum(1 for a in self._appeals.values() if a.status == "REJECTED")
        pending = sum(1 for a in self._appeals.values() if a.status == "PENDING")
        return {"total": total, "approved": approved, "rejected": rejected, "pending": pending}