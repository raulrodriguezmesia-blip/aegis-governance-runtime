"""Aegis Governance Runtime — Canonical Contracts.

V1: Verdict, ReasonCode, ActionRequest, AuditEvent.
"""
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Any
import time


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"


class ReasonCode(str, Enum):
    NONE = "NONE"
    DUPLICATE = "DUPLICATE"
    CONTRADICTION = "CONTRADICTION"
    MISSING_SOURCE = "MISSING_SOURCE"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    HIGH_RISK_TOOL = "HIGH_RISK_TOOL"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    MEMORY_TAMPERING = "MEMORY_TAMPERING"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    PROVENANCE_UNVERIFIED = "PROVENANCE_UNVERIFIED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    CONSTITUTION_COMPROMISED = "CONSTITUTION_COMPROMISED"
    QUARANTINE_EXPIRED = "QUARANTINE_EXPIRED"


@dataclass
class MemoryFact:
    subject: str
    predicate: str
    value: str
    confidence: float = 0.5
    source: str = ""
    valid_from: str = ""
    valid_to: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "predicate": self.predicate,
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
        }


@dataclass
class ActionRequest:
    request_id: str
    agent_id: str
    action_type: str
    payload: dict
    idempotency_key: str = ""
    constitution_version: str = "v1.0.0"
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


@dataclass
class AuditEvent:
    event_id: str
    timestamp_utc: str
    actor: str
    action: str
    verdict: str
    reason_code: str
    constitution_version: str
    constitution_hash: str
    prev_hash: str
    payload_hash: str
    event_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp_utc": self.timestamp_utc,
            "actor": self.actor,
            "action": self.action,
            "verdict": self.verdict,
            "reason_code": self.reason_code,
            "constitution_version": self.constitution_version,
            "constitution_hash": self.constitution_hash,
            "prev_hash": self.prev_hash,
            "payload_hash": self.payload_hash,
            "event_hash": self.event_hash,
        }