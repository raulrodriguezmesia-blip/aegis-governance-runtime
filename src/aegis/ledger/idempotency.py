"""Aegis Idempotency Enforcement — V1.5.

Full duplicate request detection.
  request_id → already seen? → DENY DUPLICATE_REQUEST
"""
import time
import hashlib
from typing import Optional


class IdempotencyStore:
    """Tracks processed request IDs to prevent duplicate execution."""

    def __init__(self):
        self._seen: dict[str, dict] = {}

    def check(self, request_id: str) -> tuple[bool, Optional[dict]]:
        """Check if request_id was already processed.
        Returns (is_duplicate, original_response).
        """
        if request_id in self._seen:
            return (True, self._seen[request_id])
        return (False, None)

    def record(self, request_id: str, response: dict):
        """Record a processed request."""
        self._seen[request_id] = {
            "response": response,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def fingerprint(self, payload: dict) -> str:
        """Generate a fingerprint for a payload."""
        import json
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def get_stats(self) -> dict:
        return {"total_processed": len(self._seen)}