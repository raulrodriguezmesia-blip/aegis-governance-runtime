# Aegis V1.5 Scope

**Rule: Only these 4 features. Nothing else.**

## V1.5 Features

1. **Quarantine Lifecycle** — TTL + review queue (PENDING → UNDER_REVIEW → PROMOTED/DENIED/EXPIRED)
2. **Constitution Signing** — Ed25519 signature verification at startup (fail-closed)
3. **Reverse Governance** — Agent appeals DENY with new evidence → re-evaluation
4. **Idempotency Enforcement** — Full duplicate request detection

## Non-Goals (V2+)

- Mnemosyne Council
- Trust Propagation
- Temporal Re-evaluation
- ZK Proofs
- Federation
- Execution Guard
- OpenTelemetry
- CloudEvents
- Merkle Checkpoints
- Adaptive Constitution

## Thesis

V1 proved deterministic governance.
V1.5 hardens that governance toward production readiness.
Nothing else.