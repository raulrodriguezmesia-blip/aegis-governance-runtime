# Aegis Governance Runtime — Failure & Security Validation Matrix

**Version:** 1.6.0  
**Generated:** 2026-11-27  
**Test Suite:** `tests/attacks/` + `tests/failures/` + `tests/` (55 tests total)

---

## Summary

| Layer | Scenarios | Pass | Fail |
|-------|-----------|------|------|
| **Ledger Attacks** | 7 | 7 | 0 |
| **Constitution Attacks** | 6 | 6 | 0 |
| **Runtime Failures** | 6 | 6 | 0 |
| **Governance Failures** | 10 | 10 | 0 |
| **Core V1/V1.5 Features** | 26 | 26 | 0 |
| **Total** | **55** | **55** | **0** |

**Key Principle:** Aegis fails closed. No attack scenario ever produces `ALLOW`. Every failure mode returns a controlled `DENY`, `QUARANTINE`, `INTEGRITY BROKEN`, `SIGNATURE_INVALID`, `CHECKPOINT_NOT_FOUND`, or `CONSTITUTION_COMPROMISED` — never an unhandled exception or traceback.

---

## Ledger Attacks (`tests/attacks/test_ledger_attacks.py`)

| # | Scenario | Expected Behaviour | Actual Behaviour | Pass/Fail |
|---|----------|-------------------|------------------|-----------|
| L1 | Payload modification (`tamper_event_payload`) | `verify()` → `INTEGRITY BROKEN` | `INTEGRITY BROKEN` (payload_hash mismatch) | ✅ PASS |
| L2 | Chain rewrite (modify `prev_hash` of middle event) | `verify()` → `INTEGRITY BROKEN` | `INTEGRITY BROKEN` (prev_hash chain broken) | ✅ PASS |
| L3 | Tail truncation (delete N events from end) | `verify()` → `VERIFIED` (sub-chain valid); `verify_checkpoint()` → `INTEGRITY MISMATCH` | Hash chain `VERIFIED`; Checkpoint `INTEGRITY MISMATCH` (record count / last hash mismatch) | ✅ PASS |
| L4 | Deleted record (bypass `DELETE` trigger) | `verify()` → `INTEGRITY BROKEN` | `INTEGRITY BROKEN` (prev_hash discontinuity) | ✅ PASS |
| L5 | Missing external checkpoint | `verify_checkpoint()` → `CHECKPOINT_NOT_FOUND` | `CHECKPOINT_NOT_FOUND` | ✅ PASS |
| L6 | Invalid checkpoint signature (corrupt file) | `verify_checkpoint()` → `SIGNATURE_INVALID` | `SIGNATURE_INVALID` (HMAC mismatch) | ✅ PASS |
| L7 | Engine evaluation on broken ledger | `evaluate()` must never return `ALLOW` | Returns `DENY/DUPLICATE` (no crash, no ALLOW) | ✅ PASS |

---

## Constitution Attacks (`tests/attacks/test_constitution_attacks.py`)

| # | Scenario | Expected Behaviour | Actual Behaviour | Pass/Fail |
|---|----------|-------------------|------------------|-----------|
| C1 | Charter modified after signing | `verify_at_startup()` → `CONSTITUTION_COMPROMISED` | `CONSTITUTION_COMPROMISED` | ✅ PASS |
| C2 | Invalid signature file (garbage bytes) | `verify_at_startup()` → `CONSTITUTION_COMPROMISED` | `CONSTITUTION_COMPROMISED` | ✅ PASS |
| C3 | Wrong public key for verification | `verify_at_startup()` → `CONSTITUTION_COMPROMISED` | `CONSTITUTION_COMPROMISED` | ✅ PASS |
| C4 | Nonexistent constitution file | `verify_at_startup()` → `CONSTITUTION_NOT_FOUND` | `CONSTITUTION_NOT_FOUND` | ✅ PASS |
| C5 | Missing signature file (unsigned constitution) | `verify_at_startup()` → `CONSTITUTION_SIGNATURE_MISSING` | `CONSTITUTION_SIGNATURE_MISSING` | ✅ PASS |
| C6 | Engine on compromised constitution | Must not produce `ALLOW` governance | Startup verification fails; governance denied | ✅ PASS |

---

## Runtime Failures (`tests/failures/test_runtime_failures.py`)

| # | Scenario | Expected Behaviour | Actual Behaviour | Pass/Fail |
|---|----------|-------------------|------------------|-----------|
| R1 | Corrupt SQLite DB file (garbage bytes) | No crash; no `ALLOW` | `sqlite3.DatabaseError` caught; no `ALLOW` returned | ✅ PASS |
| R2 | Missing ledger file | No crash; evaluates on empty state | Engine constructs; valid fact `ALLOW`s (correct V1 behavior with no prior state) | ✅ PASS |
| R3 | Invalid JSON payload stored in ledger | No crash; fact not loaded | `None` payload → 0 active facts; valid fact `ALLOW`s | ✅ PASS |
| R4 | Incomplete payload (missing `subject`) | `evaluate()` → `DENY/INVALID_SCHEMA` | `DENY/INVALID_SCHEMA` | ✅ PASS |
| R5 | NULL/empty required fields (`subject`/`predicate`/`value`) | `DENY/INVALID_SCHEMA` | `DENY/INVALID_SCHEMA` | ✅ PASS |
| R6 | Invalid confidence (NaN, Inf, out-of-range, bool) | `DENY/INVALID_SCHEMA` | `DENY/INVALID_SCHEMA` | ✅ PASS |

---

## Governance Failures (`tests/failures/test_governance_failures.py`)

| # | Scenario | Expected Behaviour | Actual Behaviour | Pass/Fail |
|---|----------|-------------------|------------------|-----------|
| G1 | Self-appeal (agent = reviewer) | `resolve()` raises `ValueError("same agent")` | `ValueError: Cannot approve appeal ... with same agent` | ✅ PASS |
| G2 | Self-review quarantine (reviewer = submitter) | `review()` raises `ValueError("same submitter")` | `ValueError: Cannot review entry ... with same submitter` | ✅ PASS |
| G3 | Review nonexistent quarantine entry | `review()` raises `ValueError("not found")` | `ValueError: Quarantine entry ... not found` | ✅ PASS |
| G4 | Invalid review decision (`INVALID_DECISION`) | `review()` raises `ValueError("invalid decision")` | `ValueError: Invalid decision: INVALID_DECISION` | ✅ PASS |
| G5 | Empty/None reviewer identity | `review()` raises `ValueError("required")` | `ValueError: Reviewer identity is required` | ✅ PASS |
| G6 | Replay request (duplicate idempotency key) | `check()` returns `(True, original_response)` | `is_dup=True`, original verdict preserved | ✅ PASS |
| G7 | Resolve nonexistent appeal | `resolve()` raises `ValueError("not found")` | `ValueError: Appeal ... not found` | ✅ PASS |
| G8 | Resolve already-resolved appeal | `resolve()` raises `ValueError("is APPROVED/REJECTED")` | `ValueError: Appeal ... is APPROVED` | ✅ PASS |
| G9 | Re-review after PROMOTE | `review()` raises `ValueError("cannot review")` | `ValueError: Entry ... is PROMOTED, cannot review` | ✅ PASS |
| G10 | Engine with empty/missing source | `evaluate()` → `DENY/MISSING_SOURCE` | `DENY/MISSING_SOURCE` | ✅ PASS |

---

## Core V1/V1.5 Features (`tests/test_aegis.py`, `tests/test_engine.py`, `tests/test_v15.py`)

| # | Scenario | Expected Behaviour | Actual Behaviour | Pass/Fail |
|---|----------|-------------------|------------------|-----------|
| F1 | Valid fact → `ALLOW/NONE` | `ALLOW/NONE` | `ALLOW/NONE` | ✅ PASS |
| F2 | Duplicate fact → `DENY/DUPLICATE` | `DENY/DUPLICATE` | `DENY/DUPLICATE` | ✅ PASS |
| F3 | Contradiction → `QUARANTINE/CONTRADICTION` | `QUARANTINE/CONTRADICTION` | `QUARANTINE/CONTRADICTION` | ✅ PASS |
| F4 | Missing source → `DENY/MISSING_SOURCE` | `DENY/MISSING_SOURCE` | `DENY/MISSING_SOURCE` | ✅ PASS |
| F5 | Low confidence → `QUARANTINE/LOW_CONFIDENCE` | `QUARANTINE/LOW_CONFIDENCE` | `QUARANTINE/LOW_CONFIDENCE` | ✅ PASS |
| F6 | Invalid schema → `DENY/INVALID_SCHEMA` | `DENY/INVALID_SCHEMA` | `DENY/INVALID_SCHEMA` | ✅ PASS |
| F7 | Ledger chain verifies (clean) | `VERIFIED` | `VERIFIED` | ✅ PASS |
| F8 | Tampered ledger detected | `INTEGRITY BROKEN` | `INTEGRITY BROKEN` | ✅ PASS |
| F9 | Payload hash determinism | Same input → same hash | Hashes match | ✅ PASS |
| F10 | Engine loads active facts from ledger | 1 fact loaded, duplicate rejected | 1 active fact, duplicate `DENY` | ✅ PASS |
| F11 | Value normalization (case-insensitive) | `JAVA` vs `java` → `DENY/DUPLICATE` | `DENY/DUPLICATE` | ✅ PASS |
| F12 | Source normalization (case-insensitive) | `Test` vs `test` → `DENY/DUPLICATE` | `DENY/DUPLICATE` | ✅ PASS |
| F13 | Bool confidence rejected | `DENY/INVALID_SCHEMA` | `DENY/INVALID_SCHEMA` | ✅ PASS |
| F14 | NaN/Inf confidence rejected | `DENY/INVALID_SCHEMA` | `DENY/INVALID_SCHEMA` | ✅ PASS |
| F15 | Persistence survives restart | New engine + same ledger → 1 fact loaded | 1 active fact, duplicate rejected | ✅ PASS |
| F16 | Quarantine PENDING → PROMOTE/DENY/EXPIRED | State transitions work | All transitions verified | ✅ PASS |
| F17 | Constitution sign/verify | Valid signature → `CONSTITUTION_VERIFIED` | `CONSTITUTION_VERIFIED` | ✅ PASS |
| F18 | Constitution tamper detected | `CONSTITUTION_COMPROMISED` | `CONSTITUTION_COMPROMISED` | ✅ PASS |
| F19 | Appeal PROMOTE (strong evidence) | `APPROVED/ALLOW` | `APPROVED/ALLOW` | ✅ PASS |
| F20 | Appeal REJECT (weak evidence) | `REJECTED` | `REJECTED` | ✅ PASS |
| F21 | Idempotency duplicate detection | `(True, original)` | `True + original verdict` | ✅ PASS |
| F22 | Idempotency fingerprint order-invariant | Same fingerprint for `{a:1,b:2}` / `{b:2,a:1}` | Fingerprints match | ✅ PASS |
| F23 | Quarantine self-review prevention | Raises `ValueError` | Raises `ValueError` | ✅ PASS |
| F24 | Quarantine PROMOTE commits to memory | Fact added to engine active facts | Fact committed to engine | ✅ PASS |
| F25 | Appeals self-approval prevention | Raises `ValueError` | Raises `ValueError` | ✅ PASS |
| F26 | UTC expiry in quarantine | `calendar.timegm` parsing works | Expiry correctly detected | ✅ PASS |

---

## Defence Layers Summary

| Threat | Layer 1: Hash Chain (`verify()`) | Layer 2: Signed Checkpoint (`verify_checkpoint()`) |
|--------|----------------------------------|-----------------------------------------------------|
| Payload modification | ✅ DETECTED (`INTEGRITY BROKEN`) | ✅ DETECTED (`INTEGRITY MISMATCH`) |
| Chain rewrite (prev_hash) | ✅ DETECTED (`INTEGRITY BROKEN`) | ✅ DETECTED (`INTEGRITY MISMATCH`) |
| Tail truncation | ❌ NOT DETECTED (sub-chain valid) | ✅ DETECTED (`INTEGRITY MISMATCH` — record count / last hash) |
| Deleted record (gap) | ✅ DETECTED (`INTEGRITY BROKEN`) | ✅ DETECTED (`INTEGRITY MISMATCH`) |
| Missing checkpoint | N/A | ✅ DETECTED (`CHECKPOINT_NOT_FOUND`) |
| Invalid checkpoint signature | N/A | ✅ DETECTED (`SIGNATURE_INVALID`) |

**Conclusion:** The pure hash chain detects in-chain modifications. The external signed checkpoint is the defence-in-depth layer that catches tail truncation — an attack that leaves the remaining chain internally consistent. This is the intended architecture: **the hash chain validates continuity; the checkpoint validates completeness.**

---

## Claims Verified

> **Aegis no solo funciona cuando todo va bien.  
> Aegis también falla de forma predecible, verificable y segura.**

All 55 tests pass. No attack or failure scenario produces `ALLOW`, crashes, or unhandled tracebacks.