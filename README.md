# Aegis Governance Runtime

> *Trust the agent's intelligence. Verify its authority. Prove its actions.*

**V1 proves deterministic governance. Nothing else.**

Aegis is a **governance middleware** that verifies agent decisions before they are allowed to modify memory, invoke tools, execute MCP operations, or change external state.

## The Problem

AI agents can act. But when something goes wrong, there's no reliable way to prove what was decided, by whom, under which policy, and when.

## The Solution

Aegis sits between agents and the systems they affect. Every proposal passes through a deterministic evaluation pipeline before execution. Every decision produces cryptographically verifiable evidence.

## Quick Start

```bash
git clone https://github.com/raulrodriguezmesia-blip/aegis-governance-runtime.git
cd aegis-governance-runtime

pip install -r requirements.txt

# Run the 60-second demo
PYTHONPATH=src python src/aegis/cli/main.py demo
```

Expected output:

```
[OK] ALLOW | NONE
[NO] DENY | DUPLICATE
[??] QUARANTINE | CONTRADICTION
[OK] VERIFIED (4 records)
[!!] INTEGRITY BROKEN at seq=2
```

## Architecture

```
Agent → Proposal → Aegis Governance Runtime → ALLOW / DENY / QUARANTINE → Execution
                         ↓
                    Audit Ledger (hash chain)
```

## What Makes It Different

- **Constitutional Governance** — deterministic rules, not prompts
- **Memory Validation** — structured facts, not free text
- **Evidence Ledger** — hash-linked, tamper-evident
- **Model-Agnostic** — works with OpenAI, Claude, Gemini, CrewAI, LangGraph, MCP

## Results

- 9/9 tests passing
- Policy evaluation p99 = 500 ns (target: < 100,000 ns)
- Tamper detection verified end-to-end
- Deterministic: same input + same constitution = same verdict

## Documentation

See [AEGIS_GOVERNANCE_RUNTIME_ARCHITECTURE.md](AEGIS_GOVERNANCE_RUNTIME_ARCHITECTURE.md) for the full v0.2 specification.

## License

MIT