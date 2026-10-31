# assurance-one: precert

Pre-execution gate for AI agent tool calls. Every governed action gets PERMIT with a signed admissibility certificate, DENY with a counterexample, or ABSTAIN (fail closed), and every call lands as a signed receipt in a Merkle transparency log. Invariants are proved inductive in Z3 at load time and in Lean 4.

- Contract: `SPEC.md`
- Agent rules: `AGENTS.md`
- Tests are read-only (`tests.lock`, checked in CI). Run: `pytest -c tests/pytest.ini tests -m m1` (then `m2`, `m3`, `m4`)

## What it claims

No executed action violates a declared invariant, given that (1) the invariants are inductive, which is checked by Z3 at load time and independently by a Lean 4 proof per action, and (2) every action passes the runtime precondition check. It does not claim the agent is right, the policy is the right policy, or that a tool did what it was asked (settlement mismatches halt the gate instead).

## Quick start

```bash
pip install -e '.[test]'               # z3-solver, cbor2, cryptography, pytest
```

```python
from precert import load_policy, Gate

policy = load_policy("tests/fixtures/payments.json")      # rejects non-inductive policies
gate = Gate(policy)
action = {"tool": "pay", "args": {"payee": "acme", "amount_cents": 1000, "ts": 10_000}, "principal": "agent-1"}
gate.check(action)                     # Verdict(decision="PERMIT", certificate={...})
gate.execute(action, my_pay_tool)      # check + run + signed receipt, one critical section
```

Lean proof and differential executable (Lean 4 core, no Mathlib; install elan if `lake` is missing):

```python
from precert.lean import generate
proj = generate(policy, "/tmp/payments_lean")   # then: cd /tmp/payments_lean && lake build
```

MCP server (stdio, newline-delimited JSON-RPC; only policy actions are listed or callable):

```bash
python -m precert.mcp_server --policy tests/fixtures/payments.json --tools mymodule:TOOLS --log receipts.bin
python -m precert.audit --log receipts.bin --pub receipts.bin.pub     # verify signatures, chain, root
```

## Reports

```bash
python3 scripts/report.py              # false permits / false denies / ABSTAIN rate over 10k random + 10k adversarial
                                       # actions (judged by tests/oracle.py), and p50/p95 check latency
```

## Design notes

- **Expression language.** Parsed with `ast` into a typed IR (int/bool; strings only as `arg in CONST_LIST`). Constants are folded. Linear arithmetic only: `*` needs a constant operand; `//` and `%` need a constant nonzero divisor, so a zero divisor is a load-time error and Z3 stays in linear integer arithmetic.
- **Floor semantics everywhere.** Z3 and Lean integer division are Euclidean. For a positive divisor that equals Python floor division; for a negative divisor `d`, `x // d` is encoded as `(-x) // (-d)` and `x % d` as `x - d * (x // d)`.
- **Strings in Z3.** Each string in a constant list gets an Int id; a string arg is a Z3 `Int`, and any other concrete string maps to -1. Membership over ids is exactly membership over strings.
- **Runtime decision.** The default solver pins the concrete state/args and decides each clause with Z3 (unsat of `¬clause` proves it holds). The gate also evaluates the clauses with the policy's Python semantics and ABSTAINs on any disagreement, so a faulty or injected solver can cause refusals but not permits. A post-state invariant check refuses invariant-breaking steps even for a policy loaded with `skip_inductive_check`.
- **Lean proofs.** Each preservation theorem is proved by `unfold`, case splits on every `if` condition (keeping its equation), on opaque string-membership atoms and on bools, then `simp` + `omega`. A non-inductive policy produces a project whose build fails; Lean never trusts the Python check.
- **Receipts.** COSE_Sign1 (tag 18, EdDSA) over a canonical CBOR payload; `verify_receipt` accepts exactly one canonical encoding, so any byte edit is rejected. The log is RFC 9162 (leaf `0x00`, node `0x01`) with inclusion proofs and a seq/prev hash chain.
