# assurance-one: precert

Pre-execution gate for AI agent tool calls. Every governed action gets PERMIT with a signed admissibility certificate, DENY with a counterexample, or ABSTAIN (fail closed), and every call lands as a signed receipt in a Merkle transparency log. Invariants are proved inductive in Z3 at load time and in Lean 4.

- Contract: `SPEC.md`
- Agent rules: `AGENTS.md`
- Tests are read-only (`tests.lock`, checked in CI). Run: `pytest -c tests/pytest.ini tests -m m1`
