# precert agent rules

- Read SPEC.md first. It is the contract.
- `tests/` and `tests.lock` are read-only. Do not edit, delete, skip, xfail, rename, or reconfigure tests. `scripts/check_tests_lock.sh` must pass.
- Implementation goes in `src/precert/`. Run tests with `pytest -c tests/pytest.ini tests -m m1` (then m2, m3, m4).
- Do not import `tests/oracle.py` from `src/`.
- Money is integer cents. Z3 uses `Int`, never `Real`. `//` and `%` are Python floor semantics everywhere.
- Never PERMIT on unknown, timeout, exception, or halted.
- If a test looks wrong, stop and report it with reasoning.
