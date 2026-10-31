# precert: SPEC

A pre-execution gate for AI agent tool calls. Every action at a governed boundary gets a verdict **before** it runs: `PERMIT` with a signed admissibility certificate, `DENY` with the violated clauses and a concrete counterexample, or `ABSTAIN` (fail closed). Every executed or refused action is written as a signed receipt to an append-only Merkle transparency log.

What precert claims, and only this: **no executed action violates a declared invariant**, given that the policy's invariants are inductive (proved at load time and in Lean) and every action passes the runtime precondition check. It does not claim the agent is correct, that the policy is the right policy, or that a tool's real-world effect matches its request (see Settlement).

## 0. Milestones

| M | Scope |
|---|---|
| M1 | Policy DSL, load-time inductiveness check (Z3), runtime gate (Z3), fail-closed semantics, CAS on pre-state, settlement halt |
| M2 | Lean 4 project generation: one preservation theorem per action, proved with no `sorry`/`admit`/new axioms; `precert_step` executable for differential testing |
| M3 | COSE_Sign1 Ed25519 receipts, hash chain, RFC 9162 Merkle log with inclusion proofs |
| M4 | MCP stdio server that is the only route to governed tools; latency report |

Tests are tagged by milestone (`@pytest.mark.m1` ... `m4`). M(n+1) tests may assume M(n) passes.

## 1. Canonical hashing

`canon(x) = json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`
`H(x) = sha256(canon(x)).hexdigest()`

- `policy.hash = H(policy_dict)` over the policy JSON exactly as loaded.
- `state_hash(state) = H(state)`
- `action_digest(action) = H(action)` where `action = {"tool": str, "args": dict, "principal": str}`.

## 2. Policy DSL

A policy is a JSON object:

```
{
  "name":       str matching ^[a-z][a-z0-9_]*$,
  "constants":  {name: int | bool | str | [str...] | [int...]},
  "state":      {name: "int" | "bool"},
  "init":       {name: value}            # every state var, correct type
  "invariants": {name: expr}             # over state + constants
  "actions": {
     name: {
       "args":   {name: "int" | "bool" | "str"},
       "pre":    {clause_name: expr},    # over state + args + constants; may be {}
       "update": {state_var: expr}       # over state + args + constants; omitted vars unchanged
     }
  }
}
```

Names across constants, state and an action's args must be disjoint; violation is a `PolicySyntaxError`.

### 2.1 Expression language

Python expression syntax, parsed with `ast`, restricted to:

- integer and boolean literals (no floats, no strings except as members of constant lists via `in`)
- names bound to constants, state vars, or (in `pre`/`update`) the action's args
- `+ - *`, `//`, `%`, unary `-`; `*`, `//`, `%` require at least one operand that is an integer literal or integer constant (linear arithmetic only); `//` and `%` have **Python floor semantics** on all integers including negatives, and a zero divisor is a `PolicySyntaxError`
- comparisons `< <= == != > >=`, chained comparisons allowed
- `x in C` / `x not in C` where `C` is a constant list
- `and`, `or`, `not`
- conditional expressions `a if c else b`

Anything else is a `PolicySyntaxError` at load time. Integers are unbounded mathematical integers.

### 2.2 Semantics

- `Inv(s)` = conjunction of all invariants.
- `Pre_a(s, x)` = conjunction of all clauses of action `a`.
- `step_a(s, x)` = simultaneous assignment: every RHS is evaluated on the pre-state.

### 2.3 Load-time checks (`load_policy`)

1. Syntax and typing (§2, §2.1).
2. `Inv(init)` holds, else `InitViolation(invariant_names)`.
3. Inductiveness, decided with Z3 over all states and all well-typed args (strings unconstrained): for every action `a`, `Inv(s) ∧ Pre_a(s,x) → Inv(step_a(s,x))`. If Z3 finds a counterexample, raise `PolicyNotInductive(action, invariant, counterexample)` where `invariant` names one invariant that fails and `counterexample` is a dict of concrete state/arg values. If Z3 returns unknown, raise `PolicyNotInductive` with `counterexample=None` (reject, fail closed).

A policy that is true on all reachable states but not inductive (fixture `nonInductive_remaining.json`) **must be rejected**; the same policy with the strengthening invariant (`inductive_remaining.json`) must load.

All load-time errors subclass `PolicyError` (`PolicySyntaxError`, `InitViolation`, `PolicyNotInductive`). Exported from `precert`: `load_policy, Policy, Gate, Verdict, ExecResult, SolverResult, Signer, ReceiptLog, verify_receipt, PolicyError, PolicySyntaxError, InitViolation, PolicyNotInductive, ReceiptInvalid`. `InitViolation.invariants` lists the failing invariant names; `PolicyNotInductive` has `.action`, `.invariant`, `.counterexample` (`{"state": {...}, "args": {...}}` or `None`).

### 2.4 Policy object

`load_policy(path_or_dict, skip_inductive_check=False) -> Policy`. `skip_inductive_check=True` exists only so tests can feed a non-inductive policy to the Lean generator; the gate must still work on such a policy but nothing else may set it.

`Policy` exposes `name`, `hash`, `init` (dict), `actions` (dict name -> spec), `step(state, action) -> new_state` (pure Python step, no checks; the same function the gate uses), and `lean_theorem_id(action_name)`.

### 2.5 Lean generation (M2)

`precert.lean.generate(policy, outdir) -> path` writes a Lake project (Lean 4 core, no Mathlib) and returns its directory.

- A header comment `-- policy_hash: <policy.hash>` in the main source file.
- Definitions of the state structure, `Inv`, one `Pre` and one `step` per action, with constants inlined.
- For each action `a`, `theorem precert_<policy>_<a>_preserves : ∀ s x, Inv s → Pre_a s x → Inv (step_a s x)` (names may be namespaced but the identifier `precert_<policy>_<a>_preserves` must appear after `theorem`), proved without `sorry`, `admit`, `axiom`, `native_decide`, `implemented_by`, `extern` or `unsafe`.
- An executable target `precert_step` that reads `{"state": ..., "action": ...}` JSON on stdin and prints the next state as JSON (same key names and JSON types as the Python state). `//` and `%` must have Python floor semantics in both Lean and Python.
- Lean must not trust the Python checker: a non-inductive policy loaded with `skip_inductive_check=True` must make `generate` raise `PolicyNotInductive` or yield a project whose `lake build` fails.

## 3. Runtime gate

```python
from precert import load_policy, Gate, Signer, ReceiptLog

policy = load_policy("tests/fixtures/payments.json")       # path or dict
gate = Gate(policy, state=None, signer=None, log=None, timeout_ms=200, solver=None)
v = gate.check(action)                                     # pure: no state change, no receipt
r = gate.execute(action, tool, certificate=None)           # check + run + receipt
```

- `state=None` means `policy.init`. A provided state must satisfy `Inv`, else `ValueError`.
- `signer=None` generates a fresh `Signer`; `log=None` creates an in-memory `ReceiptLog`.
- `gate.state` returns a copy of the current state dict. `gate.halted` is a bool. `gate.log` is the `ReceiptLog`; `gate.signer` is the `Signer`.

### 3.1 Verdict

`Verdict` has fields:

| field | meaning |
|---|---|
| `decision` | `"PERMIT"`, `"DENY"`, or `"ABSTAIN"` |
| `reason` | `"ok"`, `"precondition"`, `"malformed"`, `"unknown_tool"`, `"timeout"`, `"solver_unknown"`, `"halted"` |
| `violated` | list of violated clause names (DENY/precondition only, else `[]`), sorted |
| `counterexample` | on DENY/precondition: `{"state": {...}, "args": {...}}` with the concrete values that falsify each clause in `violated`; else `None` |
| `certificate` | on PERMIT only, else `None` |

Certificate:

```
{
  "pre_state_hash": state_hash(state at check time),
  "policy_hash":    policy.hash,
  "action_digest":  action_digest(action),
  "lean_theorem_id": "precert_<policy>_<action>_preserves",
  "solver_result":  "valid"
}
```

Decision rules, in order:

1. `gate.halted` → `ABSTAIN/halted`.
2. `action["tool"]` not an action of the policy → `DENY/unknown_tool`.
3. Malformed → `DENY/malformed`: missing or extra args, missing `principal`, wrong types. `int` args reject `bool` and `float` (even `5.0`); `bool` args reject `int`; `str` args reject non-strings.
4. Decide `Pre_a(state, args)` with the solver within `timeout_ms`:
   - all clauses hold → `PERMIT/ok`
   - some clause fails → `DENY/precondition` with every failing clause in `violated`
   - solver unknown → `ABSTAIN/solver_unknown`; time budget exceeded → `ABSTAIN/timeout`

**Never PERMIT on unknown, timeout, exception, or halted.** Any exception inside the check yields `ABSTAIN`.

### 3.2 Solver protocol

`solver` is any object with `decide(policy, state, action, timeout_ms) -> SolverResult` where `SolverResult(status, violated, model)` and `status ∈ {"valid","invalid","unknown","timeout"}`. Default is the Z3-backed solver. Tests inject fakes to exercise fail-closed paths.

### 3.3 execute

`gate.execute(action, tool, certificate=None) -> ExecResult(verdict, receipt, output, executed)`

- Execution is serialized per gate (thread-safe). Check, tool call and state update are one critical section.
- `execute` always runs the full check of §3.1 against the current state. A `certificate` is advisory and never bypasses the check, even when its `pre_state_hash` matches. When its `pre_state_hash` differs from the current state hash, the verdict simply reflects the current state (re-checked, never blindly refused).
- On PERMIT: call `tool(args)`, set `state = step(state, args)`, `executed=True`. On DENY/ABSTAIN: tool is not called, state unchanged, `executed=False`.
- If the tool raises, state is unchanged, `executed=False`, the receipt records `"tool_error": true`, and the exception is not propagated.
- Every call to `execute` appends exactly one receipt to the log, whatever the verdict.

### 3.4 Settlement

If the tool returns a dict containing `settled_amount_cents` and the action's args contain `amount_cents` with a different value, the receipt records `settlement = {"requested": a, "settled": b, "mismatch": true}`, the state is still stepped with the requested args, and the gate becomes `halted`. While halted, every check is `ABSTAIN/halted`. `gate.reconcile(state)` sets the state (must satisfy `Inv`, else `ValueError`) and clears `halted`.

## 4. Receipts and log (M3)

### 4.1 Signer

`Signer.generate()`; `signer.public_key_bytes` is the 32-byte raw Ed25519 public key.

### 4.2 Receipt format

Each receipt is the CBOR encoding of a COSE_Sign1 message (RFC 9052): CBOR tag 18 around `[protected, unprotected, payload, signature]` where

- `protected` = bstr of CBOR map `{1: -8}` (alg EdDSA)
- `unprotected` = `{}`
- `payload` = bstr of a CBOR map with text keys:

```
seq            int, 0-based position in the log
prev           bytes(32): sha256 of the previous receipt's bytes; 32 zero bytes for seq 0
principal      str
action_digest  str
tool           str
decision       str
reason         str
violated       [str]
executed       bool
tool_error     bool
policy_hash    str
admissibility  { pre_state_hash, policy_hash, lean_theorem_id, solver_result, counterexample }
               (certificate fields on PERMIT; on DENY/ABSTAIN lean_theorem_id/solver_result may be null
                and counterexample is the verdict's counterexample)
settlement     null or {requested, settled, mismatch}
```

- `signature` = Ed25519 over `Sig_structure = ["Signature1", protected, b"", payload]` (CBOR-encoded).
- `ExecResult.receipt` is the receipt bytes.
- `precert.verify_receipt(receipt_bytes, public_key_bytes) -> payload dict`, raising `ReceiptInvalid` on any bad structure or signature.

### 4.3 Log

`ReceiptLog(path=None)`: in-memory if `path` is None, else append-only file that reloads on construction.

- `append(receipt_bytes) -> index`, `size`, `entries() -> [bytes]`
- `root() -> bytes(32)`: RFC 9162 Merkle tree hash; leaf hash `sha256(0x00 || receipt_bytes)`, node `sha256(0x01 || left || right)`, split at the largest power of two less than n. Empty tree hash is `sha256(b"")`.
- `inclusion_proof(index) -> [bytes]`: RFC 9162 §2.1.3 audit path for the current tree size.
- `ReceiptLog.verify_chain(payloads) -> bool` (static): payload `seq` values consecutive from the first, each `prev` equals sha256 of the preceding receipt's bytes; takes a list of `(receipt_bytes, payload)` pairs. Deleting any record between two presented records makes it return False.

## 5. MCP server (M4)

`python -m precert.mcp_server --policy <path> --tools <module>:<attr> --log <path> [--state <json-path>]`

- stdio transport, newline-delimited JSON-RPC 2.0, MCP methods `initialize`, `notifications/initialized`, `tools/list`, `tools/call`.
- `<module>:<attr>` is a dict `{name: callable(args) -> dict}`. `tools/list` lists **only** names that are actions of the policy, with an `inputSchema` derived from the action's args. Tools in the dict that are not policy actions are never listed and any call to them returns `isError: true` without invoking them.
- `tools/call` routes through `Gate.execute`. Principal is `params["_meta"]["principal"]` if present, else `"agent"`. Result: `{"content": [{"type": "text", "text": json.dumps({"decision","reason","violated","output"})}], "isError": decision != "PERMIT"}`.
- Receipts go to `--log`.

## 6. Edge cases (all must hold)

- Budget boundary: `spent + amount == budget` is permitted; one cent more is denied.
- Window boundary: `ts` exactly divisible by `window_s` starts a new window.
- `ts` decreasing is denied (`monotone_time`).
- `amount_cents=True` is malformed; `amount_cents=5.0` is malformed.
- Payee strings match exactly (no trimming, no case folding).
- Concurrent `execute` from many threads never overspends.

## 7. Non-goals for v1

Public-chain anchoring; policy signing and key distribution; symbolic (partially unknown) args; anything other than the expression language above; network transports for MCP.

## 8. Acceptance criteria → tests

| # | Criterion | Tests |
|---|---|---|
| A1 | Soundness: zero executed actions violate an invariant across ≥10k randomized + adversarial actions (oracle replay) | `test_m1_soundness.py` |
| A2 | No false denies on oracle-valid actions; ABSTAIN rate ≤ 5% on the payments workload | `test_m1_soundness.py` |
| A3 | Fail closed on unknown, timeout, exception, halted, malformed, unknown tool | `test_m1_gate.py` |
| A4 | Every DENY's counterexample falsifies exactly the named clauses under the oracle | `test_m1_gate.py` |
| A5 | Non-inductive policy rejected; strengthened version loads; init violation rejected | `test_m1_policy.py` |
| A6 | CAS re-check on stale certificate; concurrency never overspends | `test_m1_gate.py`, `test_m1_soundness.py` |
| A7 | Settlement mismatch halts until reconcile | `test_m1_gate.py` |
| A8 | Lean project builds, zero sorry/admit/axiom, theorem ids and policy hash match | `test_m2_lean.py` |
| A9 | Lean `precert_step` agrees with Python step on random states (differential) | `test_m2_lean.py` |
| A10 | Receipts verify independently; any byte edit fails; inclusion proofs verify; middle deletion detected | `test_m3_receipts.py` |
| A11 | MCP: only governed tools reachable; refused calls have no side effect | `test_m4_mcp.py` |
| A12 | p50/p95 check latency reported; p95 < 200 ms on payments | `test_m4_latency.py` |

## 9. Repo rules

- `tests/` and `tests.lock` are read-only for the implementer. CI runs `scripts/check_tests_lock.sh` first.
- Dependencies: Python ≥ 3.11, `z3-solver`, `cbor2`, `cryptography`, `pytest`; Lean 4 via elan (core only, **no Mathlib**; use `omega`, `decide`, `simp`).
- Held-out tests live in a separate private repo and are run only by the verifier.
