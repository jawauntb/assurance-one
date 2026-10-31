"""Runtime gate (SPEC section 3)."""
import copy
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from .canon import H, action_digest, state_hash
from .log import ReceiptLog
from .receipts import Signer, make_receipt
from .solver import default_solver

ACTION_KEYS = {"tool", "args", "principal"}


@dataclass
class Verdict:
    decision: str                   # PERMIT | DENY | ABSTAIN
    reason: str                     # ok | precondition | malformed | unknown_tool | timeout | solver_unknown | halted
    violated: list = field(default_factory=list)
    counterexample: Optional[dict] = None
    certificate: Optional[dict] = None


@dataclass
class ExecResult:
    verdict: Verdict
    receipt: bytes
    output: Any
    executed: bool


def _arg_ok(v, t):
    if t == "int":
        return type(v) is int           # rejects bool and float (even 5.0)
    if t == "bool":
        return type(v) is bool          # rejects int
    return type(v) is str               # exact str only (no subclasses with custom equality)


def _safe(x):
    """Make a value CBOR/UTF-8 encodable for a receipt (e.g. lone surrogates in attacker-supplied strings)."""
    if isinstance(x, str):
        try:
            x.encode("utf-8")
            return x
        except UnicodeEncodeError:
            return x.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(x, dict):
        return {_safe(k): _safe(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_safe(v) for v in x]
    return x


def _deny(reason):
    return Verdict("DENY", reason, [], None, None)


def _abstain(reason):
    return Verdict("ABSTAIN", reason, [], None, None)


class Gate:
    def __init__(self, policy, state=None, signer=None, log=None, timeout_ms=200, solver=None):
        self.policy = policy
        self._state = self._validated(policy.init if state is None else state)
        self.signer = signer if signer is not None else Signer.generate()
        self.log = log if log is not None else ReceiptLog()
        self.timeout_ms = timeout_ms
        self.solver = solver if solver is not None else default_solver()
        self._halted = False
        self._lock = threading.RLock()

    def _validated(self, state):
        state = copy.deepcopy(state)
        if not self.policy.state_wellformed(state):
            raise ValueError("state must assign exactly every state var with the declared type")
        if not self.policy.inv_holds(state):
            raise ValueError(f"state violates invariants: {self.policy.inv_violations(state)}")
        return state

    @property
    def state(self):
        with self._lock:
            return copy.deepcopy(self._state)

    @property
    def halted(self):
        return self._halted

    def _restore(self, state, halted):
        """Resume from persisted state (used by the MCP server on restart). The state must satisfy Inv."""
        with self._lock:
            self._state = self._validated(state)
            self._halted = bool(halted)

    def reconcile(self, state):
        with self._lock:
            self._state = self._validated(state)
            self._halted = False

    # ------------------------------------------------------------------ check

    def check(self, action):
        with self._lock:
            return self._check(action, self._state)[0]

    def _check(self, action, state):
        """Returns (verdict, snapshot). `snapshot` is the plain, immutable-valued copy of the action that was
        decided; execute must use it and never re-read the caller's object (no check/use gap)."""
        try:
            return self._decide(action, state)
        except Exception:
            return _abstain("solver_unknown"), None     # any exception inside the check fails closed

    def _decide(self, action, state):
        p = self.policy
        if self._halted:
            return _abstain("halted"), None
        # Exact dicts only: a dict subclass could answer reads differently at check time and at use time.
        if type(action) is not dict:
            return _deny("malformed"), None
        action = dict(action)                           # one read of the caller's object, then never again
        tool = action.get("tool")
        if type(tool) is not str or tool not in p.actions:
            return _deny("unknown_tool"), None
        spec = p.actions[tool]
        args = action.get("args")
        principal = action.get("principal")
        if set(action) != ACTION_KEYS or type(principal) is not str:
            return _deny("malformed"), None
        if type(args) is not dict:
            return _deny("malformed"), None
        args = dict(args)
        if set(args) != set(spec.args) or not all(_arg_ok(args[k], t) for k, t in spec.args.items()):
            return _deny("malformed"), None
        # Values are exact int/bool/str, hence immutable: this snapshot cannot change under us.
        snap = {"tool": tool, "args": args, "principal": principal}
        own_state = copy.deepcopy(state)                # the gate's copy; the solver never sees this object

        res = self.solver.decide(p, copy.deepcopy(own_state), copy.deepcopy(snap), self.timeout_ms)
        status = getattr(res, "status", None)
        if status == "timeout":
            return _abstain("timeout"), None
        if status not in ("valid", "invalid"):
            return _abstain("solver_unknown"), None

        # Defense in depth: the solver's verdict must agree with the policy's Python semantics.
        py_violated = p.pre_violations(tool, own_state, args)
        if status == "invalid":
            violated = sorted(res.violated) if isinstance(res.violated, (list, tuple)) else None
            if not violated or violated != py_violated:
                return _abstain("solver_unknown"), None
            return Verdict("DENY", "precondition", violated,
                           {"state": copy.deepcopy(own_state), "args": dict(args)}, None), snap
        if py_violated:
            return _abstain("solver_unknown"), None
        # The post-state must satisfy Inv. For a policy proved inductive this always holds; it matters only for a
        # policy loaded with skip_inductive_check, where an invariant-breaking step is refused, never permitted.
        if not p.inv_holds(p.step(own_state, snap)):
            return _abstain("solver_unknown"), None
        cert = {
            "pre_state_hash": state_hash(own_state),
            "policy_hash": p.hash,
            "action_digest": action_digest(snap),
            "lean_theorem_id": p.lean_theorem_id(tool),
            "solver_result": "valid",
        }
        return Verdict("PERMIT", "ok", [], None, cert), snap

    # ------------------------------------------------------------------ execute

    def execute(self, action, tool, certificate=None):
        # `certificate` is advisory only: the full check always runs against the current state.
        with self._lock:
            pre_state = copy.deepcopy(self._state)
            verdict, snap = self._check(action, pre_state)
            executed = False
            tool_error = False
            output = None
            settlement = None
            if verdict.decision == "PERMIT":
                # Re-establish, on exactly the state and args about to be executed, what the check concluded.
                try:
                    new_state = self.policy.step(pre_state, snap)
                    sound = (verdict.certificate["pre_state_hash"] == state_hash(pre_state)
                             and verdict.certificate["action_digest"] == action_digest(snap)
                             and not self.policy.pre_violations(snap["tool"], pre_state, snap["args"])
                             and self.policy.inv_holds(new_state))
                except Exception:
                    sound = False
                if not sound:
                    verdict = _abstain("solver_unknown")
            if verdict.decision == "PERMIT":
                args = snap["args"]
                try:
                    output = tool(dict(args))
                    executed = True
                except Exception:
                    tool_error = True
                    output = None
                if executed:
                    if isinstance(output, dict) and "settled_amount_cents" in output and "amount_cents" in args:
                        req, got = args["amount_cents"], output["settled_amount_cents"]
                        match = type(got) is int and got == req
                        settlement = {"requested": req, "settled": got if type(got) is int else _safe(repr(got)),
                                      "mismatch": not match}
                    self._state = new_state
                    if settlement is not None and settlement["mismatch"]:
                        self._halted = True
            receipt = self._write_receipt(snap if snap is not None else action, verdict, pre_state, executed,
                                          tool_error, settlement)
            return ExecResult(verdict, receipt, output, executed)

    def _write_receipt(self, action, verdict, pre_state, executed, tool_error, settlement):
        p = self.policy
        a = action if isinstance(action, dict) else {}
        try:
            digest = action_digest(action)
        except Exception:
            digest = H({"unserializable_action": repr(action)})
        principal = a.get("principal")
        tool = a.get("tool")
        cert = verdict.certificate
        if cert is not None:
            adm = {"pre_state_hash": cert["pre_state_hash"], "policy_hash": cert["policy_hash"],
                   "lean_theorem_id": cert["lean_theorem_id"], "solver_result": cert["solver_result"],
                   "counterexample": None}
        else:
            adm = {"pre_state_hash": state_hash(pre_state), "policy_hash": p.hash,
                   "lean_theorem_id": None, "solver_result": None, "counterexample": _safe(verdict.counterexample)}

        def build(seq, prev):
            payload = {
                "seq": seq,
                "prev": prev,
                "principal": _safe(principal) if type(principal) is str else "",
                "action_digest": digest,
                "tool": _safe(tool) if type(tool) is str else "",
                "decision": verdict.decision,
                "reason": verdict.reason,
                "violated": _safe(list(verdict.violated)),
                "executed": executed,
                "tool_error": tool_error,
                "policy_hash": p.hash,
                "admissibility": adm,
                "settlement": settlement,
            }
            return make_receipt(self.signer, payload)

        _, receipt = self.log.append_built(build)
        return receipt
