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

    def reconcile(self, state):
        with self._lock:
            self._state = self._validated(state)
            self._halted = False

    # ------------------------------------------------------------------ check

    def check(self, action):
        with self._lock:
            return self._check(action, self._state)

    def _check(self, action, state):
        try:
            return self._decide(action, state)
        except Exception:
            return _abstain("solver_unknown")       # any exception inside the check fails closed

    def _decide(self, action, state):
        p = self.policy
        if self._halted:
            return _abstain("halted")
        if not isinstance(action, dict):
            return _deny("malformed")
        tool = action.get("tool")
        if type(tool) is not str or tool not in p.actions:
            return _deny("unknown_tool")
        spec = p.actions[tool]
        args = action.get("args")
        if set(action) != ACTION_KEYS or type(action.get("principal")) is not str:
            return _deny("malformed")
        if not isinstance(args, dict) or set(args) != set(spec.args):
            return _deny("malformed")
        if not all(_arg_ok(args[k], t) for k, t in spec.args.items()):
            return _deny("malformed")

        snap_state = copy.deepcopy(state)
        snap_action = {"tool": tool, "args": copy.deepcopy(args), "principal": action["principal"]}
        res = self.solver.decide(p, snap_state, snap_action, self.timeout_ms)
        status = getattr(res, "status", None)
        if status == "timeout":
            return _abstain("timeout")
        if status not in ("valid", "invalid"):
            return _abstain("solver_unknown")

        # Defense in depth: the solver's verdict must agree with the policy's Python semantics.
        py_violated = p.pre_violations(tool, snap_state, snap_action["args"])
        if status == "invalid":
            violated = sorted(res.violated or [])
            if not violated or violated != py_violated:
                return _abstain("solver_unknown")
            return Verdict("DENY", "precondition", violated,
                           {"state": snap_state, "args": snap_action["args"]}, None)
        if py_violated:
            return _abstain("solver_unknown")
        # The post-state must satisfy Inv. For a policy proved inductive this always holds; it matters only for a
        # policy loaded with skip_inductive_check, where an invariant-breaking step is refused, never permitted.
        if not p.inv_holds(p.step(snap_state, snap_action)):
            return _abstain("solver_unknown")
        cert = {
            "pre_state_hash": state_hash(snap_state),
            "policy_hash": p.hash,
            "action_digest": action_digest(action),
            "lean_theorem_id": p.lean_theorem_id(tool),
            "solver_result": "valid",
        }
        return Verdict("PERMIT", "ok", [], None, cert)

    # ------------------------------------------------------------------ execute

    def execute(self, action, tool, certificate=None):
        # `certificate` is advisory only: the full check always runs against the current state.
        with self._lock:
            pre_state = copy.deepcopy(self._state)
            verdict = self._check(action, pre_state)
            executed = False
            tool_error = False
            output = None
            settlement = None
            new_state = None
            if verdict.decision == "PERMIT":
                args = action["args"]
                new_state = self.policy.step(pre_state, action)
                try:
                    output = tool(copy.deepcopy(args))
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
            receipt = self._write_receipt(action, verdict, pre_state, executed, tool_error, settlement)
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
