"""Z3 backend: load-time inductiveness check and the default runtime precondition solver.

Encoding notes
- Every DSL int is a Z3 `Int` (unbounded); never `Real`.
- `//` and `%` always have a constant nonzero divisor d. For d > 0 Z3's `div`/`mod` (Euclidean) coincide with
  Python floor semantics. For d < 0 we use x // d == (-x) // (-d) and x % d == x - d * (x // d).
- Strings only occur as `arg in C` / `arg not in C` with C a constant list. Each distinct string in a constant
  list gets an integer id 0..n-1; a str arg is a Z3 Int, and a concrete string outside every list maps to -1.
  This is exact: membership over ids equals membership over strings, and an unconstrained Int ranges over
  every listed string plus "some other string".
"""
import threading
import time
from dataclasses import dataclass, field

import z3

from .errors import PolicyNotInductive

Z3_LOCK = threading.RLock()
LOAD_TIMEOUT_MS = 30_000


@dataclass
class SolverResult:
    status: str                     # "valid" | "invalid" | "unknown" | "timeout"
    violated: list = field(default_factory=list)
    model: dict = field(default_factory=dict)


def _intern(policy):
    strings = sorted({s for v in policy.str_constants.values() for s in v})
    return {s: i for i, s in enumerate(strings)}


def _fdiv(e, d):
    return e / d if d > 0 else (-e) / (-d)


def encode(ir, env, policy, ids):
    k = ir[0]
    if k == "lit":
        v = ir[1]
        return z3.BoolVal(v) if type(v) is bool else z3.IntVal(v)
    if k == "var":
        return env[(ir[1], ir[2])]
    if k == "neg":
        return -encode(ir[1], env, policy, ids)
    if k == "add":
        return encode(ir[1], env, policy, ids) + encode(ir[2], env, policy, ids)
    if k == "sub":
        return encode(ir[1], env, policy, ids) - encode(ir[2], env, policy, ids)
    if k == "mul":
        return z3.IntVal(ir[1]) * encode(ir[2], env, policy, ids)
    if k == "fdiv":
        return _fdiv(encode(ir[1], env, policy, ids), ir[2])
    if k == "fmod":
        e, d = encode(ir[1], env, policy, ids), ir[2]
        return e % d if d > 0 else e - z3.IntVal(d) * _fdiv(e, d)
    if k == "cmp":
        a, b = encode(ir[2], env, policy, ids), encode(ir[3], env, policy, ids)
        return {"<": a < b, "<=": a <= b, "==": a == b, "!=": a != b, ">": a > b, ">=": a >= b}[ir[1]]
    if k == "smem":
        v = env[("arg", ir[1])]
        m = z3.Or([v == ids[s] for s in policy.constants[ir[2]]]) if policy.constants[ir[2]] else z3.BoolVal(False)
        return z3.Not(m) if ir[3] else m
    if k == "imem":
        e = encode(ir[1], env, policy, ids)
        items = policy.constants[ir[2]]
        m = z3.Or([e == z3.IntVal(i) for i in items]) if items else z3.BoolVal(False)
        return z3.Not(m) if ir[3] else m
    if k == "and":
        return z3.And([encode(p, env, policy, ids) for p in ir[1]])
    if k == "or":
        return z3.Or([encode(p, env, policy, ids) for p in ir[1]])
    if k == "not":
        return z3.Not(encode(ir[1], env, policy, ids))
    if k == "ite":
        return z3.If(encode(ir[1], env, policy, ids), encode(ir[2], env, policy, ids), encode(ir[3], env, policy, ids))
    raise AssertionError(k)


def _mkvar(name, t):
    return z3.Bool(name) if t == "bool" else z3.Int(name)


def _vars(policy, spec):
    env = {("state", v): _mkvar("s!" + v, t) for v, t in policy.state_types.items()}
    for a, t in spec.args.items():
        env[("arg", a)] = _mkvar("x!" + a, t)
    return env


def _unlisted_string(ids):
    s = "unlisted"
    while s in ids:
        s += "_"
    return s


def _val(model, term, t, rev, ids):
    v = model.eval(term, model_completion=True)
    if t == "bool":
        return z3.is_true(v)
    n = v.as_long()
    if t == "str":
        return rev.get(n, _unlisted_string(ids))
    return n


def check_inductive(policy):
    """For every action a and invariant i: Inv(s) & Pre_a(s,x) -> i(step_a(s,x)). Raises PolicyNotInductive."""
    with Z3_LOCK:
        ids = _intern(policy)
        rev = {i: s for s, i in ids.items()}
        for aname, spec in policy.actions.items():
            env = _vars(policy, spec)
            inv = [encode(ir, env, policy, ids) for _, ir in policy.invariants]
            pre = [encode(ir, env, policy, ids) for _, ir in spec.pre]
            post = {("state", v): (encode(spec.update[v], env, policy, ids) if v in spec.update else env[("state", v)])
                    for v in policy.state_types}
            post.update({k: t for k, t in env.items() if k[0] == "arg"})
            for iname, iir in policy.invariants:
                s = z3.Solver()
                s.set("timeout", LOAD_TIMEOUT_MS)
                s.add(*inv, *pre, z3.Not(encode(iir, post, policy, ids)))
                try:
                    r = s.check()
                except z3.Z3Exception:
                    raise PolicyNotInductive(aname, iname, None) from None
                if r == z3.unsat:
                    continue
                if r != z3.sat:
                    raise PolicyNotInductive(aname, iname, None)
                m = s.model()
                cx = {"state": {v: _val(m, env[("state", v)], t, rev, ids) for v, t in policy.state_types.items()},
                      "args": {a: _val(m, env[("arg", a)], t, rev, ids) for a, t in spec.args.items()}}
                # Cross-check the model against the Python semantics; an inconsistency still rejects.
                try:
                    ok = (policy.inv_holds(cx["state"]) and not policy.pre_violations(aname, cx["state"], cx["args"])
                          and iname in policy.inv_violations(policy.step(cx["state"], {"tool": aname, "args": cx["args"]})))
                except Exception:
                    ok = False
                raise PolicyNotInductive(aname, iname, cx if ok else None)


class Z3Solver:
    """Default runtime solver: decides each precondition clause on the concrete state and args.

    For each clause c, an indicator b_c with b_c == c is asserted once; per call the state/args are pinned with
    equalities and each clause is decided by checking `not b_c`: unsat proves the clause holds, sat (with the
    model as witness) proves it fails.
    """

    def __init__(self):
        self._cache = {}

    def _compiled(self, policy, aname):
        key = (id(policy), policy.hash, aname)
        c = self._cache.get(key)
        if c is None:
            ids = _intern(policy)
            spec = policy.actions[aname]
            env = _vars(policy, spec)
            sol = z3.SolverFor("QF_LIA") if not any(t == "bool" for t in policy.state_types.values()) else z3.Solver()
            inds = []
            for i, (cname, ir) in enumerate(spec.pre):
                b = z3.Bool(f"pre!{i}")
                sol.add(b == encode(ir, env, policy, ids))
                inds.append((cname, b))
            c = (policy, env, ids, sol, inds)
            self._cache[key] = c
        return c

    def decide(self, policy, state, action, timeout_ms):
        start = time.perf_counter()
        deadline = start + timeout_ms / 1000.0
        aname = action["tool"]
        args = action["args"]
        with Z3_LOCK:
            _, env, ids, sol, inds = self._compiled(policy, aname)
            spec = policy.actions[aname]
            sol.push()
            try:
                for v, t in policy.state_types.items():
                    val = state[v]
                    sol.add(env[("state", v)] == (z3.BoolVal(val) if t == "bool" else z3.IntVal(val)))
                for a, t in spec.args.items():
                    val = args[a]
                    if t == "str":
                        val = ids.get(val, -1)
                    sol.add(env[("arg", a)] == (z3.BoolVal(val) if t == "bool" else z3.IntVal(val)))

                def run(*assume):
                    remaining = int((deadline - time.perf_counter()) * 1000)
                    if remaining <= 0:
                        return "timeout"
                    sol.set("timeout", max(1, remaining))
                    r = sol.check(*assume)
                    if r == z3.unknown:
                        why = sol.reason_unknown()
                        return "timeout" if ("timeout" in why or "canceled" in why) else "unknown"
                    return r

                base = run()
                if base in ("timeout", "unknown"):
                    return SolverResult(base, [], {})
                if base != z3.sat:      # pinned values must be consistent; anything else is not a decision
                    return SolverResult("unknown", [], {})
                violated = []
                for cname, b in inds:
                    r = run(z3.Not(b))
                    if r in ("timeout", "unknown"):
                        return SolverResult(r, [], {})
                    if r == z3.sat:
                        violated.append(cname)
                    elif r != z3.unsat:
                        return SolverResult("unknown", [], {})
            finally:
                sol.pop()
        if time.perf_counter() > deadline:
            return SolverResult("timeout", [], {})
        model = {"state": dict(state), "args": dict(args)}
        if violated:
            return SolverResult("invalid", sorted(violated), model)
        return SolverResult("valid", [], model)


_default = None


def default_solver():
    global _default
    with Z3_LOCK:
        if _default is None:
            _default = Z3Solver()
        return _default
