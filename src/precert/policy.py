"""Policy loading (SPEC section 2): syntax/typing, init check, Z3 inductiveness check."""
import copy
import json
import re

from .canon import H, canon
from .errors import InitViolation, PolicyNotInductive, PolicySyntaxError
from .expr import Scope, check_ident, compile_expr, is_bool, is_int, to_py

NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
TOP_KEYS = {"name", "constants", "state", "init", "invariants", "actions"}
REQUIRED_TOP = {"name", "state", "init", "invariants", "actions"}
ACTION_KEYS = {"args", "pre", "update"}
STATE_TYPES = ("int", "bool")
ARG_TYPES = ("int", "bool", "str")


def _label(name, what):
    if not isinstance(name, str) or not name:
        raise PolicySyntaxError(f"{what} name must be a non-empty string")


def _check_value(v, t):
    return (t == "int" and is_int(v)) or (t == "bool" and is_bool(v)) or (t == "str" and type(v) is str)


class ActionSpec:
    """Compiled action: arg types, ordered pre clauses and update expressions (all as IR)."""

    def __init__(self, name, args, pre, update, raw):
        self.name = name
        self.args = args            # name -> type
        self.pre = pre              # [(clause_name, ir)]
        self.update = update        # {state_var: ir}
        self.raw = raw              # the JSON spec as loaded

    # mapping-style access to the raw spec, so `policy.actions[name]["args"]` works
    def __getitem__(self, k):
        return self.raw[k]

    def get(self, k, default=None):
        return self.raw.get(k, default)

    def keys(self):
        return self.raw.keys()

    def __contains__(self, k):
        return k in self.raw

    def __repr__(self):
        return f"ActionSpec({self.name!r}, args={self.args!r})"


class Policy:
    def __init__(self, raw, skip_inductive_check):
        self._raw = raw
        self.inductive_checked = not skip_inductive_check
        self.name = raw["name"]
        self.hash = H(raw)
        self.constants = raw.get("constants", {})
        self.state_types = dict(raw["state"])
        self._init = dict(raw["init"])
        self.invariants = []        # [(name, ir)]
        self.actions = {}           # name -> ActionSpec
        self.str_constants = {k: v for k, v in self.constants.items()
                              if isinstance(v, list) and v and isinstance(v[0], str)}
        self.list_sets = {k: frozenset(v) for k, v in self.constants.items() if isinstance(v, list)}

    @property
    def init(self):
        return copy.deepcopy(self._init)

    @property
    def raw(self):
        return copy.deepcopy(self._raw)

    def lean_theorem_id(self, action_name):
        if action_name not in self.actions:
            raise KeyError(action_name)
        return f"precert_{self.name}_{action_name}_preserves"

    # ---- pure Python semantics (the functions the gate uses) ----

    def step(self, state, action):
        """Pure step, no checks: simultaneous assignment evaluated on the pre-state.

        `action` is {"tool", "args", ...}. For a single-action policy a bare args dict is also accepted."""
        if isinstance(action, dict) and isinstance(action.get("tool"), str) and action["tool"] in self.actions \
                and isinstance(action.get("args"), dict):
            return self.actions[action["tool"]]._step_fn(state, action["args"], self.list_sets)
        if len(self.actions) == 1 and isinstance(action, dict):
            return next(iter(self.actions.values()))._step_fn(state, action, self.list_sets)
        raise KeyError("step needs an action {'tool', 'args', ...} naming an action of the policy")

    def inv_violations(self, state):
        return [n for n, f in self._inv_fns if not f(state, None, self.list_sets)]

    def inv_holds(self, state):
        return all(f(state, None, self.list_sets) for _, f in self._inv_fns)

    def pre_violations(self, action_name, state, args):
        spec = self.actions[action_name]
        return sorted(n for n, f in spec._pre_fns if not f(state, args, self.list_sets))

    def state_wellformed(self, state):
        if not isinstance(state, dict) or set(state) != set(self.state_types):
            return False
        return all(_check_value(state[k], t) for k, t in self.state_types.items())

    def __repr__(self):
        return f"Policy({self.name!r}, hash={self.hash[:12]}...)"


def _compile_fn(src):
    code = compile(src, "<precert-policy>", "eval")
    return eval(code, {"__builtins__": {}}, {})


def _bool_fn(ir):
    return _compile_fn("lambda s, x, C: " + to_py(ir, None))


def load_policy(path_or_dict, skip_inductive_check=False):
    if isinstance(path_or_dict, dict):
        raw = copy.deepcopy(path_or_dict)
    else:
        try:
            with open(path_or_dict, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError) as e:
            raise PolicySyntaxError(f"cannot read policy: {e}") from None
    policy = _parse(raw, skip_inductive_check)
    bad = policy.inv_violations(policy.init)
    if bad:
        raise InitViolation(bad)
    if not skip_inductive_check:
        from .solver import check_inductive
        check_inductive(policy)
    return policy


def _parse(raw, skip):
    if not isinstance(raw, dict):
        raise PolicySyntaxError("policy must be a JSON object")
    missing = REQUIRED_TOP - set(raw)
    if missing:
        raise PolicySyntaxError(f"policy missing keys: {sorted(missing)}")
    extra = set(raw) - TOP_KEYS
    if extra:
        raise PolicySyntaxError(f"policy has unknown keys: {sorted(extra)}")
    try:
        canon(raw)
    except (TypeError, ValueError, UnicodeError) as e:
        raise PolicySyntaxError(f"policy is not canonical JSON: {e}") from None
    name = raw["name"]
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise PolicySyntaxError(f"policy name {name!r} must match ^[a-z][a-z0-9_]*$")

    constants = raw.get("constants", {})
    if not isinstance(constants, dict):
        raise PolicySyntaxError("constants must be an object")
    for k, v in constants.items():
        check_ident(k, "constant")
        ok = is_int(v) or is_bool(v) or type(v) is str
        if isinstance(v, list):
            ok = all(type(e) is str for e in v) or all(is_int(e) for e in v)
        if not ok:
            raise PolicySyntaxError(f"constant {k!r} must be int, bool, str, [str...] or [int...]")

    state = raw["state"]
    if not isinstance(state, dict) or not state:
        raise PolicySyntaxError("state must be a non-empty object")
    for k, t in state.items():
        check_ident(k, "state var")
        if t not in STATE_TYPES:
            raise PolicySyntaxError(f"state var {k!r} has type {t!r}; must be int or bool")
        if k in constants:
            raise PolicySyntaxError(f"name {k!r} is both a constant and a state var")

    init = raw["init"]
    if not isinstance(init, dict) or set(init) != set(state):
        raise PolicySyntaxError("init must assign exactly every state var")
    for k, t in state.items():
        if not _check_value(init[k], t):
            raise PolicySyntaxError(f"init value for {k!r} is not a {t}")

    p = Policy(raw, skip)

    invs = raw["invariants"]
    if not isinstance(invs, dict):
        raise PolicySyntaxError("invariants must be an object")
    scope = Scope(constants, state)
    for iname, src in invs.items():
        _label(iname, "invariant")
        ir, t = compile_expr(src, scope, f"invariant {iname!r}")
        if t != "bool":
            raise PolicySyntaxError(f"invariant {iname!r} must be bool")
        p.invariants.append((iname, ir))

    actions = raw["actions"]
    if not isinstance(actions, dict):
        raise PolicySyntaxError("actions must be an object")
    for aname, spec in actions.items():
        check_ident(aname, "action")
        if not isinstance(spec, dict):
            raise PolicySyntaxError(f"action {aname!r} must be an object")
        extra = set(spec) - ACTION_KEYS
        if extra:
            raise PolicySyntaxError(f"action {aname!r} has unknown keys: {sorted(extra)}")
        args = spec.get("args", {})
        pre = spec.get("pre", {})
        update = spec.get("update", {})
        if not isinstance(args, dict) or not isinstance(pre, dict) or not isinstance(update, dict):
            raise PolicySyntaxError(f"action {aname!r}: args, pre and update must be objects")
        for k, t in args.items():
            check_ident(k, "arg")
            if t not in ARG_TYPES:
                raise PolicySyntaxError(f"action {aname!r} arg {k!r} has type {t!r}")
            if k in constants or k in state:
                raise PolicySyntaxError(f"action {aname!r} arg {k!r} collides with a constant or state var")
        ascope = Scope(constants, state, args)
        pre_ir = []
        for cname, src in pre.items():
            _label(cname, "clause")
            ir, t = compile_expr(src, ascope, f"action {aname!r} pre {cname!r}")
            if t != "bool":
                raise PolicySyntaxError(f"action {aname!r} pre {cname!r} must be bool")
            pre_ir.append((cname, ir))
        upd_ir = {}
        for var, src in update.items():
            if var not in state:
                raise PolicySyntaxError(f"action {aname!r} updates unknown state var {var!r}")
            ir, t = compile_expr(src, ascope, f"action {aname!r} update {var!r}")
            if t != state[var]:
                raise PolicySyntaxError(f"action {aname!r} update {var!r} must be {state[var]}, got {t}")
            upd_ir[var] = ir
        a = ActionSpec(aname, dict(args), pre_ir, upd_ir, spec)
        a._pre_fns = [(n, _bool_fn(ir)) for n, ir in pre_ir]
        body = "{" + ", ".join(
            repr(v) + ": " + (to_py(upd_ir[v], None) if v in upd_ir else "s[" + repr(v) + "]") for v in state) + "}"
        a._step_fn = _compile_fn("lambda s, x, C: " + body)
        p.actions[aname] = a

    p._inv_fns = [(n, _bool_fn(ir)) for n, ir in p.invariants]
    return p
