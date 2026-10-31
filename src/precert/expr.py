"""Expression language (SPEC section 2.1): parse with `ast`, type-check, lower to a small IR.

IR nodes are tuples; every node evaluates to an `int` or a `bool`:

    ("lit", value)                      int or bool literal (constants are inlined)
    ("var", kind, name)                 kind in {"state", "arg"}; int or bool typed
    ("neg", e)
    ("add", a, b) / ("sub", a, b)
    ("mul", k, e)                       k is an int literal (linear arithmetic only)
    ("fdiv", e, d) / ("fmod", e, d)     d is a nonzero int literal; Python floor semantics
    ("cmp", op, a, b)                   op in {"<","<=","==","!=",">",">="}
    ("smem", arg, cname, negated)       str arg membership in a str constant list
    ("imem", e, cname, negated)         int membership in an int constant list
    ("and", [e...]) / ("or", [e...]) / ("not", e)
    ("ite", c, a, b)

Constants are folded: any subexpression built only from literals and constants becomes a literal.
"""
import ast
import keyword
import re

from .errors import PolicySyntaxError

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CMP_OPS = {ast.Lt: "<", ast.LtE: "<=", ast.Eq: "==", ast.NotEq: "!=", ast.Gt: ">", ast.GtE: ">="}
MAX_EXPR_LEN = 10_000


def is_int(v):
    return type(v) is int


def is_bool(v):
    return type(v) is bool


def check_ident(name, what):
    if not isinstance(name, str) or not IDENT.match(name) or keyword.iskeyword(name):
        raise PolicySyntaxError(f"{what} name {name!r} is not a valid identifier")


def _fold_cmp(op, a, b):
    return {"<": a < b, "<=": a <= b, "==": a == b, "!=": a != b, ">": a > b, ">=": a >= b}[op]


class Scope:
    """Names visible to an expression: constants, state vars and (optionally) one action's args."""

    def __init__(self, constants, state, args=None):
        self.constants = constants      # name -> value
        self.state = state              # name -> "int" | "bool"
        self.args = args or {}          # name -> "int" | "bool" | "str"


def compile_expr(src, scope, where):
    """Parse `src` and return (ir, type) with type in {"int", "bool"}. Raises PolicySyntaxError."""
    if not isinstance(src, str):
        raise PolicySyntaxError(f"{where}: expression must be a string, got {type(src).__name__}")
    if len(src) > MAX_EXPR_LEN:
        raise PolicySyntaxError(f"{where}: expression too long")
    try:
        tree = ast.parse(src.strip(), mode="eval")
    except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
        raise PolicySyntaxError(f"{where}: cannot parse {src!r}: {e}") from None
    try:
        return _Compiler(scope, where).node(tree.body)
    except RecursionError:
        raise PolicySyntaxError(f"{where}: expression nested too deeply") from None


class _Compiler:
    def __init__(self, scope, where):
        self.scope = scope
        self.where = where

    def err(self, msg):
        raise PolicySyntaxError(f"{self.where}: {msg}")

    # Returns (ir, type). type in {"int", "bool", "str"}; "str" only for a bare str arg / str constant
    # and is only accepted on the left of `in` / `not in`.
    def node(self, n):
        ir, t = self._node(n)
        if t == "str":
            self.err("strings may only appear on the left of `in` / `not in` against a constant list")
        return ir, t

    def _node(self, n):
        m = getattr(self, "_" + type(n).__name__, None)
        if m is None:
            self.err(f"unsupported syntax {type(n).__name__}")
        return m(n)

    def _Constant(self, n):
        v = n.value
        if is_bool(v):
            return ("lit", v), "bool"
        if is_int(v):
            return ("lit", v), "int"
        self.err(f"unsupported literal {v!r} (only integer and boolean literals are allowed)")

    def _Name(self, n):
        name = n.id
        sc = self.scope
        if name in sc.args:
            t = sc.args[name]
            return (("sarg", name) if t == "str" else ("var", "arg", name)), t
        if name in sc.state:
            return ("var", "state", name), sc.state[name]
        if name in sc.constants:
            v = sc.constants[name]
            if is_bool(v):
                return ("lit", v), "bool"
            if is_int(v):
                return ("lit", v), "int"
            if isinstance(v, str):
                return ("slit", v), "str"
            self.err(f"list constant {name!r} may only appear on the right of `in`")
        self.err(f"unknown name {name!r}")

    def _UnaryOp(self, n):
        if isinstance(n.op, ast.USub):
            e, t = self.node(n.operand)
            if t != "int":
                self.err("unary - requires an int")
            if e[0] == "lit":
                return ("lit", -e[1]), "int"
            return ("neg", e), "int"
        if isinstance(n.op, ast.Not):
            e, t = self.node(n.operand)
            if t != "bool":
                self.err("`not` requires a bool")
            if e[0] == "lit":
                return ("lit", not e[1]), "bool"
            return ("not", e), "bool"
        self.err(f"unsupported unary operator {type(n.op).__name__}")

    def _BinOp(self, n):
        a, ta = self.node(n.left)
        b, tb = self.node(n.right)
        if ta != "int" or tb != "int":
            self.err("arithmetic requires int operands")
        op = n.op
        if isinstance(op, (ast.Add, ast.Sub)):
            if a[0] == "lit" and b[0] == "lit":
                return ("lit", a[1] + b[1] if isinstance(op, ast.Add) else a[1] - b[1]), "int"
            return ("add" if isinstance(op, ast.Add) else "sub", a, b), "int"
        if isinstance(op, ast.Mult):
            if a[0] == "lit" and b[0] == "lit":
                return ("lit", a[1] * b[1]), "int"
            if a[0] == "lit":
                return ("mul", a[1], b), "int"
            if b[0] == "lit":
                return ("mul", b[1], a), "int"
            self.err("`*` requires an operand that is an integer literal or integer constant (linear arithmetic only)")
        if isinstance(op, (ast.FloorDiv, ast.Mod)):
            # Linear arithmetic: the divisor must be a literal / constant, so a zero divisor is a load-time error.
            if b[0] != "lit":
                self.err("`//` and `%` require an integer literal or integer constant divisor (linear arithmetic only)")
            d = b[1]
            if d == 0:
                self.err("zero divisor")
            fd = isinstance(op, ast.FloorDiv)
            if a[0] == "lit":
                return ("lit", a[1] // d if fd else a[1] % d), "int"
            return ("fdiv" if fd else "fmod", a, d), "int"
        self.err(f"unsupported operator {type(op).__name__}")

    def _BoolOp(self, n):
        parts = []
        for v in n.values:
            e, t = self.node(v)
            if t != "bool":
                self.err("`and` / `or` require bool operands")
            parts.append(e)
        kind = "and" if isinstance(n.op, ast.And) else "or"
        lits = [p for p in parts if p[0] == "lit"]
        if len(lits) == len(parts):
            vals = [p[1] for p in parts]
            return ("lit", all(vals) if kind == "and" else any(vals)), "bool"
        return (kind, parts), "bool"

    def _IfExp(self, n):
        c, tc = self.node(n.test)
        a, ta = self.node(n.body)
        b, tb = self.node(n.orelse)
        if tc != "bool":
            self.err("conditional test must be bool")
        if ta != tb:
            self.err("conditional branches must have the same type")
        if c[0] == "lit":
            return (a if c[1] else b), ta
        return ("ite", c, a, b), ta

    def _Compare(self, n):
        left = n.left
        parts = []
        for op, right in zip(n.ops, n.comparators):
            parts.append(self._compare1(left, op, right))
            left = right
        if len(parts) == 1:
            return parts[0], "bool"
        if all(p[0] == "lit" for p in parts):
            return ("lit", all(p[1] for p in parts)), "bool"
        return ("and", parts), "bool"

    def _compare1(self, left, op, right):
        if isinstance(op, (ast.In, ast.NotIn)):
            neg = isinstance(op, ast.NotIn)
            if not isinstance(right, ast.Name) or right.id not in self.scope.constants \
                    or not isinstance(self.scope.constants[right.id], list):
                self.err("right side of `in` must be a constant list")
            cname = right.id
            items = self.scope.constants[cname]
            e, t = self._node(left)
            elem = "str" if items and isinstance(items[0], str) else ("int" if items else None)
            if elem is not None and t != elem:
                self.err(f"`in {cname}` needs a {elem} on the left, got {t}")
            if t == "bool":
                self.err("`in` requires an int or str on the left")
            if e[0] in ("lit", "slit"):
                return ("lit", (e[1] in items) != neg)
            if t == "str":
                return ("smem", e[1], cname, neg)
            return ("imem", e, cname, neg)
        a, ta = self.node(left)
        b, tb = self.node(right)
        o = CMP_OPS.get(type(op))
        if o is None:
            self.err(f"unsupported comparison {type(op).__name__}")
        if o in ("==", "!="):
            if ta != tb:
                self.err("`==` / `!=` require operands of the same type")
        elif ta != "int" or tb != "int":
            self.err(f"`{o}` requires int operands")
        if a[0] == "lit" and b[0] == "lit":
            return ("lit", _fold_cmp(o, a[1], b[1]))
        return ("cmp", o, a, b)


# ---------------------------------------------------------------- Python code generation

def to_py(ir, consts):
    """Python source for `ir`. State is `s`, args are `x`, constant sets are `C[name]`."""
    k = ir[0]
    if k == "lit":
        return repr(ir[1])
    if k == "var":
        return ("s" if ir[1] == "state" else "x") + "[" + repr(ir[2]) + "]"
    if k == "neg":
        return "(-" + to_py(ir[1], consts) + ")"
    if k in ("add", "sub"):
        return "(" + to_py(ir[1], consts) + (" + " if k == "add" else " - ") + to_py(ir[2], consts) + ")"
    if k == "mul":
        return "(" + repr(ir[1]) + " * " + to_py(ir[2], consts) + ")"
    if k in ("fdiv", "fmod"):
        return "(" + to_py(ir[1], consts) + (" // " if k == "fdiv" else " % ") + "(" + repr(ir[2]) + "))"
    if k == "cmp":
        return "(" + to_py(ir[2], consts) + " " + ir[1] + " " + to_py(ir[3], consts) + ")"
    if k == "smem":
        return "(x[" + repr(ir[1]) + "] " + ("not in" if ir[3] else "in") + " C[" + repr(ir[2]) + "])"
    if k == "imem":
        return "(" + to_py(ir[1], consts) + " " + ("not in" if ir[3] else "in") + " C[" + repr(ir[2]) + "])"
    if k in ("and", "or"):
        return "(" + (" and " if k == "and" else " or ").join(to_py(p, consts) for p in ir[1]) + ")"
    if k == "not":
        return "(not " + to_py(ir[1], consts) + ")"
    if k == "ite":
        return "(" + to_py(ir[2], consts) + " if " + to_py(ir[1], consts) + " else " + to_py(ir[3], consts) + ")"
    raise AssertionError(k)


def walk(ir):
    yield ir
    k = ir[0]
    if k in ("neg", "not"):
        yield from walk(ir[1])
    elif k in ("add", "sub"):
        yield from walk(ir[1])
        yield from walk(ir[2])
    elif k == "mul":
        yield from walk(ir[2])
    elif k in ("fdiv", "fmod", "imem"):
        yield from walk(ir[1])
    elif k == "cmp":
        yield from walk(ir[2])
        yield from walk(ir[3])
    elif k in ("and", "or"):
        for p in ir[1]:
            yield from walk(p)
    elif k == "ite":
        for p in ir[1:]:
            yield from walk(p)
