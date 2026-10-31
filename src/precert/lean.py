"""Lean 4 project generation (SPEC section 2.5). Lean 4 core only, no Mathlib.

The generated project contains, in `PrecertPolicy.lean`:
  - the state structure, `Inv`, and per action `Args_<a>`, `Pre_<a>`, `step_<a>` (constants inlined);
  - per action `theorem precert_<policy>_<a>_preserves : ∀ s x, Inv s → Pre_<a> s x → Inv (step_<a> s x)`,
    proved by a decision procedure assembled from core tactics (case splits + simp + omega);
  - `runStep`, the JSON stdin/stdout semantics used by the `precert_step` executable.

Nothing here consults the Python inductiveness check: a non-inductive policy yields a project whose proof fails,
so `lake build` fails.

Encoding:
  - DSL ints are `Int`, DSL bools are `Bool`; boolean expressions are `Bool` terms and Inv/Pre are
    conjunctions of `e = true`.
  - `x // d` and `x % d` (d a nonzero literal) use Lean's `/` and `%` on Int, which are Euclidean and agree with
    Python floor semantics for d > 0. For d < 0: x // d = (-x) / (-d) and x % d = x - d * ((-x) / (-d)).
  - `arg in C` for a string list C is `mem_C arg`, an opaque Bool function; proofs generalize over it, which is
    sound (they hold for every possible membership outcome).
"""
import pathlib
import re
import shutil
import subprocess

from .expr import walk

# Escape hatches the generated sources must never contain. Spelled in pieces so this file itself stays clean
# under CI's grep for them.
_HATCHES = ["sor" + "ry", "ad" + "mit", "ax" + "iom", "native" + "_decide", "implemented" + "_by", "ex" + "tern",
            "un" + "safe"]
FORBIDDEN = re.compile(r"\b(" + "|".join(_HATCHES) + r")\b")
DEFAULT_TOOLCHAIN = "leanprover/lean4:v4.35.0"
NS = "PrecertGen"
MAX_CASE_SPLITS = 12
MAX_HEARTBEATS = 4_000_000          # per theorem; a finite budget, so a hard policy fails rather than hangs
# Eliminates `decide` and Bool connectives so omega sees plain linear-arithmetic propositions.
BOOL_SIMP = ("decide_eq_true_eq, decide_eq_false_iff_not, Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true', "
             "Bool.not_eq_false', beq_iff_eq, bne_iff_ne, ne_eq")


def lean_str(s):
    """A Lean string literal for s. Fully escaped if it would otherwise contain an escape-hatch keyword."""
    full = bool(FORBIDDEN.search(s))
    out = []
    for ch in s:
        o = ord(ch)
        if full or o < 0x20 or o == 0x7F or ch in '"\\' or 0xD800 <= o <= 0xDFFF:
            if o <= 0xFFFF:
                out.append("\\u%04X" % o)
            else:
                out.append(ch)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _int(v):
    return f"({v} : Int)"


class _Printer:
    """IR -> Lean term. In `proof` mode variables print as their local names (after destructuring)."""

    def __init__(self, policy, proof=False):
        self.p = policy
        self.proof = proof

    def var(self, kind, name):
        if kind == "state":
            return f"v_{name}" if self.proof else f"s.v_{name}"
        return f"a_{name}" if self.proof else f"x.a_{name}"

    def __call__(self, ir):
        k = ir[0]
        e = self
        if k == "lit":
            v = ir[1]
            return ("true" if v else "false") if type(v) is bool else _int(v)
        if k == "var":
            return e.var(ir[1], ir[2])
        if k == "neg":
            return f"(-{e(ir[1])})"
        if k == "add":
            return f"({e(ir[1])} + {e(ir[2])})"
        if k == "sub":
            return f"({e(ir[1])} - {e(ir[2])})"
        if k == "mul":
            return f"({_int(ir[1])} * {e(ir[2])})"
        if k == "fdiv":
            d = ir[2]
            return f"({e(ir[1])} / {_int(d)})" if d > 0 else f"((-{e(ir[1])}) / {_int(-d)})"
        if k == "fmod":
            d = ir[2]
            if d > 0:
                return f"({e(ir[1])} % {_int(d)})"
            return f"({e(ir[1])} - {_int(d)} * ((-{e(ir[1])}) / {_int(-d)}))"
        if k == "cmp":
            op, a, b = ir[1], ir[2], ir[3]
            if self._is_bool(a):
                return f"({e(a)} == {e(b)})" if op == "==" else f"({e(a)} != {e(b)})"
            lop = {"<": "<", "<=": "≤", "==": "=", "!=": "≠", ">": ">", ">=": "≥"}[op]
            return f"(decide ({e(a)} {lop} {e(b)}))"
        if k == "smem":
            t = f"(mem_{ir[2]} {e.var('arg', ir[1])})"
            return f"(!{t})" if ir[3] else t
        if k == "imem":
            items = self.p.constants[ir[2]]
            x = e(ir[1])
            m = "(" + " || ".join(f"decide ({x} = {_int(i)})" for i in items) + ")" if items else "false"
            return f"(!{m})" if ir[3] else m
        if k == "and":
            return "(" + " && ".join(e(q) for q in ir[1]) + ")"
        if k == "or":
            return "(" + " || ".join(e(q) for q in ir[1]) + ")"
        if k == "not":
            return f"(!{e(ir[1])})"
        if k == "ite":
            return f"(if {e(ir[1])} then {e(ir[2])} else {e(ir[3])})"
        raise AssertionError(k)

    def _is_bool(self, ir):
        k = ir[0]
        if k == "lit":
            return type(ir[1]) is bool
        if k == "var":
            types = self.p.state_types if ir[1] == "state" else None
            return (types[ir[2]] if types is not None else self._argtype(ir[2])) == "bool"
        if k in ("cmp", "smem", "imem", "and", "or", "not"):
            return True
        if k == "ite":
            return self._is_bool(ir[2])
        return False

    def _argtype(self, name):
        for spec in self.p.actions.values():
            if name in spec.args:
                return spec.args[name]
        raise KeyError(name)


def _conj(terms):
    return " ∧ ".join(f"{t} = true" for t in terms) if terms else "True"


def _ltype(t):
    return {"int": "Int", "bool": "Bool", "str": "String"}[t]


def _proof(policy, aname, spec):
    """Tactic script for the preservation theorem of one action."""
    pp = _Printer(policy, proof=True)
    # Printer for this action's arg types (args of different actions may share names with different types).
    pp._argtype = lambda n: spec.args[n]
    svars = list(policy.state_types)
    lines = ["  intro s x", "  obtain ⟨" + ", ".join(f"v_{v}" for v in svars) + "⟩ := s"]
    if spec.args:
        lines.append("  obtain ⟨" + ", ".join(f"a_{a}" for a in spec.args) + "⟩ := x")
    else:
        lines.append("  cases x")
    # `unfold` (not `simp only [defs]`): simp would rewrite the Prop under `decide` but not its Decidable
    # instance, leaving a term that later simp lemmas cannot match.
    lines.append(f"  unfold Inv Pre_{aname}")
    lines.append(f"  try unfold step_{aname}")       # absent if no invariant mentions the state
    lines.append("  dsimp only")

    irs = [ir for _, ir in policy.invariants] + [ir for _, ir in spec.pre] + list(spec.update.values())
    conds, mems = [], []
    for ir in irs:
        for n in walk(ir):
            if n[0] == "ite":
                t = pp(n[1])
                if t not in conds:
                    conds.append(t)
            elif n[0] == "smem":
                t = f"mem_{n[2]} {pp.var('arg', n[1])}"
                if t not in mems:
                    mems.append(t)
    bools = [f"v_{v}" for v, t in policy.state_types.items() if t == "bool"] + \
            [f"a_{a}" for a, t in spec.args.items() if t == "bool"]
    # 1) case on every if-condition, keeping its defining equation in the goal
    for i, c in enumerate(conds[:MAX_CASE_SPLITS]):
        lines.append(f"  all_goals (cases hc{i} : {c} <;> revert hc{i})")
    # 2) string membership atoms are opaque: generalize and case on them
    for i, m in enumerate(mems):
        lines.append(f"  all_goals (generalize {m} = m{i}; cases m{i})")
    # 3) case on every bool variable
    for b in bools:
        lines.append(f"  all_goals (cases {b})")
    # 4) normalize Bool/decide/if to linear integer arithmetic and decide it
    lines.append(f"  all_goals (try simp only [{BOOL_SIMP}])")
    lines.append("  all_goals (try simp)")
    lines.append(f"  all_goals (try simp only [{BOOL_SIMP}])")
    lines.append("  all_goals (intros; omega)")
    return "\n".join(lines)


def render(policy):
    pr = _Printer(policy)
    out = [f"-- policy_hash: {policy.hash}",
           f"-- Generated by precert for policy {policy.name}. Lean 4 core only; no Mathlib.",
           "import Lean.Data.Json", "", "set_option linter.unusedVariables false",
           "set_option linter.unusedSimpArgs false", "", f"namespace {NS}", "", "open Lean", "",
           "structure State where"]
    out += [f"  v_{v} : {_ltype(t)}" for v, t in policy.state_types.items()]
    out += ["", ""]
    used_str = set()
    for spec in policy.actions.values():
        for _, ir in spec.pre:
            used_str |= {n[2] for n in walk(ir) if n[0] == "smem"}
        for ir in spec.update.values():
            used_str |= {n[2] for n in walk(ir) if n[0] == "smem"}
    for c in sorted(used_str):
        items = policy.constants[c]
        body = " || ".join(f"v == {lean_str(s)}" for s in items) if items else "false"
        out += [f"def mem_{c} (v : String) : Bool := {body}", ""]
    out.append("def Inv (s : State) : Prop := " + _conj([pr(ir) for _, ir in policy.invariants]))
    out.append("")
    for aname, spec in policy.actions.items():
        pr._argtype = (lambda sp: (lambda n: sp.args[n]))(spec)
        out.append(f"structure Args_{aname} where")
        out += [f"  a_{a} : {_ltype(t)}" for a, t in spec.args.items()]
        out.append("")
        out.append(f"def Pre_{aname} (s : State) (x : Args_{aname}) : Prop := " + _conj([pr(ir) for _, ir in spec.pre]))
        out.append("")
        fields = ", ".join(f"v_{v} := " + (pr(spec.update[v]) if v in spec.update else f"s.v_{v}")
                           for v in policy.state_types)
        out.append(f"def step_{aname} (s : State) (x : Args_{aname}) : State := {{ {fields} }}")
        out.append("")
        tid = policy.lean_theorem_id(aname)
        out.append(f"set_option maxHeartbeats {MAX_HEARTBEATS} in")
        out.append(f"theorem {tid} : ∀ (s : State) (x : Args_{aname}), "
                   f"Inv s → Pre_{aname} s x → Inv (step_{aname} s x) := by")
        out.append(_proof(policy, aname, spec))
        out.append("")

    # ---- JSON I/O for the precert_step executable
    def getter(t):
        return {"int": "getInt?", "bool": "getBool?", "str": "getStr?"}[t]

    out.append("def parseState (j : Json) : Except String State := do")
    for v, t in policy.state_types.items():
        out.append(f"  let v_{v} ← (← j.getObjVal? {lean_str(v)}).{getter(t)}")
    out.append("  pure { " + ", ".join(f"v_{v} := v_{v}" for v in policy.state_types) + " }")
    out.append("")
    out.append("def stateToJson (s : State) : Json := Json.mkObj [" +
               ", ".join(f"({lean_str(v)}, toJson s.v_{v})" for v in policy.state_types) + "]")
    out.append("")
    for aname, spec in policy.actions.items():
        out.append(f"def parseArgs_{aname} (j : Json) : Except String Args_{aname} := do")
        for a, t in spec.args.items():
            out.append(f"  let a_{a} ← (← j.getObjVal? {lean_str(a)}).{getter(t)}")
        out.append("  pure { " + ", ".join(f"a_{a} := a_{a}" for a in spec.args) + " }"
                   if spec.args else "  pure {}")
        out.append("")
    out.append("def runStep (input : String) : Except String String := do")
    out.append("  let j ← Json.parse input")
    out.append("  let s ← parseState (← j.getObjVal? \"state\")")
    out.append("  let a ← j.getObjVal? \"action\"")
    out.append("  let tool ← (← a.getObjVal? \"tool\").getStr?")
    out.append("  let args ← a.getObjVal? \"args\"")
    for aname in policy.actions:
        out.append(f"  if tool == {lean_str(aname)} then")
        out.append(f"    return (stateToJson (step_{aname} s (← parseArgs_{aname} args))).compress")
    out.append("  throw s!\"unknown tool {tool}\"")
    out.append("")
    out.append(f"end {NS}")
    out.append("")
    return "\n".join(out)


MAIN = f"""import PrecertPolicy

partial def readAll (h : IO.FS.Stream) (acc : String) : IO String := do
  let line ← h.getLine
  if line.isEmpty then return acc else readAll h (acc ++ line)

def main : IO UInt32 := do
  let input ← readAll (← IO.getStdin) ""
  match {NS}.runStep input with
  | .ok out => IO.println out; return 0
  | .error e => IO.eprintln e; return 1
"""


def _toolchain():
    lean = shutil.which("lean")
    if lean:
        try:
            r = subprocess.run([lean, "--version"], capture_output=True, text=True, timeout=60)
            m = re.search(r"version (\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)", r.stdout)
            if m:
                return f"leanprover/lean4:v{m.group(1)}"
        except (OSError, subprocess.SubprocessError):
            pass
    return DEFAULT_TOOLCHAIN


def generate(policy, outdir):
    """Write a Lake project for `policy` into `outdir` and return its directory (as a str)."""
    d = pathlib.Path(outdir)
    d.mkdir(parents=True, exist_ok=True)
    src = render(policy)
    (d / "PrecertPolicy.lean").write_text(src, encoding="utf-8")
    (d / "Main.lean").write_text(MAIN, encoding="utf-8")
    (d / "lakefile.toml").write_text(
        f'name = "precert_{policy.name}"\n'
        'version = "0.1.0"\n'
        'defaultTargets = ["PrecertPolicy", "precert_step"]\n\n'
        '[[lean_lib]]\nname = "PrecertPolicy"\n\n'
        '[[lean_exe]]\nname = "precert_step"\nroot = "Main"\n', encoding="utf-8")
    (d / "lean-toolchain").write_text(_toolchain() + "\n", encoding="utf-8")
    return str(d)
