"""A8/A9: generated Lean project proves preservation and agrees with the Python step.

Requires `lake` on PATH (CI installs elan). These tests fail, never skip, when lake is missing.
"""
import json
import pathlib
import random
import re
import shutil
import subprocess

import pytest

from conftest import fixture_path, load_fixture
from oracle import PAY_INIT, arith_step, deploy_step, pay_step

pytestmark = pytest.mark.m2

FORBIDDEN = re.compile(r"\b(sorry|admit|axiom|native_decide|implemented_by|extern|unsafe)\b")


def _lake():
    exe = shutil.which("lake")
    assert exe, "lake not on PATH; install elan (CI does this)"
    return exe


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    from precert import load_policy
    from precert.lean import generate
    out = {}
    for name in ["payments.json", "deploy.json", "arith.json", "inductive_remaining.json"]:
        p = load_policy(fixture_path(name))
        d = pathlib.Path(tmp_path_factory.mktemp(p.name))
        proj = pathlib.Path(generate(p, d))
        res = subprocess.run([_lake(), "build"], cwd=proj, capture_output=True, text=True, timeout=1800)
        assert res.returncode == 0, res.stdout + res.stderr
        out[p.name] = (p, proj)
    return out


def _lean_sources(proj):
    return [f for f in proj.rglob("*.lean") if ".lake" not in f.parts]


@pytest.mark.parametrize("pname", ["payments", "deploy", "arith", "remaining_ok"])
def test_no_escape_hatches(built, pname):
    _, proj = built[pname]
    for f in _lean_sources(proj):
        text = re.sub(r"--.*", "", f.read_text())
        text = re.sub(r"/-.*?-/", "", text, flags=re.S)
        assert not FORBIDDEN.search(text), f"{f}: {FORBIDDEN.search(text).group(0)}"


@pytest.mark.parametrize("pname", ["payments", "deploy", "arith", "remaining_ok"])
def test_theorems_and_hash_present(built, pname):
    p, proj = built[pname]
    src = "\n".join(f.read_text() for f in _lean_sources(proj))
    assert f"-- policy_hash: {p.hash}" in src
    for action in load_fixture({"payments": "payments.json", "deploy": "deploy.json", "arith": "arith.json",
                                "remaining_ok": "inductive_remaining.json"}[pname])["actions"]:
        tid = f"precert_{pname}_{action}_preserves"
        assert re.search(rf"theorem\s+{tid}\b", src), tid


def test_theorem_statement_is_preservation(built):
    """The theorem must be stated over Inv, Pre and step, in that shape, not something weaker."""
    _, proj = built["payments"]
    src = "\n".join(f.read_text() for f in _lean_sources(proj))
    m = re.search(r"theorem\s+precert_payments_pay_preserves(.*?):=", src, flags=re.S)
    assert m, "theorem not found"
    stmt = m.group(1)
    assert "Inv" in stmt and "Pre" in stmt and "step" in stmt


def test_lean_does_not_trust_python(tmp_path):
    """Generating Lean for a non-inductive policy (Python check bypassed) must not yield a building project."""
    from precert import load_policy, PolicyNotInductive
    from precert.lean import generate
    p = load_policy(fixture_path("nonInductive_remaining.json"), skip_inductive_check=True)
    try:
        proj = pathlib.Path(generate(p, tmp_path / "bad"))
    except PolicyNotInductive:
        return
    res = subprocess.run([_lake(), "build"], cwd=proj, capture_output=True, text=True, timeout=1800)
    assert res.returncode != 0, "a non-inductive policy produced a Lean project that builds"
    src = "\n".join(f.read_text() for f in _lean_sources(proj))
    assert not FORBIDDEN.search(re.sub(r"--.*", "", src))


def _lean_step(proj, state, action):
    res = subprocess.run([_lake(), "exe", "precert_step"], cwd=proj, input=json.dumps({"state": state, "action": action}),
                         capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


def test_differential_payments(built):
    _, proj = built["payments"]
    rng = random.Random(3)
    s = dict(PAY_INIT)
    for _ in range(60):
        a = {"tool": "pay", "args": {"payee": rng.choice(["acme", "x"]), "amount_cents": rng.randint(-50, 30000),
                                     "ts": rng.randint(0, 50000)}, "principal": "d"}
        assert _lean_step(proj, s, a) == pay_step(s, a["args"])
        s = pay_step(s, a["args"]) if rng.random() < 0.5 else s


def test_differential_arith_negative_floor_semantics(built):
    _, proj = built["arith"]
    s = {"q": 0, "r": 0, "flag": False}
    for x in [-15, -14, -8, -7, -1, 0, 1, 6, 7, 13, -10**12 - 3, 10**12 + 5]:
        for tool in ["divmod", "neg"]:
            a = {"tool": tool, "args": {"x": x}, "principal": "d"}
            assert _lean_step(proj, s, a) == arith_step(s, a), (tool, x)


def test_differential_deploy(built):
    _, proj = built["deploy"]
    s = {"passed_checks": 3, "deploys": 1}
    for a in [{"tool": "record_check", "args": {"ok": True}, "principal": "d"},
              {"tool": "record_check", "args": {"ok": False}, "principal": "d"},
              {"tool": "deploy", "args": {"commit": "abc"}, "principal": "d"}]:
        assert _lean_step(proj, s, a) == deploy_step(s, a)


def test_python_step_matches_oracle(payments_policy):
    """The Python step used by the gate must be the same function the Lean side models."""
    rng = random.Random(11)
    for _ in range(500):
        s = {"spent": rng.randint(0, 100000), "cur_window": rng.randint(-1, 20), "count": rng.randint(0, 5),
             "last_ts": rng.randint(0, 70000)}
        a = {"payee": "acme", "amount_cents": rng.randint(-10, 30000), "ts": rng.randint(0, 80000)}
        assert payments_policy.step(s, {"tool": "pay", "args": a, "principal": "d"}) == pay_step(s, a)
