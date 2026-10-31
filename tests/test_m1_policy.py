import pytest

from conftest import fixture_path, load_fixture
from oracle import H

pytestmark = pytest.mark.m1


def test_payments_loads_and_hash_is_canonical(payments_policy):
    assert payments_policy.name == "payments"
    assert payments_policy.hash == H(load_fixture("payments.json"))
    assert payments_policy.init == load_fixture("payments.json")["init"]


def test_load_from_dict_equals_load_from_path():
    from precert import load_policy
    a = load_policy(fixture_path("deploy.json"))
    b = load_policy(load_fixture("deploy.json"))
    assert a.hash == b.hash


def test_non_inductive_policy_rejected_with_counterexample():
    from precert import load_policy, PolicyNotInductive
    with pytest.raises(PolicyNotInductive) as ei:
        load_policy(fixture_path("nonInductive_remaining.json"))
    e = ei.value
    assert e.action == "pay"
    assert e.invariant == "within_budget"
    cx = e.counterexample
    assert cx is not None
    # the counterexample must actually break preservation
    s, a = cx["state"], cx["args"]
    assert s["spent"] <= 100000
    assert a["amount_cents"] > 0 and a["amount_cents"] <= s["remaining"]
    assert s["spent"] + a["amount_cents"] > 100000


def test_strengthened_policy_loads():
    from precert import load_policy
    p = load_policy(fixture_path("inductive_remaining.json"))
    assert p.name == "remaining_ok"


def test_init_violation_rejected():
    from precert import load_policy, InitViolation
    with pytest.raises(InitViolation) as ei:
        load_policy(fixture_path("init_violation.json"))
    assert "within_budget" in ei.value.invariants


@pytest.mark.parametrize("name", ["bad_syntax_float.json", "bad_syntax_nonlinear.json", "bad_syntax_call.json"])
def test_syntax_errors(name):
    from precert import load_policy, PolicySyntaxError
    with pytest.raises(PolicySyntaxError):
        load_policy(fixture_path(name))


def test_name_collision_rejected():
    from precert import load_policy, PolicySyntaxError
    p = load_fixture("payments.json")
    p["actions"]["pay"]["args"]["spent"] = "int"
    with pytest.raises(PolicySyntaxError):
        load_policy(p)


def test_zero_divisor_rejected():
    from precert import load_policy, PolicySyntaxError
    p = load_fixture("arith.json")
    p["actions"]["divmod"]["update"]["q"] = "x // 0"
    with pytest.raises(PolicySyntaxError):
        load_policy(p)


def test_policy_with_bad_update_not_inductive():
    """Removing the rate clause makes 'rate' invariant non-preserved."""
    from precert import load_policy, PolicyNotInductive
    p = load_fixture("payments.json")
    del p["actions"]["pay"]["pre"]["rate"]
    with pytest.raises(PolicyNotInductive) as ei:
        load_policy(p)
    assert ei.value.invariant == "rate"


def test_arith_policy_loads():
    from precert import load_policy
    assert load_policy(fixture_path("arith.json")).name == "arith"
