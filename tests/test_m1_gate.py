import threading

import pytest

from conftest import Recorder, fixture_path, pay
from oracle import H, PAY_INIT, clause_holds, pay_step, pay_violations

pytestmark = pytest.mark.m1


def test_permit_has_certificate(payments_policy):
    from precert import Gate
    g = Gate(payments_policy)
    a = pay()
    v = g.check(a)
    assert v.decision == "PERMIT" and v.reason == "ok"
    assert v.violated == [] and v.counterexample is None
    c = v.certificate
    assert c["pre_state_hash"] == H(PAY_INIT)
    assert c["policy_hash"] == payments_policy.hash
    assert c["action_digest"] == H(a)
    assert c["lean_theorem_id"] == "precert_payments_pay_preserves"
    assert c["solver_result"] == "valid"


def test_check_is_pure(payments_policy):
    from precert import Gate
    g = Gate(payments_policy)
    before = g.state
    g.check(pay())
    assert g.state == before
    assert g.log.size == 0


@pytest.mark.parametrize("action,clauses", [
    (pay(amount=20001), ["cap"]),
    (pay(amount=0), ["positive"]),
    (pay(amount=-5), ["positive"]),
    (pay(payee="evilcorp"), ["allowlisted"]),
    (pay(payee="acme "), ["allowlisted"]),
    (pay(payee="ACME"), ["allowlisted"]),
    (pay(ts=-1), ["monotone_time", "ts_nonneg"]),
    (pay(payee="evilcorp", amount=30000), ["allowlisted", "cap"]),
])
def test_deny_names_every_violated_clause(payments_policy, action, clauses):
    from precert import Gate
    v = Gate(payments_policy).check(action)
    assert v.decision == "DENY" and v.reason == "precondition"
    assert v.violated == sorted(clauses)
    assert v.certificate is None


def test_counterexample_falsifies_named_clauses_under_oracle(payments_policy):
    from precert import Gate
    state = {"spent": 95000, "cur_window": 2, "count": 5, "last_ts": 9000}
    g = Gate(payments_policy, state=state)
    a = pay(amount=6000, ts=9500)
    v = g.check(a)
    assert v.decision == "DENY"
    assert v.violated == pay_violations(state, a["args"]) == ["budget", "rate"]
    cx = v.counterexample
    for name in v.violated:
        assert not clause_holds(name, cx["state"], cx["args"])
    assert cx["state"] == state and cx["args"] == a["args"]


def test_budget_boundary(payments_policy):
    from precert import Gate
    g = Gate(payments_policy, state={"spent": 90000, "cur_window": -1, "count": 0, "last_ts": 0})
    assert g.check(pay(amount=10000)).decision == "PERMIT"
    assert g.check(pay(amount=10001)).violated == ["budget"]


def test_window_boundary(payments_policy):
    from precert import Gate
    g = Gate(payments_policy, state={"spent": 0, "cur_window": 2, "count": 5, "last_ts": 10799})
    assert g.check(pay(ts=10799)).violated == ["rate"]
    assert g.check(pay(ts=10800)).decision == "PERMIT"


@pytest.mark.parametrize("action", [
    {"tool": "pay", "args": {"payee": "acme", "amount_cents": True, "ts": 1}, "principal": "a"},
    {"tool": "pay", "args": {"payee": "acme", "amount_cents": 5.0, "ts": 1}, "principal": "a"},
    {"tool": "pay", "args": {"payee": "acme", "amount_cents": "5", "ts": 1}, "principal": "a"},
    {"tool": "pay", "args": {"payee": 7, "amount_cents": 5, "ts": 1}, "principal": "a"},
    {"tool": "pay", "args": {"payee": "acme", "amount_cents": 5}, "principal": "a"},
    {"tool": "pay", "args": {"payee": "acme", "amount_cents": 5, "ts": 1, "memo": "x"}, "principal": "a"},
    {"tool": "pay", "args": {"payee": "acme", "amount_cents": 5, "ts": 1}},
    {"tool": "pay", "args": None, "principal": "a"},
])
def test_malformed_denied(payments_policy, action):
    from precert import Gate
    v = Gate(payments_policy).check(action)
    assert v.decision == "DENY" and v.reason == "malformed"


def test_bool_arg_rejects_int(deploy_policy):
    from precert import Gate
    v = Gate(deploy_policy).check({"tool": "record_check", "args": {"ok": 1}, "principal": "a"})
    assert (v.decision, v.reason) == ("DENY", "malformed")


def test_unknown_tool(payments_policy):
    from precert import Gate
    rec = Recorder()
    g = Gate(payments_policy)
    r = g.execute({"tool": "admin_wipe", "args": {}, "principal": "a"}, rec)
    assert (r.verdict.decision, r.verdict.reason) == ("DENY", "unknown_tool")
    assert rec.calls == [] and r.executed is False


class FakeSolver:
    def __init__(self, status=None, exc=None):
        self.status, self.exc = status, exc

    def decide(self, policy, state, action, timeout_ms):
        from precert import SolverResult
        if self.exc:
            raise self.exc
        return SolverResult(status=self.status, violated=[], model={})


@pytest.mark.parametrize("solver,reason", [
    (FakeSolver(status="unknown"), "solver_unknown"),
    (FakeSolver(status="timeout"), "timeout"),
])
def test_fail_closed_on_solver(payments_policy, solver, reason):
    from precert import Gate
    rec = Recorder()
    g = Gate(payments_policy, solver=solver)
    r = g.execute(pay(), rec)
    assert (r.verdict.decision, r.verdict.reason) == ("ABSTAIN", reason)
    assert rec.calls == [] and g.state == PAY_INIT and r.executed is False


def test_fail_closed_on_solver_exception(payments_policy):
    from precert import Gate
    rec = Recorder()
    g = Gate(payments_policy, solver=FakeSolver(exc=RuntimeError("boom")))
    r = g.execute(pay(), rec)
    assert r.verdict.decision == "ABSTAIN"
    assert rec.calls == []


def test_execute_permit_steps_state_and_calls_tool(payments_policy):
    from precert import Gate
    rec = Recorder()
    g = Gate(payments_policy)
    a = pay(amount=1234, ts=7300)
    r = g.execute(a, rec)
    assert r.executed and r.verdict.decision == "PERMIT"
    assert rec.calls == [a["args"]]
    assert g.state == pay_step(PAY_INIT, a["args"])
    assert g.log.size == 1 and isinstance(r.receipt, bytes)


def test_every_execute_writes_exactly_one_receipt(payments_policy):
    from precert import Gate
    g = Gate(payments_policy)
    g.execute(pay(), Recorder())
    g.execute(pay(amount=10**9), Recorder())
    g.execute({"tool": "nope", "args": {}, "principal": "x"}, Recorder())
    assert g.log.size == 3


def test_tool_exception_leaves_state(payments_policy):
    from precert import Gate
    g = Gate(payments_policy)
    r = g.execute(pay(), Recorder(raise_exc=IOError("down")))
    assert r.executed is False and g.state == PAY_INIT and g.log.size == 1


def test_stale_certificate_rechecked_and_denied(payments_policy):
    from precert import Gate
    g = Gate(payments_policy, state={"spent": 80000, "cur_window": -1, "count": 0, "last_ts": 0})
    a1 = pay(amount=15000, ts=100)
    v1 = g.check(a1)
    assert v1.decision == "PERMIT"
    g.execute(pay(amount=10000, ts=100), Recorder())   # state moves under the certificate
    rec = Recorder()
    r = g.execute(a1, rec, certificate=v1.certificate)
    assert r.verdict.decision == "DENY" and r.verdict.violated == ["budget"]
    assert rec.calls == []


def test_stale_certificate_rechecked_and_permitted(payments_policy):
    from precert import Gate
    g = Gate(payments_policy)
    a1 = pay(amount=100, ts=100)
    v1 = g.check(a1)
    g.execute(pay(amount=100, ts=100), Recorder())
    r = g.execute(a1, Recorder(), certificate=v1.certificate)
    assert r.verdict.decision == "PERMIT"
    assert r.verdict.certificate["pre_state_hash"] != v1.certificate["pre_state_hash"]
    assert r.verdict.certificate["pre_state_hash"] == H({"spent": 100, "cur_window": 0, "count": 1, "last_ts": 100})


def test_settlement_mismatch_halts_until_reconcile(payments_policy):
    from precert import Gate
    g = Gate(payments_policy)
    r = g.execute(pay(amount=1000, ts=50), Recorder(settle_delta=7))
    assert r.executed
    assert g.halted is True
    assert g.state["spent"] == 1000
    v = g.check(pay(amount=1, ts=60))
    assert (v.decision, v.reason) == ("ABSTAIN", "halted")
    rec = Recorder()
    assert g.execute(pay(amount=1, ts=60), rec).executed is False and rec.calls == []
    with pytest.raises(ValueError):
        g.reconcile({"spent": 999999, "cur_window": 0, "count": 1, "last_ts": 50})
    g.reconcile({"spent": 1007, "cur_window": 0, "count": 1, "last_ts": 50})
    assert g.halted is False
    assert g.check(pay(amount=1, ts=60)).decision == "PERMIT"


def test_invalid_initial_state_rejected(payments_policy):
    from precert import Gate
    with pytest.raises(ValueError):
        Gate(payments_policy, state={"spent": 100001, "cur_window": -1, "count": 0, "last_ts": 0})


def test_deploy_requires_fresh_passing_check(deploy_policy):
    from precert import Gate
    g = Gate(deploy_policy)
    d = {"tool": "deploy", "args": {"commit": "abc"}, "principal": "ci"}
    assert g.check(d).violated == ["fresh_check"]
    g.execute({"tool": "record_check", "args": {"ok": False}, "principal": "ci"}, Recorder())
    assert g.check(d).decision == "DENY"
    g.execute({"tool": "record_check", "args": {"ok": True}, "principal": "ci"}, Recorder())
    assert g.execute(d, Recorder()).executed
    assert g.check(d).decision == "DENY"


def test_concurrent_execute_never_overspends(payments_policy):
    from precert import Gate
    g = Gate(payments_policy)
    rec = Recorder()
    lock = threading.Lock()
    results = []

    def worker(i):
        for j in range(20):
            r = g.execute(pay(amount=9000, ts=3600 * (i * 20 + j)), rec)
            with lock:
                results.append(r)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sum(c["amount_cents"] for c in rec.calls) <= 100000
    assert len(rec.calls) == sum(1 for r in results if r.executed)
    assert g.state["spent"] == sum(c["amount_cents"] for c in rec.calls)
    assert g.log.size == 16 * 20
