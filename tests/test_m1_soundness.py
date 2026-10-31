"""A1/A2: soundness under randomized and adversarial agents, judged by the oracle."""
import random

import pytest

from conftest import Recorder
from oracle import PAY, PAY_INIT, pay_inv, pay_step, pay_violations, pay_wellformed

pytestmark = pytest.mark.m1

PAYEES = PAY["allowlist"] + ["evilcorp", "acme ", "Acme", ""]


def random_action(rng, s):
    kind = rng.random()
    ts = s["last_ts"] + rng.choice([0, 1, 59, 3599, 3600, 7200, rng.randint(0, 20000)])
    if rng.random() < 0.05:
        ts = s["last_ts"] - rng.randint(1, 5000)          # out of order
    amt = rng.choice([1, 99, 4999, 19999, 20000, 20001, rng.randint(-100, 40000),
                      PAY["budget"] - s["spent"], PAY["budget"] - s["spent"] + 1])
    payee = rng.choice(PAYEES)
    a = {"tool": "pay", "args": {"payee": payee, "amount_cents": amt, "ts": ts}, "principal": "fuzz"}
    if kind < 0.03:
        a["args"]["amount_cents"] = float(amt)
    elif kind < 0.05:
        a["args"]["amount_cents"] = bool(amt % 2)
    elif kind < 0.06:
        del a["args"]["ts"]
    elif kind < 0.07:
        a["tool"] = "transfer"
    return a


def splitter(rng, s):
    """Adversary: split one big payment into many small ones inside one window."""
    return {"tool": "pay", "args": {"payee": "acme", "amount_cents": 19999,
                                    "ts": s["last_ts"] + rng.randint(0, 3)}, "principal": "split"}


def run_episode(gate_cls, policy, rng, n, gen):
    g = gate_cls(policy)
    shadow = dict(PAY_INIT)
    stats = {"permit": 0, "deny": 0, "abstain": 0, "false_deny": 0, "false_permit": 0, "n": 0}
    for _ in range(n):
        a = gen(rng, shadow)
        r = g.execute(a, Recorder())
        stats["n"] += 1
        ok = pay_wellformed(a) and pay_violations(shadow, a["args"]) == []
        d = r.verdict.decision
        if d == "PERMIT":
            stats["permit"] += 1
            if not ok:
                stats["false_permit"] += 1
            shadow = pay_step(shadow, a["args"])
            assert pay_inv(shadow), f"invariant broken after {a}"
        elif d == "DENY":
            stats["deny"] += 1
            if ok:
                stats["false_deny"] += 1
        else:
            stats["abstain"] += 1
        assert r.executed == (d == "PERMIT")
        assert g.state == shadow
        if shadow["spent"] > PAY["budget"] - 1000 and rng.random() < 0.1:
            # new episode-like reset keeps the workload interesting
            g = gate_cls(policy)
            shadow = dict(PAY_INIT)
    return stats


def test_soundness_random_10k(payments_policy):
    from precert import Gate
    rng = random.Random(1729)
    stats = run_episode(Gate, payments_policy, rng, 10_000, random_action)
    assert stats["false_permit"] == 0
    assert stats["false_deny"] == 0
    assert stats["abstain"] / stats["n"] <= 0.05
    assert stats["permit"] > 500, stats   # workload must actually exercise PERMIT


def test_soundness_splitter(payments_policy):
    from precert import Gate
    rng = random.Random(7)
    stats = run_episode(Gate, payments_policy, rng, 2_000, splitter)
    assert stats["false_permit"] == 0 and stats["false_deny"] == 0
