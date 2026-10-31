#!/usr/bin/env python3
"""Acceptance report: soundness (false permits), false denies, ABSTAIN rate, p50/p95 check latency.

Every verdict is judged by the independent reference semantics in tests/oracle.py (this script lives outside
src/, so the implementation itself never imports the oracle).

    python3 scripts/report.py [--n 10000] [--seed 1729]
"""
import argparse
import json
import pathlib
import random
import statistics
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from oracle import PAY, PAY_INIT, pay_inv, pay_step, pay_violations, pay_wellformed  # noqa: E402

from precert import Gate, load_policy  # noqa: E402

PAYEES = PAY["allowlist"] + ["evilcorp", "acme ", "Acme", "ACME", "", "acme​", "globex\n"]


def tool(args):
    return {"settled_amount_cents": args["amount_cents"]}


def gen_random(rng, s):
    ts = s["last_ts"] + rng.choice([0, 1, 59, 3599, 3600, 7200, rng.randint(0, 20000)])
    if rng.random() < 0.05:
        ts = s["last_ts"] - rng.randint(1, 5000)
    amt = rng.choice([1, 99, 4999, 19999, 20000, 20001, rng.randint(-100, 40000),
                      PAY["budget"] - s["spent"], PAY["budget"] - s["spent"] + 1])
    a = {"tool": "pay", "args": {"payee": rng.choice(PAYEES), "amount_cents": amt, "ts": ts}, "principal": "fuzz"}
    k = rng.random()
    if k < 0.03:
        a["args"]["amount_cents"] = float(amt)
    elif k < 0.05:
        a["args"]["amount_cents"] = bool(amt % 2)
    elif k < 0.06:
        del a["args"]["ts"]
    elif k < 0.07:
        a["tool"] = "transfer"
    return a


def gen_adversarial(rng, s):
    """Boundary probing, splitting, type confusion, structural attacks."""
    k = rng.randrange(12)
    w = s["last_ts"] // PAY["window_s"]
    base = {"payee": "acme", "amount_cents": 1, "ts": s["last_ts"]}
    if k == 0:   # exact budget boundary and one past it
        base["amount_cents"] = min(PAY["cap"], PAY["budget"] - s["spent"]) + rng.choice([0, 1])
    elif k == 1:  # splitter inside one window
        base.update(amount_cents=19999, ts=s["last_ts"] + rng.randint(0, 3))
    elif k == 2:  # last second of the window vs first second of the next
        base["ts"] = max(s["last_ts"], (w + 1) * PAY["window_s"] - rng.choice([1, 0]))
    elif k == 3:  # time travel
        base["ts"] = s["last_ts"] - rng.randint(1, 10)
    elif k == 4:
        base["ts"] = -rng.randint(1, 10)
    elif k == 5:  # huge / negative amounts
        base["amount_cents"] = rng.choice([-1, 0, 10 ** 18, -(10 ** 18), PAY["cap"] + 1])
    elif k == 6:  # look-alike payees
        base["payee"] = rng.choice(PAYEES[3:])
    elif k == 7:  # type confusion
        base[rng.choice(["amount_cents", "ts"])] = rng.choice([True, False, 1.0, "1", None, [1]])
    elif k == 8:  # extra / missing args
        if rng.random() < 0.5:
            base["memo"] = "x"
        else:
            del base["payee"]
    elif k == 9:  # structural attacks on the action
        a = {"tool": "pay", "args": base, "principal": "adv"}
        rng.choice([lambda: a.pop("principal"), lambda: a.update(principal=7), lambda: a.update(extra=1),
                    lambda: a.update(args=None), lambda: a.update(tool="PAY")])()
        return a
    else:         # plausible valid payment
        base.update(amount_cents=rng.randint(1, 3000), ts=s["last_ts"] + rng.randint(0, 4000))
    return {"tool": "pay", "args": base, "principal": "adv"}


def run(policy, rng, n, gen, stats):
    g, shadow = Gate(policy), dict(PAY_INIT)
    for _ in range(n):
        a = gen(rng, shadow)
        r = g.execute(a, tool)
        ok = pay_wellformed(a) and pay_violations(shadow, a["args"]) == []
        d = r.verdict.decision
        stats["n"] += 1
        stats[d.lower()] += 1
        if d == "PERMIT":
            if not ok:
                stats["false_permit"] += 1
            shadow = pay_step(shadow, a["args"])
            if not pay_inv(shadow):
                stats["invariant_broken"] += 1
        elif ok:
            stats["false_deny" if d == "DENY" else "abstain_on_valid"] += 1
        if g.state != shadow:
            stats["state_divergence"] += 1
            g, shadow = Gate(policy), dict(PAY_INIT)
        if shadow["spent"] > PAY["budget"] - 1000 and rng.random() < 0.1:
            g, shadow = Gate(policy), dict(PAY_INIT)


def latency(policy, n=1000):
    g = Gate(policy, state={"spent": 50000, "cur_window": 1, "count": 2, "last_ts": 4000})
    rng = random.Random(5)
    lat = []
    for _ in range(n):
        a = {"tool": "pay", "args": {"payee": rng.choice(PAY["allowlist"] + ["x"]),
                                     "amount_cents": rng.randint(-10, 30000), "ts": rng.randint(0, 20000)},
             "principal": "lat"}
        t = time.perf_counter()
        g.check(a)
        lat.append((time.perf_counter() - t) * 1000)
    lat.sort()
    return {"p50_ms": round(statistics.median(lat), 3), "p95_ms": round(lat[int(0.95 * n) - 1], 3),
            "p99_ms": round(lat[int(0.99 * n) - 1], 3), "max_ms": round(lat[-1], 3), "n": n}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10_000)
    ap.add_argument("--seed", type=int, default=1729)
    a = ap.parse_args()
    policy = load_policy(ROOT / "tests" / "fixtures" / "payments.json")
    keys = ["n", "permit", "deny", "abstain", "false_permit", "false_deny", "abstain_on_valid",
            "invariant_broken", "state_divergence"]
    report = {}
    for name, gen in [("random", gen_random), ("adversarial", gen_adversarial)]:
        stats = dict.fromkeys(keys, 0)
        run(policy, random.Random(a.seed), a.n, gen, stats)
        stats["abstain_rate"] = round(stats["abstain"] / stats["n"], 6)
        report[name] = stats
    report["latency_check_payments"] = latency(policy)
    print(json.dumps(report, indent=2))
    bad = sum(report[k]["false_permit"] + report[k]["invariant_broken"] + report[k]["state_divergence"]
              for k in ("random", "adversarial"))
    sys.exit(1 if bad or report["latency_check_payments"]["p95_ms"] >= 200 else 0)


if __name__ == "__main__":
    main()
