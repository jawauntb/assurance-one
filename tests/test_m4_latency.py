"""A12: report p50/p95 check latency on the payments policy with the real solver."""
import json
import random
import statistics
import time

import pytest

from oracle import PAY

pytestmark = pytest.mark.m4


def test_latency(payments_policy, tmp_path):
    from precert import Gate
    g = Gate(payments_policy, state={"spent": 50000, "cur_window": 1, "count": 2, "last_ts": 4000})
    rng = random.Random(5)
    lat = []
    for _ in range(1000):
        a = {"tool": "pay", "args": {"payee": rng.choice(PAY["allowlist"] + ["x"]),
                                     "amount_cents": rng.randint(-10, 30000), "ts": rng.randint(0, 20000)},
             "principal": "lat"}
        t = time.perf_counter()
        g.check(a)
        lat.append((time.perf_counter() - t) * 1000)
    lat.sort()
    p50, p95 = statistics.median(lat), lat[int(0.95 * len(lat)) - 1]
    print(json.dumps({"p50_ms": round(p50, 3), "p95_ms": round(p95, 3)}))
    assert p95 < 200
