"""Independent reference semantics. Hand-written, shares no code with precert.

The implementer must not import this module from src; tests use it to judge the implementation.
"""
import hashlib
import json

PAY = dict(budget=100000, cap=20000, allowlist=["acme", "globex", "initech"], max_per_window=5, window_s=3600)
PAY_INIT = {"spent": 0, "cur_window": -1, "count": 0, "last_ts": 0}


def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def H(x):
    return hashlib.sha256(canon(x)).hexdigest()


def is_int(v):
    return type(v) is int


def pay_wellformed(action):
    if set(action) != {"tool", "args", "principal"} or action["tool"] != "pay":
        return False
    if not isinstance(action["principal"], str):
        return False
    a = action["args"]
    if not isinstance(a, dict) or set(a) != {"payee", "amount_cents", "ts"}:
        return False
    return isinstance(a["payee"], str) and is_int(a["amount_cents"]) and is_int(a["ts"])


def pay_violations(s, a):
    c = PAY
    out = []
    amt, ts, payee = a["amount_cents"], a["ts"], a["payee"]
    if not amt > 0:
        out.append("positive")
    if not amt <= c["cap"]:
        out.append("cap")
    if not s["spent"] + amt <= c["budget"]:
        out.append("budget")
    if payee not in c["allowlist"]:
        out.append("allowlisted")
    if not ts >= 0:
        out.append("ts_nonneg")
    if not ts >= s["last_ts"]:
        out.append("monotone_time")
    if not ((ts // c["window_s"] != s["cur_window"]) or (s["count"] < c["max_per_window"])):
        out.append("rate")
    return sorted(out)


def clause_holds(name, s, a):
    return name not in pay_violations(s, a)


def pay_step(s, a):
    w = a["ts"] // PAY["window_s"]
    return {
        "spent": s["spent"] + a["amount_cents"],
        "count": s["count"] + 1 if w == s["cur_window"] else 1,
        "cur_window": w,
        "last_ts": a["ts"],
    }


def pay_inv(s):
    return (s["spent"] <= PAY["budget"] and s["spent"] >= 0
            and s["count"] <= PAY["max_per_window"] and s["count"] >= 0)


def deploy_step(s, action):
    a = action["args"]
    if action["tool"] == "record_check":
        return {"passed_checks": s["passed_checks"] + (1 if a["ok"] else 0), "deploys": s["deploys"]}
    return {"passed_checks": s["passed_checks"], "deploys": s["deploys"] + 1}


def deploy_inv(s):
    return s["deploys"] <= s["passed_checks"] and s["deploys"] >= 0


def arith_step(s, action):
    x = action["args"]["x"]
    if action["tool"] == "divmod":
        return {"q": x // 7, "r": x % 7, "flag": x < 0}
    return {"q": -x // 3, "r": (-x) % 7, "flag": not s["flag"]}


# ---- RFC 9162 Merkle tree, written from the RFC ----

def leaf_hash(b):
    return hashlib.sha256(b"\x00" + b).digest()


def node_hash(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


def mth(leaves):
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def verify_inclusion(leaf_index, tree_size, leaf_bytes, proof, root):
    """RFC 9162 section 2.1.3.2."""
    if leaf_index >= tree_size:
        return False
    fn, sn = leaf_index, tree_size - 1
    r = leaf_hash(leaf_bytes)
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not (fn & 1 or fn == 0):
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root
