"""Canonical JSON hashing (SPEC section 1)."""
import hashlib
import json


def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def H(x):
    return hashlib.sha256(canon(x)).hexdigest()


def state_hash(state):
    return H(state)


def action_digest(action):
    return H(action)
