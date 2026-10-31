import copy
import json
import pathlib

import pytest

FIX = pathlib.Path(__file__).parent / "fixtures"


def fixture_path(name):
    return str(FIX / name)


def load_fixture(name):
    return json.loads((FIX / name).read_text())


@pytest.fixture
def payments_policy():
    from precert import load_policy
    return load_policy(fixture_path("payments.json"))


@pytest.fixture
def deploy_policy():
    from precert import load_policy
    return load_policy(fixture_path("deploy.json"))


def pay(payee="acme", amount=1000, ts=10_000, principal="agent-1"):
    return {"tool": "pay", "args": {"payee": payee, "amount_cents": amount, "ts": ts}, "principal": principal}


class Recorder:
    """Tool double: records every call, returns settled == requested unless told otherwise."""

    def __init__(self, settle_delta=0, raise_exc=None):
        self.calls = []
        self.settle_delta = settle_delta
        self.raise_exc = raise_exc

    def __call__(self, args):
        if self.raise_exc:
            raise self.raise_exc
        self.calls.append(copy.deepcopy(args))
        if "amount_cents" in args:
            return {"settled_amount_cents": args["amount_cents"] + self.settle_delta}
        return {"ok": True}
