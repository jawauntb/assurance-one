"""A10: receipts verify independently of precert; tampering and deletion are detected."""
import hashlib

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from conftest import Recorder, pay
from oracle import H, mth, verify_inclusion

pytestmark = pytest.mark.m3


def independent_verify(receipt, pub):
    obj = cbor2.loads(receipt)
    assert isinstance(obj, cbor2.CBORTag) and obj.tag == 18
    protected, unprotected, payload, sig = obj.value
    assert cbor2.loads(protected) == {1: -8}
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, sig_structure)   # raises on failure
    return cbor2.loads(payload)


@pytest.fixture
def run(payments_policy):
    from precert import Gate
    g = Gate(payments_policy)
    acts = [pay(amount=500, ts=10), pay(amount=999999, ts=20), {"tool": "zzz", "args": {}, "principal": "p"},
            pay(amount=700, ts=30, principal="other")]
    results = [g.execute(a, Recorder()) for a in acts]
    return g, acts, results


def test_receipts_verify_independently(run, payments_policy):
    g, acts, results = run
    pub = g.signer.public_key_bytes
    assert len(pub) == 32
    prev = bytes(32)
    for i, (a, r) in enumerate(zip(acts, results)):
        p = independent_verify(r.receipt, pub)
        assert p["seq"] == i
        assert p["prev"] == prev
        assert p["action_digest"] == H(a)
        assert p["principal"] == a["principal"]
        assert p["decision"] == r.verdict.decision
        assert p["executed"] == r.executed
        assert p["policy_hash"] == payments_policy.hash
        prev = hashlib.sha256(r.receipt).digest()
    p0 = independent_verify(results[0].receipt, pub)
    assert p0["admissibility"]["lean_theorem_id"] == "precert_payments_pay_preserves"
    assert p0["admissibility"]["solver_result"] == "valid"
    p1 = independent_verify(results[1].receipt, pub)
    assert p1["violated"] == ["budget", "cap"]
    assert p1["admissibility"]["counterexample"]["args"]["amount_cents"] == 999999


def test_precert_verify_matches(run):
    from precert import verify_receipt
    g, _, results = run
    for r in results:
        assert verify_receipt(r.receipt, g.signer.public_key_bytes) == independent_verify(r.receipt, g.signer.public_key_bytes)


def test_every_byte_flip_detected(run):
    from precert import verify_receipt, ReceiptInvalid
    g, _, results = run
    rec = results[0].receipt
    pub = g.signer.public_key_bytes
    for i in range(len(rec)):
        b = bytearray(rec)
        b[i] ^= 0x01
        with pytest.raises(ReceiptInvalid):
            verify_receipt(bytes(b), pub)


def test_wrong_key_rejected(run):
    from precert import verify_receipt, ReceiptInvalid, Signer
    _, _, results = run
    with pytest.raises(ReceiptInvalid):
        verify_receipt(results[0].receipt, Signer.generate().public_key_bytes)


def test_merkle_root_and_inclusion(run):
    g, _, results = run
    entries = g.log.entries()
    assert entries == [r.receipt for r in results]
    root = g.log.root()
    assert root == mth(entries)
    for i, e in enumerate(entries):
        assert verify_inclusion(i, len(entries), e, g.log.inclusion_proof(i), root)
    assert not verify_inclusion(0, len(entries), entries[1], g.log.inclusion_proof(0), root)


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13])
def test_merkle_sizes(payments_policy, n):
    from precert import Gate
    g = Gate(payments_policy)
    for i in range(n):
        g.execute(pay(amount=1, ts=i), Recorder())
    e = g.log.entries()
    assert g.log.root() == mth(e)
    for i in range(n):
        assert verify_inclusion(i, n, e[i], g.log.inclusion_proof(i), g.log.root())


def test_chain_detects_middle_deletion(run):
    from precert import ReceiptLog, verify_receipt
    g, _, results = run
    pairs = [(r.receipt, verify_receipt(r.receipt, g.signer.public_key_bytes)) for r in results]
    assert ReceiptLog.verify_chain(pairs)
    assert not ReceiptLog.verify_chain(pairs[:1] + pairs[2:])
    assert not ReceiptLog.verify_chain([pairs[1], pairs[0]])


def test_file_log_persists(payments_policy, tmp_path):
    from precert import Gate, ReceiptLog
    path = tmp_path / "log.bin"
    log = ReceiptLog(str(path))
    g = Gate(payments_policy, log=log)
    g.execute(pay(amount=1, ts=1), Recorder())
    g.execute(pay(amount=2, ts=2), Recorder())
    root = log.root()
    again = ReceiptLog(str(path))
    assert again.size == 2 and again.root() == root and again.entries() == log.entries()
