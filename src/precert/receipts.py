"""COSE_Sign1 / Ed25519 receipts (SPEC section 4.1, 4.2)."""
import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import ReceiptInvalid

COSE_SIGN1_TAG = 18
PROTECTED = cbor2.dumps({1: -8}, canonical=True)     # alg: EdDSA
PAYLOAD_FIELDS = {
    "seq": int, "prev": bytes, "principal": str, "action_digest": str, "tool": str, "decision": str,
    "reason": str, "violated": list, "executed": bool, "tool_error": bool, "policy_hash": str,
    "admissibility": dict, "settlement": (dict, type(None)),
}


class Signer:
    def __init__(self, private_key=None):
        self._sk = private_key if private_key is not None else Ed25519PrivateKey.generate()
        self.public_key_bytes = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @classmethod
    def generate(cls):
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed):
        return cls(Ed25519PrivateKey.from_private_bytes(bytes(seed)))

    def sign(self, data):
        return self._sk.sign(data)


def _sig_structure(protected, payload):
    return cbor2.dumps(["Signature1", protected, b"", payload])


def make_receipt(signer, payload):
    body = cbor2.dumps(payload, canonical=True)
    sig = signer.sign(_sig_structure(PROTECTED, body))
    return cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [PROTECTED, {}, body, sig]))


def _check_payload(p):
    if not isinstance(p, dict) or set(p) != set(PAYLOAD_FIELDS):
        raise ReceiptInvalid("payload fields")
    for k, t in PAYLOAD_FIELDS.items():
        v = p[k]
        if t is int and type(v) is not int or t is not int and not isinstance(v, t) or (t is int and v < 0):
            raise ReceiptInvalid(f"payload field {k!r} has wrong type")
    if len(p["prev"]) != 32:
        raise ReceiptInvalid("prev must be 32 bytes")
    if not all(isinstance(v, str) for v in p["violated"]):
        raise ReceiptInvalid("violated must be a list of str")


def decode_receipt(receipt_bytes):
    """Structural decode (no signature check). Returns (protected, payload_bytes, signature, payload)."""
    try:
        if not isinstance(receipt_bytes, (bytes, bytearray)):
            raise ReceiptInvalid("receipt must be bytes")
        data = bytes(receipt_bytes)
        obj = cbor2.loads(data)
        if not isinstance(obj, cbor2.CBORTag) or obj.tag != COSE_SIGN1_TAG:
            raise ReceiptInvalid("not a COSE_Sign1 (tag 18)")
        v = obj.value
        if not isinstance(v, (list, tuple)) or len(v) != 4:
            raise ReceiptInvalid("COSE_Sign1 must be a 4-element array")
        protected, unprotected, body, sig = v
        if not (isinstance(protected, bytes) and isinstance(body, bytes) and isinstance(sig, bytes)):
            raise ReceiptInvalid("protected, payload and signature must be bstr")
        if protected != PROTECTED or cbor2.loads(protected) != {1: -8}:
            raise ReceiptInvalid("protected header must be {1: -8}")
        if unprotected != {}:
            raise ReceiptInvalid("unprotected header must be empty")
        if len(sig) != 64:
            raise ReceiptInvalid("Ed25519 signature must be 64 bytes")
        # Exactly one canonical encoding is accepted: no trailing bytes, no alternative encodings.
        if cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [protected, {}, body, sig])) != data:
            raise ReceiptInvalid("non-canonical encoding")
        payload = cbor2.loads(body)
        if cbor2.dumps(payload, canonical=True) != body:
            raise ReceiptInvalid("non-canonical payload")
        _check_payload(payload)
        return protected, body, sig, payload
    except ReceiptInvalid:
        raise
    except Exception as e:
        raise ReceiptInvalid(f"malformed receipt: {type(e).__name__}: {e}") from None


def verify_receipt(receipt_bytes, public_key_bytes):
    protected, body, sig, payload = decode_receipt(receipt_bytes)
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public_key_bytes)).verify(sig, _sig_structure(protected, body))
    except (InvalidSignature, ValueError, TypeError) as e:
        raise ReceiptInvalid(f"bad signature: {type(e).__name__}") from None
    return payload
