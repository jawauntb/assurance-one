"""Append-only receipt log with an RFC 9162 Merkle tree (SPEC section 4.3).

File format: a sequence of records, each a 4-byte big-endian length followed by the receipt bytes.
"""
import hashlib
import os
import struct
import threading

import cbor2

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(b):
    return hashlib.sha256(b"\x00" + b).digest()


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


class ReceiptLog:
    def __init__(self, path=None):
        self.path = path
        self._lock = threading.RLock()
        self._entries = []
        self._leaves = []
        if path is not None and os.path.exists(path):
            with open(path, "rb") as f:
                data = f.read()
            i = 0
            while i < len(data):
                if i + 4 > len(data):
                    raise ValueError(f"receipt log {path!r} is truncated")
                (n,) = struct.unpack(">I", data[i:i + 4])
                if i + 4 + n > len(data):
                    raise ValueError(f"receipt log {path!r} is truncated")
                self._add(data[i + 4:i + 4 + n])
                i += 4 + n

    def _add(self, b):
        self._entries.append(b)
        self._leaves.append(leaf_hash(b))

    def append(self, receipt_bytes):
        b = bytes(receipt_bytes)
        with self._lock:
            if self.path is not None:
                with open(self.path, "ab") as f:
                    f.write(struct.pack(">I", len(b)) + b)
                    f.flush()
                    os.fsync(f.fileno())
            self._add(b)
            return len(self._entries) - 1

    def append_built(self, build):
        """Atomically: build(seq, prev) -> receipt bytes, then append. Returns (index, receipt)."""
        with self._lock:
            seq = len(self._entries)
            prev = hashlib.sha256(self._entries[-1]).digest() if self._entries else bytes(32)
            receipt = build(seq, prev)
            return self.append(receipt), receipt

    @property
    def size(self):
        return len(self._entries)

    def __len__(self):
        return len(self._entries)

    def entries(self):
        with self._lock:
            return list(self._entries)

    def _mth(self, lo, hi):
        n = hi - lo
        if n == 0:
            return EMPTY_ROOT
        if n == 1:
            return self._leaves[lo]
        k = _split(n)
        return node_hash(self._mth(lo, lo + k), self._mth(lo + k, hi))

    def root(self):
        with self._lock:
            return self._mth(0, len(self._leaves))

    def inclusion_proof(self, index):
        """RFC 9162 section 2.1.3.1 PATH(m, D[n]) for the current tree size n."""
        with self._lock:
            n = len(self._leaves)
            if not isinstance(index, int) or not 0 <= index < n:
                raise IndexError(index)

            def path(m, lo, hi):
                if hi - lo == 1:
                    return []
                k = _split(hi - lo)
                if m < k:
                    return path(m, lo, lo + k) + [self._mth(lo + k, hi)]
                return path(m - k, lo + k, hi) + [self._mth(lo, lo + k)]

            return path(index, 0, n)

    @staticmethod
    def verify_chain(payloads):
        """`payloads` is a list of (receipt_bytes, payload). True iff seq is consecutive, each prev is the
        sha256 of the preceding receipt, a seq-0 record has a zero prev, and each payload is the one the
        receipt actually carries."""
        try:
            pairs = list(payloads)
            for i, (rb, p) in enumerate(pairs):
                body = cbor2.loads(rb).value[2]
                if cbor2.loads(body) != p:
                    return False
                if type(p["seq"]) is not int:
                    return False
                if p["seq"] == 0 and p["prev"] != bytes(32):
                    return False
                if i > 0:
                    prb, pp = pairs[i - 1]
                    if p["seq"] != pp["seq"] + 1 or p["prev"] != hashlib.sha256(prb).digest():
                        return False
            return True
        except Exception:
            return False
