"""Audit a receipt log file: every signature, the hash chain, and the RFC 9162 root.

    python -m precert.audit --log receipts.bin --pub <hex public key | path to .pub file>

Exit status 0 iff every receipt verifies and the chain is intact from seq 0.
"""
import argparse
import json
import os
import sys

from .errors import ReceiptInvalid
from .log import ReceiptLog
from .receipts import verify_receipt


def audit(log_path, public_key_bytes):
    log = ReceiptLog(log_path)
    pairs, errors = [], []
    for i, rb in enumerate(log.entries()):
        try:
            p = verify_receipt(rb, public_key_bytes)
        except ReceiptInvalid as e:
            errors.append(f"receipt {i}: {e}")
            continue
        if p["seq"] != i:
            errors.append(f"receipt {i}: seq {p['seq']} out of place")
        pairs.append((rb, p))
    chain_ok = not errors and ReceiptLog.verify_chain(pairs)
    if not chain_ok and not errors:
        errors.append("hash chain broken")
    decisions = {}
    for _, p in pairs:
        decisions[p["decision"]] = decisions.get(p["decision"], 0) + 1
    return {"size": log.size, "root": log.root().hex(), "ok": not errors, "decisions": decisions,
            "executed": sum(1 for _, p in pairs if p["executed"]), "errors": errors}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="precert.audit")
    ap.add_argument("--log", required=True)
    ap.add_argument("--pub", required=True, help="hex Ed25519 public key, or a file containing it")
    a = ap.parse_args(argv)
    pub = a.pub
    if os.path.exists(pub):
        with open(pub, encoding="utf-8") as f:
            pub = f.read().strip()
    report = audit(a.log, bytes.fromhex(pub))
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
