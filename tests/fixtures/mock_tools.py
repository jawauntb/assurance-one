"""Mock tools for MCP tests. Side effects go to the file named by PRECERT_TEST_LEDGER."""
import json
import os


def _write(line):
    with open(os.environ["PRECERT_TEST_LEDGER"], "a") as f:
        f.write(json.dumps(line) + "\n")


def pay(args):
    _write({"tool": "pay", "args": args})
    return {"settled_amount_cents": args["amount_cents"]}


def admin_wipe(args):
    _write({"tool": "admin_wipe", "args": args})
    return {"wiped": True}


TOOLS = {"pay": pay, "admin_wipe": admin_wipe}
