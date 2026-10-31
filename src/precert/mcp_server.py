"""MCP stdio server (SPEC section 5): the only route from an agent to governed tools.

    python -m precert.mcp_server --policy <path> --tools <module>:<attr> --log <path> [--state <json-path>]

Newline-delimited JSON-RPC 2.0 on stdin/stdout. Only tools that are actions of the policy are listed or callable;
every tools/call goes through Gate.execute, which writes exactly one signed receipt to --log.
"""
import argparse
import importlib
import json
import os
import sys

from . import Gate, ReceiptLog, Signer, load_policy

PROTOCOL_VERSION = "2025-06-18"
JSON_TYPES = {"int": "integer", "bool": "boolean", "str": "string"}


class Server:
    """Gate state persists in <log>.state.json next to the log, so a restart resumes instead of resetting
    (which would let spent budget be spent again). A log with receipts but no matching state file refuses to
    start: the state cannot be rebuilt from receipts, so the server fails closed."""

    def __init__(self, policy, tools, log_path, state=None, signer=None):
        self.policy = policy
        self.tools = tools
        self.state_path = log_path + ".state.json"
        log = ReceiptLog(log_path)
        self.gate = Gate(policy, state=state, signer=signer or Signer.generate(), log=log)
        if os.path.exists(self.state_path):
            with open(self.state_path, encoding="utf-8") as f:
                saved = json.load(f)
            if saved.get("policy_hash") != policy.hash:
                raise SystemExit(f"{self.state_path} belongs to a different policy")
            if saved.get("log_size") != log.size:
                raise SystemExit(f"{self.state_path} does not match the log ({saved.get('log_size')} != {log.size})")
            if state is not None:
                print("precert: resuming persisted state; --state ignored", file=sys.stderr)
            self.gate._restore(saved["state"], saved.get("halted", False))
        elif log.size:
            raise SystemExit(f"log {log_path} has {log.size} receipts but no {self.state_path}; refusing to reset state")
        self._persist()

    def _persist(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"policy_hash": self.policy.hash, "log_size": self.gate.log.size,
                       "state": self.gate.state, "halted": self.gate.halted}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)

    def governed(self):
        """Policy actions that also have an implementation, in policy order."""
        return [a for a in self.policy.actions if a in self.tools and callable(self.tools[a])]

    def tool_list(self):
        out = []
        for name in self.governed():
            spec = self.policy.actions[name]
            out.append({
                "name": name,
                "description": f"Governed by precert policy {self.policy.name!r} ({self.policy.hash[:12]}).",
                "inputSchema": {
                    "type": "object",
                    "properties": {a: {"type": JSON_TYPES[t]} for a, t in spec.args.items()},
                    "required": list(spec.args),
                    "additionalProperties": False,
                },
            })
        return out

    def call(self, params):
        if not isinstance(params, dict):
            params = {}
        name = params.get("name")
        args = params.get("arguments", {})
        meta = params.get("_meta")
        principal = meta["principal"] if isinstance(meta, dict) and "principal" in meta else "agent"
        action = {"tool": name, "args": args, "principal": principal}
        impl = self.tools.get(name) if isinstance(name, str) and name in self.governed() else None

        def refuse(_args):
            raise RuntimeError("no governed implementation for this tool")

        # Ungoverned names never reach their implementation: the gate sees them as unknown tools (or, for a policy
        # action with no implementation, the stand-in raises and the receipt records tool_error).
        r = self.gate.execute(action, impl if impl is not None else refuse)
        self._persist()
        v = r.verdict
        body = {"decision": v.decision, "reason": v.reason, "violated": v.violated, "output": r.output}
        return {"content": [{"type": "text", "text": json.dumps(body, default=repr)}],
                "isError": v.decision != "PERMIT" or not r.executed}

    def handle(self, msg):
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return _error(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request")
        method, mid, is_note = msg["method"], msg.get("id"), "id" not in msg
        params = msg.get("params", {})
        try:
            if method == "initialize":
                req = params.get("protocolVersion") if isinstance(params, dict) else None
                result = {"protocolVersion": req if isinstance(req, str) else PROTOCOL_VERSION,
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "precert", "version": "0.1.0"}}
            elif method.startswith("notifications/"):
                return None
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": self.tool_list()}
            elif method == "tools/call":
                result = self.call(params)
            else:
                return None if is_note else _error(mid, -32601, f"method not found: {method}")
        except Exception as e:      # never crash the server; never run a tool on error
            return None if is_note else _error(mid, -32603, f"internal error: {type(e).__name__}")
        return None if is_note else {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _load_tools(spec):
    mod, _, attr = spec.partition(":")
    if not mod or not attr:
        raise SystemExit("--tools must be <module>:<attr>")
    tools = getattr(importlib.import_module(mod), attr)
    if not isinstance(tools, dict):
        raise SystemExit("--tools must name a dict {name: callable}")
    return tools


def main(argv=None):
    ap = argparse.ArgumentParser(prog="precert.mcp_server")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--tools", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--state")
    a = ap.parse_args(argv)
    policy = load_policy(a.policy)
    state = None
    if a.state:
        with open(a.state, encoding="utf-8") as f:
            state = json.load(f)
    signer = Signer.generate()
    with open(a.log + ".pub", "w", encoding="utf-8") as f:
        f.write(signer.public_key_bytes.hex() + "\n")
    server = Server(policy, _load_tools(a.tools), a.log, state=state, signer=signer)
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:           # ValueError, RecursionError on pathological nesting, ...
            resp = _error(None, -32700, "parse error")
        else:
            resp = server.handle(msg)
        if resp is not None:
            try:
                text = json.dumps(resp)
            except Exception:
                text = json.dumps(_error(None, -32603, "internal error"))
            out.write(text + "\n")
            out.flush()


if __name__ == "__main__":
    main()
