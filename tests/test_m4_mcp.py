"""A11: the MCP server is the only route to governed tools; refused calls have no side effects."""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from conftest import FIX, fixture_path

pytestmark = pytest.mark.m4

SRC = str(pathlib.Path(__file__).resolve().parents[1] / "src")


class Client:
    def __init__(self, tmp_path):
        self.ledger = tmp_path / "ledger.jsonl"
        self.log = tmp_path / "receipts.bin"
        env = dict(os.environ, PRECERT_TEST_LEDGER=str(self.ledger),
                   PYTHONPATH=os.pathsep.join([SRC, str(FIX)]))
        self.p = subprocess.Popen(
            [sys.executable, "-m", "precert.mcp_server", "--policy", fixture_path("payments.json"),
             "--tools", "mock_tools:TOOLS", "--log", str(self.log)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        self.id = 0

    def rpc(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self.id += 1
            msg["id"] = self.id
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        if notify:
            return None
        line = self.p.stdout.readline()
        assert line, self.p.stderr.read()
        resp = json.loads(line)
        assert resp["id"] == self.id
        return resp

    def ledger_lines(self):
        if not self.ledger.exists():
            return []
        return [json.loads(l) for l in self.ledger.read_text().splitlines() if l.strip()]

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


@pytest.fixture
def client(tmp_path):
    c = Client(tmp_path)
    r = c.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "t", "version": "0"}})
    assert "result" in r and "capabilities" in r["result"]
    c.rpc("notifications/initialized", notify=True)
    yield c
    c.close()


def call(c, name, args, principal="agent-x"):
    r = c.rpc("tools/call", {"name": name, "arguments": args, "_meta": {"principal": principal}})
    res = r["result"]
    body = json.loads(res["content"][0]["text"])
    return res, body


def test_only_governed_tools_listed(client):
    tools = client.rpc("tools/list")["result"]["tools"]
    assert [t["name"] for t in tools] == ["pay"]
    props = tools[0]["inputSchema"]["properties"]
    assert set(props) == {"payee", "amount_cents", "ts"}
    assert props["amount_cents"]["type"] == "integer" and props["payee"]["type"] == "string"


def test_permit_runs_tool(client):
    res, body = call(client, "pay", {"payee": "acme", "amount_cents": 100, "ts": 5})
    assert res["isError"] is False and body["decision"] == "PERMIT"
    assert client.ledger_lines() == [{"tool": "pay", "args": {"payee": "acme", "amount_cents": 100, "ts": 5}}]


def test_deny_has_no_side_effect(client):
    res, body = call(client, "pay", {"payee": "acme", "amount_cents": 50000, "ts": 5})
    assert res["isError"] is True and body["decision"] == "DENY" and body["violated"] == ["cap"]
    assert client.ledger_lines() == []


def test_ungoverned_tool_unreachable(client):
    r = client.rpc("tools/call", {"name": "admin_wipe", "arguments": {}})
    if "result" in r:
        assert r["result"]["isError"] is True
    else:
        assert "error" in r
    assert client.ledger_lines() == []


def test_receipts_written_for_every_call(client):
    from precert import ReceiptLog
    call(client, "pay", {"payee": "acme", "amount_cents": 100, "ts": 5})
    call(client, "pay", {"payee": "nobody", "amount_cents": 100, "ts": 6})
    client.close()
    assert ReceiptLog(str(client.log)).size == 2
