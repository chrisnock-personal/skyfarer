"""MCP stdio server: protocol handshake, tool list and tool calls.
Run with: python -m unittest discover tests"""
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cli  # noqa: E402
import skyfarer_mcp as mcp  # noqa: E402


class FakeClient:
    def __init__(self, result=None, error=None):
        self.result = {} if result is None else result
        self.error = error
        self.calls = []

    def _call(self, method, path, payload=None, params=None):
        self.calls.append((method, path, payload, params))
        if self.error:
            raise self.error
        return self.result

    def get(self, path, params=None):
        return self._call("GET", path, params=params)

    def post(self, path, payload=None, params=None, headers=None):
        return self._call("POST", path, payload=payload)

    def put(self, path, payload=None):
        return self._call("PUT", path, payload=payload)

    def patch(self, path, payload=None):
        return self._call("PATCH", path, payload=payload)

    def delete(self, path):
        return self._call("DELETE", path)


def run_server(messages, client=None, allow_writes=False):
    """Feed JSON-RPC messages through the real stdio loop."""
    source = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    sink = io.StringIO()
    mcp.serve(client or FakeClient(), allow_writes=allow_writes,
              stdin=source, stdout=sink)
    return [json.loads(line) for line in sink.getvalue().splitlines() if line.strip()]


def request(method, params=None, msg_id=1):
    return {"jsonrpc": "2.0", "id": msg_id, "method": method,
            "params": params if params is not None else {}}


class Handshake(unittest.TestCase):
    def test_modern_discovery_advertises_tools_and_versions(self):
        reply, = run_server([request("server/discover")])
        result = reply["result"]
        self.assertEqual(reply["id"], 1)
        self.assertEqual(result["supportedVersions"], ["2026-07-28"])
        self.assertEqual(result["capabilities"]["tools"], {"listChanged": False})
        self.assertEqual(result["_meta"]["io.modelcontextprotocol/serverInfo"],
                         {"name": "skyfarer", "version": "1.0.0"})

    def test_legacy_initialize_echoes_client_version(self):
        reply, = run_server([request("initialize", {"protocolVersion": "2025-11-25"})])
        self.assertEqual(reply["result"]["protocolVersion"], "2025-11-25")
        self.assertIn("tools", reply["result"]["capabilities"])

    def test_initialize_with_an_unknown_version_gets_ours(self):
        reply, = run_server([request("initialize", {"protocolVersion": "1999-01-01"})])
        self.assertEqual(reply["result"]["protocolVersion"], mcp.PROTOCOL_VERSION)

    def test_ping_and_empty_lists(self):
        replies = run_server([request("ping"), request("resources/list"),
                              request("prompts/list")])
        self.assertTrue(all("result" in r for r in replies))
        self.assertEqual(replies[1]["result"]["resources"], [])

    def test_notifications_get_no_reply(self):
        replies = run_server([{"jsonrpc": "2.0", "method": "notifications/initialized"},
                              request("ping", msg_id=2)])
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0]["id"], 2)

    def test_bad_json_and_unknown_methods_are_json_rpc_errors(self):
        source = io.StringIO('{not json\n' +
                             json.dumps(request("nope")) + '\n')
        sink = io.StringIO()
        mcp.serve(FakeClient(), stdin=source, stdout=sink)
        first, second = [json.loads(line) for line in sink.getvalue().splitlines()]
        self.assertEqual(first["error"]["code"], -32700)
        self.assertIsNone(first["id"])
        self.assertEqual(second["error"]["code"], -32601)


class Tools(unittest.TestCase):
    def test_read_list_is_the_default(self):
        reply, = run_server([request("tools/list")])
        names = [tool["name"] for tool in reply["result"]["tools"]]
        self.assertEqual(names, [t["name"] for t in mcp.READ_TOOLS])
        self.assertNotIn("skyfarer_create_token", names)
        for tool in reply["result"]["tools"]:
            self.assertEqual(tool["inputSchema"]["type"], "object")

    def test_write_tools_need_opt_in(self):
        reply, = run_server([request("tools/list")], allow_writes=True)
        names = [tool["name"] for tool in reply["result"]["tools"]]
        self.assertEqual(names, [t["name"] for t in mcp.READ_TOOLS + mcp.WRITE_TOOLS])

    def test_status_returns_a_tool_result(self):
        client = FakeClient({"summary": {"open": 2}})
        reply, = run_server([request("tools/call", {"name": "skyfarer_status"})], client)
        result = reply["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["content"][0]["type"], "text")
        self.assertEqual(json.loads(result["content"][0]["text"])["summary"]["open"], 2)
        self.assertEqual(client.calls[0][1], "/status")

    def test_incidents_drops_empty_filters(self):
        client = FakeClient({"items": []})
        run_server([request("tools/call", {
            "name": "skyfarer_incidents",
            "arguments": {"state": "open", "provider": "", "limit": 10}})], client)
        self.assertEqual(client.calls[0][1], "/incidents")
        self.assertEqual(client.calls[0][3], {"state": "open", "limit": 10})

    def test_incident_validates_id(self):
        client = FakeClient()
        reply, = run_server([request("tools/call", {
            "name": "skyfarer_incident", "arguments": {"id": "not-a-number"}})], client)
        self.assertTrue(reply["result"]["isError"])
        self.assertIn("id must be an integer", reply["result"]["content"][0]["text"])
        self.assertEqual(client.calls, [])

    def test_history_can_return_csv_text(self):
        client = FakeClient("Started (UTC),Provider\n")
        reply, = run_server([request("tools/call", {
            "name": "skyfarer_history",
            "arguments": {"range": "quarter", "format": "csv"}})], client)
        self.assertEqual(reply["result"]["content"][0]["text"], "Started (UTC),Provider\n")
        self.assertEqual(client.calls[0][3], {"range": "quarter", "format": "csv"})

    def test_api_errors_become_tool_errors_not_protocol_errors(self):
        client = FakeClient(error=cli.CliError("That API token is invalid or revoked.",
                                               cli.EXIT_AUTH))
        reply, = run_server([request("tools/call", {"name": "skyfarer_status"})], client)
        self.assertTrue(reply["result"]["isError"])
        self.assertIn("invalid or revoked", reply["result"]["content"][0]["text"])
        self.assertNotIn("error", reply)

    def test_unknown_tool_is_a_protocol_error_with_a_hint(self):
        reply, = run_server([request("tools/call", {"name": "skyfarer_create_token"})])
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertIn("--allow-writes", reply["error"]["message"])

    def test_test_channel_sends_webhooks_to_their_own_endpoint(self):
        client = FakeClient({"ok": True, "message": "sent"})
        run_server([request("tools/call", {"name": "skyfarer_test_channel",
                                           "arguments": {"id": "webhook-4"}}, msg_id=1),
                    request("tools/call", {"name": "skyfarer_test_channel",
                                           "arguments": {"id": "zendesk"}}, msg_id=2)],
                   client, allow_writes=True)
        self.assertEqual([c[1] for c in client.calls],
                         ["/webhooks/4/test", "/channels/zendesk/test"])

    def test_write_tools_call_the_api(self):
        client = FakeClient({"changed": []})
        messages = [
            request("tools/call", {"name": "skyfarer_set_provider", "arguments": {
                "name": "OVH", "regions": ["GRA", "SBG"], "enabled": True}}, msg_id=1),
            request("tools/call", {"name": "skyfarer_set_settings", "arguments": {
                "values": {"POLL_INTERVAL_SECONDS": "60"},
                "clear": ["ZENDESK_API_TOKEN"]}}, msg_id=2),
            request("tools/call", {"name": "skyfarer_create_token", "arguments": {
                "name": "CI", "user_id": 4, "scopes": ["incidents:read"]}}, msg_id=3),
        ]
        replies = run_server(messages, client, allow_writes=True)
        self.assertTrue(all(not r["result"]["isError"] for r in replies))
        self.assertEqual(client.calls[0][2]["items"][0]["regions"], ["GRA", "SBG"])
        self.assertIsNone(client.calls[1][2]["values"]["ZENDESK_API_TOKEN"])
        self.assertEqual(client.calls[2][1], "/tokens")

    def test_missing_tool_name_is_a_protocol_error(self):
        reply, = run_server([request("tools/call")])
        self.assertEqual(reply["error"]["code"], -32602)


class EntryPoint(unittest.TestCase):
    def test_missing_token_exits_three_without_touching_stdout(self):
        with mock.patch.object(cli, "load_profile", return_value={}), \
                mock.patch.dict(os.environ, {"SKYFARER_TOKEN": ""}), \
                mock.patch("sys.stderr", io.StringIO()):
            code = mcp.main([])
        self.assertEqual(code, cli.EXIT_AUTH)

    def test_token_from_profile_reaches_the_client(self):
        with mock.patch.object(cli, "load_profile", return_value={
                "url": "http://server.example.test", "token": "sk_live_profile"}), \
                mock.patch.dict(os.environ, {"SKYFARER_TOKEN": ""}), \
                mock.patch.object(mcp, "serve") as serve:
            code = mcp.main(["--allow-writes"])
        self.assertEqual(code, 0)
        self.assertEqual(serve.call_args.args[0].base, "http://server.example.test/api/v1")
        self.assertEqual(serve.call_args.args[0].token, "sk_live_profile")
        self.assertTrue(serve.call_args.kwargs["allow_writes"])


if __name__ == "__main__":
    unittest.main()
