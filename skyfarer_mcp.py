#!/usr/bin/env python3
"""
skyfarer-mcp
~~~~~~~~~~~~
An MCP server over stdio that exposes the Skyfarer API to agents. It speaks
newline-delimited JSON-RPC 2.0 and reuses the CLI's client, so it needs no
dependencies beyond the standard library.

    skyfarer-mcp                     # read-only tools
    skyfarer-mcp --allow-writes      # also expose admin tools

Nothing but protocol messages goes to stdout; logs go to stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

import cli

PROTOCOL_VERSION = "2026-07-28"
# Older clients still open with initialize: a version listed here is echoed
# back; any other gets the newest one we support, as MCP asks.
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05",
                   "2024-10-07")
SERVER_INFO = {"name": "skyfarer", "version": "1.0.0"}
READ_INSTRUCTIONS = (
    "Skyfarer watches cloud status pages for incidents in watched regions. "
    "Start with skyfarer_status, then skyfarer_incidents or skyfarer_history "
    "for detail. All tools return JSON unless asked for CSV. This server is "
    "read-only; restart it with --allow-writes for admin tools."
)
WRITE_INSTRUCTIONS = READ_INSTRUCTIONS + (
    " Admin tools are enabled: changes call the same API as the dashboard's "
    "settings pages, and the token's scopes and role are enforced there."
)


class RpcError(Exception):
    def __init__(self, code: int, message: str, data=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _schema(properties: dict, required=()) -> dict:
    return {"type": "object", "properties": properties,
            "required": list(required), "additionalProperties": False}


def _text(description: str, enum=None) -> dict:
    field = {"type": "string", "description": description}
    if enum:
        field["enum"] = list(enum)
    return field


def _number(description: str) -> dict:
    return {"type": "integer", "description": description, "minimum": 1}


def _flag(description: str) -> dict:
    return {"type": "boolean", "description": description}


def _list(description: str) -> dict:
    return {"type": "array", "items": {"type": "string"}, "description": description}


_RANGE = _text("Reporting window: 30d, quarter, year or custom (with from/to).",
               ("30d", "quarter", "year", "custom"))
_LIST_RANGE = _text("Window: all, today, 7d, 30d, 90d or custom (with from/to).",
                    ("all", "today", "7d", "30d", "90d", "custom"))
_DATE = _text("Inclusive start/end date, YYYY-MM-DD (used with range=custom).")
_PROVIDER = _text("Provider name, e.g. OVH; omit or use 'all' for every provider.")
_REGION = _text("Region code, e.g. GRA; omit or use 'all' for every region.")
_LIMIT = _number("Maximum rows to return (default 50, maximum 200).")
_CURSOR = _number("Pagination cursor from the previous response's next_cursor.")

READ_TOOLS = [
    {"name": "skyfarer_status",
     "title": "Skyfarer status",
     "description": "Current availability, open incidents and notification channel health.",
     "inputSchema": _schema({})},
    {"name": "skyfarer_incidents",
     "title": "List incidents",
     "description": "List open, resolved or all incidents, newest detection first.",
     "inputSchema": _schema({
         "state": _text("Which incidents to return.", ("open", "all", "resolved")),
         "provider": _PROVIDER, "region": _REGION,
         "q": _text("Free-text search over titles and summaries."),
         "range": _LIST_RANGE, "from": _DATE, "to": _DATE,
         "limit": _LIMIT, "cursor": _CURSOR,
     })},
    {"name": "skyfarer_incident",
     "title": "Incident detail",
     "description": "One incident with its updates, tickets and notification deliveries.",
     "inputSchema": _schema({"id": _number("Incident id.")}, ("id",))},
    {"name": "skyfarer_history",
     "title": "History and SLA report",
     "description": ("Availability and SLA per provider and region; maintenance is "
                     "excluded and overlapping incidents count once."),
     "inputSchema": _schema({
         "range": _RANGE, "from": _DATE, "to": _DATE,
         "provider": _PROVIDER, "region": _REGION,
         "format": _text("Return CSV instead of JSON.", ("json", "csv")),
     })},
    {"name": "skyfarer_deliveries",
     "title": "Notification deliveries",
     "description": "Recent notification deliveries, with their channel and status.",
     "inputSchema": _schema({
         "channel": _text("Channel id to filter by."),
         "status": _text("Delivery status to filter by."),
         "limit": _LIMIT, "cursor": _CURSOR,
     })},
    {"name": "skyfarer_poll_log",
     "title": "Poll cycles",
     "description": "Recent poll cycles, for checking that feeds are still being read.",
     "inputSchema": _schema({
         "range": _LIST_RANGE, "from": _DATE, "to": _DATE,
         "limit": _LIMIT, "cursor": _CURSOR})},
]

WRITE_TOOLS = [
    {"name": "skyfarer_set_provider",
     "title": "Configure a provider",
     "description": "Enable or disable a provider and set its watched regions.",
     "inputSchema": _schema({
         "name": _text("Provider name, e.g. OVH."),
         "regions": _list("Region codes to watch, e.g. GRA SBG."),
         "enabled": _flag("Whether the provider is polled."),
         "filter_keywords": _list("Global keywords used to ignore notices."),
         "poll_interval": _text("One of the poll intervals shown in Settings."),
     }, ("name",))},
    {"name": "skyfarer_test_channel",
     "title": "Test a notification channel",
     "description": "Send a test through a saved channel and return its result.",
     "inputSchema": _schema({"id": _text("Channel id, e.g. zendesk or webhook-4.")}, ("id",))},
    {"name": "skyfarer_add_webhook",
     "title": "Add a webhook",
     "description": "Add an outbound webhook. Headers and secret are write-only.",
     "inputSchema": _schema({
         "name": _text("Display name."), "url": _text("Endpoint URL."),
         "method": _text("HTTP method.", ("POST", "PUT", "PATCH")),
         "events": _list("Events to send: opened, updated, resolved."),
         "template": _text("Optional body template with {{field}} placeholders."),
         "content_type": _text("Content-Type header."),
         "headers": _text("Extra headers as a JSON object."),
         "secret": _text("HMAC secret for X-Skyfarer-Signature."),
     }, ("name", "url"))},
    {"name": "skyfarer_add_user",
     "title": "Add an account",
     "description": "Add a viewer/admin, or a passwordless service account for automation.",
     "inputSchema": _schema({
         "name": _text("Display name."), "email": _text("Email address."),
         "role": _text("Role.", ("admin", "viewer")),
         "kind": _text("Human accounts can sign in; service accounts cannot.",
                       ("human", "service")),
     }, ("name", "email"))},
    {"name": "skyfarer_create_token",
     "title": "Create a bearer token",
     "description": "Mint a token for a user; the plaintext is returned once only.",
     "inputSchema": _schema({
         "name": _text("What the token is for."),
         "user_id": _number("Id of the user the token acts as."),
         "scopes": _list("Scopes such as incidents:read; capped by the user's role."),
     }, ("name", "user_id"))},
    {"name": "skyfarer_set_settings",
     "title": "Set stored settings",
     "description": "Set or clear general, alert-rule, channel and SLA settings by key.",
     "inputSchema": _schema({
         "values": {"type": "object",
                    "description": "Setting name to value; null clears a setting.",
                    "additionalProperties": True},
         "clear": _list("Setting names to clear as null."),
     }, ("values",))},
    {"name": "skyfarer_set_rules",
     "title": "Set alert rules",
     "description": "Change which events are notified and how old or repeated work is handled.",
     "inputSchema": _schema({
         "events": _list("Events to notify: opened, updated, resolved."),
         "maintenance": _flag("Whether to notify for scheduled maintenance."),
         "max_age_hours": {"type": "number", "description": "Ignore notices older than this."},
         "retry_hours": {"type": "number", "description": "Retry failed deliveries after this."},
     })},
]


def _params(args: dict, keys) -> dict:
    return {k: args[k] for k in keys
            if k in args and args[k] not in (None, "")}


def _incident_id(args: dict) -> int:
    try:
        return int(args["id"])
    except (KeyError, TypeError, ValueError):
        raise cli.CliError("id must be an integer.", cli.EXIT_USAGE) from None


# ─── Tool implementations ──────────────────────────────────────────────────

def tool_status(client, args):
    return client.get("/status")


def tool_incidents(client, args):
    keys = ("state", "provider", "region", "q", "range", "from", "to", "limit", "cursor")
    return client.get("/incidents", _params(args, keys))


def tool_incident(client, args):
    return client.get(f"/incidents/{_incident_id(args)}")


def tool_history(client, args):
    params = _params(args, ("range", "from", "to", "provider", "region"))
    if args.get("format") == "csv":
        params["format"] = "csv"
    return client.get("/history", params)


def tool_deliveries(client, args):
    return client.get("/deliveries",
                      _params(args, ("channel", "status", "limit", "cursor")))


def tool_poll_log(client, args):
    return client.get("/poll-log", _params(args, ("range", "from", "to", "limit", "cursor")))


def tool_set_provider(client, args):
    item = {"name": args["name"]}
    if "regions" in args:
        item["regions"] = args["regions"]
    if "enabled" in args:
        item["enabled"] = args["enabled"]
    payload = {"items": [item]}
    if "filter_keywords" in args:
        payload["filter_keywords"] = args["filter_keywords"]
    if "poll_interval" in args:
        payload["poll_interval"] = args["poll_interval"]
    return client.put("/providers", payload)


def tool_test_channel(client, args):
    cid = str(args.get("id", "")).strip()
    # Webhooks have their own test endpoint; webhook-4 means webhook id 4.
    if cid.startswith("webhook-"):
        hook_id = cid[len("webhook-"):]
        if not hook_id.isdigit():
            raise cli.CliError("A webhook id looks like webhook-4.", cli.EXIT_USAGE)
        return client.post(f"/webhooks/{hook_id}/test", {})
    return client.post(f"/channels/{cid}/test", {})


def tool_add_webhook(client, args):
    keys = ("name", "url", "method", "events", "template", "content_type", "headers", "secret")
    return client.post("/webhooks", _params(args, keys))


def tool_add_user(client, args):
    keys = ("name", "email", "role", "kind")
    return client.post("/users", _params(args, keys))


def tool_create_token(client, args):
    payload = {"name": args["name"], "user_id": args["user_id"],
               "scopes": args.get("scopes", [])}
    return client.post("/tokens", payload)


def tool_set_settings(client, args):
    values = dict(args.get("values") or {})
    values.update({key: None for key in args.get("clear", [])})
    return client.put("/settings", {"values": values})


def tool_set_rules(client, args):
    keys = ("events", "maintenance", "max_age_hours", "retry_hours")
    return client.put("/rules", _params(args, keys))


HANDLERS = {
    "skyfarer_status": tool_status,
    "skyfarer_incidents": tool_incidents,
    "skyfarer_incident": tool_incident,
    "skyfarer_history": tool_history,
    "skyfarer_deliveries": tool_deliveries,
    "skyfarer_poll_log": tool_poll_log,
    "skyfarer_set_provider": tool_set_provider,
    "skyfarer_test_channel": tool_test_channel,
    "skyfarer_add_webhook": tool_add_webhook,
    "skyfarer_add_user": tool_add_user,
    "skyfarer_create_token": tool_create_token,
    "skyfarer_set_settings": tool_set_settings,
    "skyfarer_set_rules": tool_set_rules,
}


# ─── JSON-RPC dispatch ─────────────────────────────────────────────────────

def _tool_result(text: str, is_error: bool = False) -> dict:
    return {"resultType": "complete",
            "content": [{"type": "text", "text": text}],
            "isError": is_error}


def _call_tool(client, params: dict, tools: list, allow_writes: bool) -> dict:
    name = params.get("name")
    if not isinstance(name, str) or not name:
        raise RpcError(-32602, "tools/call needs a tool name.")
    args = params.get("arguments") or {}
    if not isinstance(args, dict):
        raise RpcError(-32602, "Tool arguments must be an object.")
    if name not in {t["name"] for t in tools}:
        # MCP treats an unknown tool as a protocol error, not a tool result.
        hint = "" if allow_writes else " Start with --allow-writes for admin tools."
        raise RpcError(-32602, f"Unknown tool {name!r}.{hint}")
    try:
        result = HANDLERS[name](client, args)
    except cli.CliError as err:
        return _tool_result(f"skyfarer: {err}", True)
    except Exception as err:  # keep the connection alive for the next call
        print(f"skyfarer-mcp: tool {name} failed: {err!r}", file=sys.stderr, flush=True)
        return _tool_result(f"skyfarer: {name} failed: {err}", True)
    text = result if isinstance(result, str) else json.dumps(result, indent=2, sort_keys=True)
    return _tool_result(text)


def dispatch(method: str, params: dict, client, *, allow_writes: bool = False) -> dict:
    if not isinstance(params, dict):
        raise RpcError(-32602, "params must be an object.")
    tools = READ_TOOLS + (WRITE_TOOLS if allow_writes else [])
    instructions = WRITE_INSTRUCTIONS if allow_writes else READ_INSTRUCTIONS

    if method == "server/discover":  # 2026-07-28 stateless clients
        return {"resultType": "complete",
                "supportedVersions": [PROTOCOL_VERSION],
                "capabilities": {"tools": {"listChanged": False}},
                "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO},
                "instructions": instructions,
                "ttlMs": 3_600_000, "cacheScope": "public"}
    if method == "initialize":        # 2025-11-25 and earlier clients
        asked = params.get("protocolVersion")
        version = asked if asked in (PROTOCOL_VERSION, *LEGACY_VERSIONS) else PROTOCOL_VERSION
        return {"resultType": "complete", "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO, "instructions": instructions}
    if method == "ping":
        return {"resultType": "complete"}
    if method == "tools/list":
        return {"resultType": "complete", "tools": tools}
    if method == "tools/call":
        return _call_tool(client, params, tools, allow_writes)
    if method == "resources/list":
        return {"resultType": "complete", "resources": []}
    if method == "prompts/list":
        return {"resultType": "complete", "prompts": []}
    raise RpcError(-32601, f"Method not found: {method}")


def _send(stream, message: dict) -> None:
    # json.dumps escapes embedded newlines, keeping one message per line.
    stream.write(json.dumps(message, ensure_ascii=False) + "\n")
    stream.flush()


def _error(stream, msg_id, code: int, text: str, data=None) -> None:
    error = {"code": code, "message": text}
    if data is not None:
        error["data"] = data
    _send(stream, {"jsonrpc": "2.0", "id": msg_id, "error": error})


def serve(client, *, allow_writes: bool = False, stdin=None, stdout=None) -> None:
    """Read MCP requests from stdin and answer them on stdout until EOF."""
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError as err:
            _error(stdout, None, -32700, f"Parse error: {err}")
            continue
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" \
                or "method" not in message:
            _error(stdout, None, -32600, "Invalid JSON-RPC request.")
            continue
        msg_id = message.get("id")
        is_notification = "id" not in message
        method = message["method"]
        if not isinstance(method, str):
            if not is_notification:
                _error(stdout, msg_id, -32602, "method must be a string.")
            continue
        if method.startswith("notifications/") or method == "initialized":
            continue  # no reply for notifications
        try:
            result = dispatch(method, message.get("params") or {}, client,
                              allow_writes=allow_writes)
        except RpcError as err:
            if not is_notification:
                _error(stdout, msg_id, err.code, err.message, err.data)
            continue
        except Exception as err:
            print(f"skyfarer-mcp: {method} failed: {err!r}", file=sys.stderr, flush=True)
            if not is_notification:
                _error(stdout, msg_id, -32603, f"Internal error: {err}")
            continue
        if not is_notification:
            _send(stdout, {"jsonrpc": "2.0", "id": msg_id, "result": result})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="skyfarer-mcp", description="Skyfarer MCP server (stdio, JSON-RPC 2.0).")
    parser.add_argument("--profile", default=os.getenv("SKYFARER_PROFILE", "default"))
    parser.add_argument("--url", default=os.getenv("SKYFARER_URL"))
    parser.add_argument("--token", default=os.getenv("SKYFARER_TOKEN"))
    parser.add_argument("--allow-writes", action="store_true",
                        help="Expose admin tools as well as read-only tools.")
    args = parser.parse_args(argv)

    profile = cli.load_profile(args.profile)
    url = args.url or profile.get("url", "http://127.0.0.1:8080")
    token = args.token or profile.get("token", "")
    if not token:
        print("skyfarer-mcp: set SKYFARER_TOKEN (or [profiles.NAME] token) to a "
              "Skyfarer bearer token.", file=sys.stderr, flush=True)
        return cli.EXIT_AUTH
    try:
        serve(cli.Client(url, token), allow_writes=args.allow_writes)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
