#!/usr/bin/env python3
"""
skyfarer
~~~~~~~~
A command-line client for the Skyfarer API. Uses only the standard library,
so it can be dropped into the container image or pipx-installed.

    skyfarer status
    skyfarer incidents list --state open --json
    skyfarer history --range quarter --csv report.csv
    skyfarer providers set --name OVH --regions GRA SBG
    skyfarer tokens create --name CI --user-id 4 --scopes incidents:read
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_FORBIDDEN = 4
EXIT_NOT_FOUND = 5
EXIT_CONFLICT = 6
EXIT_OPEN_INCIDENT = 7
EXIT_PARTIAL = 8

STATUS_CODES = {401: EXIT_AUTH, 403: EXIT_FORBIDDEN, 404: EXIT_NOT_FOUND,
                409: EXIT_CONFLICT, 429: EXIT_PARTIAL}


def config_path() -> Path:
    return Path(os.getenv("SKYFARER_CONFIG", "~/.config/skyfarer/config.toml")).expanduser()


def load_profile(name: str) -> dict:
    path = config_path()
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return data.get("profiles", {}).get(name, {})


class CliError(Exception):
    def __init__(self, message: str, code: int = EXIT_USAGE):
        super().__init__(message)
        self.code = code


class Client:
    def __init__(self, url: str, token: str = ""):
        self.base = url.rstrip("/") + "/api/v1"
        self.token = token

    def request(self, method: str, path: str, params: Optional[dict] = None,
                payload=None, headers: Optional[dict] = None) -> dict | str:
        query = urllib.parse.urlencode(
            {k: v for k, v in (params or {}).items() if v not in (None, "")})
        url = self.base + path + ("?" + query if query else "")
        request_headers = {
            "Accept": ("text/csv" if (params or {}).get("format") == "csv" else "application/json"),
            "User-Agent": "skyfarer-cli/1",
        }
        if self.token:
            request_headers["Authorization"] = "Bearer " + self.token
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        request_headers.update(headers or {})
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode()
                if not content:
                    return {}
                if "text/csv" in response.headers.get("Content-Type", ""):
                    return content
                return json.loads(content)
        except urllib.error.HTTPError as err:
            try:
                problem = json.loads(err.read().decode())
                detail = problem.get("detail", err.reason)
                fields = [e.get("detail", "") for e in problem.get("errors", []) if isinstance(e, dict)]
                if fields:
                    detail += " (" + "; ".join(f for f in fields if f) + ")"
                retry = err.headers.get("Retry-After")
                if retry:
                    detail += f" Retry after {retry}s."
            except (ValueError, AttributeError):
                detail = str(err.reason)
            raise CliError(detail, STATUS_CODES.get(err.code, EXIT_USAGE)) from None
        except urllib.error.URLError as err:
            raise CliError(f"Cannot reach Skyfarer: {err.reason}", EXIT_USAGE) from None

    def get(self, path: str, params: Optional[dict] = None):
        return self.request("GET", path, params)

    def post(self, path: str, payload=None, params: Optional[dict] = None, headers=None):
        return self.request("POST", path, params, payload, headers)

    def put(self, path: str, payload=None):
        return self.request("PUT", path, payload=payload)

    def patch(self, path: str, payload=None):
        return self.request("PATCH", path, payload=payload)

    def delete(self, path: str):
        return self.request("DELETE", path)


def assignments(values: list[str]) -> dict:
    out = {}
    for item in values or []:
        key, sep, value = item.partition("=")
        if not sep:
            raise CliError(f"Use KEY=VALUE, not {item!r}.", EXIT_USAGE)
        out[key.strip()] = value
    return out


def table(rows: list[dict], columns: list[str]) -> None:
    if not rows:
        print("No results.")
        return
    widths = {c: max(len(c), *(len(str(row.get(c, ""))) for row in rows)) for c in columns}
    print("  ".join(c.ljust(widths[c]) for c in columns))
    for row in rows:
        print("  ".join(str(row.get(c, ""))[:widths[c]].ljust(widths[c]) for c in columns))


def output(value, as_json: bool, columns: list[str]) -> None:
    if as_json:
        print(json.dumps(value, indent=2))
        return
    if isinstance(value, dict) and "providers" in value:
        table(value["providers"], [c for c in columns if any(c in row for row in value["providers"])])
    elif isinstance(value, dict) and "items" in value:
        rows = value["items"]
        if value.get("next_cursor"):
            print(f"next cursor: {value['next_cursor']}")
        table(rows, [c for c in columns if any(c in row for row in rows)])
    elif isinstance(value, list):
        table(value, [c for c in columns if any(c in row for row in value)])
    else:
        print(json.dumps(value, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="skyfarer", description="Command-line client for Skyfarer.")
    p.add_argument("--profile", default=os.getenv("SKYFARER_PROFILE", "default"))
    # Separate destinations: `webhooks add --url` and `bootstrap --token` are
    # their own flags, and must not clobber the connection settings.
    p.add_argument("--url", dest="server_url", default=os.getenv("SKYFARER_URL"))
    p.add_argument("--token", dest="bearer_token", default=os.getenv("SKYFARER_TOKEN"))
    p.add_argument("--json", action="store_true", help="Stable JSON output for scripts")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Current status and channel health")
    inc = sub.add_parser("incidents", help="Inspect incidents")
    inc_sub = inc.add_subparsers(dest="action", required=True)
    ilist = inc_sub.add_parser("list", help="List incidents")
    ilist.add_argument("--state", default="open")
    ilist.add_argument("--provider")
    ilist.add_argument("--region")
    ilist.add_argument("--search")
    ilist.add_argument("--range", default="all")
    ilist.add_argument("--from", dest="date_from")
    ilist.add_argument("--to", dest="date_to")
    ilist.add_argument("--limit", type=int, default=50)
    ilist.add_argument("--fail-on-open", action="store_true",
                       help="Exit 7 if any incident is returned (for checks)")
    ishow = inc_sub.add_parser("show", help="Show one incident")
    ishow.add_argument("id", type=int)

    hist = sub.add_parser("history", help="Availability and SLA report")
    hist.add_argument("--range", default="quarter")
    hist.add_argument("--from", dest="date_from")
    hist.add_argument("--to", dest="date_to")
    hist.add_argument("--provider")
    hist.add_argument("--region")
    hist.add_argument("--csv", metavar="PATH", help="Write the CSV export instead of JSON/table")

    deliv = sub.add_parser("deliveries", help="Notification deliveries")
    deliv.add_argument("--channel")
    deliv.add_argument("--status")
    deliv.add_argument("--limit", type=int, default=50)

    polls = sub.add_parser("poll-log", help="Poll cycles")
    polls.add_argument("--range", default="all")
    polls.add_argument("--from", dest="date_from")
    polls.add_argument("--to", dest="date_to")
    polls.add_argument("--limit", type=int, default=50)

    providers = sub.add_parser("providers", help="Watched providers and regions")
    provider_sub = providers.add_subparsers(dest="action", required=True)
    provider_sub.add_parser("list")
    pset = provider_sub.add_parser("set", help="Set one provider's regions and enabled state")
    pset.add_argument("--name", required=True)
    pset.add_argument("--regions", nargs="+")
    pset.add_argument("--enabled", action="store_true")
    pset.add_argument("--disabled", action="store_true")
    pset.add_argument("--filter-keywords", nargs="*")
    pset.add_argument("--poll-interval")

    channels = sub.add_parser("channels", help="Notification channels")
    channel_sub = channels.add_subparsers(dest="action", required=True)
    channel_sub.add_parser("list")
    cshow = channel_sub.add_parser("show")
    cshow.add_argument("id")
    cset = channel_sub.add_parser("set", help="Set fields on a channel")
    cset.add_argument("id")
    cset.add_argument("--field", action="append", default=[], metavar="KEY=VALUE")
    cset.add_argument("--clear", action="append", default=[], metavar="KEY")
    state = cset.add_mutually_exclusive_group()
    state.add_argument("--enable", action="store_true")
    state.add_argument("--disable", action="store_true")
    ctest = channel_sub.add_parser("test")
    ctest.add_argument("id")

    hooks = sub.add_parser("webhooks", help="Outbound webhooks")
    hook_sub = hooks.add_subparsers(dest="action", required=True)
    hook_sub.add_parser("list")
    _hook_args = lambda hp: (  # noqa: E731 - shared flags for add and edit
        hp.add_argument("--name"), hp.add_argument("--url"), hp.add_argument("--method"),
        hp.add_argument("--events", nargs="*"), hp.add_argument("--template"),
        hp.add_argument("--content-type"), hp.add_argument("--headers"),
        hp.add_argument("--secret"), hp.add_argument("--remove-headers", action="store_true"),
        hp.add_argument("--remove-secret", action="store_true"))
    hadd = hook_sub.add_parser("add")
    _hook_args(hadd)
    hedge = hook_sub.add_parser("edit")
    hedge.add_argument("id")
    _hook_args(hedge)
    hedge.add_argument("--enabled", action="store_true")
    hedge.add_argument("--disabled", action="store_true")
    hdelete = hook_sub.add_parser("delete")
    hdelete.add_argument("id", type=int)
    htest = hook_sub.add_parser("test")
    htest.add_argument("id", type=int)

    users = sub.add_parser("users", help="Accounts and service accounts")
    user_sub = users.add_subparsers(dest="action", required=True)
    user_sub.add_parser("list")
    uadd = user_sub.add_parser("add")
    uadd.add_argument("--name", required=True)
    uadd.add_argument("--email", required=True)
    uadd.add_argument("--role", default="viewer", choices=("admin", "viewer"))
    uadd.add_argument("--kind", default="human", choices=("human", "service"))
    urole = user_sub.add_parser("role")
    urole.add_argument("id", type=int)
    urole.add_argument("role", choices=("admin", "viewer"))
    ulink = user_sub.add_parser("link")
    ulink.add_argument("id", type=int)
    udelete = user_sub.add_parser("delete")
    udelete.add_argument("id", type=int)

    tokens = sub.add_parser("tokens", help="Bearer tokens")
    token_sub = tokens.add_subparsers(dest="action", required=True)
    token_sub.add_parser("list")
    tcreate = token_sub.add_parser("create")
    tcreate.add_argument("--name", required=True)
    tcreate.add_argument("--user-id", type=int, required=True)
    tcreate.add_argument("--scopes", nargs="*")
    trevoke = token_sub.add_parser("revoke")
    trevoke.add_argument("id", type=int)

    conf = sub.add_parser("settings", help="Stored settings (secrets stay write-only)")
    conf_sub = conf.add_subparsers(dest="action", required=True)
    conf_sub.add_parser("get")
    cset2 = conf_sub.add_parser("set", help="Set KEY=VALUE (use --clear for null)")
    cset2.add_argument("values", nargs="*")
    cset2.add_argument("--clear", action="append", default=[], metavar="KEY")

    rules = sub.add_parser("rules", help="Alert rules")
    rules_sub = rules.add_subparsers(dest="action", required=True)
    rset = rules_sub.add_parser("set")
    rset.add_argument("--events", nargs="*")
    rset.add_argument("--max-age-hours", type=float)
    rset.add_argument("--retry-hours", type=float)
    rset.add_argument("--maintenance", action=argparse.BooleanOptionalAction, default=None,
                      help="Alert on planned maintenance (--no-maintenance to stop)")

    boot = sub.add_parser("bootstrap", help="Create the first admin on a fresh instance")
    boot.add_argument("--name", default=os.getenv("SKYFARER_BOOTSTRAP_ADMIN_NAME", ""))
    boot.add_argument("--email", default=os.getenv("SKYFARER_BOOTSTRAP_ADMIN_EMAIL", ""))
    boot.add_argument("--password", default=os.getenv("SKYFARER_BOOTSTRAP_ADMIN_PASSWORD", ""))
    boot.add_argument("--token", default=os.getenv("SKYFARER_BOOTSTRAP_ADMIN_TOKEN", ""))
    boot.add_argument("--secret", default=os.getenv("SKYFARER_BOOTSTRAP_SECRET", ""),
                      help="The server's SKYFARER_BOOTSTRAP_SECRET")
    return p


def hook_payload(args) -> dict:
    data = {k: getattr(args, k) for k in
            ("name", "url", "method", "template", "content_type", "headers", "secret")
            if getattr(args, k, None) is not None}
    if getattr(args, "events", None) is not None:
        data["events"] = args.events
    if getattr(args, "remove_headers", False):
        data["remove_headers"] = True
    if getattr(args, "remove_secret", False):
        data["remove_secret"] = True
    return data


def run(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile)
    url = args.server_url or profile.get("url", "http://127.0.0.1:8080")
    token = args.bearer_token or profile.get("token", "")
    if args.command == "bootstrap":
        if not args.secret:
            raise CliError("Set --secret or SKYFARER_BOOTSTRAP_SECRET.", EXIT_AUTH)
        client = Client(url, token)
        result = client.post("/bootstrap", {
            "name": args.name, "email": args.email,
            "password": args.password, "token": args.token},
            headers={"X-Bootstrap-Secret": args.secret})
        output(result, args.json, ["id", "email", "setup_url", "api_token"])
        return EXIT_OK
    if not token:
        raise CliError("No token. Set SKYFARER_TOKEN or [profiles.default] token in the config.",
                       EXIT_AUTH)
    client = Client(url, token)

    if args.command == "status":
        output(client.get("/status"), args.json, ["label", "status", "regions"])
    elif args.command == "incidents":
        if args.action == "list":
            params = {"state": args.state, "provider": args.provider or "all",
                      "region": args.region, "q": args.search, "range": args.range,
                      "from": args.date_from, "to": args.date_to, "limit": args.limit}
            result = client.get("/incidents", params)
            output(result, args.json, ["id", "detected_at", "provider", "region", "state", "title"])
            if args.fail_on_open and result.get("items"):
                return EXIT_OPEN_INCIDENT
        else:
            output(client.get(f"/incidents/{args.id}"), args.json,
                   ["id", "provider", "region", "state", "title"])
    elif args.command == "history":
        params = {"range": args.range, "from": args.date_from, "to": args.date_to,
                  "provider": args.provider or "all", "region": args.region or "all"}
        if args.csv:
            report = client.get("/history", {**params, "format": "csv"})
            Path(args.csv).write_text(report, encoding="utf-8")
            print(f"Wrote {args.csv}")
        else:
            output(client.get("/history", params), args.json,
                   ["provider", "incidents", "availability_label", "downtime_label", "status"])
    elif args.command == "deliveries":
        output(client.get("/deliveries", {"channel": args.channel, "status": args.status,
                                          "limit": args.limit}), args.json,
               ["id", "created_at", "channel", "status", "incident_title"])
    elif args.command == "poll-log":
        params = {"range": args.range, "from": args.date_from, "to": args.date_to,
                  "limit": args.limit}
        output(client.get("/poll-log", params), args.json,
               ["id", "polled_at", "entries_seen", "tickets_created", "tickets_resolved",
                "open_count", "error"])
    elif args.command == "providers":
        if args.action == "list":
            output(client.get("/providers"), args.json, ["name", "label", "enabled", "regions"])
        else:
            item = {"name": args.name}
            if args.regions is not None:
                item["regions"] = args.regions
            if args.enabled:
                item["enabled"] = True
            if args.disabled:
                item["enabled"] = False
            payload = {"items": [item]}
            if args.filter_keywords is not None:
                payload["filter_keywords"] = args.filter_keywords
            if args.poll_interval:
                payload["poll_interval"] = args.poll_interval
            output(client.put("/providers", payload), args.json, ["changed"])
    elif args.command == "channels":
        if args.action == "list":
            output(client.get("/channels"), args.json, ["id", "name", "enabled", "summary"])
        elif args.action == "show":
            output(client.get(f"/channels/{args.id}"), args.json,
                   ["key", "label", "kind", "value", "configured"])
        elif args.action == "test":
            result = client.post(f"/channels/{args.id}/test", {})
            print(result.get("message", result))
            if not result.get("ok", True):
                return EXIT_PARTIAL
        else:
            values = assignments(args.field)
            values.update({key: None for key in args.clear})
            if args.enable:
                values["enabled"] = True
            if args.disable:
                values["enabled"] = False
            output(client.patch(f"/channels/{args.id}", values), args.json, ["id", "changed"])
    elif args.command == "webhooks":
        if args.action == "list":
            output(client.get("/webhooks"), args.json,
                   ["id", "name", "url", "method", "enabled", "secret_configured"])
        elif args.action in ("add", "edit"):
            payload = hook_payload(args)
            if args.action == "add":
                output(client.post("/webhooks", payload), args.json, ["id", "name", "url"])
            else:
                if getattr(args, "enabled", False):
                    payload["enabled"] = True
                if getattr(args, "disabled", False):
                    payload["enabled"] = False
                output(client.patch(f"/webhooks/{args.id}", payload), args.json, ["id", "name"])
        elif args.action == "delete":
            output(client.delete(f"/webhooks/{args.id}"), args.json, ["id", "deleted"])
        else:
            result = client.post(f"/webhooks/{args.id}/test", {})
            print(result.get("message", result))
            if not result.get("ok", True):
                return EXIT_PARTIAL
    elif args.command == "users":
        if args.action == "list":
            output(client.get("/users"), args.json, ["id", "name", "email", "role", "kind"])
        elif args.action == "add":
            output(client.post("/users", {"name": args.name, "email": args.email,
                                          "role": args.role, "kind": args.kind}),
                   args.json, ["id", "name", "email", "role", "setup_url"])
        elif args.action == "role":
            output(client.patch(f"/users/{args.id}", {"role": args.role}), args.json, ["id", "role"])
        elif args.action == "link":
            output(client.patch(f"/users/{args.id}", {"new_setup_link": True}),
                   args.json, ["id", "setup_url"])
        else:
            output(client.delete(f"/users/{args.id}"), args.json, ["id", "deleted"])
    elif args.command == "tokens":
        if args.action == "list":
            output(client.get("/tokens"), args.json,
                   ["id", "name", "user_email", "scopes", "last_used_at", "revoked"])
        elif args.action == "create":
            output(client.post("/tokens", {"name": args.name, "user_id": args.user_id,
                                           "scopes": args.scopes or []}),
                   args.json, ["id", "name", "scopes", "token"])
        else:
            output(client.delete(f"/tokens/{args.id}"), args.json, ["id", "revoked"])
    elif args.command == "settings":
        if args.action == "get":
            output(client.get("/settings"), args.json, ["key", "label", "value"])
        else:
            values = assignments(args.values)
            values.update({key: None for key in args.clear})
            output(client.put("/settings", {"values": values}), args.json, ["changed"])
    elif args.command == "rules":
        payload = {}
        if args.events is not None:
            payload["events"] = args.events
        if args.max_age_hours is not None:
            payload["max_age_hours"] = args.max_age_hours
        if args.retry_hours is not None:
            payload["retry_hours"] = args.retry_hours
        if args.maintenance is not None:
            payload["maintenance"] = args.maintenance
        output(client.put("/rules", payload), args.json, ["changed"])
    return EXIT_OK


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except CliError as err:
        print(f"skyfarer: {err}", file=sys.stderr)
        return err.code


if __name__ == "__main__":
    sys.exit(main())
