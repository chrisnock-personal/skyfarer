#!/usr/bin/env python3
"""
skyfarer
~~~~~~~~
A small command-line client for the Skyfarer API. Uses only the standard
library, so it can be dropped into the container image or pipx-installed.

    skyfarer status
    skyfarer incidents list --state open --json
    skyfarer history --range quarter --csv report.csv
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


class Client:
    def __init__(self, url: str, token: str):
        self.base = url.rstrip("/") + "/api/v1"
        self.token = token

    def get(self, path: str, params: Optional[dict] = None) -> dict | str:
        query = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v not in (None, "")})
        url = self.base + path + ("?" + query if query else "")
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "text/csv" if params and params.get("format") == "csv" else "application/json",
            "User-Agent": "skyfarer-cli/1",
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                body = response.read().decode()
                return body if "text/csv" in response.headers.get("Content-Type", "") else json.loads(body)
        except urllib.error.HTTPError as err:
            try:
                detail = json.loads(err.read().decode()).get("detail", err.reason)
            except (ValueError, AttributeError):
                detail = str(err.reason)
            raise CliError(detail, STATUS_CODES.get(err.code, EXIT_USAGE)) from None
        except urllib.error.URLError as err:
            raise CliError(f"Cannot reach Skyfarer: {err.reason}", EXIT_USAGE) from None


class CliError(Exception):
    def __init__(self, message: str, code: int = EXIT_USAGE):
        super().__init__(message)
        self.code = code


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
    p.add_argument("--url", default=os.getenv("SKYFARER_URL"))
    p.add_argument("--token", default=os.getenv("SKYFARER_TOKEN"))
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
    polls.add_argument("--limit", type=int, default=50)
    return p


def run(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile)
    url = args.url or profile.get("url", "http://127.0.0.1:8080")
    token = args.token or profile.get("token", "")
    if not token:
        raise CliError("No token. Set SKYFARER_TOKEN or [profiles.default] token in the config.",
                       EXIT_AUTH)
    client = Client(url, token)

    if args.command == "status":
        output(client.get("/status"), args.json, ["provider", "state", "last_poll"])
    elif args.command == "incidents":
        if args.action == "list":
            params = {"state": args.state, "provider": args.provider or "all",
                      "region": args.region, "q": args.search, "range": args.range,
                      "from": args.date_from, "to": args.date_to, "limit": args.limit}
            result = client.get("/incidents", params)
            output(result, args.json, ["id", "detected_at", "provider", "region", "state", "title"])
            if not args.json and result.get("items") and args.fail_on_open:
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
        output(client.get("/poll-log", {"range": args.range, "limit": args.limit}), args.json,
               ["id", "polled_at", "channel", "status"])
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
