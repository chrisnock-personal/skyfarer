"""
api.py
~~~~~~
Versioned JSON API for scripts, the CLI and agents.

Authentication and role checks happen in admin.guard(), which every /api/v1
request passes through; the decorators here only check scopes. Read handlers
call the same helpers as the HTML pages, so the two views cannot drift apart.
"""

from __future__ import annotations

import os
from datetime import date, datetime
from functools import wraps

from flask import Blueprint, Response, g, jsonify, request

import api_errors
import db
import history

bp = Blueprint("api", __name__, url_prefix="/api/v1")

SCOPES = (
    "status:read", "incidents:read", "history:read", "deliveries:read",
    "poll-log:read", "settings:read", "settings:write", "channels:test",
    "users:write", "tokens:write",
)
READ_SCOPES = frozenset(s for s in SCOPES if s.endswith(":read"))
WRITE_SCOPES = frozenset(s for s in SCOPES if s.endswith(":write") or s.endswith(":test"))

DEFAULT_SCOPES = ("status:read", "incidents:read", "history:read")
MAX_LIMIT = 200


def require(scope: str):
    """Check a token scope, and re-check the role ceiling on every request."""
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            scopes = getattr(g, "api_scopes", set())
            role = (g.get("user") or {}).get("role")
            if scope in WRITE_SCOPES and role != "admin":
                return api_errors.problem(403, "That scope needs an admin account.",
                                          code="forbidden")
            if scope not in scopes and "*" not in scopes:
                return api_errors.problem(403, f"This token needs the {scope} scope.",
                                          code="insufficient-scope")
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def clean(value):
    """Make database rows and reports safe for Flask's JSON encoder."""
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    return value


def query(sql: str, params=()) -> list[dict]:
    from psycopg2.extras import RealDictCursor
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]


def _int_arg(name: str, default: int, *, minimum: int = 1, maximum: int = MAX_LIMIT) -> int:
    raw = request.args.get(name, "")
    try:
        value = int(raw) if raw else default
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _choice(name: str, default: str, choices) -> str:
    value = request.args.get(name, default)
    return value if value in choices else default


def _page(items: list[dict], limit: int, key="id"):
    more = len(items) > limit
    page = items[:limit]
    cursor = page[-1][key] if more and page else None
    return {"items": clean(page), "next_cursor": cursor}


# ─── Read endpoints ─────────────────────────────────────────────────────────

@bp.get("/openapi.json")
def openapi():
    """The machine-readable contract, served without a token."""
    path = os.path.join(os.path.dirname(__file__), "docs", "openapi.json")
    with open(path, encoding="utf-8") as handle:
        return Response(handle.read(), mimetype="application/json")


@bp.get("/status")
@require("status:read")
def status():
    from dashboard import (fetch_channels, fetch_poll_bars, fetch_providers,
                           fetch_summary, _feed_errors)
    summary = fetch_summary()
    bars, bar_errors = fetch_poll_bars()
    providers, off = fetch_providers(summary["last_poll"])
    return jsonify(clean({
        "summary": summary, "providers": providers, "providers_off": off,
        "channels": fetch_channels(), "poll_bars": bars,
        "feed_errors": _feed_errors(summary["last_poll"]),
        "poll_errors": bar_errors,
    }))


@bp.get("/incidents")
@require("incidents:read")
def incidents():
    from dashboard import VALID_RANGES, VALID_STATES, compute_range

    state = _choice("state", "open", VALID_STATES)
    provider = request.args.get("provider", "all")
    region = request.args.get("region", "").strip()
    q = request.args.get("q", "").strip()
    range_key = _choice("range", "all", VALID_RANGES)
    start, end = compute_range(range_key, request.args.get("from", ""),
                               request.args.get("to", ""))
    limit = _int_arg("limit", 50)
    cursor = request.args.get("cursor", "").strip()

    sql = "SELECT * FROM incidents WHERE 1=1"
    params: list = []
    if state != "all":
        sql += " AND state = %s"
        params.append(state)
    if provider != "all":
        sql += " AND provider = %s"
        params.append(provider)
    if region:
        sql += """ AND EXISTS (SELECT 1 FROM regexp_split_to_table(region, ',') r
                               WHERE btrim(r) ILIKE %s)"""
        params.append(region)
    if q:
        sql += " AND (title ILIKE %s OR summary ILIKE %s OR region ILIKE %s)"
        params += [f"%{q}%"] * 3
    if start:
        sql += " AND detected_at >= %s"
        params.append(start)
    if end:
        sql += " AND detected_at < %s"
        params.append(end)
    if cursor:
        try:
            anchor = int(cursor)
        except ValueError:
            return api_errors.problem(400, "cursor must be an incident id.", code="bad-cursor")
        sql += """ AND (detected_at, id) < (SELECT detected_at, id
                                              FROM incidents WHERE id = %s)"""
        params.append(anchor)
    sql += " ORDER BY detected_at DESC, id DESC LIMIT %s"
    params.append(limit + 1)
    return jsonify(_page(query(sql, params), limit))


@bp.get("/incidents/<int:incident_id>")
@require("incidents:read")
def incident(incident_id: int):
    rows = query("SELECT * FROM incidents WHERE id = %s", (incident_id,))
    if not rows:
        return api_errors.problem(404, "No such incident.", code="not-found")
    item = rows[0]
    item["updates"] = query("""SELECT * FROM incident_updates WHERE incident_id = %s
                               ORDER BY created_at""", (incident_id,))
    item["tickets"] = query("SELECT * FROM tickets WHERE incident_id = %s ORDER BY system",
                            (incident_id,))
    item["deliveries"] = query("""SELECT id, channel, status, attempts, created_at
                                   FROM notifications WHERE incident_id = %s
                                   ORDER BY created_at""", (incident_id,))
    return jsonify(clean(item))


@bp.get("/history")
@require("history:read")
def history_report():
    from dashboard import history_context

    context = history_context(
        _choice("range", "quarter", [k for k, _ in history.RANGES]),
        request.args.get("from", ""), request.args.get("to", ""),
        request.args.get("provider", "all"), request.args.get("region", "all"))
    report = context["report"]
    if request.args.get("format") == "csv" or "text/csv" in request.headers.get("Accept", ""):
        return Response(history.csv_export(report), mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition":
                                 'attachment; filename="skyfarer-history.csv"'})
    return jsonify(clean(report))


@bp.get("/deliveries")
@require("deliveries:read")
def deliveries():
    limit = _int_arg("limit", 50)
    channel = request.args.get("channel", "")
    status = request.args.get("status", "")
    sql = """SELECT n.*, i.title AS incident_title FROM notifications n
             JOIN incidents i ON i.id = n.incident_id WHERE 1=1"""
    params: list = []
    if channel:
        sql += " AND n.channel = %s"
        params.append(channel)
    if status:
        sql += " AND n.status = %s"
        params.append(status)
    cursor = request.args.get("cursor", "").strip()
    if cursor:
        try:
            anchor = int(cursor)
        except ValueError:
            return api_errors.problem(400, "cursor must be a delivery id.", code="bad-cursor")
        sql += " AND n.id < %s"
        params.append(anchor)
    sql += " ORDER BY n.id DESC LIMIT %s"
    params.append(limit + 1)
    return jsonify(_page(query(sql, params), limit))


@bp.get("/poll-log")
@require("poll-log:read")
def poll_log():
    from dashboard import VALID_RANGES, compute_range
    limit = _int_arg("limit", 50)
    start, end = compute_range(_choice("range", "all", VALID_RANGES),
                               request.args.get("from", ""), request.args.get("to", ""))
    sql = "SELECT * FROM poll_log WHERE 1=1"
    params: list = []
    if start:
        sql += " AND polled_at >= %s"
        params.append(start)
    if end:
        sql += " AND polled_at < %s"
        params.append(end)
    cursor = request.args.get("cursor", "").strip()
    if cursor:
        try:
            anchor = int(cursor)
        except ValueError:
            return api_errors.problem(400, "cursor must be a poll id.", code="bad-cursor")
        sql += " AND id < %s"
        params.append(anchor)
    sql += " ORDER BY id DESC LIMIT %s"
    params.append(limit + 1)
    return jsonify(_page(query(sql, params), limit))
