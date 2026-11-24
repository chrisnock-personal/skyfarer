"""
api.py
~~~~~~
Versioned JSON API for scripts, the CLI and agents.

Authentication and role checks happen in admin.guard(), which every /api/v1
request passes through; the decorators here only check scopes. Read handlers
call the same helpers as the HTML pages, so the two views cannot drift apart.
"""

from __future__ import annotations

import math
import os
import secrets
from datetime import date, datetime
from functools import wraps
from typing import Optional

from flask import Blueprint, Response, g, jsonify, request, url_for

import api_errors
import db
import history
import notifiers
import settings

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


def admin_only(fn):
    """A second ceiling for admin endpoints: even an admin token with only
    read scopes can't reach them without both scope and role."""
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if (g.get("user") or {}).get("role") != "admin":
            return api_errors.problem(403, "This endpoint needs an admin account.",
                                      code="forbidden")
        return fn(*args, **kwargs)
    return wrapped


def body() -> dict:
    data = request.get_json(silent=True)
    if data is None:
        return {}
    if not isinstance(data, dict):
        return api_errors.problem(400, "Send a JSON object.", code="bad-body")
    return data


def unwrap_values(data: dict) -> dict:
    """Accept both flat channel fields and a nested `values` object."""
    nested = data.get("values")
    if nested is None:
        return data
    if not isinstance(nested, dict):
        return data
    return {**{k: v for k, v in data.items() if k != "values"}, **nested}


def as_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


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


# ─── Admin: shared write helpers ───────────────────────────────────────────

def _save_changes(conn, proposed: dict, actor: str) -> tuple[list[str], list[str]]:
    """Validate with the same settings.check() the settings pages use, then
    save only what actually differs. Returns (change lines, problems)."""
    from admin import effective
    values = settings.load(conn)
    changes = {k: v for k, v in proposed.items()
               if v is None or v != effective(values, k)}
    if not changes:
        return [], []
    baseline = set(settings.check(conn, {}))
    errors = [e for e in settings.check(conn, changes) if e not in baseline]
    if errors:
        return [], errors
    return settings.save(conn, changes, actor), []


def _problem_for(errors: list[str]):
    return api_errors.problem(400, "Some settings aren't valid.",
                              code="invalid-settings",
                              errors=[{"detail": e} for e in errors])


def _field_info(key: str, values: dict, meta: dict, unreadable: set) -> dict:
    from admin import effective
    f = settings.FIELDS.get(key)
    secret = settings.is_secret(key)
    info = {"key": key, "label": f.label if f else settings.label(key),
            "kind": f.kind if f else "text", "secret": secret,
            "configured": key in values or key in meta,
            "value": None if secret else effective(values, key)}
    if f:
        info.update(help=f.help, default=f.default,
                    options=[{"value": v, "label": label} for v, label in f.options])
    if secret and key in meta:
        info.update(updated_at=meta[key]["updated_at"], updated_by=meta[key]["updated_by"])
    if key in unreadable:
        info["unreadable"] = True
    return info


def _clean_settings(data: dict) -> tuple[dict, list[str]]:
    proposed: dict = {}
    errors = []
    for key, value in data.items():
        if key.startswith("SLA_TARGET_"):
            try:
                number = float(value)
                if not 0 <= number <= 100:
                    raise ValueError
            except (TypeError, ValueError):
                errors.append(f"{settings.label(key)} must be a percentage between 0 and 100.")
            else:
                proposed[key] = f"{number:.2f}"
            continue
        f = settings.FIELDS.get(key)
        if not f:
            errors.append(f"Unknown setting {key!r}.")
            continue
        if value is None:
            proposed[key] = None
        elif f.kind == "secret":
            # As on /channels: blank leaves a stored secret alone; null clears it.
            if str(value).strip():
                proposed[key] = str(value).strip()
        elif f.kind == "bool":
            proposed[key] = "true" if as_bool(value) else "false"
        elif f.kind in ("list", "events"):
            values = value if isinstance(value, list) else str(value).split(",")
            proposed[key] = settings.join_list(values)
        elif f.kind == "select":
            if str(value) in dict(f.options):
                proposed[key] = str(value)
            else:
                errors.append(f"{f.label} must be one of {', '.join(dict(f.options))}.")
        elif f.kind == "number":
            try:
                number = float(value)
                if not math.isfinite(number) or number < 0:
                    raise ValueError
            except (TypeError, ValueError):
                errors.append(f"{f.label} must be a non-negative number.")
            else:
                proposed[key] = str(value)
        else:
            proposed[key] = str(value).strip()
    return proposed, errors


def _clean_channel(c, data: dict) -> tuple[dict, list[str]]:
    proposed: dict = {}
    errors = []
    for f in c.fields:
        if f.key not in data:
            continue
        value = data[f.key]
        if f.kind == "secret":
            if value is None:
                proposed[f.key] = None            # explicit clear
            elif isinstance(value, str) and value.strip():
                proposed[f.key] = value.strip()   # blank means "leave as-is"
        elif f.kind == "bool":
            proposed[f.key] = "true" if as_bool(value) else "false"
        elif f.kind in ("list", "events"):
            values = value if isinstance(value, list) else str(value).split(",")
            proposed[f.key] = settings.join_list(values)
        elif f.kind == "select":
            if str(value) in dict(f.options):
                proposed[f.key] = str(value)
            else:
                errors.append(f"{f.label} must be one of {', '.join(dict(f.options))}.")
        elif f.kind == "number":
            try:
                number = float(value)
                if not math.isfinite(number) or number < 0:
                    raise ValueError
            except (TypeError, ValueError):
                errors.append(f"{f.label} must be a non-negative number.")
            else:
                proposed[f.key] = str(value)
        else:
            proposed[f.key] = str(value).strip()
    if "enabled" in data:
        proposed[c.enabled_key] = "true" if as_bool(data["enabled"]) else "false"
    return proposed, errors


def _hook_payload(data: dict, existing: Optional[dict] = None) -> tuple[dict, list[str]]:
    """Build the dict settings.webhook_save() takes, and validate it with the
    same notifiers.webhook_errors() the Settings page uses."""
    import admin
    events = data.get("events", existing["hook"].events if existing else [])
    if isinstance(events, str):
        events = settings.split_list(events)
    form = {
        "name": str(data.get("name") or "Webhook").strip() or "Webhook",
        "url": str(data.get("url") or "").strip(),
        "method": str(data.get("method") or "POST").upper(),
        "events": ",".join(e for e in notifiers.EVENTS if e in events),
        "template": str(data.get("template") or "").strip(),
        "content_type": str(data.get("content_type") or "application/json").strip(),
        "headers": str(data.get("headers") or "").strip(),
        "secret": str(data.get("secret") or "").strip(),
        "remove_headers": as_bool(data.get("remove_headers", False)),
        "remove_secret": as_bool(data.get("remove_secret", False)),
    }
    old = existing["hook"] if existing else None
    trial = notifiers.Webhook(
        id=existing["id"] if existing else 0, name=form["name"], url=form["url"],
        method=form["method"],
        headers="" if form["remove_headers"] else (form["headers"] or (old.headers if old else "")),
        template=form["template"], content_type=form["content_type"],
        secret=form["secret"] or (old.secret if old else ""),
        events=settings.split_list(form["events"]))
    return form, notifiers.webhook_errors(trial)


def _hook_info(w: dict) -> dict:
    h = w["hook"]
    return {"id": w["id"], "name": w["name"], "enabled": w["enabled"],
            "url": h.url, "method": h.method, "events": h.events,
            "template": h.template, "content_type": h.content_type,
            "headers_configured": bool(h.headers), "secret_configured": bool(h.secret),
            "unreadable": w["unreadable"], "created_at": w["created_at"],
            "updated_at": w["updated_at"]}


# ─── Admin: settings, providers, channels, rules ───────────────────────────

@bp.get("/settings")
@require("settings:read")
@admin_only
def get_settings():
    unreadable: set = set()
    with db.get_conn() as conn:
        values = settings.load(conn, unreadable)
        meta = settings.secret_meta(conn)
    groups = [{"id": "general", "title": "General",
               "fields": [_field_info(f.key, values, meta, unreadable) for f in settings.GENERAL]},
              {"id": "rules", "title": "Alert rules",
               "fields": [_field_info(f.key, values, meta, unreadable) for f in settings.RULES]}]
    for c in settings.CHANNELS:
        groups.append({"id": c.id, "title": c.name,
                       "fields": [_field_info(f.key, values, meta, unreadable) for f in c.fields]})
    import history as report
    groups.append({"id": "sla", "title": "SLA targets",
                   "fields": [_field_info(report.target_key(p.name), values, meta, unreadable)
                              for p in settings.PROVIDERS]})
    return jsonify(clean({"groups": groups}))


@bp.put("/settings")
@require("settings:write")
@admin_only
def put_settings():
    import admin
    data = body()
    if isinstance(data, Response):
        return data
    values = data.get("values", data)
    if not isinstance(values, dict):
        return api_errors.problem(400, "values must be a JSON object.", code="bad-body")
    proposed, errors = _clean_settings(values)
    if errors:
        return _problem_for(errors)
    with db.get_conn() as conn:
        lines, errors = _save_changes(conn, proposed, admin._actor())
    if errors:
        return _problem_for(errors)
    return jsonify({"changed": lines})


@bp.get("/providers")
@require("settings:read")
@admin_only
def get_providers():
    with db.get_conn() as conn:
        values = settings.load(conn)
    import admin
    items = [{"name": p.name, "label": p.label,
              "enabled": admin.effective(values, p.enabled_key) == "true",
              "regions": settings.split_list(values.get(p.key, "")),
              "suggestions": list(p.suggestions)} for p in settings.PROVIDERS]
    return jsonify({"items": items,
                    "filter_keywords": settings.split_list(values.get("FILTER_KEYWORDS", "")),
                    "poll_interval": admin.effective(values, "POLL_INTERVAL_SECONDS")})


@bp.put("/providers")
@require("settings:write")
@admin_only
def put_providers():
    import admin
    data = body()
    if isinstance(data, Response):
        return data
    proposed, errors = {}, []
    for item in data.get("items", []):
        if not isinstance(item, dict):
            errors.append("Each provider must be an object.")
            continue
        p = next((p for p in settings.PROVIDERS
                  if p.name.lower() == str(item.get("name", "")).lower()), None)
        if not p:
            errors.append(f"Unknown provider {item.get('name')!r}.")
            continue
        if "enabled" in item:
            proposed[p.enabled_key] = "true" if as_bool(item["enabled"]) else "false"
        if "regions" in item:
            regions = item["regions"]
            values = regions if isinstance(regions, list) else str(regions).split(",")
            proposed[p.key] = settings.join_list(values)
    if "filter_keywords" in data:
        keywords = data["filter_keywords"]
        if not isinstance(keywords, list):
            keywords = str(keywords).split(",")
        proposed["FILTER_KEYWORDS"] = settings.join_list(keywords)
    if "poll_interval" in data:
        interval = str(data["poll_interval"])
        if interval in dict(settings.FIELDS["POLL_INTERVAL_SECONDS"].options):
            proposed["POLL_INTERVAL_SECONDS"] = interval
        else:
            errors.append("Unknown poll interval.")
    if errors:
        return _problem_for(errors)
    with db.get_conn() as conn:
        lines, errors = _save_changes(conn, proposed, admin._actor())
    if errors:
        return _problem_for(errors)
    return jsonify({"changed": lines})


def _channel_info(c, values: dict, meta: dict, unreadable: set) -> dict:
    import admin
    fields = []
    for f in c.fields:
        info = _field_info(f.key, values, meta, unreadable)
        if info["secret"]:
            info["value"] = None
        fields.append(info)
    return {"id": c.id, "name": c.name, "group": c.group,
            "enabled": admin.effective(values, c.enabled_key) == "true",
            "summary": admin._channel_summary(c.id, values),
            "configured": c.id in notifiers.enabled_channels(), "fields": fields}


@bp.get("/channels")
@require("settings:read")
@admin_only
def get_channels():
    unreadable: set = set()
    with db.get_conn() as conn:
        values = settings.load(conn, unreadable)
        meta = settings.secret_meta(conn)
    return jsonify({"items": [_channel_info(c, values, meta, unreadable)
                              for c in settings.CHANNELS]})


@bp.post("/channels")
@require("settings:write")
@admin_only
def post_channel():
    import admin
    data = body()
    if isinstance(data, Response):
        return data
    data = unwrap_values(data)
    c = settings.CHANNEL_BY_ID.get(str(data.get("id", "")))
    if not c:
        return api_errors.problem(404, "No such channel.", code="not-found")
    proposed, errors = _clean_channel(c, data)
    if errors:
        return _problem_for(errors)
    if not proposed:
        return api_errors.problem(400, "Nothing to save.", code="bad-body")
    with db.get_conn() as conn:
        lines, errors = _save_changes(conn, proposed, admin._actor())
    if errors:
        return _problem_for(errors)
    return jsonify({"id": c.id, "changed": lines}), 201


@bp.get("/channels/<cid>")
@require("settings:read")
@admin_only
def get_channel(cid: str):
    c = settings.CHANNEL_BY_ID.get(cid)
    if not c:
        return api_errors.problem(404, "No such channel.", code="not-found")
    unreadable: set = set()
    with db.get_conn() as conn:
        values = settings.load(conn, unreadable)
        meta = settings.secret_meta(conn)
    return jsonify(_channel_info(c, values, meta, unreadable))


@bp.patch("/channels/<cid>")
@require("settings:write")
@admin_only
def patch_channel(cid: str):
    import admin
    c = settings.CHANNEL_BY_ID.get(cid)
    if not c:
        return api_errors.problem(404, "No such channel.", code="not-found")
    data = body()
    if isinstance(data, Response):
        return data
    proposed, errors = _clean_channel(c, unwrap_values(data))
    if errors:
        return _problem_for(errors)
    with db.get_conn() as conn:
        lines, errors = _save_changes(conn, proposed, admin._actor())
    if errors:
        return _problem_for(errors)
    return jsonify({"id": cid, "changed": lines})


@bp.delete("/channels/<cid>")
@require("settings:write")
@admin_only
def delete_channel(cid: str):
    import admin
    c = settings.CHANNEL_BY_ID.get(cid)
    if not c:
        return api_errors.problem(404, "No such channel.", code="not-found")
    keys = [c.enabled_key, *(f.key for f in c.fields)]
    with db.get_conn() as conn:
        settings.save(conn, {k: None for k in keys}, admin._actor())
    return jsonify({"id": cid, "deleted": True,
                    "message": "Saved settings cleared; the channel is off."})


@bp.post("/channels/<cid>/test")
@require("channels:test")
@admin_only
def test_channel(cid: str):
    import admin
    if cid not in settings.CHANNEL_BY_ID:
        return api_errors.problem(404, "No such channel.", code="not-found")
    ok, message = admin.run_test(cid)
    return jsonify({"ok": ok, "message": message})


@bp.put("/rules")
@require("settings:write")
@admin_only
def put_rules():
    import admin
    data = body()
    if isinstance(data, Response):
        return data
    # Only what the caller sends changes: a missing field keeps its setting.
    proposed, errors = {}, []
    if "events" in data:
        events = data["events"]
        if not isinstance(events, list):
            events = settings.split_list(str(events))
        proposed["NOTIFY_EVENTS"] = ",".join(e for e in notifiers.EVENTS if e in events)
    if "maintenance" in data:
        proposed["NOTIFY_MAINTENANCE"] = "true" if as_bool(data["maintenance"]) else "false"
    for key, field in (("NOTIFY_MAX_AGE_HOURS", "max_age_hours"),
                       ("NOTIFY_RETRY_HOURS", "retry_hours")):
        if field not in data:
            continue
        try:
            number = float(data[field])
            if not math.isfinite(number) or number < 0:
                raise ValueError
        except (TypeError, ValueError):
            errors.append(f"{settings.FIELDS[key].label} must be a number of hours.")
        else:
            proposed[key] = str(data[field])
    if errors:
        return _problem_for(errors)
    with db.get_conn() as conn:
        lines, errors = _save_changes(conn, proposed, admin._actor())
    if errors:
        return _problem_for(errors)
    return jsonify({"changed": lines})


# ─── Admin: webhooks ────────────────────────────────────────────────────────

@bp.get("/webhooks")
@require("settings:read")
@admin_only
def get_webhooks():
    with db.get_conn() as conn:
        hooks = settings.webhooks(conn)
    return jsonify({"items": [_hook_info(w) for w in hooks], "next_cursor": None})


@bp.post("/webhooks")
@require("settings:write")
@admin_only
def post_webhook():
    import admin
    data = body()
    if isinstance(data, Response):
        return data
    form, errors = _hook_payload(data)
    if errors:
        return _problem_for(errors)
    with db.get_conn() as conn:
        hook_id = settings.webhook_save(conn, None, form, admin._actor())
        created = _find_webhook(conn, hook_id)
    return jsonify(_hook_info(created)), 201


def _find_webhook(conn, hook_id: int):
    for w in settings.webhooks(conn):
        if w["id"] == hook_id:
            return w
    return None


@bp.get("/webhooks/<int:hook_id>")
@require("settings:read")
@admin_only
def get_webhook(hook_id: int):
    with db.get_conn() as conn:
        w = _find_webhook(conn, hook_id)
    if not w:
        return api_errors.problem(404, "No such webhook.", code="not-found")
    return jsonify(_hook_info(w))


@bp.patch("/webhooks/<int:hook_id>")
@require("settings:write")
@admin_only
def patch_webhook(hook_id: int):
    import admin
    data = body()
    if isinstance(data, Response):
        return data
    with db.get_conn() as conn:
        w = _find_webhook(conn, hook_id)
        if not w:
            return api_errors.problem(404, "No such webhook.", code="not-found")
        base = {"name": w["name"], "url": w["url"], "method": w["method"],
                "events": w["hook"].events, "template": w["template"],
                "content_type": w["content_type"]}
        form, errors = _hook_payload({**base, **data}, w)
        if errors:
            return _problem_for(errors)
        settings.webhook_save(conn, hook_id, form, admin._actor())
        if "enabled" in data:
            settings.webhook_enable(conn, hook_id, as_bool(data["enabled"]), admin._actor())
        updated = _find_webhook(conn, hook_id)
    return jsonify(_hook_info(updated))


@bp.delete("/webhooks/<int:hook_id>")
@require("settings:write")
@admin_only
def delete_webhook(hook_id: int):
    import admin
    with db.get_conn() as conn:
        if not _find_webhook(conn, hook_id):
            return api_errors.problem(404, "No such webhook.", code="not-found")
        settings.webhook_delete(conn, hook_id, admin._actor())
    return jsonify({"id": hook_id, "deleted": True})


@bp.post("/webhooks/<int:hook_id>/test")
@require("channels:test")
@admin_only
def test_webhook(hook_id: int):
    import admin
    with db.get_conn() as conn:
        if not _find_webhook(conn, hook_id):
            return api_errors.problem(404, "No such webhook.", code="not-found")
    ok, message = admin.run_test(f"webhook-{hook_id}")
    return jsonify({"ok": ok, "message": message})


# ─── Admin: users and tokens ────────────────────────────────────────────────

def _setup_url(token: str) -> str:
    return request.url_root.rstrip("/") + url_for("admin.welcome", token=token)


@bp.get("/users")
@require("settings:read")
@admin_only
def get_users():
    with db.get_conn() as conn:
        people = settings.users(conn)
    return jsonify({"items": clean(people), "next_cursor": None})


@bp.get("/users/<int:user_id>")
@require("settings:read")
@admin_only
def get_user(user_id: int):
    with db.get_conn() as conn:
        person = settings.user(conn, user_id)
    if not person:
        return api_errors.problem(404, "No such user.", code="not-found")
    return jsonify(clean(person))


@bp.post("/users")
@require("users:write")
@admin_only
def post_user():
    import psycopg2
    import admin
    data = body()
    if isinstance(data, Response):
        return data
    name = str(data.get("name") or "").strip()
    email = str(data.get("email") or "").strip()
    role = data.get("role", "viewer")
    kind = data.get("kind", "human")
    if not name or "@" not in email or role not in settings.ROLES or kind not in ("human", "service"):
        return api_errors.problem(400, "Give a name, an email, a role and a valid kind.",
                                  code="invalid-user", errors=[])
    try:
        with db.get_conn() as conn:
            new = settings.create_user(conn, email, name, role, admin._actor(), kind=kind)
    except psycopg2.errors.UniqueViolation:
        return api_errors.problem(409, f"There's already an account for {email}.", code="conflict")
    result = {"id": new.user_id, "name": name, "email": email.lower(),
              "role": role, "kind": kind}
    if new.token:
        result["setup_url"] = _setup_url(new.token)
    return jsonify(result), 201


@bp.patch("/users/<int:user_id>")
@require("users:write")
@admin_only
def patch_user(user_id: int):
    import admin
    data = body()
    if isinstance(data, Response):
        return data
    result = {"id": user_id}
    with db.get_conn() as conn:
        person = settings.user(conn, user_id)
        if not person:
            return api_errors.problem(404, "No such user.", code="not-found")
        if "role" in data:
            reason = settings.set_role(conn, user_id, data["role"], admin._actor())
            if reason:
                return api_errors.problem(400, reason, code="invalid-role")
            result["role"] = data["role"]
        if as_bool(data.get("new_setup_link", False)):
            if person["kind"] == "service" or person["active"]:
                return api_errors.problem(409, "Only accounts without a password get a setup link.",
                                          code="conflict")
            new = settings.new_setup_link(conn, user_id, admin._actor())
            result["setup_url"] = _setup_url(new.token)
    return jsonify(result)


@bp.delete("/users/<int:user_id>")
@require("users:write")
@admin_only
def delete_user(user_id: int):
    import admin
    with db.get_conn() as conn:
        reason = settings.delete_user(conn, user_id, admin._actor())
        if reason:
            return api_errors.problem(400, reason, code="conflict")
    return jsonify({"id": user_id, "deleted": True})


@bp.get("/tokens")
@require("tokens:write")
@admin_only
def get_tokens():
    with db.get_conn() as conn:
        rows = settings.api_tokens(conn)
    return jsonify({"items": clean(rows), "next_cursor": None})


@bp.get("/tokens/<int:token_id>")
@require("tokens:write")
@admin_only
def get_token(token_id: int):
    with db.get_conn() as conn:
        row = settings.api_token_by_id(conn, token_id)
    if not row:
        return api_errors.problem(404, "No such token.", code="not-found")
    return jsonify(clean(row))


@bp.post("/tokens")
@require("tokens:write")
@admin_only
def post_token():
    import admin
    data = body()
    if isinstance(data, Response):
        return data
    name = str(data.get("name") or "").strip()
    if not name:
        return api_errors.problem(400, "Give the token a name.", code="bad-body")
    try:
        user_id = int(data.get("user_id"))
    except (TypeError, ValueError):
        return api_errors.problem(400, "Choose the user the token acts as.", code="bad-body")
    scopes = data.get("scopes") or list(DEFAULT_SCOPES)
    if not isinstance(scopes, list):
        return api_errors.problem(400, "scopes must be a list.", code="bad-body")
    with db.get_conn() as conn:
        person = settings.user(conn, user_id)
        if not person:
            return api_errors.problem(404, "No such user.", code="not-found")
        allowed = set(scopes) & (set(SCOPES) | {"*"})
        if person["role"] != "admin":
            allowed &= READ_SCOPES
        if not allowed:
            allowed = set(DEFAULT_SCOPES) & (READ_SCOPES if person["role"] != "admin" else set(SCOPES))
        token_id, plaintext = settings.create_api_token(conn, user_id, name,
                                                         sorted(allowed), admin._actor())
    return jsonify({"id": token_id, "name": name, "user_id": user_id,
                    "scopes": sorted(allowed), "token": plaintext}), 201


@bp.delete("/tokens/<int:token_id>")
@require("tokens:write")
@admin_only
def delete_token(token_id: int):
    import admin
    with db.get_conn() as conn:
        name = settings.revoke_api_token(conn, token_id, admin._actor())
    if not name:
        return api_errors.problem(404, "No such active token.", code="not-found")
    return jsonify({"id": token_id, "revoked": True})


# ─── Headless install ───────────────────────────────────────────────────────

@bp.post("/bootstrap")
def bootstrap():
    """Create the first admin on a fresh instance, guarded by a secret from
    the server's environment so it can't be used by a random caller."""
    expected = os.getenv("SKYFARER_BOOTSTRAP_SECRET", "")
    sent = request.headers.get("X-Bootstrap-Secret", "")
    if not expected or not secrets.compare_digest(sent, expected):
        return api_errors.problem(401, "A bootstrap secret is required.",
                                  code="bad-secret",
                                  headers={"WWW-Authenticate": "Bootstrap"})
    data = body()
    if isinstance(data, Response):
        return data
    try:
        settings.bootstrap()
        with db.get_conn() as conn:
            result = settings.headless_bootstrap(conn, data, actor="skyfarer bootstrap")
    except ValueError as exc:
        return api_errors.problem(400, str(exc), code="bad-password")
    if not result:
        return api_errors.problem(409, "Already installed, or missing name, email and credential.",
                                  code="already-installed")
    return jsonify(clean(result)), 201
