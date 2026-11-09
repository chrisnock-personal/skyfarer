#!/usr/bin/env python3
"""
dashboard.py
~~~~~~~~~~~~
Skyfarer's web dashboard: the incidents, notifications and poll log for
everyone who signs in, and the settings pages (admin.py) for admins.

Usage:
    python dashboard.py     # serves on 0.0.0.0:$DASHBOARD_PORT (default 8080)
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from dotenv import load_dotenv
from flask import Flask, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix
from psycopg2.extras import RealDictCursor

# Before the imports below: each reads its settings when it loads.
load_dotenv()

import db  # noqa: E402
import feeds  # noqa: E402
import notifiers  # noqa: E402
import settings  # noqa: E402
from admin import bp as admin_bp  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set DASHBOARD_HTTPS=true behind a TLS proxy so the cookie is only sent over HTTPS.
    SESSION_COOKIE_SECURE=os.getenv("DASHBOARD_HTTPS", "").lower() in ("1", "true", "yes"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)
if app.config["SESSION_COOKIE_SECURE"]:
    # Behind a TLS proxy: take the client address, scheme and host from its
    # X-Forwarded-* headers, so setup links and the sign-in throttle are right.
    # Only then: without a proxy those headers would come from anyone.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

VALID_STATES = ("all", "open", "resolved")
VALID_RANGES = ("all", "today", "7d", "30d", "90d", "custom")
RANGE_LABELS = [
    ("today", "Today"), ("7d", "7d"), ("30d", "30d"),
    ("90d", "90d"), ("all", "All"),
]
STATE_LABELS = [("open", "Active"), ("resolved", "Resolved"), ("all", "All")]

# How each provider is shown; the database keeps the short names.
PROVIDER_LABELS = {"GCP": "Google Cloud", "OVH": "OVHcloud"}
CHANNEL_LABELS = {
    "zendesk": "Zendesk", "servicenow": "ServiceNow", "jsm": "Jira Service Management",
    "freshdesk": "Freshdesk",
    "pushover": "Pushover", "pagerduty": "PagerDuty",
    "teams": "Microsoft Teams", "snmp": "SNMP traps", "webhook": "Webhook",
}


def channel_label(channel: str) -> str:
    if channel.startswith("webhook-"):
        hook = notifiers.webhook_for(channel)
        return f"Webhook: {hook.name}" if hook else "Webhook (deleted)"
    return CHANNEL_LABELS.get(channel, channel)


def poll_interval() -> int:
    try:
        return int(os.getenv("POLL_INTERVAL_SECONDS", "") or 300)
    except ValueError:
        return 300


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _query(sql: str, params=()) -> list[dict]:
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def compute_range(range_key: str, from_date: str, to_date: str):
    """Returns (start, end) datetimes (either may be None for open-ended)."""
    now = datetime.now(timezone.utc)
    if range_key == "custom":
        start = end = None
        if from_date:
            try:
                start = datetime.strptime(from_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        if to_date:
            try:
                end = datetime.strptime(to_date, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=1)
            except ValueError:
                pass
        return start, end
    if range_key == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0), None
    if range_key in ("7d", "30d", "90d"):
        return now - timedelta(days=int(range_key[:-1])), None
    return None, None


def fetch_incidents(state: str, provider: str, search: str, start, end, limit: int = 200):
    query = (
        "SELECT incidents.*, (SELECT json_agg(json_build_object("
        "'system', t.system, 'ref', t.ref, 'number', t.number) ORDER BY t.system) "
        "FROM tickets t WHERE t.incident_id = incidents.id) AS other_tickets "
        "FROM incidents WHERE 1=1"
    )
    params: list = []
    if state != "all":
        query += " AND state = %s"
        params.append(state)
    if provider != "all":
        query += " AND provider = %s"
        params.append(provider)
    if search:
        like = f"%{_escape_like(search)}%"
        query += (
            " AND (title ILIKE %s ESCAPE '\\' OR summary ILIKE %s ESCAPE '\\' "
            "OR region ILIKE %s ESCAPE '\\' OR provider ILIKE %s ESCAPE '\\' "
            "OR EXISTS (SELECT 1 FROM incident_updates u WHERE u.incident_id = incidents.id "
            "AND (u.title ILIKE %s ESCAPE '\\' OR u.summary ILIKE %s ESCAPE '\\')))"
        )
        params += [like] * 6
    if start:
        query += " AND detected_at >= %s"
        params.append(start)
    if end:
        query += " AND detected_at < %s"
        params.append(end)
    # Live incidents, then maintenance under way, then upcoming work (soonest
    # first), then everything that's over, newest first.
    query += """
        ORDER BY CASE
                   WHEN state = 'open' AND NOT is_maintenance THEN 0
                   WHEN state = 'open' AND detected_at <= NOW() THEN 1
                   WHEN state = 'open' THEN 2
                   ELSE 3
                 END,
                 CASE WHEN state = 'open' AND detected_at > NOW() THEN detected_at END,
                 detected_at DESC
        LIMIT %s"""
    params.append(limit)
    return _query(query, params)


def fetch_poll_log(start, end, limit: int = 50):
    query = "SELECT * FROM poll_log WHERE 1=1"
    params: list = []
    if start:
        query += " AND polled_at >= %s"
        params.append(start)
    if end:
        query += " AND polled_at < %s"
        params.append(end)
    query += " ORDER BY polled_at DESC LIMIT %s"
    params.append(limit)
    return _query(query, params)


def fetch_notifications(start, end, limit: int = 50):
    query = (
        "SELECT n.*, i.title FROM notifications n "
        "JOIN incidents i ON i.id = n.incident_id WHERE 1=1"
    )
    params: list = []
    if start:
        query += " AND n.created_at >= %s"
        params.append(start)
    if end:
        query += " AND n.created_at < %s"
        params.append(end)
    query += " ORDER BY n.id DESC LIMIT %s"
    params.append(limit)
    return _query(query, params)


def fetch_summary():
    row = _query("""
        SELECT
          COUNT(*) FILTER (WHERE state = 'open' AND NOT is_maintenance) AS open_count,
          COUNT(*) FILTER (WHERE state = 'open' AND is_maintenance
                           AND detected_at <= NOW()) AS maint_count,
          COUNT(*) FILTER (WHERE state = 'open' AND is_maintenance
                           AND detected_at > NOW()) AS scheduled_count,
          COUNT(*) AS total_count,
          COUNT(*) FILTER (WHERE ingested_at > NOW() - INTERVAL '24 hours'
                           AND NOT already_over) AS created_24h,
          COUNT(*) FILTER (WHERE ingested_at > NOW() - INTERVAL '30 days'
                           AND NOT already_over) AS created_30d,
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT provider) FILTER (
              WHERE state = 'open' AND NOT is_maintenance), NULL) AS open_providers
        FROM (
          -- Incidents that were already over when first seen (old entries
          -- still in a feed) were never news, so they don't count as new.
          SELECT *, COALESCE(resolved_at <= ingested_at, FALSE) AS already_over
            FROM incidents
        ) i
    """)[0]
    undelivered = _query(
        "SELECT channel, COUNT(*) AS n FROM notifications WHERE status = 'pending' "
        "OR (status = 'failed' AND created_at > NOW() - INTERVAL '24 hours') "
        "GROUP BY channel")
    last_poll = _query("SELECT * FROM poll_log ORDER BY polled_at DESC LIMIT 1")
    row["undelivered"] = sum(r["n"] for r in undelivered)
    row["undelivered_channels"] = [channel_label(r["channel"])
                                   for r in undelivered]
    row["open_providers"] = [PROVIDER_LABELS.get(p, p) for p in row["open_providers"] or []]
    row["last_poll"] = last_poll[0] if last_poll else None
    return row


def _feed_errors(last_poll) -> dict[str, str]:
    """poll_log.feed_errors is "Provider: reason; Provider: reason"."""
    errors = {}
    for part in ((last_poll or {}).get("feed_errors") or "").split("; "):
        provider, _, reason = part.partition(": ")
        if provider:
            errors[provider] = reason
    return errors


def fetch_providers(last_poll):
    """One card per watched provider: open incidents, maintenance, and
    whether its feed could be read on the last poll."""
    counts = {r["provider"]: r for r in _query("""
        SELECT provider,
               COUNT(*) FILTER (WHERE NOT is_maintenance) AS incidents,
               COUNT(*) FILTER (WHERE is_maintenance) AS maintenance
          FROM incidents WHERE state = 'open' GROUP BY provider
    """)}
    errors = _feed_errors(last_poll)
    cards, off = [], []
    for provider, regions in feeds.watched_regions().items():
        label = PROVIDER_LABELS.get(provider, provider)
        if not regions:
            off.append(label)
            continue
        c = counts.get(provider, {})
        if provider in errors:
            status, tone = f"Feed unreachable ({errors[provider]})", "bad"
        elif c.get("incidents"):
            n = c["incidents"]
            status, tone = f"{n} open incident{'s' if n != 1 else ''}", "warn"
        elif c.get("maintenance"):
            status, tone = "Maintenance", "info"
        else:
            status, tone = "Operational", "good"
        cards.append({"name": provider, "label": label, "regions": ", ".join(regions),
                      "status": status, "tone": tone})
    return cards, off


def fetch_channels():
    """Delivery health per channel over the last 24 hours."""
    rows = {r["channel"]: r for r in _query("""
        SELECT channel,
               MAX(sent_at) AS last_sent,
               COUNT(*) FILTER (WHERE status = 'sent'
                                AND sent_at > NOW() - INTERVAL '24 hours') AS sent_24h,
               COUNT(*) FILTER (WHERE status = 'pending') AS pending,
               COUNT(*) FILTER (WHERE status = 'failed'
                                AND created_at > NOW() - INTERVAL '24 hours') AS failed_24h,
               (ARRAY_AGG(last_error ORDER BY id DESC)
                  FILTER (WHERE last_error IS NOT NULL
                          AND status IN ('pending', 'failed')))[1] AS last_error,
               MIN(next_attempt_at) FILTER (WHERE status = 'pending'
                                            AND attempts > 0) AS next_try
          FROM notifications GROUP BY channel
    """)}
    channels = []
    for channel in dict.fromkeys(notifiers.enabled_channels() + list(rows)):
        r = rows.get(channel, {})
        if r.get("failed_24h"):
            status, tone = "Failed", "bad"
            detail = r.get("last_error") or f"{r['failed_24h']} failed in 24 h"
        elif r.get("next_try"):
            status, tone = "Retrying", "bad"
            detail = f"{r.get('last_error') or 'error'} · next try {r['next_try']:%H:%M}"
        elif r.get("last_sent"):
            status, tone = "Healthy", "good"
            detail = f"{r['sent_24h']} sent in 24 h · last {r['last_sent']:%d %b %H:%M}"
        else:
            status, tone, detail = "Idle", "muted", "nothing sent yet"
        if channel not in notifiers.enabled_channels():
            status, tone = "Not configured", "muted"
        channels.append({"channel": channel, "label": channel_label(channel),
                         "status": status, "tone": tone, "detail": detail})
    return channels


def fetch_poll_bars(limit: int = 24):
    rows = list(reversed(_query(
        "SELECT polled_at, entries_seen, error, feed_errors FROM poll_log "
        "ORDER BY polled_at DESC LIMIT %s", (limit,))))
    peak = max((r["entries_seen"] for r in rows), default=0) or 1
    for r in rows:
        r["height"] = 100 if r["error"] else max(6, round(100 * r["entries_seen"] / peak))
    errors = [r for r in rows if r["error"] or r["feed_errors"]]
    return rows, errors


def _duration(start, end) -> str:
    if not start:
        return "—"
    delta = (end or datetime.now(timezone.utc)) - start
    if delta.total_seconds() < 0:
        return "in " + _span(-delta)
    return _span(delta)


def _span(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {minutes:02d}m"
    return f"{hours // 24}d"


def _tickets(row) -> list[dict]:
    """Each ticket an incident has, as {label, url}: Zendesk's number, then
    ServiceNow's record."""
    tickets = []
    zendesk = os.getenv("ZENDESK_SUBDOMAIN", "")
    if row["ticket_id"]:
        tickets.append({
            "label": f"#{row['ticket_id']}",
            "url": (f"https://{zendesk}.zendesk.com/agent/tickets/{row['ticket_id']}"
                    if zendesk else None)})
    for t in row.get("other_tickets") or []:
        if t["system"] == "freshdesk":
            tickets.append({"label": t["number"] or f"#{t['ref']}",
                            "url": f"{notifiers.FRESHDESK_URL}/a/tickets/{t['ref']}" if notifiers.FRESHDESK_URL else None})
        if t["system"] == "jsm":
            tickets.append({"label": t["number"] or t["ref"],
                            "url": f"{notifiers.JSM_URL}/browse/{t['ref']}" if notifiers.JSM_URL else None})
        if t["system"] == "servicenow":
            tickets.append({
                "label": t["number"] or t["ref"][:8],
                "url": (f"{notifiers.SERVICENOW_URL}/{notifiers.SERVICENOW_TABLE}.do"
                        f"?sys_id={t['ref']}" if notifiers.SERVICENOW_URL else None)})
    return tickets


def _incident_kind(row, now) -> str:
    if row["state"] == "resolved":
        return "resolved"
    if row.get("is_maintenance"):
        return "scheduled" if row["detected_at"] > now else "maintenance"
    return "open"


@app.get("/")
def index():
    state = request.args.get("state", "open")
    provider = request.args.get("provider", "all")
    q = request.args.get("q", "").strip()
    range_key = request.args.get("range", "all")
    from_date = request.args.get("from", "").strip()
    to_date = request.args.get("to", "").strip()

    state = state if state in VALID_STATES else "open"
    provider = provider if provider in ("all", *feeds.PROVIDER_NAMES) else "all"
    range_key = range_key if range_key in VALID_RANGES else "all"
    start, end = compute_range(range_key, from_date, to_date)

    current = {
        "state": state, "provider": provider, "q": q,
        "range": range_key, "from": from_date, "to": to_date,
    }

    def link(**overrides):
        params = dict(current)
        if "date_from" in overrides:
            params["from"] = overrides.pop("date_from")
        if "date_to" in overrides:
            params["to"] = overrides.pop("date_to")
        params.update(overrides)
        params = {k: v for k, v in params.items() if v}
        return "/?" + urlencode(params)

    now = datetime.now(timezone.utc)
    summary = fetch_summary()
    providers, providers_off = fetch_providers(summary["last_poll"])
    incidents = fetch_incidents(state, provider, q, start, end)
    for row in incidents:
        row["kind"] = _incident_kind(row, now)
        row["duration"] = _duration(row["detected_at"], row["resolved_at"])
        row["provider_label"] = PROVIDER_LABELS.get(row["provider"], row["provider"])
        row["tickets"] = _tickets(row)
    bars, bar_errors = fetch_poll_bars()

    return render_template(
        "index.html",
        summary=summary,
        providers=providers,
        providers_off=providers_off,
        provider_options=[(p, PROVIDER_LABELS.get(p, p)) for p in feeds.PROVIDER_NAMES],
        channels=fetch_channels(),
        bars=bars,
        bar_errors=bar_errors,
        incidents=incidents,
        poll_log=fetch_poll_log(start, end),
        notifications=fetch_notifications(start, end),
        channel_label=channel_label,
        region_count=sum(len(p["regions"].split(", ")) for p in providers),
        poll_every=(f"{poll_interval() // 60} min" if poll_interval() % 60 == 0
                    else f"{poll_interval()} s"),
        state=state, provider=provider, q=q,
        range_key=range_key, range_labels=RANGE_LABELS, state_labels=STATE_LABELS,
        from_date=from_date, to_date=to_date,
        link=link, now=now,
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


app.config["CHANNEL_HEALTH"] = fetch_channels
app.register_blueprint(admin_bp)


def configure_app() -> None:
    problem = settings.secret_key_problem()
    if problem:
        sys.exit(problem)
    app.secret_key = settings.session_key()
    db.init_schema()


if __name__ == "__main__":
    # Flask's own server, for trying things out. Compose runs wsgi.py under
    # gunicorn instead.
    configure_app()
    port = int(os.getenv("DASHBOARD_PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
