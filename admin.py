"""
admin.py
~~~~~~~~
Sign-in, accounts and the settings pages of the dashboard.

Everyone signs in. Admins see and change everything; viewers see the
dashboard only. The first visit with no accounts asks for the setup code that
the dashboard prints to its log, so whoever reaches it first can't simply
claim the admin account.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlsplit

import psycopg2
from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template,
                   request, session, url_for)

import db
import notifiers
import settings

log = logging.getLogger("skyfarer.dashboard")

bp = Blueprint("admin", __name__)

OPEN_ENDPOINTS = {"admin.login", "admin.setup", "admin.welcome"}
ALWAYS_OPEN = {"static", "healthz"}

_setup_code: list[str] = []
_failures: dict[str, deque] = defaultdict(deque)
FAILURE_LIMIT = 5
FAILURE_WINDOW = 15 * 60
_bootstrapped: list[bool] = []


# ─── Guard: every request ───────────────────────────────────────────────────

def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


@bp.app_context_processor
def _template_globals():
    return {"csrf_token": csrf_token, "current_user": g.get("user")}


@bp.before_app_request
def guard():
    g.user = None
    if request.endpoint in ALWAYS_OPEN or request.endpoint is None:
        return None
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "The form has expired. Go back, reload the page and try again.")
    with db.get_conn() as conn:
        if not _bootstrapped:
            settings.bootstrap()
            _bootstrapped.append(True)
        settings.apply(conn)
        if settings.user_count(conn) == 0:
            if request.endpoint != "admin.setup":
                return redirect(url_for("admin.setup"))
            return None
        uid = session.get("uid")
        g.user = settings.user(conn, uid) if uid else None
    if request.endpoint in OPEN_ENDPOINTS:
        return None
    if g.user is None:
        session.pop("uid", None)
        return redirect(url_for("admin.login", next=_safe_next(request.full_path)))
    if request.blueprint == "admin" and g.user["role"] != "admin":
        abort(403)
    return None


def _safe_next(target: Optional[str]) -> str:
    if not target or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target.rstrip("?")


def _sign_in(user_id: int) -> None:
    csrf = session.get("csrf")
    session.clear()
    session.permanent = True
    session["uid"] = user_id
    if csrf:
        session["csrf"] = csrf


def _actor() -> str:
    return g.user["name"] if g.get("user") else "Skyfarer"


# ─── Signing in ─────────────────────────────────────────────────────────────

def _throttled(key: str) -> bool:
    now = time.monotonic()
    q = _failures[key]
    while q and now - q[0] > FAILURE_WINDOW:
        q.popleft()
    return len(q) >= FAILURE_LIMIT


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect("/")
    error = None
    email = request.form.get("email", "").strip()
    nxt = _safe_next(request.values.get("next"))
    if request.method == "POST":
        key = f"{request.remote_addr}|{email.lower()}"
        if _throttled(key):
            error = "Too many attempts. Wait 15 minutes, or ask an admin for a setup link."
        else:
            with db.get_conn() as conn:
                user = settings.check_login(conn, email, request.form.get("password", ""))
            if user:
                _failures.pop(key, None)
                _sign_in(user["id"])
                return redirect(nxt)
            _failures[key].append(time.monotonic())
            error = "That email and password don't match an account."
    return render_template("login.html", error=error, email=email, next=nxt)


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin.login"))


def _the_setup_code() -> str:
    if not _setup_code:
        code = "-".join(secrets.token_hex(3) for _ in range(3))
        _setup_code.append(code)
        log.warning("First run: no accounts yet. Open the dashboard and enter this "
                    "setup code to create the first admin: %s", code)
    return _setup_code[0]


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    with db.get_conn() as conn:
        if settings.user_count(conn):
            return redirect(url_for("admin.login"))
        summary = settings.imported_summary(conn)
    code = _the_setup_code()
    error = None
    form = request.form
    if request.method == "POST":
        problem = settings.password_problem(form.get("password", ""))
        if not secrets.compare_digest(form.get("code", "").strip().lower(), code):
            error = "That isn't the setup code. It's in the dashboard's log."
        elif not form.get("name", "").strip() or "@" not in form.get("email", ""):
            error = "Enter your name and email."
        elif problem:
            error = problem
        else:
            with db.get_conn() as conn:
                if settings.user_count(conn):
                    return redirect(url_for("admin.login"))
                new = settings.create_user(conn, form["email"], form["name"], "admin",
                                           "Skyfarer", password=form["password"])
            _setup_code.clear()
            _sign_in(new.user_id)
            flash("Your admin account is ready. These settings came from .env; "
                  "from now on, change them here.", "ok")
            return redirect(url_for("admin.providers"))
    return render_template("setup.html", error=error, summary=summary, form=form)


@bp.route("/welcome/<token>", methods=["GET", "POST"])
def welcome(token: str):
    with db.get_conn() as conn:
        person = settings.user_by_token(conn, token)
    if not person:
        return render_template("welcome.html", expired=True, person=None, error=None), 404
    error = None
    if request.method == "POST":
        error = settings.password_problem(request.form.get("password", ""),
                                          request.form.get("confirm", ""))
        if not error:
            with db.get_conn() as conn:
                settings.set_password(conn, person["id"], request.form["password"])
                settings.history_add(conn, person["name"], "Set a password from a setup link")
            _sign_in(person["id"])
            return redirect("/")
    return render_template("welcome.html", expired=False, person=person, error=error)


# ─── Settings: providers ────────────────────────────────────────────────────

def effective(values: dict, key: str) -> str:
    """A setting's value, or its default when nothing is stored."""
    if key in values:
        return values[key]
    if key.endswith("_ENABLED"):
        return "true"
    f = settings.FIELDS.get(key)
    return f.default if f else ""


def _changes(values: dict, proposed: dict) -> dict:
    return {k: v for k, v in proposed.items() if v is None or v != effective(values, k)}


def _next_poll(conn) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT MAX(polled_at) FROM poll_log")
        last = cur.fetchone()[0]
    try:
        interval = int(effective(settings.load(conn), "POLL_INTERVAL_SECONDS"))
    except ValueError:
        interval = 300
    if not last:
        return "from its next poll"
    nxt = last + timedelta(seconds=interval)
    if nxt < datetime.now(timezone.utc):
        return "from its next poll"
    return f"from its next poll, at {nxt:%H:%M} UTC"


def _saved_message(conn, lines: list[str]) -> None:
    if not lines:
        flash("Nothing changed.", "info")
        return
    flash(f"Saved {len(lines)} change{'s' if len(lines) != 1 else ''}. "
          f"The poller uses {'it' if len(lines) == 1 else 'them'} {_next_poll(conn)}.", "ok")


@bp.get("/settings")
def settings_home():
    return redirect(url_for("admin.providers"))


@bp.route("/settings/providers", methods=["GET", "POST"])
def providers():
    with db.get_conn() as conn:
        values = settings.load(conn)
        if request.method == "POST":
            form = request.form
            proposed = {}
            for p in settings.PROVIDERS:
                proposed[p.enabled_key] = "true" if form.get(p.enabled_key) else "false"
                proposed[p.key] = settings.join_list(settings.split_list(form.get(p.key, "")))
            proposed["FILTER_KEYWORDS"] = settings.join_list(
                settings.split_list(form.get("FILTER_KEYWORDS", "")))
            interval = form.get("POLL_INTERVAL_SECONDS", "")
            if interval in dict(settings.FIELDS["POLL_INTERVAL_SECONDS"].options) or \
                    interval == effective(values, "POLL_INTERVAL_SECONDS"):
                proposed["POLL_INTERVAL_SECONDS"] = interval
            lines = settings.save(conn, _changes(values, proposed), _actor())
            _saved_message(conn, lines)
            return redirect(url_for("admin.providers"))

        with conn.cursor() as cur:
            cur.execute("SELECT polled_at, feed_errors FROM poll_log ORDER BY polled_at DESC LIMIT 1")
            last = cur.fetchone()
    feed_errors = {}
    for part in ((last[1] if last else "") or "").split("; "):
        name, _, reason = part.partition(": ")
        if name:
            feed_errors[name] = reason
    cards = []
    for p in settings.PROVIDERS:
        regions = settings.split_list(values.get(p.key, ""))
        on = effective(values, p.enabled_key) == "true"
        if not on:
            health, tone = "Off", "muted"
        elif not regions:
            health, tone = "No regions", "warn"
        elif p.name in feed_errors:
            health, tone = "Feed error", "bad"
        elif last:
            health, tone = "Feed OK", "good"
        else:
            health, tone = "Not read yet", "muted"
        cards.append({"p": p, "on": on, "regions": regions, "health": health, "tone": tone,
                      "error": feed_errors.get(p.name, ""),
                      "suggestions": [s for s in p.suggestions if s not in regions]})
    current_interval = effective(values, "POLL_INTERVAL_SECONDS")
    options = list(settings.FIELDS["POLL_INTERVAL_SECONDS"].options)
    if current_interval not in dict(options):
        options.insert(0, (current_interval, f"{current_interval} seconds"))
    return render_template("settings_providers.html", cards=cards,
                           keywords=settings.split_list(values.get("FILTER_KEYWORDS", "")),
                           interval=current_interval, interval_options=options,
                           last_poll=last[0] if last else None)


# ─── Settings: channels and webhooks ────────────────────────────────────────

def _channel_summary(cid: str, values: dict) -> str:
    v = lambda k: values.get(k, "")  # noqa: E731
    if cid == "zendesk" and v("ZENDESK_SUBDOMAIN"):
        return f"{v('ZENDESK_SUBDOMAIN')}.zendesk.com · as {v('ZENDESK_EMAIL') or 'nobody yet'}"
    if cid == "servicenow" and v("SERVICENOW_INSTANCE"):
        host = urlsplit(notifiers.servicenow_url(v("SERVICENOW_INSTANCE"))).netloc
        auth = "OAuth token" if v("SERVICENOW_TOKEN") else "user and password"
        return f"{host} · {auth}"
    if cid == "jsm" and v("JSM_SITE"):
        host = urlsplit(notifiers.jsm_url(v("JSM_SITE"))).netloc
        return f"{host} · project {v('JSM_PROJECT') or 'not set'}"
    if cid == "freshdesk" and v("FRESHDESK_DOMAIN"):
        host = urlsplit(notifiers.freshdesk_url(v("FRESHDESK_DOMAIN"))).netloc
        return f"{host} · from {v('FRESHDESK_REQUESTER_EMAIL') or 'nobody yet'}"
    if cid == "pushover" and v("PUSHOVER_USER"):
        return f"priority {effective(values, 'PUSHOVER_PRIORITY')} for new incidents"
    if cid == "pagerduty" and v("PAGERDUTY_ROUTING_KEY"):
        return f"Events API v2 · severity {effective(values, 'PAGERDUTY_SEVERITY')}"
    if cid == "teams" and v("TEAMS_WEBHOOK_URL"):
        return "Workflows webhook"
    if cid == "snmp" and v("SNMP_TRAP_TARGETS"):
        n = len(settings.split_list(v("SNMP_TRAP_TARGETS")))
        return f"v2c traps to {n} receiver{'s' if n != 1 else ''}"
    return "Not set up yet"


def _health() -> dict:
    return {c["channel"]: c for c in current_app.config["CHANNEL_HEALTH"]()}


@bp.get("/settings/channels")
def channels(submitted: Optional[dict] = None, open_id: Optional[str] = None,
             errors: Optional[list] = None):
    open_id = open_id or request.args.get("open", "")
    unreadable: set = set()
    with db.get_conn() as conn:
        values = settings.load(conn, unreadable)
        meta = settings.secret_meta(conn)
        hooks = settings.webhooks(conn, values, unreadable=unreadable)
    health = _health()
    enabled = set(notifiers.enabled_channels())

    def status(channel_id: str, on: bool, configured: bool, started: bool = True) -> dict:
        if not on:
            return {"status": "Off", "tone": "muted", "detail": ""}
        if not started:
            return {"status": "Not set up", "tone": "muted", "detail": ""}
        if not configured:
            return {"status": "Incomplete", "tone": "warn", "detail": ""}
        h = health.get(channel_id) or {}
        return {"status": h.get("status", "Idle"), "tone": h.get("tone", "muted"),
                "detail": h.get("detail", "")}

    def stored(key: str) -> Optional[str]:
        m = meta.get(key)
        if not m:
            return None
        if key in unreadable:
            return "can't be read: SKYFARER_SECRET_KEY has changed since it was set. Enter it again"
        return f"set {m['updated_at']:%d %b %Y} by {m['updated_by'] or 'Skyfarer'}"

    groups = []
    for group, title, blurb in (
            ("tickets", "Tickets", "One ticket per incident, updated as the provider posts, "
                                   "and closed or resolved when it ends."),
            ("alerts", "Alerts", "Messages to people and systems, filtered by the alert rules above.")):
        cards = []
        for c in settings.CHANNELS:
            if c.group != group:
                continue
            on = effective(values, c.enabled_key) == "true"
            sub = (submitted or {}).get(c.id)
            fields = []
            for f in c.fields:
                value = sub.get(f.key, "") if sub is not None and f.kind != "secret" else \
                    effective(values, f.key)
                if f.kind == "list":
                    value = ", ".join(settings.split_list(value))
                fields.append({"f": f, "value": value, "stored": stored(f.key) if f.kind == "secret" else None,
                               "bad": f.key in unreadable,
                               "checked": (sub.get(f.key) if sub is not None else value == "true")})
            cards.append({"id": c.id, "name": c.name, "on": on, "fields": fields,
                          "summary": _channel_summary(c.id, values),
                          **status(c.id, on, c.id in enabled,
                                   any(f.key in values for f in c.fields
                                       if f.default == "" and f.kind != "bool"))})
        groups.append({"id": group, "title": title, "blurb": blurb, "cards": cards})

    hook_cards = []
    for w in hooks:
        h = w["hook"]
        sub = (submitted or {}).get(h.channel)
        src = sub if sub is not None else None
        url = urlsplit(h.url)
        hook_cards.append({
            "id": w["id"], "channel": h.channel, "on": w["enabled"],
            "name": src.get("name", "") if src else h.name,
            "url": src.get("url", "") if src else h.url,
            "method": src.get("method", "") if src else h.method,
            "events": src.getlist("events") if src else h.events,
            "template": src.get("template", "") if src else h.template,
            "content_type": src.get("content_type", "") if src else h.content_type,
            "headers_stored": stored(settings.webhook_secret_key(w["id"], "headers")),
            "secret_stored": stored(settings.webhook_secret_key(w["id"], "secret")),
            "headers_bad": settings.webhook_secret_key(w["id"], "headers") in unreadable,
            "secret_bad": settings.webhook_secret_key(w["id"], "secret") in unreadable,
            "summary": f"{h.method} to {url.netloc or h.url}"
                       + (" · " + ", ".join(h.events) if h.events else " · follows the alert rules")
                       + (" · signed" if h.secret else ""),
            **status(h.channel, w["enabled"], h.channel in enabled)})
        if w["unreadable"] and w["enabled"]:
            hook_cards[-1].update(status="Secret unreadable", tone="bad")

    rules = {"events": settings.split_list(effective(values, "NOTIFY_EVENTS")),
             "max_age": effective(values, "NOTIFY_MAX_AGE_HOURS"),
             "retry": effective(values, "NOTIFY_RETRY_HOURS"),
             "maintenance": effective(values, "NOTIFY_MAINTENANCE") == "true"}
    return render_template("settings_channels.html", groups=groups, hooks=hook_cards, rules=rules,
                           open_id=open_id, errors=errors or [], new_hook=(submitted or {}).get("new"),
                           fields_known=", ".join(notifiers.WEBHOOK_FIELDS),
                           events=notifiers.EVENTS)


@bp.post("/settings/rules")
def rules():
    form = request.form
    events = [e for e in notifiers.EVENTS if e in form.getlist("events")]
    proposed = {"NOTIFY_EVENTS": ",".join(events),
                "NOTIFY_MAINTENANCE": "true" if form.get("NOTIFY_MAINTENANCE") else "false"}
    errors = []
    for key in ("NOTIFY_MAX_AGE_HOURS", "NOTIFY_RETRY_HOURS"):
        raw = form.get(key, "").strip()
        try:
            if float(raw) < 0:
                raise ValueError
            proposed[key] = raw
        except ValueError:
            errors.append(f"{settings.FIELDS[key].label} must be a number of hours.")
    if errors:
        return channels(errors=errors)
    with db.get_conn() as conn:
        values = settings.load(conn)
        _saved_message(conn, settings.save(conn, _changes(values, proposed), _actor()))
    return redirect(url_for("admin.channels"))


def _channel_or_404(cid: str) -> settings.Channel:
    c = settings.CHANNEL_BY_ID.get(cid)
    if not c:
        abort(404)
    return c


@bp.post("/settings/channels/<cid>")
def channel_save(cid: str):
    c = _channel_or_404(cid)
    form = request.form
    proposed: dict = {}
    for f in c.fields:
        if f.kind == "secret":
            if form.get(f"remove_{f.key}"):
                proposed[f.key] = None
            elif form.get(f.key, "").strip():
                proposed[f.key] = form[f.key].strip()
        elif f.kind == "bool":
            proposed[f.key] = "true" if form.get(f.key) else "false"
        elif f.kind == "list":
            proposed[f.key] = settings.join_list(settings.split_list(form.get(f.key, "")))
        elif f.kind == "select":
            value = form.get(f.key, "")
            if value in dict(f.options):
                proposed[f.key] = value
        else:
            proposed[f.key] = form.get(f.key, "").strip()
    with db.get_conn() as conn:
        values = settings.load(conn)
        changes = _changes(values, proposed)
        before = set(settings.check(conn, {}))
        new_errors = [e for e in settings.check(conn, changes) if e not in before]
        if new_errors:
            conn.rollback()
            return channels(submitted={cid: form}, open_id=cid, errors=new_errors)
        _saved_message(conn, settings.save(conn, changes, _actor()))
    return redirect(url_for("admin.channels", open=cid) + f"#ch-{cid}")


@bp.post("/settings/channels/<cid>/toggle")
def channel_toggle(cid: str):
    c = _channel_or_404(cid)
    with db.get_conn() as conn:
        values = settings.load(conn)
        on = effective(values, c.enabled_key) == "true"
        settings.save(conn, {c.enabled_key: "false" if on else "true"}, _actor())
        flash(f"{c.name} switched {'off' if on else 'on'}. The poller uses this {_next_poll(conn)}.", "ok")
    return redirect(url_for("admin.channels") + f"#ch-{cid}")


def _test_row(channel: str) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return {"id": 0, "incident_id": 0, "event": "opened", "channel": channel,
            "ticket_id": None, "ticket_ref": None, "payload": {
                "provider": "Skyfarer", "region": "test", "title": "Test from Skyfarer: please ignore",
                "summary": f"Sent by {_actor()} from Settings > Channels, to check this channel works.",
                "link": request.url_root.rstrip("/") + url_for("admin.channels"),
                "published": now, "updated": now, "noticed": now, "update_count": 0}}


def run_test(channel: str) -> tuple[bool, str]:
    """Send a test through a channel with its saved settings."""
    if channel not in notifiers.enabled_channels():
        return False, "Switch it on and fill in its settings, then save, before testing."
    sender = notifiers.sender_for(channel)
    row = _test_row(channel)
    started = time.monotonic()
    try:
        result = sender(row)
        if channel == "zendesk":
            sender({**row, "event": "resolved", "ticket_id": result})
            message = f"Test ticket #{result} opened and set to pending. Close it in Zendesk when you've seen it."
        elif channel == "servicenow":
            sender({**row, "event": "resolved", "ticket_ref": result["ref"]})
            message = (f"Test record {result['number'] or result['ref']} created and "
                       + ("resolved." if notifiers.SERVICENOW_RESOLVE else "given a closing note."))
        elif channel == "jsm":
            sender({**row, "event": "resolved", "ticket_ref": result["ref"]})
            message = (f"Test request {result['number']} created and "
                       + (f"resolved with “{notifiers.JSM_TRANSITION}”." if notifiers.JSM_RESOLVE
                          else "given a closing comment."))
        elif channel == "freshdesk":
            sender({**row, "event": "resolved", "ticket_ref": result["ref"]})
            status = notifiers.FRESHDESK_STATUSES.get(notifiers.FRESHDESK_RESOLVED_STATUS, "")
            message = (f"Test ticket {result['number']} created and "
                       + (f"set to {status}." if notifiers.FRESHDESK_RESOLVE else "given a closing note."))
        elif channel == "pagerduty":
            sender({**row, "event": "resolved"})
            message = "Test alert triggered and resolved again."
        elif channel == "snmp":
            n = len(notifiers.SNMP_TRAP_TARGETS)
            message = (f"Test trap sent to {n} receiver{'s' if n != 1 else ''}. Traps get no reply, "
                       "so check that your receiver logged it.")
        elif channel.startswith("webhook-"):
            message = "The receiver accepted a test “opened” request."
        else:
            message = "Test sent and accepted."
    except (notifiers.PermanentFailure, notifiers.RetryLater) as exc:
        return False, f"The test failed: {exc}."
    except Exception as exc:  # a bad setting can fail in many ways
        log.warning("Test of %s failed: %r", channel, exc)
        return False, f"The test failed: {type(exc).__name__}."
    elapsed = time.monotonic() - started
    took = f"{elapsed * 1000:.0f} ms" if elapsed < 1 else f"{elapsed:.1f} s"
    return True, f"{message} ({took})"


@bp.post("/settings/channels/<cid>/test")
def channel_test(cid: str):
    _channel_or_404(cid)
    ok, message = run_test(cid)
    flash(message, f"test:{cid}:{'ok' if ok else 'bad'}")
    return redirect(url_for("admin.channels", open=cid) + f"#ch-{cid}")


def _hook_form(form, hook_id: Optional[int], existing: Optional[notifiers.Webhook]):
    data = {"name": form.get("name", "").strip() or "Webhook",
            "url": form.get("url", "").strip(),
            "method": form.get("method", "POST").upper(),
            "events": ",".join(e for e in notifiers.EVENTS if e in form.getlist("events")),
            "template": form.get("template", "").strip(),
            "content_type": form.get("content_type", "").strip() or "application/json",
            "headers": form.get("headers", "").strip(),
            "secret": form.get("secret", "").strip(),
            "remove_headers": bool(form.get("remove_headers")),
            "remove_secret": bool(form.get("remove_secret"))}
    trial = notifiers.Webhook(
        id=hook_id or 0, name=data["name"], url=data["url"], method=data["method"],
        headers="" if data["remove_headers"] else (data["headers"] or (existing.headers if existing else "")),
        template=data["template"], content_type=data["content_type"],
        secret=data["secret"] or (existing.secret if existing else ""),
        events=settings.split_list(data["events"]))
    return data, notifiers.webhook_errors(trial)


@bp.post("/settings/webhooks/new")
def webhook_new():
    data, errors = _hook_form(request.form, None, None)
    if errors:
        return channels(submitted={"new": request.form}, open_id="new", errors=errors)
    with db.get_conn() as conn:
        hook_id = settings.webhook_save(conn, None, data, _actor())
        flash(f"Webhook {data['name']!r} added. The poller uses it {_next_poll(conn)}.", "ok")
    return redirect(url_for("admin.channels", open=f"webhook-{hook_id}") + f"#ch-webhook-{hook_id}")


def _hook_or_404(conn, hook_id: int) -> dict:
    for w in settings.webhooks(conn):
        if w["id"] == hook_id:
            return w
    abort(404)


@bp.post("/settings/webhooks/<int:hook_id>")
def webhook_save(hook_id: int):
    with db.get_conn() as conn:
        w = _hook_or_404(conn, hook_id)
        data, errors = _hook_form(request.form, hook_id, w["hook"])
        if errors:
            return channels(submitted={f"webhook-{hook_id}": request.form},
                            open_id=f"webhook-{hook_id}", errors=errors)
        settings.webhook_save(conn, hook_id, data, _actor())
        flash(f"Webhook {data['name']!r} saved. The poller uses it {_next_poll(conn)}.", "ok")
    return redirect(url_for("admin.channels", open=f"webhook-{hook_id}") + f"#ch-webhook-{hook_id}")


@bp.post("/settings/webhooks/<int:hook_id>/toggle")
def webhook_toggle(hook_id: int):
    with db.get_conn() as conn:
        w = _hook_or_404(conn, hook_id)
        settings.webhook_enable(conn, hook_id, not w["enabled"], _actor())
        flash(f"Webhook {w['name']!r} switched {'off' if w['enabled'] else 'on'}.", "ok")
    return redirect(url_for("admin.channels") + f"#ch-webhook-{hook_id}")


@bp.post("/settings/webhooks/<int:hook_id>/delete")
def webhook_delete(hook_id: int):
    with db.get_conn() as conn:
        w = _hook_or_404(conn, hook_id)
        settings.webhook_delete(conn, hook_id, _actor())
        flash(f"Webhook {w['name']!r} deleted. Notices already queued for it won't be sent.", "ok")
    return redirect(url_for("admin.channels"))


@bp.post("/settings/webhooks/<int:hook_id>/test")
def webhook_test(hook_id: int):
    with db.get_conn() as conn:
        _hook_or_404(conn, hook_id)
    channel = f"webhook-{hook_id}"
    ok, message = run_test(channel)
    flash(message, f"test:{channel}:{'ok' if ok else 'bad'}")
    return redirect(url_for("admin.channels", open=channel) + f"#ch-{channel}")


# ─── Settings: users ────────────────────────────────────────────────────────

def _link(token: str) -> str:
    return request.url_root.rstrip("/") + url_for("admin.welcome", token=token)


@bp.get("/settings/users")
def users(new_link: Optional[dict] = None, error: Optional[str] = None, adding: bool = False,
          form: Optional[dict] = None):
    with db.get_conn() as conn:
        people = settings.users(conn)
        history = settings.history(conn)
    now = datetime.now(timezone.utc)
    for p in people:
        if p["active"]:
            p["last"] = f"{p['last_login']:%d %b %Y %H:%M}" if p["last_login"] else "Never"
        elif p["setup_expires"] and p["setup_expires"] > now:
            hours = max(1, int((p["setup_expires"] - now).total_seconds() // 3600))
            p["last"] = f"Not yet: setup link expires in {hours} h"
        else:
            p["last"] = "Not yet: setup link expired"
    return render_template("settings_users.html", people=people, history=history,
                           new_link=new_link, error=error,
                           adding=adding or request.args.get("add") == "1", form=form or {})


@bp.post("/settings/users/new")
def user_new():
    form = request.form
    name, email, role = form.get("name", "").strip(), form.get("email", "").strip(), form.get("role")
    if not name or "@" not in email or role not in settings.ROLES:
        return users(error="Enter a name, an email and a role.", adding=True, form=form)
    with db.get_conn() as conn:
        try:
            new = settings.create_user(conn, email, name, role, _actor())
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            return users(error=f"There's already an account for {email}.", adding=True, form=form)
    return users(new_link={"name": name, "role": role, "url": _link(new.token)})


@bp.post("/settings/users/<int:user_id>/role")
def user_role(user_id: int):
    if user_id == g.user["id"]:
        return users(error="You can't change your own role. Ask another admin.")
    with db.get_conn() as conn:
        problem = settings.set_role(conn, user_id, request.form.get("role", ""), _actor())
    if problem:
        return users(error=problem)
    flash("Role changed.", "ok")
    return redirect(url_for("admin.users"))


@bp.post("/settings/users/<int:user_id>/link")
def user_link(user_id: int):
    with db.get_conn() as conn:
        person = settings.user(conn, user_id)
        if not person:
            abort(404)
        new = settings.new_setup_link(conn, user_id, _actor())
    return users(new_link={"name": person["name"], "role": person["role"], "url": _link(new.token)})


@bp.post("/settings/users/<int:user_id>/delete")
def user_delete(user_id: int):
    if user_id == g.user["id"]:
        return users(error="You can't remove your own account.")
    with db.get_conn() as conn:
        problem = settings.delete_user(conn, user_id, _actor())
    if problem:
        return users(error=problem)
    flash("Account removed. They're signed out on their next click.", "ok")
    return redirect(url_for("admin.users"))
