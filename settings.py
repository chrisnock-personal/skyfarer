"""
settings.py
~~~~~~~~~~~
Settings, users and the change history, kept in Postgres and edited in the
dashboard.

On the first start with an empty database, the settings found in .env are
imported once; from then on the database is what counts. Only the database
connection, the dashboard's address and SKYFARER_SECRET_KEY stay in .env.

Settings keep the names they have in .env (AWS_REGIONS, ZENDESK_API_TOKEN, ...).
apply() puts the stored values into the environment and has feeds and notifiers
read them again, so the poller picks up a change at its next poll. Secrets are
encrypted with a key derived from SKYFARER_SECRET_KEY and never shown again
once saved. Webhooks live in a table of their own, as there can be any number.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from psycopg2.extras import RealDictCursor

import db
import feeds
import notifiers

log = logging.getLogger("skyfarer.settings")

SETUP_LINK_HOURS = 24
MIN_PASSWORD = 12


# ─── What can be set ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Field:
    key: str
    label: str
    kind: str = "text"     # text | list | select | secret | bool | json | number | events | template
    help: str = ""
    options: tuple = ()    # (value, label) pairs for select
    default: str = ""
    wide: bool = False


@dataclass(frozen=True)
class Provider:
    name: str              # as feeds.watched_regions() names it
    label: str
    key: str               # its regions setting
    about: str
    suggestions: tuple = ()

    @property
    def enabled_key(self) -> str:
        return self.key.replace("_REGIONS", "_ENABLED")


@dataclass(frozen=True)
class Channel:
    id: str
    name: str
    group: str             # tickets | alerts
    fields: tuple

    @property
    def enabled_key(self) -> str:
        return f"{self.id.upper()}_ENABLED"


PROVIDERS = (
    Provider("AWS", "AWS", "AWS_REGIONS", "One RSS feed per region, by region code",
             ("eu-west-1", "eu-west-2", "eu-central-1", "us-east-1", "us-west-2", "ap-southeast-1")),
    Provider("Azure", "Azure", "AZURE_REGIONS", "Azure status RSS. Names match exactly",
             ("UK South", "UK West", "West Europe", "North Europe", "East US", "Multiple Regions")),
    Provider("GCP", "Google Cloud", "GCP_REGIONS", "incidents.json, by region code",
             ("europe-west1", "europe-west2", "us-central1", "us-east1", "global")),
    Provider("OVH", "OVHcloud", "OVH_REGIONS", "Public Cloud status RSS, by datacentre code",
             ("GRA", "SBG", "RBX", "BHS", "WAW", "UK1", "DE1")),
    Provider("DigitalOcean", "DigitalOcean", "DIGITALOCEAN_REGIONS", "status.digitalocean.com, by datacentre",
             ("LON1", "AMS3", "FRA1", "NYC1", "NYC3", "SFO3", "SGP1", "TOR1", "Global")),
    Provider("Linode", "Linode", "LINODE_REGIONS", "status.linode.com, by component name",
             ("GB-LON", "Linode.com")),
    Provider("Cloudflare", "Cloudflare", "CLOUDFLARE_REGIONS", "cloudflarestatus.com, by airport code",
             ("LHR", "MAN", "AMS", "FRA", "CDG", "IAD")),
    Provider("Scaleway", "Scaleway", "SCALEWAY_REGIONS", "status.scaleway.com, by region",
             ("fr-par", "nl-ams", "pl-waw")),
    Provider("Hetzner", "Hetzner", "HETZNER_REGIONS", "status.hetzner.com Atom feed, by location",
             ("FSN1", "NBG1", "HEL1", "ASH", "HIL", "SIN", "Network")),
)

GENERAL = (
    Field("FILTER_KEYWORDS", "Keywords", "list"),
    Field("POLL_INTERVAL_SECONDS", "Poll every", "select",
          options=(("60", "1 minute"), ("120", "2 minutes"), ("300", "5 minutes"),
                   ("600", "10 minutes"), ("900", "15 minutes")), default="300"),
)

RULES = (
    Field("NOTIFY_EVENTS", "Send when an incident", "events", default="opened,resolved"),
    Field("NOTIFY_MAX_AGE_HOURS", "Skip events older than (hours)", "number", default="24",
          help="So a first start doesn't page anyone about last week."),
    Field("NOTIFY_RETRY_HOURS", "Keep retrying a failed notice for (hours)", "number", default="24"),
    Field("NOTIFY_MAINTENANCE", "Alert on planned maintenance too", "bool", default="false"),
)

_LEVELS = (("1", "1 - High"), ("2", "2 - Medium"), ("3", "3 - Low"))

CHANNELS = (
    Channel("zendesk", "Zendesk", "tickets", (
        Field("ZENDESK_SUBDOMAIN", "Subdomain", help="The part before .zendesk.com."),
        Field("ZENDESK_EMAIL", "Agent email"),
        Field("ZENDESK_API_TOKEN", "API token", "secret"),
        Field("ZD_TICKET_PRIORITY", "Priority", "select", default="high",
              options=(("low", "Low"), ("normal", "Normal"), ("high", "High"), ("urgent", "Urgent"))),
        Field("ZD_TICKET_GROUP_ID", "Group ID", help="Optional. A number from Zendesk's group settings."),
        Field("ZD_TICKET_TAGS", "Tags", "list", default="skyfarer,auto-raised"),
    )),
    Channel("servicenow", "ServiceNow", "tickets", (
        Field("SERVICENOW_INSTANCE", "Instance", help="The part before .service-now.com, or the full URL."),
        Field("SERVICENOW_USER", "User", help="An integration user. Leave empty when using a token."),
        Field("SERVICENOW_PASSWORD", "Password", "secret"),
        Field("SERVICENOW_TOKEN", "OAuth token", "secret", help="Instead of a user and password."),
        Field("SERVICENOW_IMPACT", "Impact", "select", options=_LEVELS, default="2"),
        Field("SERVICENOW_URGENCY", "Urgency", "select", options=_LEVELS, default="2"),
        Field("SERVICENOW_ASSIGNMENT_GROUP", "Assignment group"),
        Field("SERVICENOW_CALLER", "Caller"),
        Field("SERVICENOW_CATEGORY", "Category"),
        Field("SERVICENOW_RESOLVE", "Resolve the record when the incident ends", "bool", default="true"),
        Field("SERVICENOW_CLOSE_CODE", "Close code", default="Resolved by caller",
              help="Must be one your instance accepts."),
        Field("SERVICENOW_RESOLVED_STATE", "Resolved state", default="6"),
        Field("SERVICENOW_TABLE", "Table", default="incident"),
        Field("SERVICENOW_EXTRA_FIELDS", "Extra fields (JSON)", "json", wide=True,
              help='Added to every new record, such as {"u_source": "Skyfarer"}.'),
    )),
    Channel("jsm", "Jira Service Management", "tickets", (
        Field("JSM_SITE", "Site", help="The part before .atlassian.net, or the full URL."),
        Field("JSM_EMAIL", "Account email", help="The Atlassian account the API token belongs to: an agent on the service desk."),
        Field("JSM_API_TOKEN", "API token", "secret", help="From id.atlassian.com, under Security."),
        Field("JSM_PROJECT", "Project key", help="The service project's key, such as ITSM."),
        Field("JSM_REQUEST_TYPE", "Request type", help="Its name, such as Report a system problem. Empty: the project's first."),
        Field("JSM_RESOLVE", "Resolve the request when the incident ends", "bool", default="true"),
        Field("JSM_TRANSITION", "Resolve with the transition", default="Resolve",
              help="Its name or ID in your workflow. Part of a name will do."),
        Field("JSM_EXTRA_FIELDS", "Extra fields (JSON)", "json", wide=True,
              help='Added to every new request, such as {"priority": {"name": "High"}}.'),
    )),
    Channel("freshdesk", "Freshdesk", "tickets", (
        Field("FRESHDESK_DOMAIN", "Helpdesk", help="The part before .freshdesk.com, or the full URL."),
        Field("FRESHDESK_API_KEY", "API key", "secret", help="An agent's key, from their profile settings."),
        Field("FRESHDESK_REQUESTER_EMAIL", "Requester email",
              help="Who tickets come from, such as skyfarer@yourcompany.com. Freshdesk adds them as a contact."),
        Field("FRESHDESK_PRIORITY", "Priority", "select", default="2",
              options=(("1", "Low"), ("2", "Medium"), ("3", "High"), ("4", "Urgent"))),
        Field("FRESHDESK_GROUP_ID", "Group ID", help="Optional. A number from Admin > Groups."),
        Field("FRESHDESK_TAGS", "Tags", "list", default="skyfarer,auto-raised"),
        Field("FRESHDESK_RESOLVE", "Change the status when the incident ends", "bool", default="true"),
        Field("FRESHDESK_RESOLVED_STATUS", "Status when it ends", "select", default="4",
              options=(("4", "Resolved"), ("5", "Closed"))),
        Field("FRESHDESK_EXTRA_FIELDS", "Extra fields (JSON)", "json", wide=True,
              help='Added to every new ticket, such as {"type": "Incident"}.'),
    )),
    Channel("pushover", "Pushover", "alerts", (
        Field("PUSHOVER_TOKEN", "Application token", "secret"),
        Field("PUSHOVER_USER", "User or group key", "secret"),
        Field("PUSHOVER_PRIORITY", "Priority for new incidents", "select", default="0",
              options=(("-2", "-2 lowest"), ("-1", "-1 quiet"), ("0", "0 normal"),
                       ("1", "1 high"), ("2", "2 emergency"))),
    )),
    Channel("pagerduty", "PagerDuty", "alerts", (
        Field("PAGERDUTY_ROUTING_KEY", "Routing key", "secret",
              help="An Events API v2 integration key."),
        Field("PAGERDUTY_SEVERITY", "Severity", "select", default="error",
              options=tuple((s, s) for s in notifiers.PAGERDUTY_SEVERITIES)),
    )),
    Channel("teams", "Microsoft Teams", "alerts", (
        Field("TEAMS_WEBHOOK_URL", "Workflow URL", "secret",
              help="The URL carries its own key, so it is stored like a password."),
    )),
    Channel("snmp", "SNMP traps", "alerts", (
        Field("SNMP_TRAP_TARGETS", "Receivers", "list", help="host or host:port, comma-separated."),
        Field("SNMP_COMMUNITY", "Community", "secret"),
        Field("SNMP_BASE_OID", "Base OID", default="1.3.6.1.3.77701",
              help="Change SKYFARER-MIB.txt to match if you change this."),
    )),
)

CHANNEL_BY_ID = {c.id: c for c in CHANNELS}
FIELDS = {f.key: f for f in GENERAL + RULES + tuple(f for c in CHANNELS for f in c.fields)}

# Every key apply() manages in the environment.
MANAGED = (tuple(p.key for p in PROVIDERS) + tuple(p.enabled_key for p in PROVIDERS)
           + tuple(FIELDS) + tuple(c.enabled_key for c in CHANNELS))

# The single webhook .env can describe, imported as the first webhook.
ENV_WEBHOOK_KEYS = ("WEBHOOK_URL", "WEBHOOK_NAME", "WEBHOOK_METHOD", "WEBHOOK_HEADERS",
                    "WEBHOOK_TEMPLATE", "WEBHOOK_CONTENT_TYPE", "WEBHOOK_SECRET", "WEBHOOK_EVENTS")


def label(key: str) -> str:
    """How the change history names a setting."""
    for p in PROVIDERS:
        if key == p.key:
            return f"{p.label} regions"
        if key == p.enabled_key:
            return p.label
    for c in CHANNELS:
        if key == c.enabled_key:
            return c.name
        for f in c.fields:
            if f.key == key:
                return f"{c.name}: {f.label[0].lower() + f.label[1:]}"
    if key in FIELDS:
        return FIELDS[key].label
    if key.startswith("WEBHOOK_"):
        part = key.split("_", 2)[2]
        return "Webhook: " + {"SECRET": "signing secret", "HEADERS": "extra headers"}.get(part, part.lower())
    return key


def is_secret(key: str) -> bool:
    if key in FIELDS:
        return FIELDS[key].kind == "secret"
    return key.startswith("WEBHOOK_") and key.endswith(("_HEADERS", "_SECRET"))


def webhook_secret_key(hook_id: int, part: str) -> str:
    """Where a webhook's headers or signing secret are kept: in the settings
    table, so they're encrypted and dated like every other secret."""
    return f"WEBHOOK_{hook_id}_{part.upper()}"


def split_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def join_list(values) -> str:
    seen = []
    for v in values:
        v = v.strip()
        if v and v not in seen:
            seen.append(v)
    return ",".join(seen)


# ─── Encryption ─────────────────────────────────────────────────────────────

class SettingsError(Exception):
    pass


def secret_key_problem() -> Optional[str]:
    key = os.getenv("SKYFARER_SECRET_KEY", "")
    if not key:
        return ("SKYFARER_SECRET_KEY is not set. Put a long random value in .env, "
                "for example the output of: openssl rand -hex 32")
    if len(key) < 16:
        return "SKYFARER_SECRET_KEY is too short: use at least 16 random characters"
    return None


def _derived(purpose: str) -> bytes:
    problem = secret_key_problem()
    if problem:
        raise SettingsError(problem)
    return hashlib.sha256(f"skyfarer:{purpose}:{os.environ['SKYFARER_SECRET_KEY']}".encode()).digest()


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_derived("settings")))


def session_key() -> bytes:
    return _derived("session")


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()


# ─── Stored values ──────────────────────────────────────────────────────────

def _rows(conn, sql: str, params=None) -> list[dict]:
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def load(conn, unreadable: Optional[set] = None) -> dict[str, str]:
    """Every stored setting, secrets decrypted. A secret that can't be
    decrypted (the key has changed) is left out, and named in `unreadable`."""
    values = {}
    for r in _rows(conn, "SELECT key, value, secret FROM settings WHERE key NOT LIKE '\\_%'"):
        if r["secret"]:
            try:
                values[r["key"]] = decrypt(r["value"])
            except InvalidToken:
                log.error("Can't decrypt %s: SKYFARER_SECRET_KEY has changed since it was "
                          "saved. Enter it again in the dashboard.", r["key"])
                if unreadable is not None:
                    unreadable.add(r["key"])
                continue
        else:
            values[r["key"]] = r["value"]
    return values


def secret_meta(conn) -> dict[str, dict]:
    """When and by whom each secret was last set: all the dashboard shows of it."""
    return {r["key"]: r for r in _rows(
        conn, "SELECT key, updated_at, updated_by FROM settings WHERE secret")}


def save(conn, changes: dict[str, Optional[str]], actor: str, *, record: bool = True) -> list[str]:
    """Store changes (None removes a setting) and record each in the change
    history (unless record is False), secrets without their value. Returns what
    changed, as history lines."""
    current = load(conn)
    lines = []
    with conn.cursor() as cur:
        for key, value in changes.items():
            value = (value or "").strip() or None
            old = current.get(key)
            if (old or None) == value:
                continue
            name = label(key)
            if value is None:
                cur.execute("DELETE FROM settings WHERE key = %s", (key,))
                line = f"{name}: removed"
            else:
                secret = is_secret(key)
                cur.execute("""
                    INSERT INTO settings (key, value, secret, updated_at, updated_by)
                    VALUES (%s, %s, %s, NOW(), %s)
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value,
                        secret = EXCLUDED.secret, updated_at = NOW(), updated_by = EXCLUDED.updated_by
                """, (key, encrypt(value) if secret else value, secret, actor))
                if secret:
                    line = f"{name}: replaced" if old else f"{name}: set"
                else:
                    line = describe_change(key, old, value)
            lines.append(line)
            if record:
                history_add(conn, actor, line)
    return lines


def describe_change(key: str, old: Optional[str], new: str) -> str:
    name = label(key)
    f = FIELDS.get(key)
    if key.endswith("_ENABLED"):
        return f"{name}: switched {'on' if new == 'true' else 'off'}"
    if key.endswith("_REGIONS") or (f and f.kind in ("list", "events")):
        before, after = split_list(old or ""), split_list(new)
        added = [v for v in after if v not in before]
        removed = [v for v in before if v not in after]
        parts = []
        if added:
            parts.append("added " + ", ".join(added))
        if removed:
            parts.append("removed " + ", ".join(removed))
        return f"{name}: {'; '.join(parts) or 'reordered'}"
    if f and f.kind in ("json", "template") or len(new) > 60 or len(old or "") > 60:
        return f"{name}: changed"
    if not old:
        return f"{name}: set to {new}"
    return f"{name}: changed from {old} to {new}"


# ─── Webhooks ───────────────────────────────────────────────────────────────

def webhooks(conn, values: Optional[dict] = None, *, enabled_only: bool = False,
             unreadable: Optional[set] = None) -> list[dict]:
    """Every webhook as a dict, with its notifiers.Webhook under "hook". A
    webhook whose headers or signing secret can't be decrypted is marked
    "unreadable" and left out with enabled_only: sending it without its
    signature or API key would quietly weaken it."""
    if values is None:
        unreadable = set() if unreadable is None else unreadable
        values = load(conn, unreadable)
    unreadable = unreadable or set()
    out = []
    for r in _rows(conn, "SELECT * FROM webhooks ORDER BY id"):
        r["unreadable"] = bool({webhook_secret_key(r["id"], "headers"),
                                webhook_secret_key(r["id"], "secret")} & unreadable)
        if enabled_only and (not r["enabled"] or r["unreadable"]):
            continue
        r["hook"] = notifiers.Webhook(
            id=r["id"], name=r["name"], url=r["url"], method=r["method"],
            headers=values.get(webhook_secret_key(r["id"], "headers"), ""),
            template=r["template"], content_type=r["content_type"],
            secret=values.get(webhook_secret_key(r["id"], "secret"), ""),
            events=split_list(r["events"]))
        out.append(r)
    return out


def webhook_save(conn, hook_id: Optional[int], form: dict, actor: str, *,
                 record: bool = True) -> int:
    """Create (hook_id None) or update a webhook from cleaned form values."""
    with conn.cursor() as cur:
        if hook_id is None:
            cur.execute("""INSERT INTO webhooks (name, url, method, events, template, content_type)
                           VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                        (form["name"], form["url"], form["method"], form["events"],
                         form["template"], form["content_type"]))
            hook_id = cur.fetchone()[0]
            if record:
                history_add(conn, actor, f"Webhook {form['name']!r}: added")
        else:
            before = _rows(conn, "SELECT * FROM webhooks WHERE id = %s", (hook_id,))[0]
            cur.execute("""UPDATE webhooks SET name = %s, url = %s, method = %s, events = %s,
                           template = %s, content_type = %s, updated_at = NOW() WHERE id = %s""",
                        (form["name"], form["url"], form["method"], form["events"],
                         form["template"], form["content_type"], hook_id))
            changed = [k for k in ("name", "url", "method", "events", "template", "content_type")
                       if (before[k] or "") != (form[k] or "")]
            if changed:
                history_add(conn, actor, f"Webhook {form['name']!r}: changed "
                                         + ", ".join(c.replace("_", " ") for c in changed))
    secrets_changed = {}
    for part in ("headers", "secret"):
        if form.get(f"remove_{part}"):
            secrets_changed[webhook_secret_key(hook_id, part)] = None
        elif form.get(part):
            secrets_changed[webhook_secret_key(hook_id, part)] = form[part]
    if secrets_changed:
        for line in save(conn, secrets_changed, actor, record=False):
            if record:
                history_add(conn, actor, f"Webhook {form['name']!r}: " + line.split(": ", 1)[1])
    return hook_id


def webhook_enable(conn, hook_id: int, enabled: bool, actor: str) -> None:
    with conn.cursor() as cur:
        cur.execute("UPDATE webhooks SET enabled = %s, updated_at = NOW() WHERE id = %s RETURNING name",
                    (enabled, hook_id))
        row = cur.fetchone()
    if row:
        history_add(conn, actor, f"Webhook {row[0]!r}: switched {'on' if enabled else 'off'}")


def webhook_delete(conn, hook_id: int, actor: str) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM webhooks WHERE id = %s RETURNING name", (hook_id,))
        row = cur.fetchone()
        cur.execute("DELETE FROM settings WHERE key IN (%s, %s)",
                    (webhook_secret_key(hook_id, "headers"), webhook_secret_key(hook_id, "secret")))
    if row:
        history_add(conn, actor, f"Webhook {row[0]!r}: deleted")


# ─── Putting settings to work ───────────────────────────────────────────────

_apply_lock = threading.Lock()


def _to_env(values: dict[str, str]) -> None:
    """Make the environment match the stored values for every managed key.
    A provider or channel that is switched off keeps its settings but they
    aren't passed on, which is what switches it off."""
    env = {k: values[k] for k in MANAGED if values.get(k)}
    for p in PROVIDERS:
        if values.get(p.enabled_key, "true") == "false":
            env.pop(p.key, None)
    for c in CHANNELS:
        if values.get(c.enabled_key, "true") == "false":
            for f in c.fields:
                env.pop(f.key, None)
    for k in MANAGED + ENV_WEBHOOK_KEYS:
        if k in env:
            os.environ[k] = env[k]
        else:
            os.environ.pop(k, None)


def _configure(values: dict[str, str], hooks: list) -> None:
    _to_env(values)
    feeds.configure()
    notifiers.configure(webhooks=hooks)


def apply(conn=None) -> dict[str, str]:
    """Load the stored settings and put them to work in this process."""
    def run(c):
        unreadable: set = set()
        values = load(c, unreadable)
        hooks = [w["hook"] for w in webhooks(c, values, enabled_only=True, unreadable=unreadable)]
        with _apply_lock:
            _configure(values, hooks)
        return values
    if conn is not None:
        return run(conn)
    with db.get_conn() as c:
        return run(c)


def check(conn, changes: dict[str, Optional[str]], hooks: Optional[list] = None) -> list[str]:
    """The problems the stored settings would have with these changes made,
    without saving them. Configures this process with the trial values and
    puts the stored ones back afterwards."""
    unreadable: set = set()
    values = load(conn, unreadable)
    trial = dict(values)
    for k, v in changes.items():
        if (v or "").strip():
            trial[k] = v.strip()
        else:
            trial.pop(k, None)
    current_hooks = [w["hook"] for w in webhooks(conn, values, enabled_only=True,
                                                 unreadable=unreadable)]
    with _apply_lock:
        try:
            _configure(trial, current_hooks if hooks is None else hooks)
            return notifiers.config_errors()
        finally:
            _configure(values, current_hooks)


# ─── First start ────────────────────────────────────────────────────────────

def bootstrap() -> None:
    """On the first start with these tables empty, import what .env says.
    Runs in the poller and the dashboard; the lock keeps it to one."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(77701)")
            cur.execute("SELECT 1 FROM settings WHERE key = '_imported'")
            if cur.fetchone():
                return
        found = {k: os.environ[k].strip() for k in MANAGED if os.getenv(k, "").strip()}
        save(conn, found, "Skyfarer", record=False)
        hook = notifiers._env_webhook()
        if hook:
            h = hook[0]
            webhook_save(conn, None, {
                "name": h.name, "url": h.url, "method": h.method, "events": ",".join(h.events),
                "template": h.template, "content_type": h.content_type,
                "headers": h.headers, "secret": h.secret}, "Skyfarer", record=False)
        summary = import_summary(found, bool(hook))
        with conn.cursor() as cur:
            cur.execute("INSERT INTO settings (key, value) VALUES ('_imported', %s)", (summary,))
        history_add(conn, "Skyfarer", f"Imported settings from .env: {summary}")
        log.info("Imported settings from .env: %s", summary)


def import_summary(found: dict[str, str], webhook: bool) -> str:
    providers = [p for p in PROVIDERS if found.get(p.key)]
    regions = sum(len(split_list(found[p.key])) for p in providers)
    channels = [c.name for c in CHANNELS if any(found.get(f.key) for f in c.fields
                                                 if f.kind == "secret" or f.key.endswith(
                                                     ("_SUBDOMAIN", "_INSTANCE", "_SITE", "_DOMAIN", "_TARGETS")))]
    if webhook:
        channels.append("a webhook")
    if not providers and not channels:
        return "nothing set"
    parts = [f"{len(providers)} provider{'s' if len(providers) != 1 else ''} with "
             f"{regions} region{'s' if regions != 1 else ''}"]
    if channels:
        parts.append(f"{len(channels)} channel{'s' if len(channels) != 1 else ''}: "
                     + ", ".join(channels))
    return "; ".join(parts)


def imported_summary(conn) -> str:
    rows = _rows(conn, "SELECT value FROM settings WHERE key = '_imported'")
    return rows[0]["value"] if rows else ""


# ─── Change history ─────────────────────────────────────────────────────────

def history_add(conn, actor: str, what: str) -> None:
    with conn.cursor() as cur:
        cur.execute("INSERT INTO settings_log (actor, what) VALUES (%s, %s)", (actor, what))


def history(conn, limit: int = 50) -> list[dict]:
    return _rows(conn, "SELECT at, actor, what FROM settings_log ORDER BY id DESC LIMIT %s", (limit,))


# ─── Users ──────────────────────────────────────────────────────────────────

ROLES = ("admin", "viewer")


@dataclass
class NewLink:
    user_id: int
    token: str = field(repr=False)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def user_count(conn) -> int:
    return _rows(conn, "SELECT COUNT(*) AS n FROM users")[0]["n"]


def users(conn) -> list[dict]:
    return _rows(conn, """SELECT id, email, name, role, last_login, setup_expires,
                                 password_hash IS NOT NULL AS active
                            FROM users ORDER BY role, name""")


def user(conn, user_id: int) -> Optional[dict]:
    rows = _rows(conn, "SELECT id, email, name, role FROM users WHERE id = %s", (user_id,))
    return rows[0] if rows else None


def admin_count(conn) -> int:
    return _rows(conn, "SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")[0]["n"]


def password_problem(password: str, confirm: Optional[str] = None) -> Optional[str]:
    if len(password) < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters."
    if confirm is not None and password != confirm:
        return "The two passwords don't match."
    return None


def create_user(conn, email: str, name: str, role: str, actor: str,
                password: Optional[str] = None) -> NewLink:
    """Create an account. Without a password, it gets a setup link instead,
    returned once and stored only as a hash."""
    from werkzeug.security import generate_password_hash
    if role not in ROLES:
        raise ValueError(role)
    token = None if password else secrets.token_urlsafe(32)
    with conn.cursor() as cur:
        # With a password, it's the first admin, signed in as the account is made.
        cur.execute("""INSERT INTO users (email, name, role, password_hash, setup_token,
                                          setup_expires, last_login)
                       VALUES (lower(%s), %s, %s, %s, %s, %s, %s) RETURNING id""",
                    (email.strip(), name.strip(), role,
                     generate_password_hash(password) if password else None,
                     _token_hash(token) if token else None,
                     datetime.now(timezone.utc) + timedelta(hours=SETUP_LINK_HOURS) if token else None,
                     datetime.now(timezone.utc) if password else None))
        user_id = cur.fetchone()[0]
    history_add(conn, actor, f"Added {name.strip()} ({role})"
                + ("" if password else " and created a setup link"))
    return NewLink(user_id, token or "")


def new_setup_link(conn, user_id: int, actor: str) -> NewLink:
    token = secrets.token_urlsafe(32)
    with conn.cursor() as cur:
        cur.execute("""UPDATE users SET setup_token = %s, setup_expires = %s
                        WHERE id = %s RETURNING name""",
                    (_token_hash(token), datetime.now(timezone.utc) + timedelta(hours=SETUP_LINK_HOURS),
                     user_id))
        name = cur.fetchone()[0]
    history_add(conn, actor, f"Created a setup link for {name}")
    return NewLink(user_id, token)


def user_by_token(conn, token: str) -> Optional[dict]:
    rows = _rows(conn, """SELECT id, email, name, role FROM users
                           WHERE setup_token = %s AND setup_expires > NOW()""", (_token_hash(token),))
    return rows[0] if rows else None


def set_password(conn, user_id: int, password: str) -> None:
    from werkzeug.security import generate_password_hash
    with conn.cursor() as cur:
        cur.execute("""UPDATE users SET password_hash = %s, setup_token = NULL, setup_expires = NULL,
                              last_login = NOW() WHERE id = %s""",
                    (generate_password_hash(password), user_id))


def check_login(conn, email: str, password: str) -> Optional[dict]:
    from werkzeug.security import check_password_hash
    rows = _rows(conn, "SELECT id, name, role, password_hash FROM users WHERE email = lower(%s)",
                 (email.strip(),))
    # Hash something either way, so a wrong email takes as long as a wrong password.
    stored = rows[0]["password_hash"] if rows and rows[0]["password_hash"] else _DUMMY_HASH()
    if not check_password_hash(stored, password) or not rows or not rows[0]["password_hash"]:
        return None
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (rows[0]["id"],))
    return {k: rows[0][k] for k in ("id", "name", "role")}


_dummy: list[str] = []


def _DUMMY_HASH() -> str:
    if not _dummy:
        from werkzeug.security import generate_password_hash
        _dummy.append(generate_password_hash(secrets.token_hex(16)))
    return _dummy[0]


def set_role(conn, user_id: int, role: str, actor: str) -> Optional[str]:
    """Returns a reason when the change isn't allowed."""
    if role not in ROLES:
        return "Unknown role."
    target = user(conn, user_id)
    if not target or target["role"] == role:
        return None
    if target["role"] == "admin" and admin_count(conn) <= 1:
        return "There must always be at least one admin."
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
    history_add(conn, actor, f"{target['name']}: role changed from {target['role']} to {role}")
    return None


def delete_user(conn, user_id: int, actor: str) -> Optional[str]:
    target = user(conn, user_id)
    if not target:
        return None
    if target["role"] == "admin" and admin_count(conn) <= 1:
        return "There must always be at least one admin."
    with conn.cursor() as cur:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    history_add(conn, actor, f"Removed {target['name']}")
    return None
