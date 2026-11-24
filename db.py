"""
db.py
~~~~~
Postgres persistence layer for Skyfarer.

Tables
------
incidents         – one row per incident, tracks full lifecycle
incident_updates  – later feed entries about an incident (AWS posts each
                    update as a separate entry, Azure rewords its entries)
notifications     – delivery queue: one row per notice per channel
poll_log          – one row per poll cycle for observability
settings, webhooks, users, settings_log – see settings.py
api_tokens         – hashed bearer tokens for the JSON API
api_rate_limits    – short-lived request counters shared by every worker
dashboard_state, login_failures – shared first-run code and sign-in throttle
"""

from __future__ import annotations

import logging
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import Json, RealDictCursor

log = logging.getLogger("skyfarer.db")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://{user}:{password}@{host}:{port}/{dbname}".format(
        user=os.getenv("POSTGRES_USER", "skyfarer"),
        password=os.getenv("POSTGRES_PASSWORD", "skyfarer"),
        host=os.getenv("POSTGRES_HOST", "db"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        dbname=os.getenv("POSTGRES_DB", "skyfarer"),
    ),
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
    id              SERIAL PRIMARY KEY,
    guid            TEXT UNIQUE NOT NULL,
    provider        TEXT NOT NULL,             -- AWS, Azure, GCP, OVH, DigitalOcean, ...
    region          TEXT NOT NULL,
    title           TEXT NOT NULL,
    summary         TEXT,
    link            TEXT,
    feed_published  TEXT,                      -- timestamp string from RSS
    feed_updated    TEXT,                      -- timestamp string from RSS
    state           TEXT NOT NULL DEFAULT 'open',  -- open | resolved
    ticket_id       INTEGER,                  -- Zendesk ticket number
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Migration for tables created before ingested_at existed.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS update_count INTEGER NOT NULL DEFAULT 0;

-- Planned work rather than a fault (scheduled maintenance).
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS is_maintenance BOOLEAN NOT NULL DEFAULT FALSE;

-- Account resources an incident touches, from an optional provider API key.
-- resource_counts is {region: count}; NULL means no key/snapshot for that
-- provider, while an empty object means the key was read and found none there.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resource_counts JSONB;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS resources_affected INTEGER;

CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents (state);
CREATE INDEX IF NOT EXISTS idx_incidents_provider ON incidents (provider);

CREATE TABLE IF NOT EXISTS incident_updates (
    id              SERIAL PRIMARY KEY,
    incident_id     INTEGER NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    guid            TEXT UNIQUE NOT NULL,      -- the update's own RSS entry ID
    title           TEXT NOT NULL,
    summary         TEXT,
    link            TEXT,
    feed_published  TEXT,                      -- timestamp string from RSS
    published_at    TIMESTAMPTZ,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_updates_incident ON incident_updates (incident_id);

CREATE TABLE IF NOT EXISTS notifications (
    id              SERIAL PRIMARY KEY,
    incident_id     INTEGER NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    channel         TEXT NOT NULL,             -- any notifiers.SENDERS key, or webhook-<id>
    event           TEXT NOT NULL,             -- opened | updated | resolved
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending | sent | failed
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_notifications_pending ON notifications (id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_notifications_incident ON notifications (incident_id, channel);

CREATE TABLE IF NOT EXISTS poll_log (
    id              SERIAL PRIMARY KEY,
    polled_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    entries_seen    INTEGER NOT NULL DEFAULT 0,
    tickets_created INTEGER NOT NULL DEFAULT 0,
    tickets_resolved INTEGER NOT NULL DEFAULT 0,
    open_count      INTEGER NOT NULL DEFAULT 0,
    error           TEXT
);

-- Last good read of each provider's account API: how many resources the
-- account has in each region. Only providers with an API key have rows here.
CREATE TABLE IF NOT EXISTS provider_resources (
    provider       TEXT NOT NULL,
    region         TEXT NOT NULL,
    count          INTEGER NOT NULL,
    discovered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, region)
);

-- Records in ticketing systems other than Zendesk (whose ticket number is
-- incidents.ticket_id): one per incident per system.
CREATE TABLE IF NOT EXISTS tickets (
    incident_id     INTEGER NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    system          TEXT NOT NULL,             -- servicenow
    ref             TEXT NOT NULL,             -- the system's own ID (ServiceNow sys_id)
    number          TEXT,                      -- what people call it (INC0010001)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (incident_id, system)
);

-- Feeds that could not be read in a cycle, as "Provider: reason; ...".
ALTER TABLE poll_log ADD COLUMN IF NOT EXISTS feed_errors TEXT;

-- Settings edited in the dashboard (see settings.py). Keys are the .env names;
-- secrets are encrypted. Keys starting with "_" are Skyfarer's own markers.
CREATE TABLE IF NOT EXISTS settings (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    secret          BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      TEXT
);

-- Outbound webhooks; their headers and signing secret are in settings.
CREATE TABLE IF NOT EXISTS webhooks (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    url             TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'POST',
    events          TEXT NOT NULL DEFAULT '',      -- empty: follow NOTIFY_EVENTS
    template        TEXT NOT NULL DEFAULT '',
    content_type    TEXT NOT NULL DEFAULT 'application/json',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    name            TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    password_hash   TEXT,                          -- NULL until the setup link is used
    setup_token     TEXT,                          -- SHA-256 of the one-time link's token
    setup_expires   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login      TIMESTAMPTZ
);

-- Bearer tokens for the JSON API. The plaintext is shown once at creation;
-- only its SHA-256 hash is kept. Scopes are a Postgres text array.
CREATE TABLE IF NOT EXISTS api_tokens (
    id            SERIAL PRIMARY KEY,
    user_id       INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    scopes        TEXT[] NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens (user_id);

-- API throttle: one row per request, pruned as it ages out of the window.
CREATE TABLE IF NOT EXISTS api_rate_limits (
    id              BIGSERIAL PRIMARY KEY,
    bucket          TEXT NOT NULL,             -- token id or client address
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_rate_limits_bucket ON api_rate_limits (bucket, at);
CREATE INDEX IF NOT EXISTS idx_api_rate_limits_at ON api_rate_limits (at);

-- First-run setup code and sign-in throttling live here, not in a worker's
-- memory, so gunicorn can run several workers (or replicas).
CREATE TABLE IF NOT EXISTS dashboard_state (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS login_failures (
    id              BIGSERIAL PRIMARY KEY,
    bucket          TEXT NOT NULL,             -- client address + email
    failed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_failures_bucket ON login_failures (bucket, failed_at);
CREATE INDEX IF NOT EXISTS idx_login_failures_time ON login_failures (failed_at);

-- Who changed what. Secret values are never written here.
CREATE TABLE IF NOT EXISTS settings_log (
    id              SERIAL PRIMARY KEY,
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor           TEXT NOT NULL,
    what            TEXT NOT NULL
);
"""


@contextmanager
def get_conn():
    """Yield a psycopg2 connection; commit on clean exit, rollback on error."""
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema():
    """Create tables and indexes if they don't exist, and apply the small
    column additions that older databases need. Every dashboard worker and the
    poller run this at start; the lock stops their CREATE TABLE IF NOT EXISTS
    statements racing, which Postgres can refuse with a unique violation."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(77700)")
            cur.execute(SCHEMA_SQL)
            # Added for the API's service accounts; safe to run repeatedly.
            cur.execute("""ALTER TABLE users ADD COLUMN IF NOT EXISTS kind
                           TEXT NOT NULL DEFAULT 'human'
                           CHECK (kind IN ('human', 'service'))""")
    log.info("Database schema initialised")


def api_rate_limit(conn, bucket: str, limit: int, window: int = 60) -> tuple[bool, int]:
    """Count this request in a shared, fixed-window throttle.

    The advisory lock keeps concurrent workers from each allowing their own
    quota. Returns (allowed, retry_after_seconds).
    """
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(77705, hashtext(%s))", (bucket,))
        cur.execute("DELETE FROM api_rate_limits WHERE at < NOW() - %s * INTERVAL '1 second'",
                    (window,))
        cur.execute("""SELECT COUNT(*), MIN(at) FROM api_rate_limits WHERE bucket = %s""",
                    (bucket,))
        count, oldest = cur.fetchone()
        if count >= limit:
            left = (datetime.now(timezone.utc) - oldest).total_seconds()
            return False, max(1, int(window - left) + 1)
        cur.execute("INSERT INTO api_rate_limits (bucket) VALUES (%s)", (bucket,))
        return True, 0


def get_known_guids(conn) -> set[str]:
    """Return the set of all GUIDs already in the database."""
    with conn.cursor() as cur:
        cur.execute("SELECT guid FROM incidents UNION SELECT guid FROM incident_updates")
        return {row[0] for row in cur.fetchall()}


def get_open_guids(conn) -> dict[str, dict]:
    """Return open incidents as {guid: {id, guid, ticket_id, provider, region,
    title, summary}}."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT id, guid, ticket_id, provider, region, title, summary "
            "FROM incidents WHERE state = 'open'"
        )
        return {row["guid"]: dict(row) for row in cur.fetchall()}


def get_incident(conn, guid: str) -> dict:
    """Return one incident's {id, guid, ticket_id, provider, region, title}."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT id, guid, ticket_id, provider, region, title "
            "FROM incidents WHERE guid = %s", (guid,)
        )
        return dict(cur.fetchone())


def insert_incident(conn, *, guid: str, provider: str, region: str,
                    title: str, summary: str, link: str,
                    feed_published: str, feed_updated: str,
                    state: str, ticket_id: int | None,
                    detected_at: datetime | None = None,
                    resolved_at: datetime | None = None,
                    is_maintenance: bool = False,
                    resource_counts: dict | None = None,
                    resources_affected: int | None = None) -> int | None:
    """Insert a new incident row and return its ID (None if it already exists).

    detected_at / resolved_at reflect the real incident timeline (the feed's
    own published/updated times) when the caller has one; ingested_at always
    records when the poller itself wrote the row.
    """
    now = datetime.now(timezone.utc)
    if detected_at is None:
        detected_at = now
    if resolved_at is None and state == "resolved":
        resolved_at = now
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO incidents
                (guid, provider, region, title, summary, link,
                 feed_published, feed_updated, state, ticket_id,
                 detected_at, resolved_at, ingested_at, is_maintenance,
                 resource_counts, resources_affected)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (guid) DO NOTHING
            RETURNING id
        """, (guid, provider, region, title, summary, link,
              feed_published, feed_updated, state, ticket_id,
              detected_at, resolved_at, now, is_maintenance,
              Json(resource_counts) if resource_counts is not None else None,
              resources_affected))
        row = cur.fetchone()
        return row[0] if row else None


def update_resource_impact(conn, incident_id: int, counts: dict,
                           affected: int) -> None:
    """Keep an incident's resource count in step with the last account read."""
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE incidents
               SET resource_counts = %s, resources_affected = %s, updated_at = %s
             WHERE id = %s
        """, (Json(counts), affected, datetime.now(timezone.utc), incident_id))


def replace_provider_resources(conn, discovered: dict[str, dict[str, int]],
                               cleared=(), failed=()) -> None:
    """Store a good account read. A provider whose read failed keeps its old
    rows, so a brief API outage doesn't make its regions disappear."""
    failed = set(failed)
    with conn.cursor() as cur:
        for provider in set(discovered) | set(cleared):
            if provider in failed:
                continue
            cur.execute("DELETE FROM provider_resources WHERE provider = %s", (provider,))
            for region, count in sorted((discovered.get(provider) or {}).items()):
                cur.execute("""
                    INSERT INTO provider_resources (provider, region, count)
                    VALUES (%s, %s, %s)
                """, (provider, region, count))


def provider_resources(conn) -> dict[str, dict[str, int]]:
    """Last good account read as {provider: {region: count}}."""
    out: dict[str, dict[str, int]] = {}
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT provider, region, count FROM provider_resources")
        for row in cur.fetchall():
            out.setdefault(row["provider"], {})[row["region"]] = row["count"]
    return out


def mark_resolved(conn, guid: str, resolved_at: datetime | None = None) -> None:
    """Set an incident to resolved. resolved_at defaults to now() if the
    caller doesn't have a real feed-reported resolution time."""
    if resolved_at is None:
        resolved_at = datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE incidents
               SET state = 'resolved',
                   resolved_at = %s,
                   updated_at = %s
             WHERE guid = %s AND state = 'open'
        """, (resolved_at, datetime.now(timezone.utc), guid))


def add_update(conn, *, incident_id: int, guid: str, title: str, summary: str,
               link: str, feed_published: str,
               published_at: datetime | None) -> None:
    """Store a later feed entry against its incident."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO incident_updates
                (incident_id, guid, title, summary, link, feed_published, published_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (guid) DO NOTHING
        """, (incident_id, guid, title, summary, link, feed_published, published_at))


def refresh_incident(conn, incident_id: int, *, title: str, summary: str,
                     link: str, feed_updated: str, added_updates: int) -> None:
    """Show an incident's newest update on its row."""
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE incidents
               SET title = %s, summary = %s, link = %s, feed_updated = %s,
                   update_count = update_count + %s, updated_at = %s
             WHERE id = %s
        """, (title, summary, link, feed_updated, added_updates,
              datetime.now(timezone.utc), incident_id))


def add_notification(conn, *, incident_id: int, channel: str, event: str,
                     payload: dict) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO notifications (incident_id, channel, event, payload)
            VALUES (%s, %s, %s, %s)
        """, (incident_id, channel, event, Json(payload)))


def was_notified(conn, incident_id: int, channel: str) -> bool:
    """Has this channel been told about this incident opening?"""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT 1 FROM notifications
             WHERE incident_id = %s AND channel = %s AND event = 'opened'
               AND status IN ('pending', 'sent')
        """, (incident_id, channel))
        return cur.fetchone() is not None


def pending_notifications(conn) -> list[dict]:
    """Everything undelivered, oldest first, with the incident's ticket."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT n.*, i.ticket_id, t.ref AS ticket_ref
              FROM notifications n JOIN incidents i ON i.id = n.incident_id
              LEFT JOIN tickets t ON t.incident_id = n.incident_id
                                 AND t.system = n.channel
             WHERE n.status = 'pending'
             ORDER BY n.id
        """)
        return cur.fetchall()


def notification_sent(conn, notification_id: int) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE notifications
               SET status = 'sent', attempts = attempts + 1, last_error = NULL,
                   sent_at = NOW()
             WHERE id = %s
        """, (notification_id,))


def notification_retry(conn, notification_id: int, error: str,
                       next_attempt_at: datetime) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE notifications
               SET attempts = attempts + 1, last_error = %s, next_attempt_at = %s
             WHERE id = %s
        """, (error, next_attempt_at, notification_id))


def notification_failed(conn, notification_id: int, error: str) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE notifications
               SET status = 'failed', attempts = attempts + 1, last_error = %s
             WHERE id = %s
        """, (error, notification_id))


def set_ticket(conn, incident_id: int, ticket_id: int) -> None:
    with conn.cursor() as cur:
        cur.execute("UPDATE incidents SET ticket_id = %s WHERE id = %s",
                    (ticket_id, incident_id))


def set_external_ticket(conn, incident_id: int, system: str, *, ref: str,
                        number: str) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO tickets (incident_id, system, ref, number)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (incident_id, system) DO UPDATE
               SET ref = EXCLUDED.ref, number = EXCLUDED.number
        """, (incident_id, system, ref, number))


def count_open(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM incidents WHERE state = 'open'")
        return cur.fetchone()[0]


def log_poll(conn, *, entries_seen: int, tickets_created: int,
             tickets_resolved: int, open_count: int, error: str | None = None,
             feed_errors: str | None = None):
    """Write a poll-cycle summary row."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO poll_log
                (entries_seen, tickets_created, tickets_resolved, open_count,
                 error, feed_errors)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (entries_seen, tickets_created, tickets_resolved, open_count,
              error, feed_errors))


# ─── Dashboard state shared by every worker ─────────────────────────────────

SETUP_CODE_KEY = "setup_code"


def lock_setup(conn) -> None:
    """Hold off other workers while the first admin is being created."""
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(77702)")


def setup_code(conn) -> str:
    """Return the one-time setup code, creating it once if it doesn't exist.

    The caller logs it. Workers that start later can read the same value, so a
    restart doesn't strand the setup page with a code nobody can find.
    """
    lock_setup(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT value FROM dashboard_state WHERE key = %s", (SETUP_CODE_KEY,))
        existing = cur.fetchone()
        if existing:
            return existing[0]
        code = "-".join(secrets.token_hex(3) for _ in range(3))
        cur.execute("""
            INSERT INTO dashboard_state (key, value) VALUES (%s, %s)
            ON CONFLICT (key) DO NOTHING RETURNING value
        """, (SETUP_CODE_KEY, code))
        inserted = cur.fetchone()
        if inserted:
            return inserted[0]
        cur.execute("SELECT value FROM dashboard_state WHERE key = %s", (SETUP_CODE_KEY,))
        return cur.fetchone()[0]


def clear_setup_code(conn) -> None:
    """The code is single-use: drop it once the first admin exists."""
    with conn.cursor() as cur:
        cur.execute("DELETE FROM dashboard_state WHERE key = %s", (SETUP_CODE_KEY,))


def lock_login(conn, bucket: str) -> None:
    """Serialise counting and recording failures for one sign-in attempt."""
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(77703, hashtext(%s))", (bucket,))


def login_failures(conn, bucket: str, window: int) -> int:
    """Wrong attempts for this address/email inside the last `window` seconds."""
    with conn.cursor() as cur:
        cur.execute("DELETE FROM login_failures WHERE failed_at < NOW() - %s * INTERVAL '1 second'",
                    (window,))
        cur.execute("SELECT COUNT(*) FROM login_failures WHERE bucket = %s", (bucket,))
        return cur.fetchone()[0]


def login_failed(conn, bucket: str) -> None:
    with conn.cursor() as cur:
        cur.execute("INSERT INTO login_failures (bucket) VALUES (%s)", (bucket,))


def login_succeeded(conn, bucket: str) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM login_failures WHERE bucket = %s", (bucket,))
