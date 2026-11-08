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
"""

from __future__ import annotations

import logging
import os
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
    channel         TEXT NOT NULL,             -- zendesk | servicenow | pushover | pagerduty | teams | snmp | webhook
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
    """Create tables and indexes if they don't exist."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
    log.info("Database schema initialised")


def get_known_guids(conn) -> set[str]:
    """Return the set of all GUIDs already in the database."""
    with conn.cursor() as cur:
        cur.execute("SELECT guid FROM incidents UNION SELECT guid FROM incident_updates")
        return {row[0] for row in cur.fetchall()}


def get_open_guids(conn) -> dict[str, dict]:
    """Return open incidents as {guid: {id, guid, ticket_id, provider, region, title}}."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT id, guid, ticket_id, provider, region, title "
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
                    is_maintenance: bool = False) -> int | None:
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
                 detected_at, resolved_at, ingested_at, is_maintenance)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (guid) DO NOTHING
            RETURNING id
        """, (guid, provider, region, title, summary, link,
              feed_published, feed_updated, state, ticket_id,
              detected_at, resolved_at, now, is_maintenance))
        row = cur.fetchone()
        return row[0] if row else None


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
