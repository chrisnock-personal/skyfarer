#!/usr/bin/env python3
"""
poller.py
~~~~~~~~~
Skyfarer's poller. Reads the public status feeds of AWS, Azure, Google Cloud,
OVHcloud, DigitalOcean, Hetzner, Linode, Cloudflare and Scaleway (see
feeds.py) and sends a notice whenever an entry touches a region you watch:
Zendesk tickets or ServiceNow incidents, plus Pushover, PagerDuty, Microsoft
Teams and SNMP traps (see notifiers.py). When the provider marks the incident
over, the Zendesk ticket gets a comment and moves to "pending" for manual
closure, and the ServiceNow record is resolved.

All incident state is held in Postgres -no local files.

Usage:
    python poller.py              # continuous loop
    python poller.py --once       # single poll then exit
    python poller.py --dry-run    # parse feeds, send nothing
    python poller.py --init-db    # create tables then exit
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

# Before the imports below: each reads its settings when it loads.
load_dotenv()

import db  # noqa: E402
import feeds  # noqa: E402
import notifiers  # noqa: E402
import settings  # noqa: E402
from feeds import FeedEntry, fmt_dt  # noqa: E402

# Providers whose feed has no stable ID for one event (see _process_grouped).
GROUPED_PROVIDERS = ("AWS", "Azure")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("skyfarer")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ─── Preflight ──────────────────────────────────────────────────────────────

def poll_interval() -> int:
    try:
        return max(30, int(os.getenv("POLL_INTERVAL_SECONDS", "") or 300))
    except ValueError:
        return 300


def preflight(dry_run: bool = False) -> bool:
    """Report what's missing or wrong. Settings are edited in the dashboard,
    so these are warnings: the poller keeps running and picks up the fix."""
    ok = True
    for error in notifiers.config_errors():
        log.error(error); ok = False
    if not dry_run and not notifiers.enabled_channels():
        log.warning("No notification channel is set up: add one in the dashboard, "
                    "under Settings > Channels"); ok = False
    if not any(feeds.watched_regions().values()):
        log.warning("No regions are being watched: add some in the dashboard, "
                    "under Settings > Providers and regions"); ok = False
    return ok


# ─── Incident lifecycle ─────────────────────────────────────────────────────

def _notice(entry: FeedEntry, **extra) -> dict:
    """What a channel needs to know, as stored in the delivery queue."""
    return {
        "provider": entry.provider, "region": entry.region, "title": entry.title,
        "summary": entry.summary, "link": entry.link, "published": entry.published,
        "updated": entry.updated, "noticed": _now_utc(), **extra,
    }


def _worth_alerting(entry: FeedEntry) -> bool:
    """Should this incident reach channels that interrupt people? Zendesk
    gets everything regardless. Without this, a first start would page someone
    for every old event still in the feeds, and for next month's maintenance."""
    if entry.is_maintenance and not notifiers.NOTIFY_MAINTENANCE:
        log.info("No alert, scheduled maintenance: %s", entry.title)
        return False
    if entry.published_dt:
        age = datetime.now(timezone.utc) - entry.published_dt
        if age > timedelta(hours=notifiers.NOTIFY_MAX_AGE_HOURS):
            log.info("No alert, published %d days ago: %s", age.days, entry.title)
            return False
    return True


def _notify(conn, incident_id: int, event: str, entry: FeedEntry, dry_run: bool,
            *, alert: bool = True, **extra) -> None:
    if dry_run:
        log.info("[DRY-RUN] Would send %s notices for %s", event, entry.title)
    else:
        notifiers.enqueue(conn, incident_id, event, _notice(entry, **extra), alert=alert)


def _record_new(conn, entry: FeedEntry, dry_run: bool) -> None:
    """First sight of an incident: store it, and queue notices unless it's
    already over."""
    fields = dict(
        guid=entry.guid, provider=entry.provider, region=entry.region,
        title=entry.title, summary=entry.summary, link=entry.link,
        feed_published=entry.published, feed_updated=entry.updated,
        ticket_id=None, detected_at=entry.published_dt,
        is_maintenance=entry.is_maintenance,
    )
    if entry.is_resolved:
        log.info("Skipping already-resolved: %s – %s", entry.provider, entry.title)
        db.insert_incident(conn, state="resolved", resolved_at=entry.updated_dt, **fields)
        return

    log.info("New incident: [%s] %s – %s", entry.provider, entry.region, entry.title)
    incident_id = db.insert_incident(conn, state="open", **fields)
    if incident_id is not None:
        _notify(conn, incident_id, "opened", entry, dry_run,
                alert=_worth_alerting(entry))


def _resolve_incident(conn, rec: dict, entry: FeedEntry, dry_run: bool) -> None:
    """Mark an incident resolved and queue the notices that say so."""
    log.info("Resolved: [%s] %s – %s", entry.provider, entry.region, entry.title)
    db.mark_resolved(conn, rec["guid"], resolved_at=entry.updated_dt)
    _notify(conn, rec["id"], "resolved", entry, dry_run)


def _apply_updates(conn, rec: dict, updates: list[FeedEntry], dry_run: bool) -> None:
    """Attach new entries to their open incident. However many arrived, the
    channels get one notice, about the newest."""
    latest = updates[-1]
    for entry in updates:
        db.add_update(conn, incident_id=rec["id"], guid=entry.guid,
                      title=entry.title, summary=entry.summary,
                      link=entry.link, feed_published=entry.published,
                      published_at=entry.published_dt)
    db.refresh_incident(conn, rec["id"], title=latest.title,
                        summary=latest.summary, link=latest.link,
                        feed_updated=latest.updated,
                        added_updates=len(updates))
    if latest.is_resolved:
        _resolve_incident(conn, rec, latest, dry_run)
    else:
        _notify(conn, rec["id"], "updated", latest, dry_run,
                update_count=len(updates))


def _regions(region: str) -> set[str]:
    return set(region.split(", "))


def _process_grouped(conn, provider: str, entries: list[FeedEntry],
                     known_guids: set[str], open_incidents: dict[str, dict],
                     dry_run: bool) -> tuple[int, int]:
    """For feeds with no stable event ID. AWS gives every update its own GUID
    and changes the title as an event progresses, and Azure rewords its
    titles, so entries can't be matched on either. Everything from the first
    unresolved entry to the entry that resolves it counts as one incident with
    one ticket, per region: entries sharing a region with an open incident
    belong to it."""
    created = resolved = 0
    live = [r for r in open_incidents.values() if r["provider"] == provider]
    pending: dict[int, tuple[dict, list[FeedEntry]]] = {}

    far_future = datetime.max.replace(tzinfo=timezone.utc)
    new_entries = [e for e in entries if e.guid not in known_guids]
    for entry in sorted(new_entries, key=lambda e: e.published_dt or far_future):
        regions = _regions(entry.region)
        rec = next((r for r in live if regions & _regions(r["region"])), None)
        if rec is None:
            _record_new(conn, entry, dry_run)
            if not entry.is_resolved:
                created += 1
                live.append(db.get_incident(conn, entry.guid))
            continue
        pending.setdefault(rec["id"], (rec, []))[1].append(entry)
        if entry.is_resolved:
            _, updates = pending.pop(rec["id"])
            _apply_updates(conn, rec, updates, dry_run)
            resolved += 1
            live.remove(rec)

    for rec, updates in pending.values():
        _apply_updates(conn, rec, updates, dry_run)

    return created, resolved


def _ended_entry(rec: dict, page: str, provider_label: str) -> FeedEntry:
    now = datetime.now(timezone.utc)
    return FeedEntry(
        provider=rec["provider"], region=rec["region"], guid=rec["guid"],
        title=rec["title"],
        summary=f"This notice is no longer listed on the {provider_label} status page.",
        link=page, published=fmt_dt(now), updated=fmt_dt(now),
        is_resolved=True, published_dt=now, updated_dt=now,
    )


def _resolve_unlisted_azure(conn, listed: set[str], dry_run: bool) -> int:
    """Azure's feed only lists events in progress, so an open incident whose
    regions have nothing listed any more has ended, whether or not a
    "Mitigated" entry was ever published."""
    resolved = 0
    for rec in db.get_open_guids(conn).values():
        if rec["provider"] != "Azure" or _regions(rec["region"]) & listed:
            continue
        _resolve_incident(conn, rec, _ended_entry(rec, feeds.AZURE_STATUS_PAGE, "Azure"),
                          dry_run)
        resolved += 1
    return resolved


def _resolve_unlisted_hetzner(conn, listed: set[str], dry_run: bool) -> int:
    """Hetzner's feed only lists current and upcoming notices, each under a
    stable ID, so an open one that has left the feed is over."""
    resolved = 0
    for rec in db.get_open_guids(conn).values():
        if rec["provider"] != "Hetzner" or rec["guid"] in listed:
            continue
        _resolve_incident(conn, rec, _ended_entry(rec, feeds.HETZNER_STATUS_PAGE, "Hetzner"),
                          dry_run)
        resolved += 1
    return resolved


def fetch_all(errors: feeds.FeedErrors):
    azure_entries, azure_listed = feeds.fetch_azure_entries(errors)
    hetzner_entries, hetzner_listed = feeds.fetch_hetzner_entries(errors)
    entries = (feeds.fetch_aws_entries(errors) + feeds.fetch_ovh_entries(errors)
               + feeds.fetch_gcp_entries(errors) + azure_entries + hetzner_entries)
    for provider in feeds.STATUSPAGE_PROVIDERS:
        entries += feeds.fetch_statuspage_entries(provider, errors)
    return entries, azure_listed, hetzner_listed


def poll_once(dry_run: bool = False) -> tuple[int, int]:
    """Run one poll cycle. Returns (incidents_created, incidents_resolved)."""
    errors = feeds.FeedErrors()
    all_entries, azure_listed, hetzner_listed = fetch_all(errors)
    created = 0
    resolved = 0

    try:
        with db.get_conn() as conn:
            known_guids = db.get_known_guids(conn)
            open_incidents = db.get_open_guids(conn)

            # Everyone but AWS and Azure keeps one ID for an incident's life.
            for entry in all_entries:
                if entry.provider in GROUPED_PROVIDERS:
                    continue
                if entry.guid not in known_guids:
                    _record_new(conn, entry, dry_run)
                    if not entry.is_resolved:
                        created += 1
                elif entry.guid in open_incidents and entry.is_resolved:
                    rec = open_incidents[entry.guid]
                    # Show how it ended, not how it began.
                    db.refresh_incident(conn, rec["id"], title=entry.title,
                                        summary=entry.summary, link=entry.link,
                                        feed_updated=entry.updated, added_updates=0)
                    _resolve_incident(conn, rec, entry, dry_run)
                    resolved += 1

            for provider in GROUPED_PROVIDERS:
                new, done = _process_grouped(
                    conn, provider,
                    [e for e in all_entries if e.provider == provider],
                    known_guids, open_incidents, dry_run)
                created += new
                resolved += done

            if azure_listed is not None:
                resolved += _resolve_unlisted_azure(conn, azure_listed, dry_run)
            if hetzner_listed is not None:
                resolved += _resolve_unlisted_hetzner(conn, hetzner_listed, dry_run)

            db.log_poll(conn, entries_seen=len(all_entries),
                        tickets_created=created, tickets_resolved=resolved,
                        open_count=db.count_open(conn),
                        feed_errors=errors.summary())

    except Exception as exc:
        log.exception("Error during poll cycle")
        try:
            with db.get_conn() as conn:
                db.log_poll(conn, entries_seen=len(all_entries),
                            tickets_created=created, tickets_resolved=resolved,
                            open_count=-1, error=str(exc),
                            feed_errors=errors.summary())
        except Exception:
            pass

    # After the commit above: a cycle that rolled back has queued nothing, so
    # it can't have told anyone about an incident it then forgot. This also
    # retries anything left over from earlier cycles.
    if not dry_run:
        try:
            notifiers.deliver_pending()
        except Exception:
            log.exception("Error delivering notifications")

    open_count = 0
    try:
        with db.get_conn() as conn:
            open_count = db.count_open(conn)
    except Exception:
        pass

    log.info("Cycle complete: %d new, %d resolved, %d still open",
             created, resolved, open_count)
    return created, resolved


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="skyfarer", description="Poll cloud status feeds and send notifications")
    parser.add_argument("--once", action="store_true",
                        help="Run a single poll then exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse feeds but send no notifications")
    parser.add_argument("--init-db", action="store_true",
                        help="Create database tables then exit")
    args = parser.parse_args()

    # Also honour env vars -easier when running via compose
    dry_run = args.dry_run or os.getenv("DRY_RUN", "").lower() in ("1", "true", "yes")
    run_once = args.once or os.getenv("RUN_ONCE", "").lower() in ("1", "true", "yes")

    if dry_run:
        log.info("DRY-RUN mode – no notifications will be sent")

    problem = settings.secret_key_problem()
    if problem:
        log.error(problem)
        sys.exit(1)

    db.init_schema()  # idempotent – safe on every start
    if args.init_db:
        log.info("Database ready")
        return
    settings.bootstrap()   # imports .env on the very first start
    settings.apply()
    preflight(dry_run=dry_run)

    if run_once:
        poll_once(dry_run=dry_run)
        return

    watching = {p: r for p, r in feeds.watched_regions().items() if r}
    log.info("Watching: %s", "; ".join(f"{p} ({', '.join(r)})" for p, r in watching.items())
             or "nothing yet")
    log.info("Notification channels: %s", ", ".join(notifiers.enabled_channels()) or "none")
    log.info("Starting continuous poll loop (every %ds)", poll_interval())
    first = True
    while True:
        try:
            if not first:
                # Changes made in the dashboard since the last poll.
                before = _snapshot()
                settings.apply()
                if _snapshot() != before:
                    log.info("Settings changed in the dashboard")
                    preflight(dry_run=dry_run)
            first = False
            poll_once(dry_run=dry_run)
        except Exception:
            log.exception("Unhandled error during poll cycle")
        time.sleep(poll_interval())


def _snapshot() -> tuple:
    return (tuple(sorted((k, os.getenv(k, "")) for k in settings.MANAGED)),
            tuple(repr(h) for h in notifiers.WEBHOOKS))

if __name__ == "__main__":
    main()
