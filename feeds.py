"""
feeds.py
~~~~~~~~
Reads each provider's public status feed and turns the entries that touch a
watched region into FeedEntry records. Nothing here writes to the database or
sends anything: poller.py decides what an entry means for an incident.

Providers
---------
AWS            one RSS feed per region; every update is a new entry
OVH            Statuspage RSS, filtered by region code in the text
Azure          RSS listing only events in progress
GCP            incidents.json, structured, with location IDs
DigitalOcean,  Statuspage JSON API (incidents + scheduled maintenance),
Linode,        matched on the incident's components and title
Cloudflare,
Scaleway
Hetzner        Atom feed listing only current and upcoming notices
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

import feedparser
import requests

log = logging.getLogger("skyfarer.feeds")


def _env_list(name: str) -> list[str]:
    return [v.strip() for v in os.getenv(name, "").split(",") if v.strip()]


# ─── Configuration ──────────────────────────────────────────────────────────

AWS_REGIONS = _env_list("AWS_REGIONS")
OVH_REGIONS = _env_list("OVH_REGIONS")
AZURE_REGIONS = _env_list("AZURE_REGIONS")
GCP_REGIONS = _env_list("GCP_REGIONS")
HETZNER_REGIONS = _env_list("HETZNER_REGIONS")
FILTER_KEYWORDS = _env_list("FILTER_KEYWORDS")

OVH_FEED_URL = os.getenv("OVH_FEED_URL", "https://public-cloud.status-ovhcloud.com/history.rss")
AZURE_FEED_URL = os.getenv("AZURE_FEED_URL", "https://rssfeed.azure.status.microsoft/en-us/status/feed/")
GCP_INCIDENTS_URL = os.getenv("GCP_INCIDENTS_URL", "https://status.cloud.google.com/incidents.json")
HETZNER_FEED_URL = os.getenv("HETZNER_FEED_URL", "https://status.hetzner.com/en.atom")

AWS_FEED_TEMPLATE = "https://status.aws.amazon.com/rss/multipleservices-{region}.rss"
AZURE_STATUS_PAGE = "https://azure.status.microsoft/en-us/status/"
GCP_STATUS_PAGE = "https://status.cloud.google.com/"
HETZNER_STATUS_PAGE = "https://status.hetzner.com/"
SUMMARY_LIMIT = 4000


@dataclass(frozen=True)
class StatuspageProvider:
    """A provider whose status page runs on Atlassian Statuspage, read through
    its public JSON API rather than the RSS feed: the API names the affected
    components (which is where these providers put the region) and gives each
    incident a stable ID and a machine-readable status."""
    name: str
    env: str          # prefix of its settings: <env>_REGIONS, <env>_STATUS_URL
    default_url: str

    @property
    def regions(self) -> list[str]:
        return _env_list(f"{self.env}_REGIONS")

    @property
    def base_url(self) -> str:
        return os.getenv(f"{self.env}_STATUS_URL", self.default_url).rstrip("/")


STATUSPAGE_PROVIDERS = (
    StatuspageProvider("DigitalOcean", "DIGITALOCEAN", "https://status.digitalocean.com"),
    StatuspageProvider("Linode", "LINODE", "https://status.linode.com"),
    StatuspageProvider("Cloudflare", "CLOUDFLARE", "https://www.cloudflarestatus.com"),
    StatuspageProvider("Scaleway", "SCALEWAY", "https://status.scaleway.com"),
)


def watched_regions() -> dict[str, list[str]]:
    """Every provider and the regions watched on it, in display order. A
    provider with no regions is switched off."""
    regions = {
        "AWS": AWS_REGIONS, "Azure": AZURE_REGIONS, "GCP": GCP_REGIONS,
        "OVH": OVH_REGIONS,
    }
    for p in STATUSPAGE_PROVIDERS:
        regions[p.name] = p.regions
    regions["Hetzner"] = HETZNER_REGIONS
    return regions


PROVIDER_NAMES = tuple(watched_regions())

# ─── Status markers ─────────────────────────────────────────────────────────

# OVH's feed is a Statuspage feed: each entry's description lists its updates,
# newest first, each one labelled with a status word. Only the newest label
# says where the incident stands now.
STATUSPAGE_LATEST_STATUS = re.compile(
    r"</small>\s*(?:<br\s*/?>)?\s*<strong>([^<]+)</strong>", re.IGNORECASE)
STATUSPAGE_DONE = {"resolved", "completed", "postmortem"}

# AWS marks the end of an event in the title ("Informational message:
# [RESOLVED] ...", "Service is operating normally: [RESOLVED] ...").
RESOLVED_TITLE_MARKERS = ("[resolved]", "service is operating normally")
RESOLVED_PHRASES = ("the issue has been resolved",)

# Azure's end state is a title prefix ("Mitigated - ..."). The feed only lists
# events in progress, so an entry can also just disappear when one ends.
AZURE_RESOLVED_TITLE = re.compile(r"^\s*(mitigated|resolved)\b", re.IGNORECASE)

# How a Statuspage RSS entry marks planned work rather than a fault.
SCHEDULED_MARKER = "this is a scheduled event"

# Hetzner labels each update with a status word (<strong>In_progress</strong>,
# <strong>Update</strong>, ...), newest first. Maintenance moves through
# planned -> in progress -> completed; incidents through investigating ->
# identified -> monitoring -> resolved.
HETZNER_STATUS = re.compile(r"<strong>\s*([^<]+?)\s*</strong>", re.IGNORECASE)
HETZNER_DONE = {"resolved", "completed", "finished"}
HETZNER_MAINTENANCE_WORDS = {"planned", "scheduled", "in_progress", "in progress", "completed"}
HETZNER_START = re.compile(r"<p>\s*Start:\s*([0-9T:+\-]+)\s*</p>")


# ─── Data model ─────────────────────────────────────────────────────────────

@dataclass
class FeedEntry:
    """Represents a single entry from a provider's status feed."""
    provider: str
    region: str
    guid: str
    title: str
    summary: str
    link: str
    published: str
    updated: str
    is_resolved: bool
    published_dt: Optional[datetime]
    updated_dt: Optional[datetime]
    is_maintenance: bool = False


class FeedErrors:
    """Feeds that couldn't be read this cycle, for poll_log and the dashboard.
    A provider with an unreadable feed still has its incidents left as they
    were: only a good read can close anything."""

    def __init__(self) -> None:
        self.errors: dict[str, str] = {}

    def add(self, provider: str, message: str) -> None:
        log.error("%s feed: %s", provider, message)
        self.errors.setdefault(provider, message)

    def summary(self) -> Optional[str]:
        if not self.errors:
            return None
        return "; ".join(f"{p}: {m}" for p, m in self.errors.items())


# ─── Helpers ────────────────────────────────────────────────────────────────

def _clean(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html or "")
    return re.sub(r"\s+", " ", text).strip()


def _pub_date(entry) -> str:
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        return time.strftime("%Y-%m-%d %H:%M UTC", entry.published_parsed)
    return entry.get("published", entry.get("updated", "unknown"))


def _updated_date(entry) -> str:
    if hasattr(entry, "updated_parsed") and entry.updated_parsed:
        return time.strftime("%Y-%m-%d %H:%M UTC", entry.updated_parsed)
    if entry.get("updated"):
        return entry["updated"]
    return _pub_date(entry)


def _pub_dt(entry) -> Optional[datetime]:
    """The feed's own published time, as a real datetime (UTC) -None if unparseable."""
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        return datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
    return None


def _updated_dt(entry) -> Optional[datetime]:
    """The feed's own updated time, as a real datetime (UTC) -falls back to published."""
    if hasattr(entry, "updated_parsed") and entry.updated_parsed:
        return datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc)
    return _pub_dt(entry)


def iso_dt(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp to UTC -None if missing or unparseable."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        return None


def fmt_dt(value: Optional[datetime]) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "unknown"


def region_pattern(region: str) -> re.Pattern:
    """Match a region code as a whole word, so GRA finds [GRA] and GRA11 but
    not upGRAde or miGRAted. A code ending in a letter also takes a site
    number (GRA -> GRA7, fr-par -> fr-par-1); one ending in a digit is exact
    (GRA7 is not GRA71, NBG1 is not NBG10)."""
    suffix = r"(?:-?\d+)?" if region[-1:].isalpha() else ""
    return re.compile(rf"(?<![A-Z0-9]){re.escape(region)}{suffix}(?![A-Z0-9])",
                      re.IGNORECASE)


def azure_region_pattern(region: str) -> re.Pattern:
    """Match an Azure region name exactly: West US is not West US 2, and
    Central US is not South Central US."""
    return re.compile(
        rf"(?<![A-Z0-9])(?<!North )(?<!South )(?<!West )(?<!East )"
        rf"{re.escape(region)}(?![A-Z0-9])(?!\s*\d)",
        re.IGNORECASE)


def _match_regions(regions: list[str], text: str) -> list[str]:
    """The watched regions named in `text`. `*` watches everything."""
    if "*" in regions:
        return ["all"]
    return [r for r in regions if region_pattern(r).search(text)]


def matches_filter(entry) -> bool:
    """True if the entry should be ingested. With no FILTER_KEYWORDS
    configured, everything passes -this is an opt-in narrowing filter."""
    if not FILTER_KEYWORDS:
        return True
    blob = f"{entry.get('title', '')} {entry.get('summary', entry.get('description', ''))}".upper()
    return any(kw.upper() in blob for kw in FILTER_KEYWORDS)


def safe_link(raw_link: str, fallback: str) -> str:
    """Only ever store an http(s) link -this value ends up rendered into an
    <a href> on the dashboard, and feed content is untrusted input."""
    scheme = urlsplit(raw_link or "").scheme.lower()
    if scheme in ("http", "https"):
        return raw_link
    return fallback


def _parse(provider: str, url: str, errors: FeedErrors):
    """feedparser never raises on a network error; it hands back an empty
    feed. Returns None (and records why) unless the feed was really read."""
    try:
        feed = feedparser.parse(url)
    except Exception as exc:
        errors.add(provider, type(exc).__name__)
        return None
    status = getattr(feed, "status", None)
    if status is None or status >= 400:
        reason = getattr(feed, "bozo_exception", None)
        errors.add(provider, f"HTTP {status}" if status else
                   (type(reason).__name__ if reason else "no response"))
        return None
    return feed


def _is_resolved(entry) -> bool:
    """True if an RSS entry says the incident is over.

    Checks the provider's own status markers, not every word of the text:
    prose such as "power has not yet been restored" or "the console is
    operational, though customers..." is an update on a live incident.
    """
    match = STATUSPAGE_LATEST_STATUS.search(entry.get("summary", ""))
    if match:
        return match.group(1).strip().lower() in STATUSPAGE_DONE
    title = entry.get("title", "").lower()
    text = _clean(entry.get("summary", entry.get("description", ""))).lower()
    return (any(marker in title for marker in RESOLVED_TITLE_MARKERS)
            or any(phrase in text for phrase in RESOLVED_PHRASES))


# ─── AWS, OVH, Azure, Google Cloud ──────────────────────────────────────────

def fetch_aws_entries(errors: FeedErrors) -> list[FeedEntry]:
    entries: list[FeedEntry] = []
    for region in AWS_REGIONS:
        url = AWS_FEED_TEMPLATE.format(region=region)
        log.info("Polling AWS  %s", url)
        feed = _parse("AWS", url, errors)
        if feed is None:
            continue
        for entry in feed.entries:
            if not matches_filter(entry):
                continue
            guid = entry.get("id") or entry.get("link") or entry.get("title", "")
            entries.append(FeedEntry(
                provider="AWS", region=region, guid=guid,
                title=entry.get("title", "(no title)"),
                summary=_clean(entry.get("summary", entry.get("description", ""))),
                link=safe_link(entry.get("link", url), url),
                published=_pub_date(entry),
                updated=_updated_date(entry),
                is_resolved=_is_resolved(entry),
                published_dt=_pub_dt(entry),
                updated_dt=_updated_dt(entry),
            ))
    return entries


def fetch_ovh_entries(errors: FeedErrors) -> list[FeedEntry]:
    entries: list[FeedEntry] = []
    if not OVH_REGIONS:
        return entries
    log.info("Polling OVH  %s", OVH_FEED_URL)
    feed = _parse("OVH", OVH_FEED_URL, errors)
    if feed is None:
        return entries
    for entry in feed.entries:
        guid = entry.get("id") or entry.get("link") or entry.get("title", "")
        text = f"{entry.get('title', '')} {_clean(entry.get('summary', entry.get('description', '')))}"
        matched = _match_regions(OVH_REGIONS, text)
        if not matched or not matches_filter(entry):
            continue
        entries.append(FeedEntry(
            provider="OVH", region=", ".join(matched), guid=guid,
            title=entry.get("title", "(no title)"),
            summary=_clean(entry.get("summary", entry.get("description", ""))),
            link=safe_link(entry.get("link", OVH_FEED_URL), OVH_FEED_URL),
            published=_pub_date(entry),
            updated=_updated_date(entry),
            is_resolved=_is_resolved(entry),
            published_dt=_pub_dt(entry),
            updated_dt=_updated_dt(entry),
            is_maintenance=SCHEDULED_MARKER in entry.get("summary", "").lower(),
        ))
    return entries


def fetch_azure_entries(errors: FeedErrors) -> tuple[list[FeedEntry], Optional[set[str]]]:
    """Returns the entries to process, and every region the feed currently
    lists an event for. The second value is None unless the feed was
    definitely read, because an empty result then means "nothing is wrong"
    and open incidents get closed on the strength of it."""
    entries: list[FeedEntry] = []
    if not AZURE_REGIONS:
        return entries, None
    log.info("Polling Azure  %s", AZURE_FEED_URL)
    feed = _parse("Azure", AZURE_FEED_URL, errors)
    if feed is None:
        return entries, None
    if getattr(feed, "status", None) != 200 or not feed.feed.get("title"):
        errors.add("Azure", f"feed unreadable (status {getattr(feed, 'status', None)})")
        return entries, None

    patterns = {r: azure_region_pattern(r) for r in AZURE_REGIONS if r != "*"}
    listed: set[str] = set()
    for entry in feed.entries:
        title = entry.get("title", "(no title)")
        summary = _clean(entry.get("summary", entry.get("description", "")))
        if "*" in AZURE_REGIONS:
            matched = ["all"]
        else:
            matched = [r for r, pattern in patterns.items()
                       if pattern.search(f"{title} {summary}")]
        if not matched:
            log.info("Azure entry names no watched region: %s", title)
            continue
        listed.update(matched)
        if not matches_filter(entry):
            continue
        if not _pub_dt(entry):
            log.warning("Azure entry has no parseable date: %s", title)
        # One Azure event is reworded repeatedly, and whether its ID survives
        # that isn't documented. Keying on the content makes any change a new
        # update, whichever way the feed behaves.
        raw_id = entry.get("id") or entry.get("link") or title
        digest = hashlib.sha1(f"{title}\n{summary}".encode()).hexdigest()[:12]
        entries.append(FeedEntry(
            provider="Azure", region=", ".join(matched), guid=f"{raw_id}#{digest}",
            title=title, summary=summary,
            link=safe_link(entry.get("link", AZURE_STATUS_PAGE), AZURE_STATUS_PAGE),
            published=_pub_date(entry),
            updated=_updated_date(entry),
            is_resolved=bool(AZURE_RESOLVED_TITLE.search(title)),
            published_dt=_pub_dt(entry),
            updated_dt=_updated_dt(entry),
        ))
    return entries, listed


def _get_json(provider: str, url: str, errors: FeedErrors):
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": "skyfarer"})
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        errors.add(provider, f"HTTP {exc.response.status_code}")
    except (requests.RequestException, ValueError) as exc:
        errors.add(provider, type(exc).__name__)
    return None


def fetch_gcp_entries(errors: FeedErrors) -> list[FeedEntry]:
    """Google publishes structured incidents: one stable ID each, location IDs
    such as europe-west2, and an `end` time once an incident is over."""
    entries: list[FeedEntry] = []
    if not GCP_REGIONS:
        return entries
    log.info("Polling GCP  %s", GCP_INCIDENTS_URL)
    incidents = _get_json("GCP", GCP_INCIDENTS_URL, errors)
    if incidents is None:
        return entries

    for incident in incidents:
        locations = {loc.get("id") for key in ("currently_affected_locations",
                                               "previously_affected_locations")
                     for loc in incident.get(key) or []}
        matched = (["all"] if "*" in GCP_REGIONS
                   else [r for r in GCP_REGIONS if r in locations])
        if not matched:
            continue
        products = ", ".join(p.get("title", "") for p in incident.get("affected_products") or [])
        title = incident.get("external_desc") or incident.get("service_name") or "(no title)"
        detail = (incident.get("most_recent_update") or {}).get("text", "")
        summary = _clean(f"{products}: {detail}" if products else detail)[:SUMMARY_LIMIT]
        if not matches_filter({"title": title, "summary": summary}):
            continue
        begin = iso_dt(incident.get("begin"))
        end = iso_dt(incident.get("end"))
        last = end or iso_dt(incident.get("modified")) or begin
        link = GCP_STATUS_PAGE + incident.get("uri", "")
        entries.append(FeedEntry(
            provider="GCP", region=", ".join(matched), guid=f"gcp:{incident.get('id')}",
            title=title, summary=summary,
            link=safe_link(link, GCP_STATUS_PAGE),
            published=fmt_dt(begin),
            updated=fmt_dt(last),
            is_resolved=end is not None,
            published_dt=begin,
            updated_dt=last,
        ))
    return entries


# ─── Statuspage JSON (DigitalOcean, Linode, Cloudflare, Scaleway) ───────────

def statuspage_entry(provider: StatuspageProvider, item: dict,
                     maintenance: bool) -> Optional[FeedEntry]:
    """One incident or scheduled maintenance from the Statuspage API, or None
    if it touches no watched region. Regions are matched against the names of
    the affected components and the title, not the update text, which tends
    to list every product the provider has."""
    components = [c.get("name", "") for c in item.get("components") or []]
    title = item.get("name") or "(no title)"
    matched = _match_regions(provider.regions, " | ".join([title, *components]))
    if not matched:
        return None

    updates = item.get("incident_updates") or []   # newest first
    latest = updates[0] if updates else {}
    status = (item.get("status") or "").lower()
    detail = _clean(latest.get("body", ""))
    if latest.get("status"):
        detail = f"{latest['status'].replace('_', ' ').capitalize()}: {detail}"
    affected = ", ".join(components)
    summary = (f"{detail} (Affects: {affected})" if affected else detail)[:SUMMARY_LIMIT]
    if not matches_filter({"title": title, "summary": summary}):
        return None

    if maintenance:
        start = iso_dt(item.get("scheduled_for")) or iso_dt(item.get("created_at"))
    else:
        start = iso_dt(item.get("started_at")) or iso_dt(item.get("created_at"))
    last = (iso_dt(item.get("resolved_at")) or iso_dt(item.get("updated_at"))
            or start)
    link = f"{provider.base_url}/incidents/{item.get('id', '')}"
    return FeedEntry(
        provider=provider.name, region=", ".join(matched),
        guid=f"{provider.name.lower()}:{item.get('id')}",
        title=title, summary=summary,
        link=safe_link(link, provider.base_url),
        published=fmt_dt(start), updated=fmt_dt(last),
        is_resolved=status in STATUSPAGE_DONE,
        published_dt=start, updated_dt=last,
        is_maintenance=maintenance,
    )


def fetch_statuspage_entries(provider: StatuspageProvider,
                             errors: FeedErrors) -> list[FeedEntry]:
    entries: list[FeedEntry] = []
    if not provider.regions:
        return entries
    for path, key, maintenance in (
            ("incidents.json", "incidents", False),
            ("scheduled-maintenances.json", "scheduled_maintenances", True)):
        url = f"{provider.base_url}/api/v2/{path}"
        log.info("Polling %s  %s", provider.name, url)
        data = _get_json(provider.name, url, errors)
        if not isinstance(data, dict):
            continue
        for item in data.get(key) or []:
            entry = statuspage_entry(provider, item, maintenance)
            if entry:
                entries.append(entry)
    return entries


# ─── Hetzner ────────────────────────────────────────────────────────────────

def hetzner_entry(entry) -> tuple[str, Optional[FeedEntry]]:
    """Returns the notice's stable ID, and the entry if it touches a watched
    region. Hetzner's entry IDs end in an update counter
    (.../<uuid>/3), so the ID without it is the one that lasts."""
    raw_id = entry.get("id") or entry.get("link") or entry.get("title", "")
    notice_id = re.sub(r"/\d+$", "", raw_id)
    title = entry.get("title", "(no title)")
    content = ""
    if entry.get("content"):
        content = entry["content"][0].get("value", "")
    content = content or entry.get("summary", "")
    categories = [t.get("term", "") for t in entry.get("tags") or []]
    text = _clean(content)

    matched = _match_regions(HETZNER_REGIONS, " | ".join([title, *categories, text]))
    if not matched:
        return notice_id, None
    if not matches_filter({"title": title, "summary": text}):
        return notice_id, None

    words = [w.strip().lower() for w in HETZNER_STATUS.findall(content)]
    status = next((w for w in words if w != "update"), "")
    start = iso_dt((HETZNER_START.search(content) or [None, None])[1]) or _pub_dt(entry)
    updated = _updated_dt(entry) or start
    is_maintenance = ("maintenance" in title.lower()
                      or any(w in HETZNER_MAINTENANCE_WORDS for w in words)
                      or bool(start and start > datetime.now(timezone.utc)))
    summary = text[:SUMMARY_LIMIT]
    if status:
        summary = f"{status.replace('_', ' ').capitalize()}: {summary}"[:SUMMARY_LIMIT]
    return notice_id, FeedEntry(
        provider="Hetzner", region=", ".join(matched),
        guid=f"hetzner:{notice_id.rsplit('/', 1)[-1]}",
        title=title, summary=summary,
        link=safe_link(entry.get("link", HETZNER_STATUS_PAGE), HETZNER_STATUS_PAGE),
        published=fmt_dt(start), updated=fmt_dt(updated),
        is_resolved=status in HETZNER_DONE,
        published_dt=start, updated_dt=updated,
        is_maintenance=is_maintenance,
    )


def fetch_hetzner_entries(errors: FeedErrors) -> tuple[list[FeedEntry], Optional[set[str]]]:
    """Like Azure, Hetzner's feed only lists current and upcoming notices, so
    a notice that leaves it has ended. The second value is the guid of every
    notice listed, or None unless the feed was definitely read."""
    entries: list[FeedEntry] = []
    if not HETZNER_REGIONS:
        return entries, None
    log.info("Polling Hetzner  %s", HETZNER_FEED_URL)
    feed = _parse("Hetzner", HETZNER_FEED_URL, errors)
    if feed is None:
        return entries, None
    if not feed.feed.get("title"):
        errors.add("Hetzner", "feed unreadable")
        return entries, None
    listed: set[str] = set()
    for raw in feed.entries:
        notice_id, entry = hetzner_entry(raw)
        listed.add(f"hetzner:{notice_id.rsplit('/', 1)[-1]}")
        if entry:
            entries.append(entry)
    return entries, listed
