<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="static/skyfarer-logo-dark.svg">
    <img src="static/skyfarer-logo-light.svg" alt="Skyfarer" width="300">
  </picture>
</p>

**Skyfarer** keeps watch over the clouds you run on. It polls the public status
pages of AWS, Azure, Google Cloud, OVHcloud, DigitalOcean, Hetzner, Linode,
Cloudflare and Scaleway for incidents and maintenance in the regions you care
about. It raises Zendesk tickets and sends Pushover, PagerDuty, Microsoft Teams
and SNMP trap notifications, then follows up when the provider marks the
incident clear.

All incident state is held in **Postgres** -no local JSON files.  The whole stack runs in Docker Compose.

Skyfarer was called Cloud Status Poller until November 2026. See
[Upgrading from Cloud Status Poller](#upgrading-from-cloud-status-poller).

## Quick start

```bash
cp .env.example .env         # fill in your regions and notification channels
docker compose up -d          # builds the poller image, starts Postgres
docker compose logs -f poller # watch it work
```

To tear it down (data is preserved in the `pgdata` volume):

```bash
docker compose down
```

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│  docker compose                                            │
│                                                             │
│                        ┌──────────────────────────┐        │
│                   ┌───►│  poller                   │        │
│  ┌────────────┐   │    │  poll status feeds         │        │
│  │  postgres   │◄──┤    │  ↕ send notifications      │        │
│  │  :5432      │   │    │  ↕ write to postgres       │        │
│  │             │   │    └──────────────────────────┘        │
│  │  incidents  │   │    ┌──────────────────────────┐        │
│  │  poll_log   │   └───►│  dashboard                 │        │
│  └────────────┘        │  read-only web UI            │        │
│                         └──────────────────────────┘        │
└───────────────────────────────────────────────────────────┘
         ▲                              ▲
         │ 127.0.0.1:5432               │ 127.0.0.1:8080
         │ psql / pgAdmin                │ browser
```

## Dashboard

A read-only web dashboard is available at `http://127.0.0.1:8080` once the
stack is up. It opens in dark mode; the button at the top right switches to
light, and the browser remembers the choice. It shows:

- Summary tiles: open incidents and which providers they're on, maintenance
  under way and scheduled, new incidents in the last 24 hours, undelivered
  notices, and the last poll cycle
- A card per watched provider: its regions, and whether it's operational,
  has open incidents, is in maintenance, or had a feed that couldn't be read
  on the last poll
- Delivery health per notification channel, and a chart of the last 24 poll
  cycles with failures marked
- The `incidents` table: live incidents first, then maintenance under way,
  then upcoming work (soonest first). Filter by state (Active / Resolved /
  All) and provider; Zendesk ticket numbers link to the ticket
- The last 50 notifications, with their status, attempts and any error
- The last 50 rows of `poll_log`, with errors called out
- Full-text search across incident title, summary, region, provider, and
  every stored update
- Time-range filtering (Today / 7d / 30d / 90d / All time, or a custom
  from–to date range), applied to the incidents, notifications and poll_log
  tables

It only issues `SELECT` queries -no notifications, no config changes, no
write access. The page auto-refreshes every 30 seconds.

## Database schema

### `incidents`

| Column | Type | Notes |
|--------|------|-------|
| id | serial | PK |
| guid | text | unique -the RSS entry ID (for AWS, the entry that opened the incident) |
| provider | text | AWS, Azure, GCP, OVH, DigitalOcean, Linode, Cloudflare, Scaleway or Hetzner |
| region | text | matched region(s) |
| title | text | feed entry title (for AWS and Azure, the newest update's) |
| summary | text | cleaned description (for AWS and Azure, the newest update's) |
| update_count | integer | later AWS or Azure entries attached to this incident |
| is_maintenance | boolean | planned work rather than a fault |
| link | text | URL to status page |
| feed_published | text | published timestamp from RSS |
| feed_updated | text | updated timestamp from RSS |
| state | text | `open` or `resolved` |
| ticket_id | integer | Zendesk ticket number |
| detected_at | timestamptz | when the incident actually started, per the feed's own `published` time (falls back to poll time if the feed entry has no parseable date) |
| resolved_at | timestamptz | when the incident actually resolved, per the feed's own `updated` time (same fallback) |
| ingested_at | timestamptz | when *our poller* first wrote this row -independent of the feed's own timeline, useful for spotting poller lag |
| created_at | timestamptz | row creation time |
| updated_at | timestamptz | last row modification |

Note: an incident that's already resolved the first time the poller sees it
(common for OVH maintenance notices) will have `detected_at` and `resolved_at`
set from the feed's published/updated timestamps -which may be identical if
the feed itself only reports one timestamp for the whole notice. That's a
real zero-duration event, not a poller artifact; `ingested_at` will show when
the poller actually picked it up, which can lag well behind both.

### `incident_updates`

AWS posts each update on an event as a separate feed entry with its own GUID,
and Azure rewords its entries as an event goes on. Each update is stored here
against the incident, one row per update.

| Column | Type | Notes |
|--------|------|-------|
| incident_id | integer | FK to `incidents.id` |
| guid | text | unique -the update's own RSS entry ID |
| title, summary, link | text | the update as published |
| feed_published | text | published timestamp from RSS |
| published_at | timestamptz | the same, parsed |
| ingested_at | timestamptz | when the poller stored it |

### `notifications`

The delivery queue: one row per notice per channel. See
[Notifications](#notifications).

| Column | Type | Notes |
|--------|------|-------|
| incident_id | integer | FK to `incidents.id` |
| channel | text | `zendesk`, `pushover`, `pagerduty`, `teams` or `snmp` |
| event | text | `opened`, `updated` or `resolved` |
| payload | jsonb | the notice's content |
| status | text | `pending`, `sent` or `failed` |
| attempts | integer | delivery attempts so far |
| last_error | text | why the last attempt failed |
| created_at | timestamptz | when it was queued |
| next_attempt_at | timestamptz | earliest next try |
| sent_at | timestamptz | when it was delivered |

### `poll_log`

One row per poll cycle -useful for spotting gaps or failures.

| Column | Type | Notes |
|--------|------|-------|
| polled_at | timestamptz | when the cycle ran |
| entries_seen | integer | total RSS entries parsed |
| tickets_created | integer | new incidents this cycle (the name predates the delivery queue) |
| tickets_resolved | integer | incidents resolved this cycle |
| open_count | integer | incidents still open |
| error | text | null on success |
| feed_errors | text | feeds that couldn't be read, as `Provider: reason; ...` |

## Incident lifecycle

```
RSS entry appears          → row inserted (state=open), notices queued, ZD ticket created
RSS entry updated          → re-checked each cycle for a resolved status
Resolved status found      → row → resolved, notices queued, ZD note + ticket → pending
Operator reviews & closes  → manual step in Zendesk
```

If an entry is already resolved the first time the poller sees it, it's recorded in the database but nothing is sent.

### How resolution is detected

Only the provider's own status markers count, not words in the text, so an
update such as "power has not yet been restored" leaves the incident open.

- **OVH** (a Statuspage feed): the status word on the newest update.
  `Resolved`, `Completed` and `Postmortem` end an incident; `Investigating`,
  `Identified`, `Monitoring`, `Scheduled` and the like don't.
- **AWS**: `[RESOLVED]` or `Service is operating normally` in the title, or
  "the issue has been resolved" in the text.
- **Azure**: a title starting `Mitigated` or `Resolved`, or the event leaving
  the feed. The feed only lists events in progress, so an open incident ends
  when nothing is listed for its regions any more. That check needs a good
  read of the feed: a failed fetch closes nothing.
- **Google Cloud**: the incident has an `end` time.
- **DigitalOcean, Linode, Cloudflare, Scaleway** (Statuspage JSON API): the
  incident's status is `resolved` or `postmortem`, or a maintenance's is
  `completed`.
- **Hetzner**: the newest update is labelled `Resolved` or `Completed`, or the
  notice leaves the feed. Like Azure's, the feed only lists current and
  upcoming notices, and only a good read of it closes anything.

A feed that can't be read leaves its incidents as they were, and is shown on
the dashboard and recorded in `poll_log.feed_errors`.

### Providers without a stable event ID

AWS publishes each update as a separate entry with its own GUID, no event ID,
and a title that changes as the event progresses. Within a region, everything
from the first unresolved entry to the entry that resolves it is one incident
with one ticket. New updates go on the ticket as a single internal note per
poll cycle, and on the dashboard the row shows the newest update and how many
there have been. Two separate AWS events open in one region at the same time
share one incident.

Azure is handled the same way, because one event's title gets reworded several
times. Any change to an entry's title or text counts as an update, and entries
sharing a watched region with an open incident belong to it.

Azure's feed has been empty whenever this has been checked, so this handling
comes from Azure's published history and reports of its feed's behaviour, not
from a live entry. Check it against the first real Azure event you see: entries
that name no watched region are logged, as are entries with no parseable date.


## Notifications

Five channels, each on once its settings in `.env` are filled in. At least one
is needed, and any can run alone, Zendesk included.

| Channel | What it sends | Settings |
|---------|---------------|----------|
| Zendesk | A ticket, internal notes for updates, pending when resolved | `ZENDESK_*`, `ZD_TICKET_*` |
| Pushover | A push message per event, with a link to the status page | `PUSHOVER_TOKEN`, `PUSHOVER_USER`, `PUSHOVER_PRIORITY` |
| PagerDuty | An Events API v2 alert, resolved automatically when the incident ends | `PAGERDUTY_ROUTING_KEY`, `PAGERDUTY_SEVERITY` |
| Microsoft Teams | An Adaptive Card, posted to a Workflows webhook | `TEAMS_WEBHOOK_URL` |
| SNMP traps | A v2c trap to each receiver, defined in `SKYFARER-MIB.txt` | `SNMP_TRAP_TARGETS`, `SNMP_COMMUNITY`, `SNMP_BASE_OID` |

**What reaches the channels that interrupt people.** Zendesk records every
incident. The other channels skip incidents published more than
`NOTIFY_MAX_AGE_HOURS` ago (24) and scheduled maintenance
(`NOTIFY_MAINTENANCE`), so a first start doesn't page anyone for what's already
in the feeds or for next month's work. They get the events in `NOTIFY_EVENTS`,
by default `opened` and `resolved`. A channel only hears that an incident ended
if it heard it begin.

**How delivery works.** A poll cycle queues notices in the `notifications` table
in the same transaction that records the incident, and they're sent after it
commits. So a cycle that fails partway sends nothing and repeats nothing, each
channel fails and retries alone, and a Zendesk outage doesn't delay a page.
Notices for one incident on one channel stay in order.

| Result | What happens |
|--------|--------------|
| Network error, HTTP 5xx | Retried with growing gaps, up to an hour apart, for `NOTIFY_RETRY_HOURS` (24) |
| HTTP 429 | The same, except Pushover, whose rules say not to retry a 4xx |
| HTTP 401, 403 from Zendesk | The same, so tickets survive an expired token |
| Other HTTP 4xx | Marked failed, not retried |

Failures show on the dashboard. Retries run once per poll cycle, so a retry
can't happen more often than `POLL_INTERVAL_SECONDS`. An SNMP trap is one UDP
packet with no acknowledgement: `sent` means it left this host, not that a
receiver got it. The MIB's OID sits under the experimental arc; if you have your
own enterprise number, change `SNMP_BASE_OID` and the MIB together.

## Useful queries

```sql
-- Current open incidents
SELECT provider, region, title, ticket_id, detected_at
  FROM incidents WHERE state = 'open' ORDER BY detected_at;

-- Average time-to-resolve by provider
SELECT provider,
       AVG(resolved_at - detected_at) AS avg_resolve_time
  FROM incidents
 WHERE state = 'resolved' AND resolved_at IS NOT NULL
 GROUP BY provider;

-- Last 20 poll cycles
SELECT * FROM poll_log ORDER BY polled_at DESC LIMIT 20;

-- Incidents in the last 7 days
SELECT * FROM incidents
 WHERE detected_at > NOW() - INTERVAL '7 days'
 ORDER BY detected_at DESC;
```

## Filtering what gets ingested

Two layers of filtering decide whether a feed entry is written to the
database at all:

1. **Region** (`*_REGIONS`) -AWS only polls the region
   feeds you list; OVH entries must mention one of your listed regions as a
   whole word. `GRA` matches `[GRA]`, `GRA11` and `gra7`, not "upgrade" or
   "migrated". A code ending in a digit is exact, and `SBG` is the safer
   setting for titles such as `[SBG5/7]`, where `SBG7` doesn't appear as such.
   Azure's `AZURE_REGIONS` takes display names, matched exactly: `West US`
   isn't `West US 2`, and `Central US` isn't `South Central US`. Include
   `Multiple Regions` to catch broad events, or use `*` for all of them.
   `GCP_REGIONS` takes location IDs from `incidents.json` (`europe-west2`,
   `global`), matched exactly.

   DigitalOcean, Linode, Cloudflare and Scaleway are read through their
   Statuspage JSON API, and regions are matched the same whole-word way
   against each incident's affected components and its title: `LON1` or
   `Global` on DigitalOcean, `GB-LON` or `Linode.com` on Linode, airport
   codes such as `LHR` on Cloudflare, `fr-par` (which also matches
   `fr-par-1`) on Scaleway. Hetzner's `HETZNER_REGIONS` takes locations
   (`FSN1`, `NBG1`, `HEL1`, `ASH`), matched against each notice's title,
   category and text; many Hetzner notices name no location, so add the
   categories `Network` or `General`, or `*`, to catch those.

   `*` watches everything a provider publishes. Leave a setting blank to turn
   that provider off.
2. **Keywords** (`FILTER_KEYWORDS`, optional) -a comma-separated list of
   words. If set, an entry must also contain at least one of these
   (case-insensitive, matched against title + summary) to be ingested.
   Leave it blank to ingest everything that already passes the region
   filter.

   ```
   FILTER_KEYWORDS=Compute,Storage
   ```

Entries that don't pass are skipped before any database write or
notification -they never appear in `incidents`, `poll_log`'s `entries_seen` count,
or the dashboard. This runs on every poll cycle, so changing `FILTER_KEYWORDS`
in `.env` takes effect the next time the poller restarts.

## Running outside Docker

If you prefer to run the poller directly:

```bash
pip install -r requirements.txt
export POSTGRES_HOST=localhost   # or wherever your PG is
python poller.py --init-db
python poller.py --once --dry-run   # test first
python poller.py                     # continuous
python dashboard.py                  # the dashboard, on :8080
```

## Modes

| Flag | Behaviour |
|------|-----------|
| *(none)* | Continuous loop, polling every `POLL_INTERVAL_SECONDS` |
| `--once` | Single poll then exit (ideal for cron) |
| `--dry-run` | Fetches feeds, logs matches, sends no notifications |
| `--init-db` | Creates tables/indexes then exits |

## Tests

```bash
python -m unittest discover tests
```

Covers each channel's payload against its published limits, which failures
retry, what gets queued for which channel, delivery order, and startup checks,
plus region matching and parsing for the Statuspage and Hetzner feeds (from
trimmed copies of real payloads). They need no database or network.

## Upgrading from Cloud Status Poller

The code now lives in `poller.py` (was `status_poller.py`) and `feeds.py`,
and the defaults changed to the new name. An existing install keeps working
if you:

- Add `PGDATA_VOLUME=cloud-status-poller_pgdata` to `.env`, so Compose (whose
  project is now called `skyfarer`) uses the volume your data is in, and keep
  `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB` at the values it was
  created with (`poller` / `poller` / `status_poller` by default). The schema
  gains two columns on the next start, with no other change.
- Keep `ZD_TICKET_TAGS` as it is if Zendesk views or triggers use the
  `cloud-status` tag; the new default is `skyfarer,auto-raised`.
- Load `SKYFARER-MIB.txt` on trap receivers in place of
  `CLOUD-STATUS-POLLER-MIB.txt`. The OIDs are unchanged; only the names are
  (`cspProvider` is now `sfProvider`, and so on).

PagerDuty dedup keys keep their `cloud-status-` prefix, so alerts raised
before the upgrade still resolve.

## .env reference

See `.env.example` for the full list with comments.
