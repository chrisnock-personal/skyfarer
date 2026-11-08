<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="static/skyfarer-logo-dark.svg">
    <img src="static/skyfarer-logo-light.svg" alt="Skyfarer" width="300">
  </picture>
</p>

**Skyfarer** keeps watch over the clouds you run on. It polls the public status
pages of AWS, Azure, Google Cloud, OVHcloud, DigitalOcean, Hetzner, Linode,
Cloudflare and Scaleway for incidents and maintenance in the regions you care
about. It raises Zendesk tickets or ServiceNow incidents and sends Pushover,
PagerDuty, Microsoft Teams, SNMP trap and webhook notifications, then follows
up when the provider marks the incident clear.

Providers, regions, channels and their keys are set in the dashboard, by
admins; viewers see the dashboard only. Everything is held in **Postgres**,
and the whole stack runs in Docker Compose.


## Quick start

```bash
cp .env.example .env         # set SKYFARER_SECRET_KEY; regions and channels optional
docker compose up -d          # builds the image, starts Postgres, the poller and the dashboard
docker compose logs dashboard # shows the one-time setup code
```

Then open `http://127.0.0.1:8080`, enter the setup code and create the first
admin account. Whatever regions and channels `.env` had are imported on that
first start; from then on they're changed in the dashboard, under Settings.

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
│  └────────────┘        │  web UI and settings         │        │
│                         └──────────────────────────┘        │
└───────────────────────────────────────────────────────────┘
         ▲                              ▲
         │ 127.0.0.1:5432               │ 127.0.0.1:8080
         │ psql / pgAdmin                │ browser
```

## Dashboard

The dashboard is at `http://127.0.0.1:8080` once the stack is up, for everyone
with an account. It opens in dark mode; the button at the top right switches to
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
  All) and provider; Zendesk and ServiceNow ticket numbers link to the ticket
- The last 50 notifications, with their status, attempts and any error
- The last 50 rows of `poll_log`, with errors called out
- Full-text search across incident title, summary, region, provider, and
  every stored update
- Time-range filtering (Today / 7d / 30d / 90d / All time, or a custom
  from–to date range), applied to the incidents, notifications and poll_log
  tables

The page auto-refreshes every 30 seconds. Admins also see **Settings**.

## Settings and accounts

Only three things stay in `.env`: `SKYFARER_SECRET_KEY`, the Postgres
connection and the dashboard's address (plus the feed URLs, which only change
for testing). Everything else is kept in the database and changed in the
dashboard:

- **Providers and regions.** Each provider can be switched on or off without
  losing its regions. Regions are added as tags, with suggestions of common
  codes, and there's the keyword filter and the poll interval.
- **Channels.** The alert rules (which events, how old is too old, how long to
  retry, maintenance), then Zendesk, ServiceNow, Pushover, PagerDuty, Teams and
  SNMP, each with its own switch, editor and test button. A test uses the saved
  settings: a ServiceNow test creates a record and resolves it, a Zendesk test
  opens a ticket and sets it to pending.
- **Webhooks.** Any number, each with its own URL, method, events, template,
  headers and signing secret.
- **Users and access.** Admins see and change everything; viewers see the
  dashboard and nothing under Settings. There's always at least one admin, and
  nobody can change their own role.

**How changes take effect.** The poller reloads the settings at the start of
every poll, so a change applies within one poll interval, without a restart.
Settings are checked when they're saved: a template with an unknown field,
extra fields that aren't JSON, or a channel left half set up is refused with a
message, and nothing is saved.

**Secrets.** Keys, passwords, tokens, Teams' workflow URL and webhook headers
are encrypted in the database with a key derived from `SKYFARER_SECRET_KEY`.
Once saved they can't be read back through the dashboard: it shows when and by
whom each was set, and offers to replace or remove it. Keep the secret key with
your backups: without it, the stored secrets can't be decrypted and have to be
entered again.

**Accounts.** On the first visit with no accounts, the dashboard asks for a
setup code that it prints to its own log, so whoever reaches the page first
can't take the admin account. Further people are added by an admin, who gets a
one-time setup link to pass on (Skyfarer sends no email); it expires after 24
hours. The same is how a forgotten password is reset. Passwords are hashed
(scrypt); after five wrong attempts for one email from one address, that pair
waits 15 minutes.
Sessions last 12 hours. Behind an HTTPS proxy, set `DASHBOARD_HTTPS=true` so
the session cookie is only sent over HTTPS.

**Change history.** Every change is recorded with who made it and when,
including switches, regions added and removed, and users added or removed.
Secret changes are recorded as "replaced" or "removed", never with the value.

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

### `tickets`

Records in ticketing systems other than Zendesk, whose ticket number is
`incidents.ticket_id`. One row per incident per system.

| Column | Type | Notes |
|--------|------|-------|
| incident_id | integer | FK to `incidents.id` |
| system | text | `servicenow` |
| ref | text | the system's own ID (a ServiceNow `sys_id`) |
| number | text | what people call it (`INC0010001`) |
| created_at | timestamptz | when it was created |

### `notifications`

The delivery queue: one row per notice per channel. See
[Notifications](#notifications).

| Column | Type | Notes |
|--------|------|-------|
| incident_id | integer | FK to `incidents.id` |
| channel | text | `zendesk`, `servicenow`, `pushover`, `pagerduty`, `teams` or `snmp` |
| event | text | `opened`, `updated` or `resolved` |
| payload | jsonb | the notice's content |
| status | text | `pending`, `sent` or `failed` |
| attempts | integer | delivery attempts so far |
| last_error | text | why the last attempt failed |
| created_at | timestamptz | when it was queued |
| next_attempt_at | timestamptz | earliest next try |
| sent_at | timestamptz | when it was delivered |

### `settings`, `webhooks`, `users`, `settings_log`

The dashboard's settings (keyed by their `.env` names, secrets encrypted),
the webhooks, the accounts (password hashes, and setup links as SHA-256 hashes)
and the change history. See [Settings and accounts](#settings-and-accounts).

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
Feed entry appears         → row inserted (state=open), notices queued,
                             Zendesk ticket / ServiceNow record created
Feed entry updated         → re-checked each cycle for a resolved status
Resolved status found      → row → resolved, notices queued,
                             Zendesk note + ticket → pending,
                             ServiceNow work note + record → Resolved
Operator reviews & closes  → manual step in Zendesk; ServiceNow auto-closes
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

Six channels plus any number of webhooks, each set up under Settings >
Channels (or in `.env` before the first start). Any can run alone. Zendesk and
ServiceNow are the ticketing channels; the rest alert people and systems. The
settings column gives each setting's name in `.env` and in the database.

| Channel | What it sends | Settings |
|---------|---------------|----------|
| Zendesk | A ticket, internal notes for updates, pending when resolved | `ZENDESK_*`, `ZD_TICKET_*` |
| ServiceNow | A record in the `incident` table through the Table API, work notes for updates, Resolved (with a close code) when the incident ends | `SERVICENOW_*` |
| Pushover | A push message per event, with a link to the status page | `PUSHOVER_TOKEN`, `PUSHOVER_USER`, `PUSHOVER_PRIORITY` |
| PagerDuty | An Events API v2 alert, resolved automatically when the incident ends | `PAGERDUTY_ROUTING_KEY`, `PAGERDUTY_SEVERITY` |
| Microsoft Teams | An Adaptive Card, posted to a Workflows webhook | `TEAMS_WEBHOOK_URL` |
| SNMP traps | A v2c trap to each receiver, defined in `SKYFARER-MIB.txt` | `SNMP_TRAP_TARGETS`, `SNMP_COMMUNITY`, `SNMP_BASE_OID` |
| Webhooks | A request to any URL, with a JSON document or a body of your own | One per webhook, under Settings; `WEBHOOK_*` in `.env` describes the first |

**What reaches the channels that interrupt people.** Zendesk and ServiceNow
record every incident. The other channels skip incidents published more than
`NOTIFY_MAX_AGE_HOURS` ago (24) and scheduled maintenance
(`NOTIFY_MAINTENANCE`), so a first start doesn't page anyone for what's already
in the feeds or for next month's work. They get the events in `NOTIFY_EVENTS`,
by default `opened` and `resolved`. A channel only hears that an incident ended
if it heard it begin.

**How delivery works.** A poll cycle queues notices in the `notifications` table
in the same transaction that records the incident, and they're sent after it
commits. So a cycle that fails partway sends nothing and repeats nothing, each
channel fails and retries alone, and a ticketing outage doesn't delay a page.
Notices for one incident on one channel stay in order.

| Result | What happens |
|--------|--------------|
| Network error, HTTP 5xx | Retried with growing gaps, up to an hour apart, for `NOTIFY_RETRY_HOURS` (24) |
| HTTP 429 | The same, except Pushover, whose rules say not to retry a 4xx |
| HTTP 401, 403 from Zendesk or ServiceNow | The same, so tickets survive an expired token or password |
| Other HTTP 4xx | Marked failed, not retried |

**ServiceNow.** Records are created through the Table API (`/api/now/table/incident`
by default, `SERVICENOW_TABLE` to change it) as an integration user with
`SERVICENOW_USER` and `SERVICENOW_PASSWORD`, or with an OAuth bearer token in
`SERVICENOW_TOKEN`. Each record gets `correlation_id` `skyfarer-<incident id>`
and `correlation_display` `Skyfarer`, so it can be found from the incident and
matched by dedup rules. Impact and urgency (1 to 3), the assignment group,
caller and category are settings, and `SERVICENOW_EXTRA_FIELDS` takes a JSON
object of any other fields, such as `{"contact_type": "monitoring"}`. When the
provider says it's over, the record moves to Resolved (state 6) with
`SERVICENOW_CLOSE_CODE` and close notes, and ServiceNow's own auto-close closes
it later; `SERVICENOW_RESOLVE=false` only adds a work note and leaves it for a
person. The close code must be one your instance accepts.

**Webhooks.** For anything else: a chat tool, an on-call service, an automation
platform or your own system, as many as you need. Each sends its own requests,
retries alone and has its own row in the dashboard's delivery health. By
default a webhook sends a JSON document:

```json
{"source": "skyfarer", "event": "opened", "incident_id": 42, "provider": "DigitalOcean",
 "region": "LON1", "title": "Droplet creates failing in LON1", "summary": "Investigating: ...",
 "link": "https://status.digitalocean.com/incidents/abc123", "published": "2026-11-08 15:03 UTC",
 "updated": "2026-11-08 15:03 UTC", "noticed": "2026-11-08 15:03 UTC", "update_count": 0}
```

`incident_id` is the same on an incident's `opened` and `resolved` notices, so
the receiver can pair them; the `X-Skyfarer-Event` and `X-Skyfarer-Incident`
headers carry both too. A body template replaces the document with your own,
filling in `{{field}}` placeholders; with a JSON content type, each value is
escaped for use inside a JSON string, so a Slack-style message is:

```
{"text": "{{event}}: [{{provider}}] {{region}} {{title}} {{link}}"}
```

A template is checked when it's saved: an unknown placeholder, or one that
wouldn't make valid JSON, is refused with a message. Extra headers (a JSON
object) can carry an API key, and a signing secret signs each request with
`X-Skyfarer-Signature: sha256=<HMAC-SHA256 of the body>`, so the receiver can
check it came from Skyfarer. Each webhook can pick its own events; with none
ticked, it follows the alert rules.

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

   `*` watches everything a provider publishes. A provider with no regions, or
   switched off under Settings, isn't read at all.
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
or the dashboard. Both are set under Settings > Providers and regions, and a
change applies from the next poll.

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
retry, what gets queued for which channel, delivery order, and settings checks,
plus region matching and parsing for the Statuspage and Hetzner feeds (from
trimmed copies of real payloads), and how stored settings reach the poller,
switches, secret encryption and the change history's wording. They need no
database or network.

## .env reference

See `.env.example` for the full list with comments. Apart from
`SKYFARER_SECRET_KEY`, Postgres, the dashboard's address and the feed URLs,
those settings are read once, on the first start, and imported into the
database; after that, change them in the dashboard.
