"""Feed parsing for the providers added with the rename to Skyfarer, and the
region matching they share. Fixtures are trimmed from real payloads (November
2026). Run with: python -m unittest discover tests"""
import os
import sys
import unittest
from unittest import mock

import feedparser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import feeds  # noqa: E402

DO = feeds.StatuspageProvider("DigitalOcean", "DIGITALOCEAN", "https://status.digitalocean.com")
CLOUDFLARE = feeds.StatuspageProvider("Cloudflare", "CLOUDFLARE", "https://www.cloudflarestatus.com")
SCALEWAY = feeds.StatuspageProvider("Scaleway", "SCALEWAY", "https://status.scaleway.com")

DO_INCIDENT = {
    "id": "6z6dt3t1bhb9",
    "name": "A Network Disruption in BLR1 Region Impacted Multiple Products",
    "status": "monitoring", "impact": "major",
    "created_at": "2026-10-03T14:51:13.541Z",
    "started_at": "2026-10-03T14:20:00.000Z",
    "updated_at": "2026-10-03T15:10:00.000Z",
    "resolved_at": None,
    "components": [{"name": "Bangalore"}, {"name": "BLR1"}],
    "incident_updates": [
        {"status": "monitoring", "body": "A fix has been <b>implemented</b>."},
        {"status": "investigating", "body": "We are investigating."},
    ],
}

CLOUDFLARE_MAINTENANCE = {
    "id": "m1", "name": "EWR (Newark) on 2026-11-18", "status": "scheduled",
    "created_at": "2026-11-01T10:00:00.000Z",
    "scheduled_for": "2026-11-18T06:00:00.000Z",
    "updated_at": "2026-11-01T10:00:00.000Z", "resolved_at": None,
    "components": [{"name": "Newark, United States - (EWR)"}],
    "incident_updates": [{"status": "scheduled", "body": "Scheduled maintenance."}],
}

HETZNER_ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Hetzner Online GmbH - Status-Webseite</title>
  <id>https://status.hetzner.com/</id>
  <updated>2026-11-06T15:36:38+00:00</updated>
  <entry>
    <id>https://status.hetzner.com/cd31dd45-f431-4639-8f9a-d4bfb5353f30/1</id>
    <updated>2026-11-06T15:36:38+00:00</updated>
    <link href="https://status.hetzner.com/incident/cd31dd45-f431-4639-8f9a-d4bfb5353f30" />
    <title>Urgent maintenance on all core routers</title>
    <category term="Network"/>
    <content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">
      <p>Start: 2026-10-15T10:00:00+00:00</p>
      <p>We are currently carrying out urgent maintenance on all of our core routers.</p>
      <strong>In_progress</strong>
      <small>2026-11-06T15:36:38+00:00</small>
      <p>We are still in the process of performing this maintenance.</p>
    </div></content>
  </entry>
  <entry>
    <id>https://status.hetzner.com/77777777-0000-4000-8000-000000000001/2</id>
    <updated>2026-11-07T09:00:00+00:00</updated>
    <link href="https://status.hetzner.com/incident/77777777-0000-4000-8000-000000000001" />
    <title>Cloud servers unreachable in FSN1-DC14</title>
    <category term="Cloud Server"/>
    <content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">
      <p>Start: 2026-11-07T08:12:00+00:00</p>
      <p>Some cloud servers in FSN1-DC14 are unreachable.</p>
      <strong>Resolved</strong>
      <small>2026-11-07T09:00:00+00:00</small>
      <p>All servers are reachable again.</p>
      <strong>Investigating</strong>
      <small>2026-11-07T08:20:00+00:00</small>
      <p>We are looking into it.</p>
    </div></content>
  </entry>
  <entry>
    <id>https://status.hetzner.com/88888888-0000-4000-8000-000000000002/0</id>
    <updated>2026-11-07T09:00:00+00:00</updated>
    <link href="javascript:alert(1)" />
    <title>Power work in HEL1-DC2</title>
    <category term="HEL1-DC2"/>
    <content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">
      <p>Start: 2026-11-20T06:00:00+00:00</p>
      <p>Replacement of UPS components.</p>
    </div></content>
  </entry>
</feed>"""


def _env(**values):
    return mock.patch.dict(os.environ, values)


class RegionPattern(unittest.TestCase):
    def test_letter_codes_take_site_numbers(self):
        for region, text in (("GRA", "[GRA11]"), ("LON", "LON1"), ("fr-par", "fr-par-1"),
                             ("NBG1", "NBG1-DC2"), ("EWR", "Newark - (EWR)")):
            self.assertTrue(feeds.region_pattern(region).search(text), (region, text))

    def test_no_partial_words(self):
        for region, text in (("GRA", "upgrade"), ("LON", "London"), ("NBG1", "NBG10"),
                             ("fr-par", "fr-paris"), ("SIN", "single")):
            self.assertFalse(feeds.region_pattern(region).search(text), (region, text))


class Statuspage(unittest.TestCase):
    def test_incident_matches_on_component(self):
        with _env(DIGITALOCEAN_REGIONS="BLR1,LON1"):
            entry = feeds.statuspage_entry(DO, DO_INCIDENT, maintenance=False)
        self.assertEqual(entry.region, "BLR1")
        self.assertEqual(entry.guid, "digitalocean:6z6dt3t1bhb9")
        self.assertFalse(entry.is_resolved)
        self.assertFalse(entry.is_maintenance)
        self.assertTrue(entry.summary.startswith("Monitoring: A fix has been implemented"))
        self.assertIn("Affects: Bangalore, BLR1", entry.summary)
        self.assertEqual(entry.link, "https://status.digitalocean.com/incidents/6z6dt3t1bhb9")
        self.assertEqual(entry.published_dt.isoformat(), "2026-10-03T14:20:00+00:00")

    def test_unwatched_region_is_skipped(self):
        with _env(DIGITALOCEAN_REGIONS="LON1"):
            self.assertIsNone(feeds.statuspage_entry(DO, DO_INCIDENT, maintenance=False))

    def test_resolved_and_postmortem_end_an_incident(self):
        for status in ("resolved", "postmortem"):
            item = dict(DO_INCIDENT, status=status, resolved_at="2026-10-03T16:00:00Z")
            with _env(DIGITALOCEAN_REGIONS="*"):
                entry = feeds.statuspage_entry(DO, item, maintenance=False)
            self.assertTrue(entry.is_resolved, status)
            self.assertEqual(entry.updated_dt.isoformat(), "2026-10-03T16:00:00+00:00")
            self.assertEqual(entry.region, "all")

    def test_maintenance_starts_when_scheduled(self):
        with _env(CLOUDFLARE_REGIONS="EWR"):
            entry = feeds.statuspage_entry(CLOUDFLARE, CLOUDFLARE_MAINTENANCE, maintenance=True)
        self.assertTrue(entry.is_maintenance)
        self.assertFalse(entry.is_resolved)
        self.assertEqual(entry.published_dt.isoformat(), "2026-11-18T06:00:00+00:00")
        with _env(CLOUDFLARE_REGIONS="EWR"):
            done = feeds.statuspage_entry(
                CLOUDFLARE, dict(CLOUDFLARE_MAINTENANCE, status="completed"), maintenance=True)
        self.assertTrue(done.is_resolved)

    def test_zone_with_site_number(self):
        item = dict(DO_INCIDENT, name="[Block Storage] - fr-par-1 - Write latency",
                    components=[{"name": "fr-par-1"}, {"name": "Block Storage"}])
        with _env(SCALEWAY_REGIONS="fr-par,nl-ams"):
            entry = feeds.statuspage_entry(SCALEWAY, item, maintenance=False)
        self.assertEqual(entry.region, "fr-par")

    def test_fetch_reads_both_endpoints_and_survives_errors(self):
        def fake_get(provider, url, errors):
            if url.endswith("incidents.json"):
                return {"incidents": [DO_INCIDENT]}
            errors.add(provider, "HTTP 503")
            return None
        errors = feeds.FeedErrors()
        with _env(DIGITALOCEAN_REGIONS="BLR1"), mock.patch.object(feeds, "_get_json", fake_get):
            entries = feeds.fetch_statuspage_entries(DO, errors)
        self.assertEqual(len(entries), 1)
        self.assertEqual(errors.summary(), "DigitalOcean: HTTP 503")


class Hetzner(unittest.TestCase):
    def fetch(self, regions):
        parsed = feedparser.parse(HETZNER_ATOM)
        with mock.patch.object(feeds, "HETZNER_REGIONS", regions), \
                mock.patch.object(feeds, "_parse", lambda *a: parsed):
            return feeds.fetch_hetzner_entries(feeds.FeedErrors())

    def test_stable_id_and_status(self):
        entries, listed = self.fetch(["FSN1", "HEL1", "Network"])
        by_title = {e.title: e for e in entries}
        routers = by_title["Urgent maintenance on all core routers"]
        self.assertEqual(routers.guid, "hetzner:cd31dd45-f431-4639-8f9a-d4bfb5353f30")
        self.assertEqual(routers.region, "Network")
        self.assertTrue(routers.is_maintenance)
        self.assertFalse(routers.is_resolved)
        self.assertTrue(routers.summary.startswith("In progress:"))
        self.assertEqual(routers.published_dt.isoformat(), "2026-10-15T10:00:00+00:00")

        outage = by_title["Cloud servers unreachable in FSN1-DC14"]
        self.assertTrue(outage.is_resolved)
        self.assertFalse(outage.is_maintenance)
        self.assertEqual(outage.region, "FSN1")

    def test_future_work_is_maintenance_and_links_are_safe(self):
        entries, _ = self.fetch(["HEL1"])
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0].is_maintenance)
        self.assertEqual(entries[0].link, feeds.HETZNER_STATUS_PAGE)

    def test_listed_covers_every_notice(self):
        # Even notices for unwatched locations: only leaving the feed ends one.
        entries, listed = self.fetch(["NBG1"])
        self.assertEqual(entries, [])
        self.assertEqual(len(listed), 3)
        self.assertIn("hetzner:cd31dd45-f431-4639-8f9a-d4bfb5353f30", listed)

    def test_unreadable_feed_closes_nothing(self):
        errors = feeds.FeedErrors()
        with mock.patch.object(feeds, "HETZNER_REGIONS", ["*"]), \
                mock.patch.object(feeds, "_parse", lambda *a: None):
            self.assertEqual(feeds.fetch_hetzner_entries(errors), ([], None))


class Providers(unittest.TestCase):
    def test_every_provider_has_a_regions_setting(self):
        self.assertEqual(
            list(feeds.PROVIDER_NAMES),
            ["AWS", "Azure", "GCP", "OVH", "DigitalOcean", "Linode", "Cloudflare",
             "Scaleway", "Hetzner"])


if __name__ == "__main__":
    unittest.main()
