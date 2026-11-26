"""Azure only closes open incidents when they vanish from its feed. Unwatching
a region must not look like a vanishing incident there: that region's entries
stop being read, so an unwatched event is still live as far as we know.
Run with: python -m unittest discover -s tests"""
import os
import sys
import unittest
from unittest import mock

import feedparser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import feeds  # noqa: E402
import poller  # noqa: E402

GUID = "azure:west-us#abc123"

AZURE_FEED = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Azure Status</title>
  <entry>
    <id>west-us-1</id>
    <title>Elevated storage latency in West US</title>
    <summary type="html">We are investigating latency in West US.</summary>
    <link href="https://azure.status.microsoft/en-us/status/" />
    <published>2026-11-26T09:00:00Z</published>
    <updated>2026-11-26T10:00:00Z</updated>
  </entry>
</feed>"""


class AzureUnlistedResolution(unittest.TestCase):
    def rec(self, region):
        return {"id": 3, "guid": GUID, "ticket_id": None, "provider": "Azure",
                "region": region, "title": "Elevated storage latency in West US",
                "summary": "Investigating"}

    def poll(self, *, watched, listed, region):
        with mock.patch.object(feeds, "AZURE_REGIONS", watched), \
                mock.patch.object(poller, "_seed_discovery"), \
                mock.patch.object(poller.providers, "discover", return_value=({}, {}, set())), \
                mock.patch.object(poller, "fetch_all", return_value=([], listed, None)), \
                mock.patch.object(poller.db, "get_conn"), \
                mock.patch.object(poller.db, "replace_provider_resources"), \
                mock.patch.object(poller.db, "get_known_guids", return_value=set()), \
                mock.patch.object(poller.db, "get_open_guids",
                                  return_value={GUID: self.rec(region)}), \
                mock.patch.object(poller.db, "mark_resolved") as mark_resolved, \
                mock.patch.object(poller.db, "log_poll"), \
                mock.patch.object(poller.db, "count_open", return_value=1), \
                mock.patch.object(poller.notifiers, "enqueue") as enqueue, \
                mock.patch.object(poller.notifiers, "deliver_pending"):
            created, resolved = poller.poll_once()
        return created, resolved, mark_resolved, enqueue

    def test_unwatched_region_stays_open_with_no_resolution_notice(self):
        # West US has just been removed from AZURE_REGIONS while its incident
        # is live. The next poll no longer reads that entry, so `listed` is
        # empty - but that must not be taken as the incident ending.
        created, resolved, mark_resolved, enqueue = self.poll(
            watched=["East US"], listed=set(), region="West US")
        self.assertEqual((created, resolved), (0, 0))
        mark_resolved.assert_not_called()
        self.assertEqual([call.args[2] for call in enqueue.call_args_list], [])

    def test_partly_unwatched_region_stays_open(self):
        created, resolved, mark_resolved, enqueue = self.poll(
            watched=["East US"], listed=set(), region="East US, West US")
        self.assertEqual((created, resolved), (0, 0))
        mark_resolved.assert_not_called()
        enqueue.assert_not_called()

    def test_watched_region_that_leaves_the_feed_is_still_resolved(self):
        created, resolved, mark_resolved, enqueue = self.poll(
            watched=["West US"], listed=set(), region="West US")
        self.assertEqual((created, resolved), (0, 1))
        mark_resolved.assert_called_once()
        self.assertEqual(mark_resolved.call_args.args[1], GUID)
        self.assertEqual([call.args[2] for call in enqueue.call_args_list], ["resolved"])
        self.assertIn("no longer listed", enqueue.call_args.args[3]["summary"])

    def test_wildcard_still_resolves_any_region(self):
        created, resolved, mark_resolved, enqueue = self.poll(
            watched=["*"], listed=set(), region="West US")
        self.assertEqual((created, resolved), (0, 1))
        mark_resolved.assert_called_once()
        self.assertEqual([call.args[2] for call in enqueue.call_args_list], ["resolved"])

    def test_case_of_a_watched_region_does_not_matter(self):
        created, resolved, mark_resolved, enqueue = self.poll(
            watched=["west us"], listed=set(), region="West US")
        self.assertEqual((created, resolved), (0, 1))
        mark_resolved.assert_called_once()

    def test_feed_listing_excludes_an_unwatched_region(self):
        # The feed entry for West US is still there; only the watch list has
        # changed. This is the state behind the resolution bug above.
        parsed = feedparser.parse(AZURE_FEED)
        parsed.status = 200
        with mock.patch.object(feeds, "AZURE_REGIONS", ["East US"]), \
                mock.patch.object(feeds, "_parse", lambda *args: parsed):
            entries, listed = feeds.fetch_azure_entries(feeds.FeedErrors())
        self.assertEqual(entries, [])
        self.assertEqual(listed, set())


if __name__ == "__main__":
    unittest.main()
