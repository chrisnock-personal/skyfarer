"""Optional read-only account keys: region discovery, incident impact, and
the way discovered regions join the configured ones. APIs are mocked.
Run with: python -m unittest discover tests"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import feeds  # noqa: E402
import providers  # noqa: E402


def api_response(body, status=200):
    resp = mock.Mock()
    resp.status_code = status
    resp.json.return_value = body
    if status >= 400:
        import requests
        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
    return resp


class Discovery(unittest.TestCase):
    def test_digitalocean_counts_every_page(self):
        # DigitalOcean's own shape: links.pages.next until the last page.
        pages = [
            {"droplets": [{"region": {"slug": "lon1"}}, {"region": {"slug": "ams3"}}],
             "links": {"pages": {"next": "https://api.digitalocean.com/v2/droplets?page=2",
                                 "last": "https://api.digitalocean.com/v2/droplets?page=2"}},
             "meta": {"total": 3}},
            {"droplets": [{"region": {"slug": "LON1"}}],
             "links": {"pages": {"first": "https://api.digitalocean.com/v2/droplets?page=1",
                                 "prev": "https://api.digitalocean.com/v2/droplets?page=1"}},
             "meta": {"total": 3}},
        ]
        calls = []

        def get(url, params=None, headers=None, timeout=None):
            calls.append((url, dict(params or {}), dict(headers or {})))
            return api_response(pages[params["page"] - 1])

        with mock.patch.object(providers.requests, "get", side_effect=get):
            counts = providers._discover_digitalocean("token")
        self.assertEqual(counts, {"LON1": 2, "AMS3": 1})
        self.assertEqual([c[1]["page"] for c in calls], [1, 2])
        self.assertEqual(calls[0][2]["Authorization"], "Bearer token")

    def test_hetzner_follows_next_page(self):
        pages = [
            {"servers": [{"location": {"name": "fsn1"}}],
             "meta": {"pagination": {"next_page": 2}}},
            {"servers": [{"location": {"name": "hel1"}}],
             "meta": {"pagination": {"next_page": None}}},
        ]
        with mock.patch.object(providers.requests, "get",
                               side_effect=lambda url, **kw: api_response(
                                   pages[kw["params"]["page"] - 1])):
            self.assertEqual(providers._discover_hetzner("token"),
                             {"FSN1": 1, "HEL1": 1})

    def test_linode_uses_region_ids(self):
        pages = [
            {"data": [{"region": "gb-lon"}], "pages": 2},
            {"data": [{"region": "eu-west"}, {"region": "gb-lon"}], "pages": 2},
        ]
        with mock.patch.object(providers.requests, "get",
                               side_effect=lambda url, **kw: api_response(
                                   pages[kw["params"]["page"] - 1])):
            self.assertEqual(providers._discover_linode("token"),
                             {"GB-LON": 2, "EU-WEST": 1})

    def test_discover_skips_unset_keys_and_reports_failures(self):
        old_regions, old_errors = providers.DISCOVERED, providers.ERRORS
        self.addCleanup(setattr, providers, "DISCOVERED", old_regions)
        self.addCleanup(setattr, providers, "ERRORS", old_errors)
        providers.DISCOVERED = {"Hetzner": {"FSN1": 1}}
        with mock.patch.dict(os.environ, {"DIGITALOCEAN_API_KEY": "ok",
                                          "HETZNER_API_KEY": "bad"},
                             clear=False), \
             mock.patch.object(providers, "_discover_digitalocean", return_value={"LON1": 2}), \
             mock.patch.object(providers, "_discover_hetzner",
                               side_effect=RuntimeError("HTTP 401")):
            os.environ.pop("LINODE_API_KEY", None)
            regions, errors, cleared = providers.discover()
        self.assertEqual(regions, {"DigitalOcean": {"LON1": 2}, "Hetzner": {"FSN1": 1}})
        self.assertEqual(errors, {"Hetzner": "HTTP 401"})
        self.assertEqual(cleared, {"Linode"})
        self.assertEqual(providers.DISCOVERED, regions)
        self.assertEqual(providers.ERRORS, errors)


    def test_a_restart_with_a_failing_api_keeps_the_stored_regions(self):
        old_regions, old_errors = providers.DISCOVERED, providers.ERRORS
        self.addCleanup(setattr, providers, "DISCOVERED", old_regions)
        self.addCleanup(setattr, providers, "ERRORS", old_errors)
        providers.DISCOVERED = {}
        providers.seed({"Hetzner": {"FSN1": 2}})
        with mock.patch.dict(os.environ, {"HETZNER_API_KEY": "key"}), \
             mock.patch.object(providers, "_discover_hetzner",
                               side_effect=RuntimeError("HTTP 503")):
            os.environ.pop("DIGITALOCEAN_API_KEY", None)
            os.environ.pop("LINODE_API_KEY", None)
            regions, errors, _ = providers.discover()
        self.assertEqual(regions, {"Hetzner": {"FSN1": 2}})
        self.assertEqual(errors, {"Hetzner": "HTTP 503"})


class Impact(unittest.TestCase):
    def test_counts_only_the_regions_an_incident_touches(self):
        with mock.patch.dict(os.environ, {"DIGITALOCEAN_API_KEY": "token"}), \
             mock.patch.object(providers, "DISCOVERED",
                               {"DigitalOcean": {"LON1": 3, "AMS3": 1, "FRA1": 2}}), \
             mock.patch.object(providers, "ERRORS", {}):
            self.assertEqual(providers.impact("DigitalOcean", ["LON1"]),
                             {"total": 3, "regions": {"LON1": 3}})
            self.assertEqual(providers.impact("DigitalOcean", ["AMS3", "FRA1"]),
                             {"total": 3, "regions": {"AMS3": 1, "FRA1": 2}})
            self.assertEqual(providers.impact("DigitalOcean", ["all"])["total"], 6)
            self.assertEqual(providers.impact("DigitalOcean", ["NYC1"]),
                             {"total": 0, "regions": {}})

    def test_configured_short_code_includes_numbered_sites(self):
        with mock.patch.dict(os.environ, {"DIGITALOCEAN_API_KEY": "token"}), \
             mock.patch.object(providers, "DISCOVERED",
                               {"DigitalOcean": {"LON1": 2, "LON2": 1}}), \
             mock.patch.object(providers, "ERRORS", {}):
            self.assertEqual(providers.impact("DigitalOcean", ["LON"])["total"], 3)

    def test_no_key_or_failed_read_is_unknown_not_zero(self):
        counts = {"DigitalOcean": {"LON1": 2}}
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(providers, "DISCOVERED", counts), \
             mock.patch.object(providers, "ERRORS", {}):
            self.assertIsNone(providers.impact("DigitalOcean", ["LON1"]))
        with mock.patch.dict(os.environ, {"DIGITALOCEAN_API_KEY": "token"}), \
             mock.patch.object(providers, "DISCOVERED", counts), \
             mock.patch.object(providers, "ERRORS", {"DigitalOcean": "HTTP 500"}):
            self.assertIsNone(providers.impact("DigitalOcean", ["LON1"]))


class WatchedRegions(unittest.TestCase):
    def test_discovered_regions_join_configured_ones(self):
        saved = {k: getattr(feeds, k) for k in ("AWS_REGIONS", "HETZNER_REGIONS",
                                                "DISCOVERED_REGIONS")}
        self.addCleanup(lambda: [setattr(feeds, k, v) for k, v in saved.items()])
        with mock.patch.dict(os.environ, {"AWS_REGIONS": "",
                                          "DIGITALOCEAN_REGIONS": "NYC1",
                                          "HETZNER_REGIONS": ""}):
            feeds.configure()
            feeds.apply_discovered({"DigitalOcean": {"LON1": 2}, "Hetzner": {"FSN1": 1}})
            watched = feeds.watched_regions()
            self.assertEqual(watched["DigitalOcean"], ["NYC1", "LON1"])
            self.assertEqual(watched["Hetzner"], ["FSN1"])
        self.assertEqual(feeds.AWS_REGIONS, [])
