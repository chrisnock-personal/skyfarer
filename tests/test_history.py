"""Availability maths for History & SLA: windows, clamping, maintenance,
overlapping incidents, error budgets and CSV. No database needed.
Run with: python -m unittest discover tests"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import history  # noqa: E402


NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
DAY = timedelta(days=1)


def incident(provider="DigitalOcean", region="LON1", title="An incident",
             detected=None, resolved=None, state="resolved", maintenance=False,
             link="https://status.example.test/1"):
    return {"provider": provider, "region": region, "title": title, "link": link,
            "detected_at": detected, "resolved_at": resolved,
            "state": state, "is_maintenance": maintenance}


def run(rows, start, end, targets=None, **kwargs):
    return history.build(rows, start, end, targets or {"DigitalOcean": 99.9},
                         now=end, **kwargs)


class Windows(unittest.TestCase):
    def test_presets_are_open_ended_at_now(self):
        start, end = history.window("quarter", now=NOW)
        self.assertEqual(end, NOW)
        self.assertEqual(start, NOW - timedelta(days=90))
        self.assertEqual(history.window("year", now=NOW)[0], NOW - timedelta(days=365))

    def test_custom_to_date_is_inclusive(self):
        start, end = history.window("custom", "2026-11-01", "2026-11-07", now=NOW)
        self.assertEqual(start, datetime(2026, 11, 1, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2026, 11, 8, tzinfo=timezone.utc))

    def test_bad_custom_dates_fall_back(self):
        start, end = history.window("custom", "not a date", "not a date", now=NOW)
        self.assertEqual(start, NOW - timedelta(days=90))
        self.assertEqual(end, NOW)


class Targets(unittest.TestCase):
    def test_stored_default_and_bad_values(self):
        key = history.target_key("DigitalOcean")
        self.assertEqual(key, "SLA_TARGET_DIGITALOCEAN")
        self.assertEqual(history.target_value({}, "DigitalOcean"), 99.9)
        self.assertEqual(history.target_value({key: "99.95"}, "DigitalOcean"), 99.95)
        for bad in ("", "abc", "101", "-1"):
            self.assertEqual(history.target_value({key: bad}, "DigitalOcean"), 99.9)


class Report(unittest.TestCase):
    def setUp(self):
        self.start = NOW - timedelta(days=30)
        self.targets = {"DigitalOcean": 99.9}

    def test_downtime_uses_feed_times_and_clamps_to_window(self):
        rows = [
            incident(detected=NOW - 10 * DAY, resolved=NOW - 9 * DAY - timedelta(hours=23)),
            # Started before the window: only the part inside it counts.
            incident(detected=NOW - 40 * DAY, resolved=NOW - 29 * DAY,
                     state="resolved", title="Old one", region="AMS3"),
        ]
        report = run(rows, self.start, NOW, self.targets)
        self.assertEqual(report["incident_count"], 2)
        self.assertAlmostEqual(report["downtime"], 60 + 1440, delta=0.01)
        self.assertTrue(report["items"][-1]["notes"].startswith("Started before"))

    def test_open_incident_counts_to_now_and_is_marked_ongoing(self):
        rows = [incident(detected=NOW - timedelta(minutes=12), resolved=None, state="open")]
        report = run(rows, self.start, NOW, self.targets)
        self.assertEqual(report["items"][0]["kind"], "ongoing")
        self.assertAlmostEqual(report["downtime"], 12, delta=0.01)
        self.assertEqual(report["longest"]["duration"], "12m")

    def test_maintenance_is_listed_but_not_counted(self):
        rows = [incident(detected=NOW - timedelta(hours=2),
                         resolved=NOW - timedelta(hours=1), maintenance=True),
                incident(detected=NOW - timedelta(minutes=5), resolved=NOW)]
        report = run(rows, self.start, NOW, self.targets)
        self.assertEqual(report["maintenance_count"], 1)
        self.assertEqual(report["incident_count"], 1)
        self.assertAlmostEqual(report["downtime"], 5, delta=0.01)
        self.assertEqual(report["providers"][0]["status"], "Within target")

    def test_overlapping_regions_count_once_per_provider(self):
        rows = [
            incident(detected=NOW - timedelta(hours=2), resolved=NOW - timedelta(hours=1)),
            incident(detected=NOW - timedelta(minutes=90), resolved=NOW - timedelta(minutes=30),
                     region="AMS3"),
        ]
        report = run(rows, self.start, NOW, self.targets)
        self.assertEqual(report["incident_count"], 2)
        self.assertAlmostEqual(report["downtime"], 90, delta=0.01)
        self.assertAlmostEqual(report["providers"][0]["downtime"], 90, delta=0.01)

    def test_budget_availability_and_status(self):
        rows = [incident(detected=NOW - timedelta(hours=1), resolved=NOW)]
        report = run(rows, self.start, NOW, self.targets)
        budget = 30 * 24 * 60 * 0.001  # 0.1% of 30 days
        self.assertAlmostEqual(report["budget"], budget, delta=0.01)
        self.assertAlmostEqual(report["used"], 60 / budget * 100, delta=0.01)
        self.assertEqual(report["used_label"], "139%")
        self.assertEqual(report["providers"][0]["status"], "Below target")
        self.assertLess(report["availability"], 99.9)

    def test_multiple_providers_average_and_strictest_target(self):
        rows = [
            incident(provider="DigitalOcean", detected=NOW - timedelta(minutes=30), resolved=NOW),
            incident(provider="Hetzner", detected=NOW - timedelta(minutes=10), resolved=NOW),
        ]
        report = run(rows, self.start, NOW,
                     {"DigitalOcean": 99.9, "Hetzner": 99.95})
        self.assertEqual(report["n_providers"], 2)
        self.assertEqual(report["target"], 99.9)
        self.assertAlmostEqual(report["downtime"], 40, delta=0.01)
        self.assertAlmostEqual(report["availability"], 100 - 100 * 40 / (2 * 30 * 24 * 60),
                               delta=0.0001)
        self.assertAlmostEqual(report["budget"], 2 * 30 * 24 * 60 * 0.001, delta=0.01)

    def test_region_and_provider_filters(self):
        rows = [
            incident(detected=NOW - timedelta(minutes=20), resolved=NOW, region="LON1,AMS3"),
            incident(provider="Hetzner", detected=NOW - timedelta(minutes=10), resolved=NOW,
                     region="FSN1"),
        ]
        targets = {"DigitalOcean": 99.9, "Hetzner": 99.9}
        self.assertEqual(run(rows, self.start, NOW, targets, region="AMS3")["incident_count"], 1)
        self.assertEqual(run(rows, self.start, NOW, targets, region="LON1")["downtime"], 20)
        self.assertEqual(run(rows, self.start, NOW, targets, provider="Hetzner")["incident_count"], 1)
        self.assertEqual(run(rows, self.start, NOW, targets, region="LON")["incident_count"], 0)

    def test_future_maintenance_is_not_downtime(self):
        rows = [incident(detected=NOW + DAY, resolved=None, state="open", maintenance=True)]
        self.assertEqual(run(rows, self.start, NOW, self.targets)["maintenance_count"], 0)

    def test_monthly_bars_split_an_incident_across_months(self):
        start = datetime(2026, 10, 15, tzinfo=timezone.utc)
        rows = [incident(detected=datetime(2026, 10, 31, 23, 30, tzinfo=timezone.utc),
                         resolved=datetime(2026, 11, 1, 0, 30, tzinfo=timezone.utc))]
        months = {m["key"]: m["minutes"] for m in run(rows, start, NOW, self.targets)["months"]}
        self.assertEqual(months["2026-10"], 30)
        self.assertEqual(months["2026-11"], 30)


class Export(unittest.TestCase):
    def test_csv_has_every_incident_and_its_numbers(self):
        start = NOW - timedelta(days=7)
        rows = [incident(detected=NOW - timedelta(minutes=12), resolved=NOW, state="open"),
                incident(detected=NOW - timedelta(hours=2), resolved=NOW,
                         maintenance=True, title="Planned work")]
        text = history.csv_export(run(rows, start, NOW, {"DigitalOcean": 99.9}))
        self.assertIn("Started (UTC),Ended (UTC),Provider,Region", text)
        self.assertIn("An incident,ongoing,12.0", text)
        self.assertIn("Planned work,maintenance,120.0", text)
        self.assertEqual(len(text.strip().splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
