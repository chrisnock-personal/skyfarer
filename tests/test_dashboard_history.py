"""The History page and the SLA-targets settings page render end to end with
the database and the sign-in guard mocked out. No server or database needed.
Run with: python -m unittest discover tests"""
import os
import sys
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import admin  # noqa: E402
import dashboard  # noqa: E402

NOW = datetime(2026, 11, 24, 12, tzinfo=timezone.utc)

ROWS = [{
    "provider": "DigitalOcean", "region": "LON1", "title": "Droplet creates failing",
    "link": "https://status.example.test/1", "state": "open", "is_maintenance": False,
    "detected_at": NOW - timedelta(minutes=12), "resolved_at": None,
}, {
    "provider": "Hetzner", "region": "FSN1", "title": "Power work",
    "link": "https://status.example.test/2", "state": "resolved", "is_maintenance": True,
    "detected_at": NOW - timedelta(hours=2), "resolved_at": NOW - timedelta(hours=1),
}]


@contextmanager
def fake_conn():
    yield mock.MagicMock()


class HistoryPage(unittest.TestCase):
    def setUp(self):
        dashboard.app.secret_key = "test-only"
        self.patches = [
            mock.patch.object(dashboard, "_query", return_value=list(ROWS)),
            mock.patch.object(dashboard.history, "window",
                              return_value=(NOW - timedelta(days=30), NOW)),
            mock.patch.object(dashboard.db, "get_conn", side_effect=fake_conn),
            mock.patch.object(dashboard.settings, "load", return_value={}),
            mock.patch.object(dashboard.feeds, "watched_regions",
                              return_value={"DigitalOcean": ["LON1"], "Hetzner": ["FSN1"]}),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_page_shows_the_report_and_filters(self):
        with dashboard.app.test_request_context("/history?range=quarter"):
            html = dashboard.history_page()
        self.assertIn("History &amp; SLA", html)
        self.assertIn("Availability by provider", html)
        self.assertIn("Droplet creates failing", html)
        self.assertIn("Monthly downtime", html)
        self.assertIn("Export CSV", html)
        self.assertNotIn("SLA_TARGET_DIGITALOCEAN", html)

    def test_csv_download(self):
        with dashboard.app.test_request_context("/history?range=quarter&format=csv"):
            response = dashboard.history_page()
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn("attachment; filename=", response.headers["Content-Disposition"])
        body = response.get_data(as_text=True)
        self.assertIn("Started (UTC),Ended (UTC),Provider", body)
        self.assertIn("Droplet creates failing,ongoing", body)
        # Maintenance is listed, but not counted as vendor downtime.
        self.assertIn("Power work,maintenance", body)


class SlaSettingsPage(unittest.TestCase):
    def setUp(self):
        dashboard.app.secret_key = "test-only"
        self.conn = mock.patch.object(admin.db, "get_conn", side_effect=fake_conn)
        self.values = mock.patch.object(admin.settings, "load", return_value={})
        self.conn.start()
        self.values.start()
        self.addCleanup(self.conn.stop)
        self.addCleanup(self.values.stop)

    def test_form_has_a_target_per_provider(self):
        with dashboard.app.test_request_context("/settings/sla"):
            html = admin.sla()
        self.assertIn("SLA targets", html)
        self.assertIn('name="SLA_TARGET_DIGITALOCEAN"', html)
        self.assertIn('name="SLA_TARGET_HETZNER"', html)

    def test_valid_target_is_saved(self):
        form = {"SLA_TARGET_DIGITALOCEAN": "99.95"}
        with mock.patch.object(admin.settings, "save", return_value=["one change"]) as save, \
                mock.patch.object(admin, "_saved_message"):
            with dashboard.app.test_request_context("/settings/sla", method="POST", data=form):
                admin.sla()
        self.assertEqual(save.call_args.args[1], {"SLA_TARGET_DIGITALOCEAN": "99.95"})

    def test_bad_number_is_refused_without_saving(self):
        form = {"SLA_TARGET_DIGITALOCEAN": "not a number"}
        with dashboard.app.test_request_context("/settings/sla", method="POST", data=form):
            html = admin.sla()
        self.assertIn("enter a percentage", html)
        with mock.patch.object(admin.settings, "save") as save:
            with dashboard.app.test_request_context("/settings/sla", method="POST", data=form):
                admin.sla()
            save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
