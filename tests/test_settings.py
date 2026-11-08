"""Settings kept in the database: what reaches the poller, encryption and the
change history's wording. No database needed: the stored values are mocked.
Run with: python -m unittest discover tests"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import feeds  # noqa: E402
import notifiers  # noqa: E402
import settings  # noqa: E402

KEY = {"SKYFARER_SECRET_KEY": "0123456789abcdef0123456789abcdef"}


class Applying(unittest.TestCase):
    def setUp(self):
        # apply() rewrites the environment and both modules' settings: put
        # them back as they were after each test.
        saved = {k: os.environ.get(k) for k in settings.MANAGED + settings.ENV_WEBHOOK_KEYS}

        def restore():
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            feeds.configure()
            notifiers.configure()
        self.addCleanup(restore)

    def apply(self, values, hooks=()):
        rows = [{"id": h.id, "enabled": True, "hook": h} for h in hooks]
        with mock.patch.object(settings, "load", return_value=values), \
                mock.patch.object(settings, "webhooks", return_value=rows):
            settings.apply(conn=object())

    def test_stored_values_reach_feeds_and_notifiers(self):
        self.apply({"AWS_REGIONS": "eu-west-2,us-east-1", "PAGERDUTY_ROUTING_KEY": "k",
                    "PAGERDUTY_SEVERITY": "warning", "DIGITALOCEAN_REGIONS": "LON1"})
        self.assertEqual(feeds.AWS_REGIONS, ["eu-west-2", "us-east-1"])
        self.assertEqual(feeds.watched_regions()["DigitalOcean"], ["LON1"])
        self.assertEqual(notifiers.PAGERDUTY_SEVERITY, "warning")
        self.assertIn("pagerduty", notifiers.enabled_channels())

    def test_what_is_not_stored_is_not_used(self):
        os.environ["PUSHOVER_TOKEN"] = "left over from .env"
        os.environ["PUSHOVER_USER"] = "u"
        self.apply({})
        self.assertEqual(notifiers.PUSHOVER_TOKEN, "")
        self.assertNotIn("pushover", notifiers.enabled_channels())

    def test_switched_off_keeps_settings_but_stops(self):
        values = {"HETZNER_REGIONS": "FSN1", "HETZNER_ENABLED": "false",
                  "TEAMS_WEBHOOK_URL": "https://x.example.test/", "TEAMS_ENABLED": "false"}
        self.apply(values)
        self.assertEqual(feeds.HETZNER_REGIONS, [])
        self.assertNotIn("teams", notifiers.enabled_channels())
        values.update(HETZNER_ENABLED="true", TEAMS_ENABLED="true")
        self.apply(values)
        self.assertEqual(feeds.HETZNER_REGIONS, ["FSN1"])
        self.assertIn("teams", notifiers.enabled_channels())

    def test_webhooks_come_from_their_table_not_env(self):
        os.environ["WEBHOOK_URL"] = "https://from-env.example.test/"
        hooks = [notifiers.Webhook(id=4, name="Slack", url="https://a.example.test/"),
                 notifiers.Webhook(id=7, name="n8n", url="https://b.example.test/")]
        self.apply({}, hooks)
        self.assertEqual([h.channel for h in notifiers.WEBHOOKS], ["webhook-4", "webhook-7"])
        self.assertEqual(notifiers.enabled_channels(), ["webhook-4", "webhook-7"])


class Secrets(unittest.TestCase):
    def test_round_trip_and_wrong_key(self):
        with mock.patch.dict(os.environ, KEY):
            token = settings.encrypt("routing-key")
            self.assertNotIn("routing-key", token)
            self.assertEqual(settings.decrypt(token), "routing-key")
        with mock.patch.dict(os.environ, {"SKYFARER_SECRET_KEY": "another-key-of-enough-length"}):
            with self.assertRaises(Exception):
                settings.decrypt(token)

    def test_key_must_be_set_and_long_enough(self):
        with mock.patch.dict(os.environ, {"SKYFARER_SECRET_KEY": ""}):
            self.assertIn("not set", settings.secret_key_problem())
            with self.assertRaises(settings.SettingsError):
                settings.encrypt("x")
        with mock.patch.dict(os.environ, {"SKYFARER_SECRET_KEY": "short"}):
            self.assertIn("too short", settings.secret_key_problem())

    def test_session_key_differs_from_encryption_key(self):
        with mock.patch.dict(os.environ, KEY):
            self.assertNotEqual(settings.session_key(), settings._derived("settings"))

    def test_which_settings_are_secret(self):
        for key in ("ZENDESK_API_TOKEN", "SERVICENOW_PASSWORD", "TEAMS_WEBHOOK_URL",
                    "SNMP_COMMUNITY", "WEBHOOK_3_SECRET", "WEBHOOK_3_HEADERS"):
            self.assertTrue(settings.is_secret(key), key)
        for key in ("ZENDESK_SUBDOMAIN", "AWS_REGIONS", "NOTIFY_EVENTS", "WEBHOOK_3_URL"):
            self.assertFalse(settings.is_secret(key), key)


class History(unittest.TestCase):
    def test_wording(self):
        self.assertEqual(settings.describe_change("DIGITALOCEAN_REGIONS", "LON1", "LON1,AMS3"),
                         "DigitalOcean regions: added AMS3")
        self.assertEqual(settings.describe_change("HETZNER_ENABLED", "true", "false"),
                         "Hetzner: switched off")
        self.assertEqual(settings.describe_change("SERVICENOW_ASSIGNMENT_GROUP", "Service Desk",
                                                  "Cloud Operations"),
                         "ServiceNow: assignment group: changed from Service Desk to Cloud Operations")
        self.assertEqual(settings.describe_change("SERVICENOW_EXTRA_FIELDS", "", '{"a": "b"}'),
                         "ServiceNow: extra fields (JSON): changed")

    def test_save_never_records_a_secret(self):
        lines = []
        conn = mock.MagicMock()
        with mock.patch.dict(os.environ, KEY), \
                mock.patch.object(settings, "load", return_value={"PAGERDUTY_ROUTING_KEY": "old"}), \
                mock.patch.object(settings, "history_add", lambda c, a, w: lines.append(w)):
            settings.save(conn, {"PAGERDUTY_ROUTING_KEY": "new-secret-value",
                                 "PAGERDUTY_SEVERITY": "warning"}, "Chris")
        self.assertEqual(lines, ["PagerDuty: routing key: replaced",
                                 "PagerDuty: severity: set to warning"])
        stored = [c.args[1] for c in conn.cursor().__enter__().execute.call_args_list]
        self.assertFalse(any("new-secret-value" in str(p) for p in stored))

    def test_import_summary(self):
        found = {"AWS_REGIONS": "eu-west-2", "HETZNER_REGIONS": "FSN1,NBG1",
                 "PAGERDUTY_ROUTING_KEY": "k", "ZENDESK_SUBDOMAIN": "acme"}
        self.assertEqual(settings.import_summary(found, True),
                         "2 providers with 3 regions; 3 channels: Zendesk, PagerDuty, a webhook")
        self.assertEqual(settings.import_summary({}, False), "nothing set")


class Passwords(unittest.TestCase):
    def test_rules(self):
        self.assertIsNotNone(settings.password_problem("short"))
        self.assertIsNotNone(settings.password_problem("long enough pass", "different one"))
        self.assertIsNone(settings.password_problem("long enough pass", "long enough pass"))


if __name__ == "__main__":
    unittest.main()
