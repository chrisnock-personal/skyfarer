"""Run with: python -m unittest discover tests  (needs requirements.txt)."""
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import notifiers  # noqa: E402
import feeds  # noqa: E402
import poller  # noqa: E402

NOTICE = {
    "provider": "AWS", "region": "eu-west-2", "title": "Service impact",
    "summary": "Detail. " * 400, "link": "https://example.test/i/1",
    "published": "2026-11-04 10:00 UTC", "updated": "2026-11-04 10:05 UTC",
    "noticed": "2026-11-04 10:06 UTC",
}


def row(event="opened", **extra):
    return {"id": 1, "incident_id": 7, "event": event, "ticket_id": 99,
            "payload": dict(NOTICE), **extra}


def response(status):
    resp = requests.Response()
    resp.status_code = status
    resp._content = b"{}"
    return resp


class Payloads(unittest.TestCase):
    def test_pushover_respects_limits(self):
        m = notifiers.pushover_message(row())
        self.assertLessEqual(len(m["message"]), 1024)
        self.assertLessEqual(len(m["title"]), 250)
        self.assertLessEqual(len(m["url"]), 512)

    def test_pushover_emergency_needs_retry_and_expire(self):
        with mock.patch.object(notifiers, "PUSHOVER_PRIORITY", "2"):
            m = notifiers.pushover_message(row())
            self.assertEqual((m["priority"], m["retry"], m["expire"]), (2, 60, 3600))
            # An all-clear shouldn't repeat until acknowledged.
            self.assertEqual(notifiers.pushover_message(row("resolved"))["priority"], 0)

    def test_pagerduty_resolve_matches_its_trigger(self):
        trigger = notifiers.pagerduty_event(row())
        resolve = notifiers.pagerduty_event(row("resolved"))
        self.assertEqual(trigger["dedup_key"], resolve["dedup_key"])
        self.assertLessEqual(len(trigger["dedup_key"]), 255)
        self.assertEqual((trigger["event_action"], resolve["event_action"]), ("trigger", "resolve"))
        for field in ("summary", "source", "severity"):
            self.assertTrue(trigger["payload"][field])

    def test_pagerduty_summary_limit(self):
        long = row()
        long["payload"]["title"] = "x" * 2000
        self.assertLessEqual(len(notifiers.pagerduty_event(long)["payload"]["summary"]), 1024)

    def test_teams_card_shape(self):
        for event in notifiers.EVENTS:
            card = notifiers.teams_card(row(event))
            self.assertEqual(card["type"], "message")
            attachment = card["attachments"][0]
            self.assertEqual(attachment["contentType"], "application/vnd.microsoft.card.adaptive")
            self.assertIn("contentUrl", attachment)
            self.assertIsNone(attachment["contentUrl"])
            self.assertEqual(attachment["content"]["type"], "AdaptiveCard")
            self.assertLess(len(json.dumps(card)), 28_000)

    def test_zendesk_group_is_optional(self):
        self.assertNotIn("group_id", notifiers.zendesk_ticket(row())["ticket"])
        with mock.patch.object(notifiers, "ZD_GROUP_ID", 42):
            self.assertEqual(notifiers.zendesk_ticket(row())["ticket"]["group_id"], 42)

    def test_zendesk_updates_stay_internal(self):
        self.assertIs(notifiers.zendesk_resolve(row())["ticket"]["comment"]["public"], False)
        self.assertIs(notifiers.zendesk_note(row())["ticket"]["comment"]["public"], False)

    def test_snmp_values_are_short_enough(self):
        long = row()
        long["payload"]["title"] = "x" * 900
        values = dict(notifiers.snmp_varbinds(long))
        self.assertTrue(all(len(v) <= 255 for v in values.values() if isinstance(v, str)))
        self.assertEqual(values[f"{notifiers.SNMP_BASE_OID}.1.5"], 7)


class Failures(unittest.TestCase):
    def test_server_errors_and_429_retry(self):
        for status in (429, 500, 503):
            with self.assertRaises(notifiers.RetryLater):
                notifiers._check(response(status))

    def test_bad_requests_do_not_retry(self):
        for status in (400, 401, 404):
            with self.assertRaises(notifiers.PermanentFailure):
                notifiers._check(response(status))

    def test_pushover_never_retries_a_4xx(self):
        with mock.patch.object(notifiers, "_request", return_value=response(429)):
            with self.assertRaises(notifiers.PermanentFailure):
                notifiers.send_pushover(row())

    def test_pushover_retries_a_5xx(self):
        with mock.patch.object(notifiers, "_request", return_value=response(500)):
            with self.assertRaises(notifiers.RetryLater):
                notifiers.send_pushover(row())

    def test_zendesk_keeps_tickets_queued_through_an_auth_failure(self):
        with mock.patch.object(notifiers, "_request", return_value=response(401)):
            with self.assertRaises(notifiers.RetryLater):
                notifiers.send_zendesk(row())

    def test_zendesk_update_without_a_ticket_fails_for_good(self):
        with self.assertRaises(notifiers.PermanentFailure):
            notifiers.send_zendesk(row("resolved", ticket_id=None))

    def test_errors_do_not_contain_the_teams_url(self):
        secret = "https://example.test/workflows/SECRET-SIGNATURE"
        boom = requests.ConnectionError(f"Max retries exceeded with url: {secret}")
        with mock.patch.object(notifiers, "TEAMS_WEBHOOK_URL", secret), \
                mock.patch.object(notifiers.requests, "request", side_effect=boom):
            with self.assertRaises(notifiers.RetryLater) as caught:
                notifiers.send_teams(row())
        self.assertNotIn("SECRET", str(caught.exception))


class Enqueue(unittest.TestCase):
    def queued(self, event, *, alert=True, notified=True, events=("opened", "resolved")):
        with mock.patch.object(notifiers, "enabled_channels", return_value=[
                "zendesk", "pushover", "pagerduty", "teams", "snmp"]), \
                mock.patch.object(notifiers, "NOTIFY_EVENTS", list(events)), \
                mock.patch.object(notifiers.db, "was_notified", return_value=notified), \
                mock.patch.object(notifiers.db, "add_notification") as add:
            notifiers.enqueue(None, 7, event, dict(NOTICE), alert=alert)
        return {call.kwargs["channel"] for call in add.call_args_list}

    def test_opened_reaches_everyone(self):
        self.assertEqual(self.queued("opened"),
                         {"zendesk", "pushover", "pagerduty", "teams", "snmp"})

    def test_suppressed_incident_only_reaches_zendesk(self):
        self.assertEqual(self.queued("opened", alert=False), {"zendesk"})

    def test_no_all_clear_without_an_alert(self):
        self.assertEqual(self.queued("resolved", notified=False), {"zendesk"})

    def test_updates_are_zendesk_only_by_default(self):
        self.assertEqual(self.queued("updated"), {"zendesk"})

    def test_pagerduty_never_gets_updates(self):
        got = self.queued("updated", events=notifiers.EVENTS)
        self.assertEqual(got, {"zendesk", "pushover", "teams", "snmp"})


class Delivery(unittest.TestCase):
    def queued(self, rid, event, *, channel="zendesk", **extra):
        when = datetime.now(timezone.utc)
        base = {"id": rid, "incident_id": 7, "channel": channel, "event": event,
                "ticket_id": None, "payload": dict(NOTICE), "attempts": 0,
                "created_at": when, "next_attempt_at": when - timedelta(seconds=1)}
        return {**base, **extra}

    def deliver(self, rows, sender):
        with mock.patch.object(notifiers, "enabled_channels", return_value=["zendesk", "teams"]), \
                mock.patch.dict(notifiers.SENDERS, {"zendesk": sender, "teams": sender}), \
                mock.patch.object(notifiers.db, "get_conn"), \
                mock.patch.object(notifiers.db, "pending_notifications", return_value=rows), \
                mock.patch.object(notifiers.db, "notification_sent"), \
                mock.patch.object(notifiers.db, "notification_retry") as retry, \
                mock.patch.object(notifiers.db, "notification_failed") as failed, \
                mock.patch.object(notifiers.db, "set_ticket"):
            return notifiers.deliver_pending(), retry, failed

    def test_first_update_can_use_a_ticket_opened_in_the_same_pass(self):
        seen = []

        def sender(r):
            seen.append(r["ticket_id"])
            return 99 if r["event"] == "opened" else None

        rows = [self.queued(1, "opened"), self.queued(2, "updated")]
        sent, _, failed = self.deliver(rows, sender)
        self.assertEqual((sent, seen), (2, [None, 99]))
        failed.assert_not_called()

    def test_a_retry_holds_back_later_notices_for_that_incident_and_channel(self):
        calls = []

        def sender(r):
            calls.append((r["channel"], r["event"]))
            if r["channel"] == "teams":
                raise notifiers.RetryLater("HTTP 503")

        rows = [self.queued(1, "opened", channel="teams"),
                self.queued(2, "resolved", channel="teams"),
                self.queued(3, "opened")]
        _, retry, _ = self.deliver(rows, sender)
        self.assertEqual(calls, [("teams", "opened"), ("zendesk", "opened")])
        retry.assert_called_once()

    def test_a_notice_waiting_for_its_retry_time_keeps_its_place(self):
        later = datetime.now(timezone.utc) + timedelta(minutes=5)
        calls = []
        rows = [self.queued(1, "opened", next_attempt_at=later), self.queued(2, "resolved")]
        self.deliver(rows, lambda r: calls.append(r["event"]))
        self.assertEqual(calls, [])

    def test_gives_up_after_the_retry_window(self):
        old = datetime.now(timezone.utc) - timedelta(hours=25)

        def sender(r):
            raise notifiers.RetryLater("HTTP 503")

        _, retry, failed = self.deliver([self.queued(1, "opened", created_at=old)], sender)
        retry.assert_not_called()
        failed.assert_called_once()


class Config(unittest.TestCase):
    def test_half_configured_channels_are_errors(self):
        for name in ("PUSHOVER_TOKEN", "ZENDESK_EMAIL"):
            with mock.patch.object(notifiers, name, "x"):
                self.assertTrue(notifiers.config_errors())

    def test_bad_values_are_errors(self):
        for name, value in (("PUSHOVER_PRIORITY", "3"), ("PAGERDUTY_SEVERITY", "high"),
                            ("NOTIFY_EVENTS", ["started"])):
            with mock.patch.object(notifiers, name, value):
                self.assertTrue(notifiers.config_errors(), name)

    def test_snmp_needs_a_community_and_a_valid_port(self):
        with mock.patch.object(notifiers, "SNMP_TRAP_TARGETS", ["host:abc"]), \
                mock.patch.object(notifiers, "SNMP_COMMUNITY", ""):
            self.assertEqual(len(notifiers.config_errors()), 2)


class Alerting(unittest.TestCase):
    def entry(self, *, age_hours=1, maintenance=False):
        when = datetime.now(timezone.utc) - timedelta(hours=age_hours)
        return feeds.FeedEntry(
            provider="OVH", region="GRA", guid="g", title="t", summary="s", link="l",
            published="p", updated="u", is_resolved=False, published_dt=when,
            updated_dt=when, is_maintenance=maintenance)

    def test_fresh_incident_alerts(self):
        self.assertTrue(poller._worth_alerting(self.entry()))

    def test_old_incident_does_not(self):
        self.assertFalse(poller._worth_alerting(self.entry(age_hours=48)))

    def test_future_dated_maintenance_does_not(self):
        self.assertFalse(poller._worth_alerting(
            self.entry(age_hours=-500, maintenance=True)))

    def test_maintenance_can_be_opted_into(self):
        with mock.patch.object(notifiers, "NOTIFY_MAINTENANCE", True):
            self.assertTrue(poller._worth_alerting(self.entry(maintenance=True)))


if __name__ == "__main__":
    unittest.main()
