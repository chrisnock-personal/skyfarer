"""Run with: python -m unittest discover tests  (needs requirements.txt)."""
import hashlib
import hmac
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


def response(status, body=b"{}"):
    resp = requests.Response()
    resp.status_code = status
    resp._content = body
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


SN_CREATED = json.dumps({"result": {"sys_id": "a" * 32, "number": "INC0010042"}}).encode()


class ServiceNow(unittest.TestCase):
    def setUp(self):
        patches = {"SERVICENOW_URL": "https://example.service-now.com",
                   "SERVICENOW_USER": "skyfarer", "SERVICENOW_PASSWORD": "pw"}
        for name, value in patches.items():
            p = mock.patch.object(notifiers, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_record_shape(self):
        record = notifiers.servicenow_record(row())
        self.assertLessEqual(len(record["short_description"]), 160)
        self.assertEqual(record["correlation_id"], "skyfarer-7")
        self.assertEqual((record["impact"], record["urgency"]), ("2", "2"))
        self.assertIn("Region: eu-west-2", record["description"])
        for unset in ("assignment_group", "caller_id", "category"):
            self.assertNotIn(unset, record)

    def test_optional_and_extra_fields(self):
        with mock.patch.object(notifiers, "SERVICENOW_ASSIGNMENT_GROUP", "Cloud Ops"), \
                mock.patch.object(notifiers, "SERVICENOW_EXTRA_FIELDS_RAW",
                                  '{"u_service": "Hosting", "impact": "1"}'):
            record = notifiers.servicenow_record(row())
        self.assertEqual(record["assignment_group"], "Cloud Ops")
        self.assertEqual((record["u_service"], record["impact"]), ("Hosting", "1"))

    def test_resolve_sets_state_and_close_fields(self):
        payload = notifiers.servicenow_resolve(row("resolved"))
        self.assertEqual((payload["state"], payload["close_code"]), ("6", "Resolved by caller"))
        self.assertTrue(payload["close_notes"])
        with mock.patch.object(notifiers, "SERVICENOW_RESOLVE", False):
            self.assertEqual(set(notifiers.servicenow_resolve(row("resolved"))), {"work_notes"})

    def test_create_returns_the_record(self):
        with mock.patch.object(notifiers, "_request",
                               return_value=response(201, SN_CREATED)) as req:
            result = notifiers.send_servicenow(row())
        self.assertEqual(result, {"ref": "a" * 32, "number": "INC0010042"})
        method, url = req.call_args.args
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://example.service-now.com/api/now/table/incident"
                              "?sysparm_fields=sys_id,number")
        self.assertEqual(req.call_args.kwargs["auth"], ("skyfarer", "pw"))

    def test_updates_patch_the_record(self):
        with mock.patch.object(notifiers, "_request", return_value=response(200)) as req:
            notifiers.send_servicenow(row("updated", ticket_ref="b" * 32))
        method, url = req.call_args.args
        self.assertEqual((method, url.rsplit("/", 1)[1]), ("PATCH", "b" * 32))
        self.assertIn("work_notes", req.call_args.kwargs["json"])

    def test_token_replaces_basic_auth(self):
        with mock.patch.object(notifiers, "SERVICENOW_TOKEN", "tok"):
            auth = notifiers._sn_auth()
        self.assertNotIn("auth", auth)
        self.assertEqual(auth["headers"]["Authorization"], "Bearer tok")

    def test_update_without_a_record_fails_for_good(self):
        with self.assertRaises(notifiers.PermanentFailure):
            notifiers.send_servicenow(row("resolved", ticket_ref=None))

    def test_auth_failure_keeps_it_queued(self):
        with mock.patch.object(notifiers, "_request", return_value=response(401)):
            with self.assertRaises(notifiers.RetryLater):
                notifiers.send_servicenow(row())

    def test_bad_request_is_permanent(self):
        with mock.patch.object(notifiers, "_request", return_value=response(400)):
            with self.assertRaises(notifiers.PermanentFailure):
                notifiers.send_servicenow(row())

    def test_enabled_with_a_user_or_a_token(self):
        self.assertIn("servicenow", notifiers.enabled_channels())
        with mock.patch.object(notifiers, "SERVICENOW_PASSWORD", ""):
            self.assertNotIn("servicenow", notifiers.enabled_channels())
            with mock.patch.object(notifiers, "SERVICENOW_TOKEN", "tok"):
                self.assertIn("servicenow", notifiers.enabled_channels())

    def test_config_errors(self):
        self.assertEqual(notifiers.config_errors(), [])
        for name, value in (("SERVICENOW_PASSWORD", ""), ("SERVICENOW_IMPACT", "4"),
                            ("SERVICENOW_EXTRA_FIELDS_RAW", "[1, 2]"),
                            ("SERVICENOW_EXTRA_FIELDS_RAW", "{oops")):
            with mock.patch.object(notifiers, name, value):
                self.assertTrue(notifiers.config_errors(), (name, value))

    def test_instance_name_or_url(self):
        self.assertEqual(notifiers.servicenow_url("acme"), "https://acme.service-now.com")
        self.assertEqual(notifiers.servicenow_url(" https://acme.example.com/ "),
                         "https://acme.example.com")
        self.assertEqual(notifiers.servicenow_url(""), "")


class JiraServiceManagement(unittest.TestCase):
    DESKS = {"values": [{"id": "1", "projectKey": "HR"}, {"id": "4", "projectKey": "ISTM"}]}
    TYPES = {"values": [{"id": "10", "name": "Get IT help"},
                        {"id": "12", "name": "Report a system problem"}]}
    # As Jira's issue API lists them for a new ITSM request.
    TRANSITIONS = {"transitions": [{"id": "51", "name": "Pending"}, {"id": "101", "name": "Cancel"},
                                   {"id": "111", "name": "Resolve this issue"}]}

    def setUp(self):
        settings = {"JSM_URL": "https://acme.atlassian.net", "JSM_EMAIL": "bot@example.test",
                    "JSM_API_TOKEN": "tok", "JSM_PROJECT": "ISTM",
                    "JSM_REQUEST_TYPE": "system problem", "JSM_TRANSITION": "Resolve",
                    "JSM_RESOLVE": True, "JSM_EXTRA_FIELDS_RAW": ""}
        for name, value in settings.items():
            p = mock.patch.object(notifiers, name, value)
            p.start()
            self.addCleanup(p.stop)
        notifiers._jsm_ids.clear()

    def fake(self, *responses):
        """_request answering GETs from the lookups above and POSTs in order."""
        posts = list(responses)
        calls = []

        def request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            if method == "GET":
                if url.endswith("/servicedesk?limit=100"):
                    return response(200, json.dumps(self.DESKS).encode())
                if "/requesttype" in url:
                    return response(200, json.dumps(self.TYPES).encode())
                return response(200, json.dumps(self.TRANSITIONS).encode())
            return posts.pop(0)
        return calls, mock.patch.object(notifiers, "_request", side_effect=request)

    def test_site_name_or_url(self):
        self.assertEqual(notifiers.jsm_url("acme"), "https://acme.atlassian.net")
        self.assertEqual(notifiers.jsm_url("https://jira.example.test/"), "https://jira.example.test")

    def test_opens_a_request_in_the_right_desk_and_type(self):
        calls, p = self.fake(response(201, b'{"issueKey": "ISTM-7"}'))
        with p:
            result = notifiers.send_jsm(row())
        self.assertEqual(result, {"ref": "ISTM-7", "number": "ISTM-7"})
        method, url, kwargs = calls[-1]
        self.assertEqual((method, url), ("POST", "https://acme.atlassian.net/rest/servicedeskapi/request"))
        body = kwargs["json"]
        self.assertEqual((body["serviceDeskId"], body["requestTypeId"]), ("4", "12"))
        self.assertLessEqual(len(body["requestFieldValues"]["summary"]), 250)
        self.assertIn("Region: eu-west-2", body["requestFieldValues"]["description"])
        self.assertEqual(kwargs["auth"], ("bot@example.test", "tok"))

    def test_lookups_happen_once(self):
        calls, p = self.fake(response(201, b'{"issueKey": "ISTM-7"}'), response(201, b'{"issueKey": "ISTM-8"}'))
        with p:
            notifiers.send_jsm(row())
            notifiers.send_jsm(row())
        self.assertEqual(sum(1 for c in calls if c[0] == "GET"), 2)

    def test_update_is_an_internal_comment(self):
        calls, p = self.fake(response(201))
        with p:
            notifiers.send_jsm(row("updated", ticket_ref="ISTM-7"))
        method, url, kwargs = calls[-1]
        self.assertTrue(url.endswith("/request/ISTM-7/comment"))
        self.assertIs(kwargs["json"]["public"], False)

    def test_resolve_notes_then_uses_the_named_transition(self):
        calls, p = self.fake(response(201), response(204))
        with p:
            notifiers.send_jsm(row("resolved", ticket_ref="ISTM-7"))
        self.assertTrue(calls[0][1].endswith("/rest/api/3/issue/ISTM-7/transitions"))
        (_, note_url, note), (_, url, kwargs) = calls[-2], calls[-1]
        self.assertTrue(note_url.endswith("/servicedeskapi/request/ISTM-7/comment"))
        self.assertIn("resolved", note["json"]["body"])
        self.assertIs(note["json"]["public"], False)
        self.assertEqual(url, "https://acme.atlassian.net/rest/api/3/issue/ISTM-7/transitions")
        self.assertEqual(kwargs["json"], {"transition": {"id": "111"}})

    def test_resolve_off_leaves_a_comment(self):
        calls, p = self.fake(response(201))
        with mock.patch.object(notifiers, "JSM_RESOLVE", False), p:
            notifiers.send_jsm(row("resolved", ticket_ref="ISTM-7"))
        self.assertTrue(calls[-1][1].endswith("/comment"))
        self.assertIn("manual review", calls[-1][2]["json"]["body"])

    def test_unknown_names_say_what_exists(self):
        with mock.patch.object(notifiers, "JSM_PROJECT", "ITSM"):
            calls, p = self.fake()
            with p, self.assertRaises(notifiers.PermanentFailure) as caught:
                notifiers.send_jsm(row())
        self.assertIn("HR, ISTM", str(caught.exception))
        calls, p = self.fake()
        with mock.patch.object(notifiers, "JSM_TRANSITION", "Close"), p, \
                self.assertRaises(notifiers.PermanentFailure) as caught:
            notifiers.send_jsm(row("resolved", ticket_ref="ISTM-7"))
        self.assertIn("Pending, Cancel, Resolve this issue", str(caught.exception))
        self.assertEqual([c[0] for c in calls], ["GET"])   # nothing posted

    def test_refusals_carry_jsm_reason_and_auth_errors_retry(self):
        calls, p = self.fake(response(400, b'{"errorMessage": "Field Priority is required"}'))
        with p, self.assertRaises(notifiers.PermanentFailure) as caught:
            notifiers.send_jsm(row())
        self.assertIn("Field Priority is required", str(caught.exception))
        calls, p = self.fake(response(201), response(400, b'{"errorMessages": [], "errors": {"resolution": "Resolution is required."}}'))
        with p, self.assertRaises(notifiers.PermanentFailure) as caught:
            notifiers.send_jsm(row("resolved", ticket_ref="ISTM-7"))
        self.assertIn("resolution: Resolution is required.", str(caught.exception))
        for status in (401, 429, 503):
            calls, p = self.fake(response(status))
            with p, self.assertRaises(notifiers.RetryLater):
                notifiers.send_jsm(row())

    def test_extra_fields_and_config_errors(self):
        with mock.patch.object(notifiers, "JSM_EXTRA_FIELDS_RAW", '{"priority": {"name": "High"}}'):
            calls, p = self.fake(response(201, b'{"issueKey": "ISTM-9"}'))
            with p:
                notifiers.send_jsm(row())
            self.assertEqual(calls[-1][2]["json"]["requestFieldValues"]["priority"], {"name": "High"})
        self.assertEqual([e for e in notifiers.config_errors() if "Jira" in e], [])
        with mock.patch.object(notifiers, "JSM_API_TOKEN", ""):
            self.assertTrue(any("Jira" in e for e in notifiers.config_errors()))
            self.assertNotIn("jsm", notifiers.enabled_channels())
        with mock.patch.object(notifiers, "JSM_EXTRA_FIELDS_RAW", "[1]"):
            self.assertTrue(any("Jira" in e for e in notifiers.config_errors()))


class Webhook(unittest.TestCase):
    def hook(self, **fields):
        return notifiers.Webhook(**{"id": 3, "name": "Test", "url": "https://hooks.example.test/in",
                                    **fields})

    def send(self, r, **fields):
        hook = self.hook(**fields)
        with mock.patch.object(notifiers, "WEBHOOKS", [hook]), \
                mock.patch.object(notifiers, "_request", return_value=response(200)) as req:
            notifiers.send_webhook({**r, "channel": hook.channel})
        return req.call_args

    def test_default_body_has_every_field(self):
        call = self.send(row("resolved"))
        body = json.loads(call.kwargs["data"])
        self.assertEqual(body["source"], "skyfarer")
        self.assertEqual((body["event"], body["incident_id"]), ("resolved", 7))
        self.assertEqual(set(notifiers.WEBHOOK_FIELDS) - set(body), set())
        self.assertEqual(call.args, ("POST", "https://hooks.example.test/in"))
        headers = call.kwargs["headers"]
        self.assertEqual((headers["X-Skyfarer-Event"], headers["X-Skyfarer-Incident"]),
                         ("resolved", "7"))
        self.assertNotIn("X-Skyfarer-Signature", headers)

    def test_template_values_are_escaped_for_json(self):
        r = row()
        r["payload"]["title"] = 'Say "hi"\nnext line'
        template = '{"text": "{{event}}: {{title}}", "id": {{incident_id}}}'
        body = json.loads(self.send(r, template=template).kwargs["data"])
        self.assertEqual(body, {"text": 'opened: Say "hi"\nnext line', "id": 7})

    def test_plain_text_template(self):
        call = self.send(row(), template="{{ provider }} {{region}}: {{title}}",
                         content_type="text/plain")
        self.assertEqual(call.kwargs["data"], b"AWS eu-west-2: Service impact")
        self.assertEqual(call.kwargs["headers"]["Content-Type"], "text/plain")

    def test_signature_and_headers(self):
        call = self.send(row(), secret="s3cret", headers='{"Authorization": "Bearer abc"}')
        headers, body = call.kwargs["headers"], call.kwargs["data"]
        expected = hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-Skyfarer-Signature"], f"sha256={expected}")
        self.assertEqual(headers["Authorization"], "Bearer abc")

    def test_each_webhook_uses_its_own_settings(self):
        a = self.hook(id=1, url="https://a.example.test/", method="PUT")
        b = self.hook(id=2, url="https://b.example.test/")
        with mock.patch.object(notifiers, "WEBHOOKS", [a, b]), \
                mock.patch.object(notifiers, "_request", return_value=response(200)) as req:
            notifiers.send_webhook({**row(), "channel": "webhook-2"})
            notifiers.send_webhook({**row(), "channel": "webhook-1"})
        self.assertEqual([c.args for c in req.call_args_list],
                         [("POST", "https://b.example.test/"), ("PUT", "https://a.example.test/")])
        self.assertEqual(notifiers.sender_for("webhook-2"), notifiers.send_webhook)

    def test_deleted_webhook_fails_for_good(self):
        with mock.patch.object(notifiers, "WEBHOOKS", []):
            with self.assertRaises(notifiers.PermanentFailure):
                notifiers.send_webhook({**row(), "channel": "webhook-9"})

    def test_retries_like_the_others(self):
        for status, error in ((503, notifiers.RetryLater), (429, notifiers.RetryLater),
                              (404, notifiers.PermanentFailure)):
            with mock.patch.object(notifiers, "WEBHOOKS", [self.hook()]), \
                    mock.patch.object(notifiers, "_request", return_value=response(status)):
                with self.assertRaises(error):
                    notifiers.send_webhook({**row(), "channel": "webhook-3"})

    def test_errors(self):
        self.assertEqual(notifiers.webhook_errors(self.hook()), [])
        for fields in ({"url": "ftp://x"}, {"method": "GET"}, {"headers": '{"X": 1}'},
                       {"template": '{"t": "{{titel}}"}'}, {"template": '{"t": {{title}}}'},
                       {"events": ["started"]}):
            self.assertTrue(notifiers.webhook_errors(self.hook(**fields)), fields)
        with mock.patch.object(notifiers, "WEBHOOKS", [self.hook(method="GET")]):
            self.assertTrue(any("Webhook 'Test'" in e for e in notifiers.config_errors()))

    def test_own_event_list(self):
        def queued(event, events):
            hook = self.hook(events=events)
            with mock.patch.object(notifiers, "WEBHOOKS", [hook]), \
                    mock.patch.object(notifiers, "enabled_channels", return_value=[hook.channel, "teams"]), \
                    mock.patch.object(notifiers.db, "was_notified", return_value=True), \
                    mock.patch.object(notifiers.db, "add_notification") as add:
                notifiers.enqueue(None, 7, event, dict(NOTICE))
            return {c.kwargs["channel"] for c in add.call_args_list}
        self.assertEqual(queued("updated", ["opened", "updated", "resolved"]), {"webhook-3"})
        self.assertEqual(queued("opened", ["resolved"]), {"teams"})
        # No list of its own: it follows NOTIFY_EVENTS like the others.
        self.assertEqual(queued("opened", []), {"webhook-3", "teams"})

    def test_env_describes_one_webhook(self):
        env = {"WEBHOOK_URL": "https://h.example.test/", "WEBHOOK_SECRET": "x",
               "WEBHOOK_EVENTS": "opened"}
        with mock.patch.dict(os.environ, env):
            hooks = notifiers._env_webhook()
        self.assertEqual([(h.channel, h.url, h.secret, h.events) for h in hooks],
                         [("webhook-1", "https://h.example.test/", "x", ["opened"])])


class Enqueue(unittest.TestCase):
    def queued(self, event, *, alert=True, notified=True, events=("opened", "resolved")):
        with mock.patch.object(notifiers, "enabled_channels", return_value=[
                "zendesk", "servicenow", "pushover", "pagerduty", "teams", "snmp"]), \
                mock.patch.object(notifiers, "NOTIFY_EVENTS", list(events)), \
                mock.patch.object(notifiers.db, "was_notified", return_value=notified), \
                mock.patch.object(notifiers.db, "add_notification") as add:
            notifiers.enqueue(None, 7, event, dict(NOTICE), alert=alert)
        return {call.kwargs["channel"] for call in add.call_args_list}

    def test_opened_reaches_everyone(self):
        self.assertEqual(self.queued("opened"),
                         {"zendesk", "servicenow", "pushover", "pagerduty", "teams", "snmp"})

    def test_suppressed_incident_only_reaches_ticketing(self):
        self.assertEqual(self.queued("opened", alert=False), {"zendesk", "servicenow"})

    def test_no_all_clear_without_an_alert(self):
        self.assertEqual(self.queued("resolved", notified=False), {"zendesk", "servicenow"})

    def test_updates_are_ticketing_only_by_default(self):
        self.assertEqual(self.queued("updated"), {"zendesk", "servicenow"})

    def test_pagerduty_never_gets_updates(self):
        got = self.queued("updated", events=notifiers.EVENTS)
        self.assertEqual(got, {"zendesk", "servicenow", "pushover", "teams", "snmp"})


class Delivery(unittest.TestCase):
    def queued(self, rid, event, *, channel="zendesk", **extra):
        when = datetime.now(timezone.utc)
        base = {"id": rid, "incident_id": 7, "channel": channel, "event": event,
                "ticket_id": None, "payload": dict(NOTICE), "attempts": 0,
                "created_at": when, "next_attempt_at": when - timedelta(seconds=1)}
        return {**base, **extra}

    def deliver(self, rows, sender):
        with mock.patch.object(notifiers, "enabled_channels",
                               return_value=["zendesk", "servicenow", "teams"]), \
                mock.patch.dict(notifiers.SENDERS, {"zendesk": sender, "servicenow": sender,
                                                    "teams": sender}), \
                mock.patch.object(notifiers.db, "get_conn"), \
                mock.patch.object(notifiers.db, "pending_notifications", return_value=rows), \
                mock.patch.object(notifiers.db, "notification_sent"), \
                mock.patch.object(notifiers.db, "notification_retry") as retry, \
                mock.patch.object(notifiers.db, "notification_failed") as failed, \
                mock.patch.object(notifiers.db, "set_ticket"), \
                mock.patch.object(notifiers.db, "set_external_ticket") as self.stored:
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

    def test_servicenow_update_can_use_a_record_opened_in_the_same_pass(self):
        seen = []

        def sender(r):
            seen.append(r.get("ticket_ref"))
            return {"ref": "c" * 32, "number": "INC1"} if r["event"] == "opened" else None

        rows = [self.queued(1, "opened", channel="servicenow"),
                self.queued(2, "resolved", channel="servicenow")]
        sent, _, _ = self.deliver(rows, sender)
        self.assertEqual((sent, seen), (2, [None, "c" * 32]))
        self.stored.assert_called_once_with(mock.ANY, 7, "servicenow", ref="c" * 32, number="INC1")

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



class StableIdUpdates(unittest.TestCase):
    """Providers that keep one ID per incident (Statuspage ones, Hetzner, GCP,
    OVH) pass new updates on while the incident is open, not just at the end."""

    def entry(self, summary, resolved=False):
        now = datetime.now(timezone.utc)
        return feeds.FeedEntry(
            provider="DigitalOcean", region="LON1", guid="digitalocean:abc", title="Droplet creates failing",
            summary=summary, link="l", published="p", updated="u", is_resolved=resolved,
            published_dt=now, updated_dt=now)

    def poll(self, entries, rec):
        with mock.patch.object(poller, "fetch_all", return_value=(entries, None, None)), \
                mock.patch.object(poller.db, "get_conn"), \
                mock.patch.object(poller.db, "get_known_guids", return_value={"digitalocean:abc"}), \
                mock.patch.object(poller.db, "get_open_guids", return_value={"digitalocean:abc": rec}), \
                mock.patch.object(poller.db, "add_update") as add, \
                mock.patch.object(poller.db, "refresh_incident") as refresh, \
                mock.patch.object(poller.db, "mark_resolved"), \
                mock.patch.object(poller.db, "log_poll"), \
                mock.patch.object(poller.db, "count_open", return_value=1), \
                mock.patch.object(poller.notifiers, "enqueue") as enqueue, \
                mock.patch.object(poller.notifiers, "deliver_pending"):
            poller.poll_once()
        return add, refresh, enqueue

    def rec(self, summary):
        return {"id": 3, "guid": "digitalocean:abc", "ticket_id": None, "provider": "DigitalOcean",
                "region": "LON1", "title": "Droplet creates failing", "summary": summary}

    def test_new_words_are_an_update(self):
        add, refresh, enqueue = self.poll([self.entry("Identified: a storage cluster is degraded")],
                                          self.rec("Investigating: failed creates"))
        self.assertTrue(add.call_args.kwargs["guid"].startswith("digitalocean:abc#"))
        self.assertEqual(refresh.call_args.kwargs["summary"], "Identified: a storage cluster is degraded")
        self.assertEqual(refresh.call_args.kwargs["added_updates"], 1)
        (conn, incident_id, event, notice), kwargs = enqueue.call_args
        self.assertEqual((incident_id, event), (3, "updated"))
        self.assertEqual(notice["summary"], "Identified: a storage cluster is degraded")

    def test_same_words_are_not(self):
        add, refresh, enqueue = self.poll([self.entry("Investigating: failed creates")],
                                          self.rec("Investigating: failed creates"))
        add.assert_not_called()
        enqueue.assert_not_called()

    def test_ending_is_still_a_resolve_not_an_update(self):
        add, refresh, enqueue = self.poll([self.entry("Resolved: all good", resolved=True)],
                                          self.rec("Investigating: failed creates"))
        add.assert_not_called()
        self.assertEqual([c.args[2] for c in enqueue.call_args_list], ["resolved"])

    def test_the_update_id_follows_the_words(self):
        first = self.poll([self.entry("A")], self.rec("x"))[0].call_args.kwargs["guid"]
        again = self.poll([self.entry("A")], self.rec("y"))[0].call_args.kwargs["guid"]
        other = self.poll([self.entry("B")], self.rec("x"))[0].call_args.kwargs["guid"]
        self.assertEqual(first, again)
        self.assertNotEqual(first, other)

if __name__ == "__main__":
    unittest.main()
