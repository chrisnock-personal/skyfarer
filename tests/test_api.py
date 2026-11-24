"""API auth, scopes, endpoint shapes and CLI basics. No database or network:
the guard's DB work and the query helper are mocked. Run with:
python -m unittest discover tests"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import admin  # noqa: E402
import api  # noqa: E402
import cli  # noqa: E402
import dashboard  # noqa: E402
import history  # noqa: E402
import notifiers  # noqa: E402
import settings  # noqa: E402

NOW = datetime(2026, 11, 24, 12, tzinfo=timezone.utc)


def report():
    start = NOW - timedelta(days=30)
    return history.build([], start, NOW, {"DigitalOcean": 99.9}, now=NOW)


@contextmanager
def no_db():
    yield mock.MagicMock()


class ApiAuth(unittest.TestCase):
    def setUp(self):
        dashboard.app.secret_key = "test-only"
        self.client = dashboard.app.test_client()
        self.patches = [
            mock.patch.object(admin, "_bootstrapped", [True]),
            mock.patch.object(admin.db, "get_conn", side_effect=no_db),
            mock.patch.object(admin.settings, "bootstrap"),
            mock.patch.object(admin.settings, "apply"),
            mock.patch.object(admin.settings, "user_count", return_value=2),
            mock.patch.object(admin.db, "api_rate_limit", return_value=(True, 0)),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def patch_token(self, role="viewer", scopes=("status:read",)):
        record = {"token_id": 1, "id": 7, "email": "svc@example.test", "name": "CI",
                  "role": role, "kind": "service", "scopes": list(scopes)}
        patcher = mock.patch.object(admin.settings, "api_token", return_value=record)
        patcher.start()
        self.addCleanup(patcher.stop)
        touch = mock.patch.object(admin.settings, "touch_api_token")
        touch.start()
        self.addCleanup(touch.stop)

    def test_no_token_is_a_problem_response(self):
        response = self.client.get("/api/v1/status")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.mimetype, "application/problem+json")
        self.assertEqual(response.json["status"], 401)
        self.assertIn("WWW-Authenticate", response.headers)

    def test_bad_token_is_rejected(self):
        with mock.patch.object(admin.settings, "api_token", return_value=None):
            response = self.client.get("/api/v1/status",
                                       headers={"Authorization": "Bearer sk_live_bad"})
        self.assertEqual(response.status_code, 401)

    def test_openapi_is_public_and_valid(self):
        response = self.client.get("/api/v1/openapi.json")
        self.assertEqual(response.status_code, 200)
        spec = json.loads(response.get_data())
        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertIn("/history", spec["paths"])

    def test_openapi_covers_every_route(self):
        spec = json.loads(self.client.get("/api/v1/openapi.json").get_data())
        for rule in dashboard.app.url_map.iter_rules():
            if not rule.rule.startswith("/api/v1"):
                continue
            path = __import__("re").sub(r"<[^>]+>", "{id}", rule.rule[len("/api/v1"):])
            self.assertIn(path, spec["paths"], rule.rule)
            for method in rule.methods & {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                self.assertIn(method.lower(), spec["paths"][path], f"{method} {rule.rule}")

    def test_openapi_documents_poll_log_date_filters(self):
        spec = json.loads(self.client.get("/api/v1/openapi.json").get_data())
        params = {p["name"] for p in spec["paths"]["/poll-log"]["get"]["parameters"]}
        self.assertTrue({"from", "to"} <= params)
        self.assertIn("incident, delivery and poll-cycle lists use cursor pagination",
                      spec["info"]["description"])
        self.assertNotIn("NotModified", spec["components"]["responses"])

    def test_missing_scope_is_forbidden(self):
        self.patch_token(scopes=("status:read",))
        response = self.client.get("/api/v1/history",
                                   headers={"Authorization": "Bearer sk_live_ok"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json["detail"], "This token needs the history:read scope.")

    def test_role_caps_write_scopes(self):
        # The ceiling is checked at the endpoint, not only when the token is made.
        @api.require("settings:write")
        def endpoint():
            return "ok"

        with dashboard.app.test_request_context("/api/v1/status"):
            from flask import g
            g.user = {"role": "viewer"}
            g.api_scopes = {"settings:write"}
            response = endpoint()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json["detail"], "That scope needs an admin account.")


class ApiEndpoints(unittest.TestCase):
    def setUp(self):
        dashboard.app.secret_key = "test-only"
        self.client = dashboard.app.test_client()
        self.headers = {"Authorization": "Bearer sk_live_ok"}
        record = {"token_id": 1, "id": 7, "email": "svc@example.test", "name": "CI",
                  "role": "admin", "kind": "service",
                  "scopes": ["status:read", "incidents:read", "history:read",
                             "deliveries:read", "poll-log:read"]}
        self.patches = [
            mock.patch.object(admin, "_bootstrapped", [True]),
            mock.patch.object(admin.db, "get_conn", side_effect=no_db),
            mock.patch.object(admin.settings, "bootstrap"),
            mock.patch.object(admin.settings, "apply"),
            mock.patch.object(admin.settings, "user_count", return_value=2),
            mock.patch.object(admin.settings, "api_token", return_value=record),
            mock.patch.object(admin.settings, "touch_api_token"),
            mock.patch.object(admin.db, "api_rate_limit", return_value=(True, 0)),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_status_reuses_dashboard_helpers(self):
        with mock.patch.object(dashboard, "fetch_summary", return_value={"last_poll": NOW}), \
                mock.patch.object(dashboard, "fetch_providers", return_value=([{"name": "OVH"}], [])), \
                mock.patch.object(dashboard, "fetch_channels", return_value=[{"id": "zendesk"}]), \
                mock.patch.object(dashboard, "fetch_poll_bars", return_value=([], [])), \
                mock.patch.object(dashboard, "_feed_errors", return_value={}):
            response = self.client.get("/api/v1/status", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["providers"], [{"name": "OVH"}])

    def test_incidents_are_paginated_by_cursor(self):
        rows = [{"id": i, "provider": "OVH", "state": "open",
                 "detected_at": NOW - timedelta(minutes=i)} for i in (9, 8, 7)]
        with mock.patch.object(api, "query", return_value=rows):
            response = self.client.get("/api/v1/incidents?limit=2", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json["items"]], [9, 8])
        self.assertEqual(response.json["next_cursor"], 8)
        self.assertIn("Z", response.json["items"][0]["detected_at"])

    def test_bad_cursor_is_rejected(self):
        response = self.client.get("/api/v1/incidents?cursor=abc", headers=self.headers)
        self.assertEqual(response.status_code, 400)

    def test_incident_detail_404(self):
        with mock.patch.object(api, "query", return_value=[]):
            response = self.client.get("/api/v1/incidents/99", headers=self.headers)
        self.assertEqual(response.status_code, 404)

    def test_history_json_and_csv(self):
        with mock.patch.object(dashboard, "history_context", return_value={"report": report()}):
            response = self.client.get("/api/v1/history?range=year", headers=self.headers)
            csv = self.client.get("/api/v1/history?range=year&format=csv", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("availability_label", response.json)
        self.assertEqual(csv.mimetype, "text/csv")
        self.assertIn("Started (UTC)", csv.get_data(as_text=True))


class TokenSettings(unittest.TestCase):
    def setUp(self):
        dashboard.app.secret_key = "test-only"
        self.client = dashboard.app.test_client()
        self.patches = [
            mock.patch.object(admin, "_bootstrapped", [True]),
            mock.patch.object(admin.db, "get_conn", side_effect=no_db),
            mock.patch.object(admin.settings, "bootstrap"),
            mock.patch.object(admin.settings, "apply"),
            mock.patch.object(admin.settings, "user_count", return_value=2),
            mock.patch.object(admin.settings, "user", return_value={
                "id": 1, "email": "admin@example.test", "name": "Admin", "role": "admin",
                "kind": "human"}),
            mock.patch.object(admin.settings, "api_tokens", return_value=[]),
            mock.patch.object(admin.settings, "users", return_value=[]),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        with self.client.session_transaction() as session:
            session["uid"] = 1
            session["csrf"] = "test-csrf"

    def test_page_lists_scopes(self):
        response = self.client.get("/settings/tokens")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"incidents:read", response.data)
        self.assertIn(b"API tokens", response.data)

    def test_create_token_filters_viewer_scopes(self):
        with mock.patch.object(admin.settings, "api_token") as token, \
                mock.patch.object(admin.settings, "touch_api_token"), \
                mock.patch.object(admin.settings, "create_api_token",
                                  return_value=(1, "sk_live_once")) as create, \
                mock.patch.object(admin.settings, "user", side_effect=lambda conn, uid: {
                    1: {"id": 1, "role": "admin", "name": "Admin"},
                    5: {"id": 5, "role": "viewer", "name": "CI"}}[uid]):
            response = self.client.post("/settings/tokens/new", data={
                "csrf": "test-csrf", "name": "CI", "user_id": "5",
                "incidents:read": "1", "settings:write": "1"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"sk_live_once", response.data)
        scopes = create.call_args.args[3]
        self.assertEqual(scopes, ["incidents:read"])

    def test_service_account_has_no_password(self):
        with mock.patch.object(admin.settings, "create_user") as create:
            response = self.client.post("/settings/tokens/service", data={
                "csrf": "test-csrf", "name": "Deploy", "email": "deploy@example.test",
                "role": "viewer"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(create.call_args.kwargs["kind"], "service")


def hook_row(hook_id: int = 4) -> dict:
    hook = notifiers.Webhook(
        id=hook_id, name="Hook", url="https://example.com/hook", method="POST",
        headers="", template="", content_type="application/json", secret="", events=["opened"])
    return {"id": hook_id, "name": "Hook", "enabled": True, "url": hook.url,
            "method": "POST", "events": "opened", "template": "",
            "content_type": "application/json", "created_at": NOW, "updated_at": NOW,
            "unreadable": False, "hook": hook}


class ApiAdmin(unittest.TestCase):
    """Write endpoints, all sharing the guard's admin token."""
    def setUp(self):
        dashboard.app.secret_key = "test-only"
        self.client = dashboard.app.test_client()
        record = {"token_id": 1, "id": 7, "email": "admin@example.test", "name": "Admin",
                  "role": "admin", "kind": "human", "scopes": list(api.SCOPES)}
        self.headers = {"Authorization": "Bearer sk_live_ok"}
        self.values = {"ZENDESK_API_TOKEN": "super-secret", "ZENDESK_SUBDOMAIN": "acme",
                       "OVH_REGIONS": "GRA,SBG", "NOTIFY_EVENTS": "opened,resolved"}
        self.patches = [
            mock.patch.object(admin, "_bootstrapped", [True]),
            mock.patch.object(admin.db, "get_conn", side_effect=no_db),
            mock.patch.object(admin.db, "api_rate_limit", return_value=(True, 0)),
            mock.patch.object(admin.settings, "bootstrap"),
            mock.patch.object(admin.settings, "apply"),
            mock.patch.object(admin.settings, "user_count", return_value=2),
            mock.patch.object(admin.settings, "api_token", return_value=record),
            mock.patch.object(admin.settings, "touch_api_token"),
            mock.patch.object(admin.settings, "load", side_effect=lambda *a, **k: dict(self.values)),
            mock.patch.object(admin.settings, "secret_meta", return_value={
                "ZENDESK_API_TOKEN": {"updated_at": NOW, "updated_by": "Admin"}}),
            mock.patch.object(admin.settings, "check", return_value=[]),
            mock.patch.object(admin.settings, "save", return_value=["changed"]),
            mock.patch.object(admin.settings, "webhooks", return_value=[hook_row()]),
            mock.patch.object(admin.settings, "webhook_save", return_value=4),
            mock.patch.object(admin.settings, "webhook_enable"),
            mock.patch.object(admin.settings, "webhook_delete"),
            mock.patch.object(admin.settings, "users", return_value=[]),
            mock.patch.object(admin.settings, "user", return_value={
                "id": 5, "email": "ci@example.test", "name": "CI", "role": "viewer", "kind": "human"}),
            mock.patch.object(admin.settings, "create_user",
                              return_value=settings.NewLink(user_id=9, token="setup-token")),
            mock.patch.object(admin.settings, "create_api_token", return_value=(3, "sk_live_new")),
            mock.patch.object(admin.settings, "api_tokens", return_value=[]),
            mock.patch.object(admin.settings, "api_token_by_id", return_value={
                "id": 3, "name": "CI", "scopes": ["incidents:read"], "revoked": False}),
            mock.patch.object(admin.settings, "set_role", return_value=None),
            mock.patch.object(admin.settings, "delete_user", return_value=None),
            mock.patch.object(admin.settings, "new_setup_link",
                              return_value=settings.NewLink(user_id=5, token="new-link")),
            mock.patch.object(admin.settings, "revoke_api_token", return_value="CI"),
            mock.patch.object(admin.notifiers, "enabled_channels", return_value=[]),
            mock.patch.object(admin.notifiers, "webhook_errors", return_value=[]),
            mock.patch.object(admin, "run_test", return_value=(True, "Test sent")),
            mock.patch.object(admin.settings, "headless_bootstrap", return_value={
                "user_id": 1, "email": "admin@example.test", "api_token": "sk_live_boot"}),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_settings_never_return_secret_values(self):
        response = self.client.get("/api/v1/settings", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"super-secret", response.data)
        fields = {f["key"]: f for g in response.json["groups"] for f in g["fields"]}
        self.assertTrue(fields["ZENDESK_API_TOKEN"]["secret"])
        self.assertTrue(fields["ZENDESK_API_TOKEN"]["configured"])
        self.assertEqual(fields["ZENDESK_SUBDOMAIN"]["value"], "acme")

    def test_put_settings_cleans_and_saves(self):
        response = self.client.put("/api/v1/settings", headers=self.headers, json={
            "values": {"NOTIFY_MAINTENANCE": True, "POLL_INTERVAL_SECONDS": "60",
                       "ZENDESK_API_TOKEN": None}})
        self.assertEqual(response.status_code, 200)
        changes = admin.settings.save.call_args.args[1]
        self.assertEqual(changes["NOTIFY_MAINTENANCE"], "true")
        self.assertIsNone(changes["ZENDESK_API_TOKEN"])

    def test_put_settings_blank_secret_keeps_it(self):
        response = self.client.put("/api/v1/settings", headers=self.headers, json={
            "values": {"ZENDESK_API_TOKEN": "", "POLL_INTERVAL_SECONDS": "60"}})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("ZENDESK_API_TOKEN", admin.settings.save.call_args.args[1])

    def test_put_settings_needs_an_object(self):
        response = self.client.put("/api/v1/settings", headers=self.headers,
                                   json={"values": ["POLL_INTERVAL_SECONDS"]})
        self.assertEqual(response.status_code, 400)

    def test_put_settings_rejects_bad_select(self):
        response = self.client.put("/api/v1/settings", headers=self.headers, json={
            "values": {"POLL_INTERVAL_SECONDS": "7"}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.mimetype, "application/problem+json")

    def test_providers_round_trip(self):
        listed = self.client.get("/api/v1/providers", headers=self.headers)
        ovh = next(p for p in listed.json["items"] if p["name"] == "OVH")
        self.assertEqual(ovh["regions"], ["GRA", "SBG"])
        response = self.client.put("/api/v1/providers", headers=self.headers, json={
            "items": [{"name": "OVH", "enabled": False, "regions": ["GRA", "WAW"]}]})
        self.assertEqual(response.status_code, 200)
        changes = admin.settings.save.call_args.args[1]
        self.assertEqual(changes["OVH_REGIONS"], "GRA,WAW")
        self.assertEqual(changes["OVH_ENABLED"], "false")

    def test_channel_write_and_test(self):
        response = self.client.patch("/api/v1/channels/zendesk", headers=self.headers, json={
            "enabled": True, "ZENDESK_SUBDOMAIN": "newco"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(admin.settings.save.call_args.args[1]["ZENDESK_SUBDOMAIN"], "newco")
        nested = self.client.patch("/api/v1/channels/zendesk", headers=self.headers,
                                   json={"values": {"ZENDESK_SUBDOMAIN": "nested"}})
        self.assertEqual(nested.status_code, 200)
        self.assertEqual(admin.settings.save.call_args.args[1]["ZENDESK_SUBDOMAIN"], "nested")
        tested = self.client.post("/api/v1/channels/zendesk/test", headers=self.headers, json={})
        self.assertEqual(tested.json, {"ok": True, "message": "Test sent"})
        cleared = self.client.delete("/api/v1/channels/zendesk", headers=self.headers)
        self.assertTrue(cleared.json["deleted"])

    def test_rules_validate_hours(self):
        response = self.client.put("/api/v1/rules", headers=self.headers, json={
            "events": ["opened"], "max_age_hours": -4})
        self.assertEqual(response.status_code, 400)

    def test_rules_change_only_what_is_sent(self):
        response = self.client.put("/api/v1/rules", headers=self.headers,
                                   json={"retry_hours": 2})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(admin.settings.save.call_args.args[1], {"NOTIFY_RETRY_HOURS": "2"})

    def test_webhook_crud(self):
        created = self.client.post("/api/v1/webhooks", headers=self.headers, json={
            "name": "Hook", "url": "https://example.com/hook", "method": "POST"})
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json["id"], 4)
        patched = self.client.patch("/api/v1/webhooks/4", headers=self.headers, json={"enabled": False})
        self.assertEqual(patched.status_code, 200)
        self.assertEqual(admin.settings.webhook_enable.call_args.args[2], False)
        self.assertEqual(self.client.delete("/api/v1/webhooks/4", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.post("/api/v1/webhooks/4/test", headers=self.headers,
                                           json={}).json["ok"], True)

    def test_users_and_tokens(self):
        created = self.client.post("/api/v1/users", headers=self.headers, json={
            "name": "CI", "email": "ci@example.test", "role": "viewer"})
        self.assertEqual(created.status_code, 201)
        self.assertIn("/welcome/setup-token", created.json["setup_url"])
        self.assertEqual(admin.settings.create_user.call_args.kwargs["kind"], "human")
        self.assertEqual(self.client.patch("/api/v1/users/5", headers=self.headers,
                                           json={"role": "admin"}).json["role"], "admin")
        self.assertEqual(self.client.delete("/api/v1/users/5", headers=self.headers).status_code, 200)
        token = self.client.post("/api/v1/tokens", headers=self.headers, json={
            "name": "CI", "user_id": 5, "scopes": ["settings:write", "incidents:read"]})
        self.assertEqual(token.json["token"], "sk_live_new")
        self.assertEqual(token.json["scopes"], ["incidents:read"])  # viewer ceiling
        self.assertEqual(self.client.delete("/api/v1/tokens/3", headers=self.headers).status_code, 200)

    def test_rate_limit_returns_retry_after(self):
        admin.db.api_rate_limit.return_value = (False, 12)
        response = self.client.get("/api/v1/status", headers=self.headers)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "12")

    def test_bootstrap_needs_secret(self):
        response = self.client.post("/api/v1/bootstrap", json={
            "name": "Admin", "email": "admin@example.test", "password": "long-password-123"})
        self.assertEqual(response.status_code, 401)
        with mock.patch.dict(os.environ, {"SKYFARER_BOOTSTRAP_SECRET": "s3cret"}):
            allowed = self.client.post("/api/v1/bootstrap", headers={
                "X-Bootstrap-Secret": "s3cret"}, json={
                "name": "Admin", "email": "admin@example.test", "password": "long-password-123"})
        self.assertEqual(allowed.status_code, 201)
        self.assertEqual(allowed.json["api_token"], "sk_live_boot")


class CliClient(unittest.TestCase):
    def test_missing_token_exits_three(self):
        with mock.patch.dict(os.environ, {"SKYFARER_TOKEN": ""}), \
                mock.patch.object(cli, "load_profile", return_value={}):
            code = cli.main(["status"])
        self.assertEqual(code, 3)

    def test_status_prints_json(self):
        out = io.StringIO()
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "get", return_value={"summary": {"open": 1}}), \
                mock.patch("sys.stdout", out):
            code = cli.main(["--json", "status"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), {"summary": {"open": 1}})

    def test_poll_log_passes_date_filters(self):
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "get", return_value={"items": []}) as get, \
                mock.patch("sys.stdout", io.StringIO()):
            code = cli.main(["--json", "poll-log", "--range", "custom",
                             "--from", "2026-11-01", "--to", "2026-11-24"])
        self.assertEqual(code, 0)
        self.assertEqual(get.call_args.args[1], {
            "range": "custom", "from": "2026-11-01", "to": "2026-11-24", "limit": 50})

    def test_fail_on_open_exit_code(self):
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "get", return_value={"items": [{"id": 1}],
                                                                   "next_cursor": None}):
            code = cli.main(["incidents", "list", "--fail-on-open"])
        self.assertEqual(code, 7)
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "get", return_value={"items": [{"id": 1}],
                                                                   "next_cursor": None}), \
                mock.patch("sys.stdout", io.StringIO()):
            code = cli.main(["--json", "incidents", "list", "--fail-on-open"])
        self.assertEqual(code, 7)

    def test_status_table_shows_the_providers(self):
        out = io.StringIO()
        status = {"summary": {}, "providers": [{"name": "OVH", "label": "OVHcloud",
                                                "status": "Operational", "regions": "GRA"}]}
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "get", return_value=status), \
                mock.patch("sys.stdout", out):
            cli.main(["status"])
        self.assertIn("OVHcloud", out.getvalue())
        self.assertIn("Operational", out.getvalue())

    def test_rules_can_turn_maintenance_off(self):
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "put", return_value={"changed": []}) as put, \
                mock.patch("sys.stdout", io.StringIO()):
            cli.main(["rules", "set", "--no-maintenance"])
            self.assertEqual(put.call_args.args[1], {"maintenance": False})
            cli.main(["rules", "set", "--retry-hours", "2"])
            self.assertEqual(put.call_args.args[1], {"retry_hours": 2.0})

    def test_history_csv_is_written(self):
        path = os.path.join(tempfile.mkdtemp(), "cli-test.csv")
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "get", return_value="Started (UTC),Provider\n"):
            code = cli.main(["history", "--csv", path])
        self.assertEqual(code, 0)
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "Started (UTC),Provider\n")
        os.remove(path)


    def test_providers_set_sends_put(self):
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "put", return_value={"changed": ["OVH regions"]}) as put:
            code = cli.main(["providers", "set", "--name", "OVH", "--regions", "GRA", "SBG"])
        self.assertEqual(code, 0)
        self.assertEqual(put.call_args.args[1]["items"][0]["regions"], ["GRA", "SBG"])

    def test_webhook_url_does_not_replace_server_url(self):
        with mock.patch.object(cli, "load_profile", return_value={}), \
                mock.patch.object(cli.Client, "post", autospec=True,
                                  return_value={"id": 1}) as post:
            code = cli.main(["--url", "http://server.example.test",
                             "--token", "sk_live_bearer", "webhooks", "add",
                             "--name", "Hook", "--url", "https://hook.example.test"])
        self.assertEqual(code, 0)
        self.assertEqual(post.call_args.args[0].base, "http://server.example.test/api/v1")
        self.assertEqual(post.call_args.args[0].token, "sk_live_bearer")
        self.assertEqual(post.call_args.args[2]["url"], "https://hook.example.test")

    def test_tokens_create_prints_plaintext(self):
        out = io.StringIO()
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "post", return_value={"token": "sk_live_once"}), \
                mock.patch("sys.stdout", out):
            code = cli.main(["tokens", "create", "--name", "CI", "--user-id", "5",
                             "--scopes", "incidents:read"])
        self.assertEqual(code, 0)
        self.assertIn("sk_live_once", out.getvalue())

    def test_settings_set_passes_nulls(self):
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "put", return_value={"changed": []}) as put:
            code = cli.main(["settings", "set", "POLL_INTERVAL_SECONDS=60",
                             "--clear", "ZENDESK_API_TOKEN"])
        self.assertEqual(code, 0)
        self.assertEqual(put.call_args.args[1]["values"],
                         {"POLL_INTERVAL_SECONDS": "60", "ZENDESK_API_TOKEN": None})

    def test_bootstrap_does_not_need_a_token(self):
        with mock.patch.object(cli, "load_profile", return_value={}), \
                mock.patch.object(cli.Client, "post", return_value={"id": 1}) as post:
            code = cli.main(["bootstrap", "--name", "Admin", "--email", "a@example.test",
                             "--password", "long-password-123", "--secret", "s3cret"])
        self.assertEqual(code, 0)
        self.assertEqual(post.call_args.kwargs["headers"], {"X-Bootstrap-Secret": "s3cret"})


if __name__ == "__main__":
    unittest.main()
