"""API auth, scopes, endpoint shapes and CLI basics. No database or network:
the guard's DB work and the query helper are mocked. Run with:
python -m unittest discover tests"""
import io
import json
import os
import sys
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

    def test_fail_on_open_exit_code(self):
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "get", return_value={"items": [{"id": 1}],
                                                                   "next_cursor": None}):
            code = cli.main(["incidents", "list", "--fail-on-open"])
        self.assertEqual(code, 7)

    def test_history_csv_is_written(self):
        path = os.path.join("/tmp", "opencode", "cli-test.csv")
        with mock.patch.object(cli, "load_profile", return_value={"url": "http://x", "token": "t"}), \
                mock.patch.object(cli.Client, "get", return_value="Started (UTC),Provider\n"):
            code = cli.main(["history", "--csv", path])
        self.assertEqual(code, 0)
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "Started (UTC),Provider\n")
        os.remove(path)


if __name__ == "__main__":
    unittest.main()
