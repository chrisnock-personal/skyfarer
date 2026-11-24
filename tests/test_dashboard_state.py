"""The first-run code and sign-in throttle are shared in Postgres, not held in
a worker's memory. No database needed: the cursor and the Flask request are
mocked. Run with: python -m unittest discover tests"""
import contextlib
import os
import sys
import unittest
from unittest import mock

from flask import Flask

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import admin  # noqa: E402
import db  # noqa: E402
import settings  # noqa: E402


class SharedState(unittest.TestCase):
    def test_setup_code_is_created_once_then_reused(self):
        conn = mock.MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.side_effect = [None, ("ab-cd-ef",)]
        with mock.patch.object(db, "lock_setup") as lock:
            self.assertEqual(db.setup_code(conn), "ab-cd-ef")
        lock.assert_called_once_with(conn)
        self.assertIn("ON CONFLICT", cur.execute.call_args_list[1].args[0])

        conn = mock.MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchone.return_value = ("ab-cd-ef",)
        with mock.patch.object(db, "lock_setup"):
            self.assertEqual(db.setup_code(conn), "ab-cd-ef")
        self.assertEqual(conn.cursor.return_value.__enter__.return_value.execute.call_count, 1)

    def test_setup_code_is_cleared_after_the_admin_is_created(self):
        conn = mock.MagicMock()
        db.clear_setup_code(conn)
        cur = conn.cursor.return_value.__enter__.return_value
        self.assertEqual(cur.execute.call_args.args[0],
                         "DELETE FROM dashboard_state WHERE key = %s")

    def test_login_helpers_use_a_locked_bucket(self):
        conn = mock.MagicMock()
        cur = conn.cursor.return_value.__enter__.return_value
        cur.fetchone.return_value = (5,)
        self.assertEqual(db.login_failures(conn, "1.2.3.4|me@x.test", 900), 5)
        sql = [c.args[0] for c in cur.execute.call_args_list]
        self.assertIn("failed_at", sql[0])
        self.assertIn("bucket", sql[1])

        db.lock_login(conn, "1.2.3.4|me@x.test")
        self.assertIn("pg_advisory_xact_lock(77703, hashtext(%s))",
                      conn.cursor.return_value.__enter__.return_value.execute.call_args.args[0])
        db.login_failed(conn, "bucket")
        db.login_succeeded(conn, "bucket")
        sql = [c.args[0] for c in cur.execute.call_args_list]
        self.assertTrue(any(s.startswith("INSERT INTO login_failures") for s in sql))
        self.assertTrue(any(s.startswith("DELETE FROM login_failures WHERE bucket") for s in sql))


class Web(unittest.TestCase):
    """Exercise the routes so the shared state is used by the real handlers."""

    def setUp(self):
        app = Flask(__name__, template_folder=os.path.join(ROOT, "templates"))
        app.config.update(TESTING=True, SECRET_KEY="test-secret")
        app.register_blueprint(admin.bp)
        self.conn = object()
        patches = [
            mock.patch.object(db, "get_conn", side_effect=lambda: contextlib.nullcontext(self.conn)),
            mock.patch.object(settings, "bootstrap"),
            mock.patch.object(settings, "apply"),
            mock.patch.object(settings, "user_count", return_value=1),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.client = app.test_client()
        with self.client.session_transaction() as sess:
            sess["csrf"] = "token"

    def post_login(self, email="Person@Example.test", password="wrong"):
        return self.client.post("/login", data={"csrf": "token", "email": email,
                                                "password": password})

    def test_throttle_is_checked_and_recorded_in_the_database(self):
        state = {"failures": 0}
        with mock.patch.object(db, "lock_login") as lock, \
                mock.patch.object(db, "login_failures",
                                  side_effect=lambda c, b, w: state["failures"]), \
                mock.patch.object(db, "login_failed",
                                  side_effect=lambda c, b: state.update(failures=state["failures"] + 1)), \
                mock.patch.object(db, "login_succeeded",
                                  side_effect=lambda c, b: state.update(failures=0)), \
                mock.patch.object(settings, "check_login", return_value=None) as check:
            for _ in range(admin.FAILURE_LIMIT):
                self.assertIn(b"don&#39;t match", self.post_login().data)
            response = self.post_login()
            self.assertEqual(check.call_count, admin.FAILURE_LIMIT)
            self.assertIn(b"Too many attempts", response.data)
            lock.assert_called_with(self.conn, "127.0.0.1|person@example.test")

    def test_a_correct_password_clears_the_recorded_failures(self):
        state = {"failures": admin.FAILURE_LIMIT - 1}
        with mock.patch.object(db, "lock_login"), \
                mock.patch.object(db, "login_failures",
                                  side_effect=lambda c, b, w: state["failures"]), \
                mock.patch.object(db, "login_failed"), \
                mock.patch.object(db, "login_succeeded",
                                  side_effect=lambda c, b: state.update(failures=0)), \
                mock.patch.object(settings, "check_login",
                                  return_value={"id": 9, "name": "P", "role": "admin"}):
            self.assertEqual(self.post_login(password="right").status_code, 302)
        self.assertEqual(state["failures"], 0)

    def test_setup_code_comes_from_the_database_on_every_visit(self):
        settings.user_count.return_value = 0
        with mock.patch.object(settings, "imported_summary", return_value="nothing set"), \
                mock.patch.object(db, "setup_code", return_value="aa-bb-cc") as code, \
                mock.patch.object(db, "clear_setup_code"), \
                self.assertLogs("skyfarer.dashboard", "WARNING") as logs:
            response = self.client.get("/setup")
        self.assertEqual(response.status_code, 200)
        self.assertIn("aa-bb-cc", " ".join(logs.output))
        code.assert_called_with(self.conn)

    def test_setup_uses_the_shared_code_and_removes_it(self):
        settings.user_count.return_value = 0
        with mock.patch.object(settings, "imported_summary", return_value="nothing set"), \
                mock.patch.object(db, "setup_code", return_value="aa-bb-cc"), \
                mock.patch.object(db, "clear_setup_code") as clear, \
                mock.patch.object(settings, "create_user",
                                  return_value=settings.NewLink(9, "")) as create:
            response = self.client.post("/setup", data={
                "csrf": "token", "code": "AA-BB-CC", "name": "Person",
                "email": "person@example.test", "password": "long enough password",
            })
        self.assertEqual(response.status_code, 302)
        create.assert_called_once()
        clear.assert_called_once_with(self.conn)


if __name__ == "__main__":
    unittest.main()
