"""Non-finite numbers must never reach settings that are later turned into
timedeltas. The API is covered in test_api.py; this covers the dashboard form
and the fallback used when reading numbers from the environment.
Run with: python -m unittest discover tests"""
import os
import sys
import unittest
from unittest import mock

from flask import Flask

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import admin  # noqa: E402
import notifiers  # noqa: E402

NONFINITE = ("nan", "NaN", "inf", "-Infinity", "1e309")


class DashboardRules(unittest.TestCase):
    def test_the_form_rejects_nonfinite_hours(self):
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY="test-only")
        with mock.patch.object(admin, "channels", return_value="errors") as channels, \
                mock.patch.object(admin.settings, "save") as save:
            for raw in NONFINITE:
                with self.subTest(raw=raw), app.test_request_context(
                        "/settings/rules", method="POST",
                        data={"NOTIFY_MAX_AGE_HOURS": raw, "NOTIFY_RETRY_HOURS": "2"}):
                    self.assertEqual(admin.rules(), "errors")
                    errors = channels.call_args.kwargs["errors"]
                    self.assertEqual(len(errors), 1)
                    self.assertIn("number of hours", errors[0])
        self.assertEqual(channels.call_count, len(NONFINITE))
        save.assert_not_called()


class EnvNumbers(unittest.TestCase):
    def test_env_float_ignores_nonfinite_values(self):
        for raw in NONFINITE:
            with self.subTest(raw=raw), mock.patch.dict(
                    os.environ, {"SKYFARER_TEST_FLOAT": raw}):
                self.assertEqual(notifiers._env_float("SKYFARER_TEST_FLOAT", 24), 24)
        with mock.patch.dict(os.environ, {"SKYFARER_TEST_FLOAT": "2.5"}):
            self.assertEqual(notifiers._env_float("SKYFARER_TEST_FLOAT", 24), 2.5)


if __name__ == "__main__":
    unittest.main()
