"""Keep installs reproducible: every runtime requirement must be pinned.
Run with: python -m unittest discover tests"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class Requirements(unittest.TestCase):
    def test_every_runtime_requirement_is_pinned(self):
        path = os.path.join(ROOT, "requirements.txt")
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
        requirements = [line.strip() for line in lines
                        if line.strip() and not line.lstrip().startswith("#")]
        self.assertTrue(requirements)
        for item in requirements:
            with self.subTest(item=item):
                self.assertEqual(item.count("=="), 1, f"{item!r} is not pinned")
                name, version = item.split("==")
                self.assertTrue(name and version, f"{item!r} is incomplete")
                self.assertNotIn(" ", item, f"{item!r} has stray whitespace")


if __name__ == "__main__":
    unittest.main()
