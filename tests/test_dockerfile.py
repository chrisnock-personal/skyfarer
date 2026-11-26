"""Keep the image runnable: the entrypoint's local modules must ship in it.
Run with: python -m unittest discover tests"""
import ast
import json
import os
import shlex
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _instructions(path):
    """Read a Dockerfile as (keyword, arguments) pairs, joining continuations."""
    instructions = []
    pending = ""
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith("\\"):
                pending += line[:-1].strip() + " "
                continue
            parts = (pending + line).split(None, 1)
            pending = ""
            if len(parts) == 2:
                instructions.append((parts[0].upper(), parts[1]))
    return instructions


def _imported_local_modules(name):
    """Local modules imported by a module in the repository root."""
    path = os.path.join(ROOT, name + ".py")
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return {candidate for candidate in names
            if os.path.isfile(os.path.join(ROOT, candidate + ".py"))}


class DockerImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instructions = _instructions(os.path.join(ROOT, "Dockerfile"))

    def copied_sources(self):
        """Basenames of everything the Dockerfile copies into the image."""
        copied = set()
        for keyword, arguments in self.instructions:
            if keyword == "COPY":
                parts = [part for part in shlex.split(arguments)
                         if not part.startswith("--")]
                copied.update(os.path.basename(part.rstrip("/"))
                              for part in parts[:-1])  # last part is the target
        return copied

    def entrypoint_scripts(self):
        arguments = next((args for keyword, args in self.instructions
                          if keyword == "ENTRYPOINT"), None)
        self.assertIsNotNone(arguments, "Dockerfile has no ENTRYPOINT")
        parts = (json.loads(arguments) if arguments.lstrip().startswith("[")
                 else shlex.split(arguments))
        return [os.path.basename(part) for part in parts if part.endswith(".py")]

    def test_entrypoint_script_is_copied(self):
        scripts = self.entrypoint_scripts()
        self.assertTrue(scripts, "could not find the entrypoint script")
        copied = self.copied_sources()
        for script in scripts:
            with self.subTest(script=script):
                self.assertIn(script, copied,
                              f"{script} is the image entrypoint but is not copied")

    def test_entrypoint_local_imports_are_copied(self):
        copied = self.copied_sources()
        required = set()
        pending = [script[:-3] for script in self.entrypoint_scripts()]
        while pending:
            module = pending.pop()
            if module in required or not os.path.isfile(
                    os.path.join(ROOT, module + ".py")):
                continue
            required.add(module)
            pending.extend(_imported_local_modules(module) - required)

        self.assertTrue(required)
        for module in sorted(required):
            with self.subTest(module=module):
                self.assertIn(module + ".py", copied,
                              f"{module}.py is imported by the image entrypoint "
                              "but is not copied into the image")


if __name__ == "__main__":
    unittest.main()
