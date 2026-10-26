"""Checks for the DeepSeek Harness config writer.

DSH stores MCP servers in two shapes depending on which front end reads the
file, and the two are easy to confuse:

  profiles/<name>/cordis.patch.yml   a list of `- insert:` patch objects
  .agent-presets/<name>/agent.cordis.yml   a plain list of plugin objects

If the nesting is wrong the file still looks plausible and DSH just ignores
it, which is exactly how a whole evening disappears. So parse both shapes
back and assert the fields landed where DSH expects them.
"""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from sidewire import cli


PY = r"C:\Python312\python.exe"
LAUNCHER = r"C:\tools\sidewire\sw.py"
CWD = r"C:\tools\sidewire"


@unittest.skipIf(yaml is None, "PyYAML not installed")
class DshBlockTest(unittest.TestCase):

    def test_profile_shape_is_insert_wrapper(self):
        block = cli._dsh_block(PY, LAUNCHER, CWD, wrapped=True)
        doc = yaml.safe_load(block)
        self.assertIsInstance(doc, list)
        self.assertEqual(len(doc), 1)
        self.assertIn("insert", doc[0])
        entry = doc[0]["insert"][0]
        self.assertEqual(entry["id"], "mcp-sidewire")
        self.assertEqual(entry["name"], "@deepseek-ai/dsh-mcp-client")
        cfg = entry["config"]
        self.assertEqual(cfg["transport"], "stdio")
        self.assertEqual(cfg["command"], PY)
        self.assertEqual(cfg["args"], [LAUNCHER, "serve"])
        self.assertEqual(cfg["cwd"], CWD)

    def test_preset_shape_is_plain_list(self):
        block = cli._dsh_block(PY, LAUNCHER, CWD, wrapped=False)
        doc = yaml.safe_load(block)
        self.assertIsInstance(doc, list)
        self.assertEqual(len(doc), 1)
        self.assertNotIn("insert", doc[0])
        entry = doc[0]
        self.assertEqual(entry["id"], "mcp-sidewire")
        cfg = entry["config"]
        self.assertEqual(cfg["command"], PY)
        self.assertEqual(cfg["args"], [LAUNCHER, "serve"])

    def test_comment_comes_before_the_list(self):
        # a comment wedged between "- insert:" and the item parses fine but
        # reads like a mistake, and the first version did exactly that
        for wrapped in (True, False):
            block = cli._dsh_block(PY, LAUNCHER, CWD, wrapped)
            first_code = [ln for ln in block.splitlines()
                          if ln.strip() and not ln.lstrip().startswith("#")][0]
            self.assertTrue(first_code.startswith("- insert:") or
                            first_code.startswith("- id:"), first_code)

    def test_windows_backslashes_survive(self):
        # the paths go through %s formatting and a YAML single-quoted scalar;
        # backslashes must not be eaten by either
        block = cli._dsh_block(PY, LAUNCHER, CWD, wrapped=False)
        self.assertIn(PY, block)
        doc = yaml.safe_load(block)
        self.assertEqual(doc[0]["config"]["command"], PY)


class AppendEntryTest(unittest.TestCase):

    def test_appends_after_file_without_trailing_newline(self):
        # DSH preset files are frequently written without a final newline.
        # Appending blindly welds the comment onto the previous line and
        # silently breaks the YAML.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "agent.cordis.yml")
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("- id: something-else\n  name: x")
            cli._append_entry(path, "# marker\n- id: mcp-sidewire\n", "t")
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("\n# marker", text)
            self.assertNotIn("x# marker", text)

    def test_skips_when_already_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "agent.cordis.yml")
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("- id: mcp-sidewire\n")
            added = cli._append_entry(path, "# again\n- id: mcp-sidewire\n", "t")
            self.assertFalse(added)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "- id: mcp-sidewire\n")

    def test_empty_file_gets_no_leading_blank(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "agent.cordis.yml")
            open(path, "w", encoding="utf-8").close()
            cli._append_entry(path, "- id: mcp-sidewire\n", "t")
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "- id: mcp-sidewire\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
