import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from upm import cli

class CLITests(unittest.TestCase):
    def test_inspect_help_contains_command(self):
        with self.assertRaises(SystemExit):
            cli.main(["-h"])

    def test_inspect_uses_engine(self):
        with tempfile.NamedTemporaryFile() as f:
            data = bytearray(128)
            data[:2] = b"MZ"
            data[0x3c:0x40] = (64).to_bytes(4, "little")
            data[64:68] = b"PE\0\0"
            Path(f.name).write_bytes(data)
            out = io.StringIO()
            with redirect_stdout(out):
                code = cli.main(["inspect", f.name, "--json"])
            self.assertEqual(code, 0)
            self.assertIn('"engine": "exe"', out.getvalue())

    def test_validate_unknown_returns_nonzero(self):
        with tempfile.NamedTemporaryFile() as f:
            out = io.StringIO()
            with redirect_stdout(out):
                code = cli.main(["validate", f.name, "--json"])
            self.assertEqual(code, 1)
