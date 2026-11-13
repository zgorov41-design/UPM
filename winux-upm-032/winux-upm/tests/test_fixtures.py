import tempfile
import unittest
from pathlib import Path
from upm.detector import detect_package
from upm.fixtures import make_minimal_deb, make_minimal_pe, make_squashfs_signature

class FixtureTests(unittest.TestCase):
    def test_minimal_pe_fixture(self):
        with tempfile.NamedTemporaryFile(suffix=".exe") as f:
            make_minimal_pe(f.name)
            r = detect_package(f.name)
            self.assertEqual(r.format, "exe")
            self.assertEqual(r.status, "valid")

    def test_minimal_deb_fixture(self):
        with tempfile.NamedTemporaryFile(suffix=".deb") as f:
            make_minimal_deb(f.name)
            r = detect_package(f.name)
            self.assertEqual(r.format, "deb")
            self.assertIn("metadata", r.details)

    def test_squashfs_fixture(self):
        with tempfile.NamedTemporaryFile(suffix=".snap") as f:
            make_squashfs_signature(f.name)
            r = detect_package(f.name)
            self.assertEqual(r.format, "snap")
