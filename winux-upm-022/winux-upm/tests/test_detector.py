import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from upm.detector import detect_package, _parse_deb_control, _parse_snap_yaml


class DetectorTests(unittest.TestCase):
    def make_file(self, data: bytes, suffix: str = ".bin") -> Path:
        temp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        temp.write(data)
        temp.close()
        self.addCleanup(lambda: Path(temp.name).unlink(missing_ok=True))
        return Path(temp.name)

    def test_detects_deb_by_signature_not_extension(self):
        path = self.make_file(b"!<arch>\n" + b"0" * 32, ".anything")
        result = detect_package(path)
        self.assertEqual(result.format, "DEB")
        self.assertIn(result.status, {"valid", "invalid", "candidate"})

    def test_detects_squashfs_as_possible_snap(self):
        path = self.make_file(b"hsqs" + b"0" * 64, ".data")
        result = detect_package(path)
        self.assertEqual(result.format, "SNAP")
        self.assertIn(result.status, {"valid", "invalid", "candidate"})
        self.assertEqual(result.confidence, "medium")

    def test_detects_pe(self):
        data = bytearray(0x100)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        data[0x80:0x84] = b"PE\x00\x00"
        data[0x84:0x86] = (0x8664).to_bytes(2, "little")
        data[0x86:0x88] = (3).to_bytes(2, "little")
        data[0x94:0x96] = (0xF0).to_bytes(2, "little")
        path = self.make_file(bytes(data), ".not-exe")
        result = detect_package(path)
        self.assertEqual(result.format, "EXE")
        self.assertEqual(result.status, "valid")

    def test_rejects_mz_without_pe(self):
        data = bytearray(0x100)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        path = self.make_file(bytes(data), ".exe")
        self.assertEqual(detect_package(path).format, "UNKNOWN")

    def test_unknown(self):
        path = self.make_file(b"hello world")
        result = detect_package(path)
        self.assertEqual(result.format, "UNKNOWN")
        self.assertEqual(result.status, "invalid")

    def test_json_result_contains_status(self):
        path = self.make_file(b"hello world")
        result = detect_package(path)
        payload = result.to_dict()
        self.assertEqual(payload["status"], "invalid")
        self.assertIn("details", payload)

    def test_parse_deb_control(self):
        control = """Package: hello\nVersion: 1.2.3\nArchitecture: amd64\nMaintainer: Test <test@example.invalid>\nDescription: Short description\n long description line\n"""
        fields = _parse_deb_control(control)
        self.assertEqual(fields["Package"], "hello")
        self.assertEqual(fields["Version"], "1.2.3")
        self.assertEqual(fields["Architecture"], "amd64")
        self.assertEqual(fields["Description"], "Short description\nlong description line")

    def test_parse_snap_yaml(self):
        yaml = """name: hello\nversion: '1.2.3'\nsummary: Test snap\ndescription: |\n  A longer description.\n  Second line.\narchitectures:\n  - amd64\n  - arm64\n"""
        metadata = _parse_snap_yaml(yaml)
        self.assertEqual(metadata["name"], "hello")
        self.assertEqual(metadata["version"], "1.2.3")
        self.assertEqual(metadata["summary"], "Test snap")
        self.assertEqual(metadata["description"], "A longer description.\nSecond line.")
        self.assertEqual(metadata["architectures"], ["amd64", "arm64"])

    @patch("upm.detector.shutil.which", return_value="/usr/bin/dpkg-deb")
    @patch("upm.detector.subprocess.run")
    def test_deb_metadata_is_structured(self, mock_run, _mock_which):
        info = type("Completed", (), {"returncode": 0, "stderr": "", "stdout": "info"})()
        field = type("Completed", (), {
            "returncode": 0,
            "stderr": "",
            "stdout": "Package: hello\nVersion: 1.2.3\nArchitecture: amd64\nMaintainer: Test <test@example.invalid>\nDescription: Hello\n"
        })()
        mock_run.side_effect = [info, field]
        path = self.make_file(b"!<arch>\n" + b"0" * 32, ".deb")
        result = detect_package(path)
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.details["metadata"]["Package"], "hello")
        self.assertEqual(result.details["metadata"]["Version"], "1.2.3")
        self.assertEqual(result.details["metadata"]["Architecture"], "amd64")

    @patch("upm.detector.shutil.which", return_value="/usr/bin/unsquashfs")
    @patch("upm.detector.subprocess.run")
    def test_snap_metadata_is_structured(self, mock_run, _mock_which):
        listing = type("Completed", (), {
            "returncode": 0,
            "stderr": "",
            "stdout": "squashfs-root/meta/\nsquashfs-root/meta/snap.yaml\n"
        })()
        metadata = type("Completed", (), {
            "returncode": 0,
            "stderr": "",
            "stdout": "name: hello\nversion: '1.2.3'\nsummary: Test snap\narchitectures:\n  - amd64\n"
        })()
        mock_run.side_effect = [listing, metadata]
        path = self.make_file(b"hsqs" + b"0" * 64, ".snap")
        result = detect_package(path)
        self.assertEqual(result.format, "SNAP")
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.details["has_snap_yaml"], True)
        self.assertEqual(result.details["metadata"]["name"], "hello")
        self.assertEqual(result.details["metadata"]["version"], "1.2.3")
        self.assertEqual(result.details["metadata"]["architectures"], ["amd64"])

    @patch("upm.detector.shutil.which", return_value="/usr/bin/unsquashfs")
    @patch("upm.detector.subprocess.run")
    def test_snap_without_name_is_invalid(self, mock_run, _mock_which):
        listing = type("Completed", (), {
            "returncode": 0,
            "stderr": "",
            "stdout": "meta/snap.yaml\n"
        })()
        metadata = type("Completed", (), {
            "returncode": 0,
            "stderr": "",
            "stdout": "version: '1.2.3'\nsummary: Missing name\n"
        })()
        mock_run.side_effect = [listing, metadata]
        path = self.make_file(b"hsqs" + b"0" * 64, ".snap")
        result = detect_package(path)
        self.assertEqual(result.format, "SNAP")
        self.assertEqual(result.status, "invalid")
        self.assertIn("name", result.details["metadata_warning"])


if __name__ == "__main__":
    unittest.main()
