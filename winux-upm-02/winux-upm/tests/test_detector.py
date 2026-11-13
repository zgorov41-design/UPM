import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from upm.detector import detect_package


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


if __name__ == "__main__":
    unittest.main()
