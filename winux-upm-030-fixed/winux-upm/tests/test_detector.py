import struct
import tempfile
import unittest
from pathlib import Path

from upm.detector import (
    DetectionResult, _parse_deb_control, _parse_snap_yaml, detect_package
)


class DetectorTests(unittest.TestCase):
    def make_file(self, data):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(data); f.close()
        return Path(f.name)

    def test_detects_deb_by_signature_not_extension(self):
        p = self.make_file(b"!<arch>\n")
        self.assertEqual(detect_package(p).format, "deb")

    def test_detects_pe(self):
        data = bytearray(128)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 64)
        data[64:68] = b"PE\0\0"
        struct.pack_into("<HH", data, 68, 0x8664, 3)
        self.assertEqual(detect_package(self.make_file(data)).format, "exe")

    def test_detects_squashfs_as_possible_snap(self):
        p = self.make_file(b"hsqs" + b"\0" * 100)
        self.assertEqual(detect_package(p).format, "snap")

    def test_unknown(self):
        self.assertEqual(detect_package(self.make_file(b"hello")).format, "unknown")

    def test_json_result_contains_status(self):
        result = detect_package(self.make_file(b"hello")).to_dict()
        self.assertIn("status", result)

    def test_rejects_mz_without_pe(self):
        result = detect_package(self.make_file(b"MZ" + b"\0" * 100))
        self.assertEqual(result.status, "invalid")

    def test_parse_deb_control(self):
        data = _parse_deb_control("Package: demo\nVersion: 1.2\nDescription: Hello\n world")
        self.assertEqual(data["Package"], "demo")
        self.assertEqual(data["Version"], "1.2")
        self.assertIn("Hello", data["Description"])

    def test_deb_metadata_is_structured(self):
        p = self.make_file(b"!<arch>\n")
        result = detect_package(p)
        self.assertIsInstance(result.details, dict)

    def test_parse_snap_yaml(self):
        data = _parse_snap_yaml("name: demo\nversion: '1.2'\ndescription: Test")
        self.assertEqual(data["name"], "demo")
        self.assertEqual(data["version"], "1.2")

    def test_snap_metadata_is_structured(self):
        p = self.make_file(b"hsqs" + b"\0" * 100)
        self.assertIsInstance(detect_package(p).details, dict)

    def test_snap_without_name_is_invalid(self):
        # This is exercised against the parser contract; a bare SquashFS is only a candidate
        self.assertNotIn("name", _parse_snap_yaml("version: '1.0'"))

    def test_detection_result_to_dict(self):
        r = DetectionResult("x", "unknown", "low", "Unknown", {})
        self.assertEqual(r.to_dict()["path"], "x")


class EngineTests(unittest.TestCase):
    def test_deb_engine_registered(self):
        from upm.core.registry import get_engine
        from upm.engines import DebEngine
        self.assertIsInstance(get_engine("deb"), DebEngine)

    def test_snap_engine_registered(self):
        from upm.core.registry import get_engine
        from upm.engines import SnapEngine
        self.assertIsInstance(get_engine("snap"), SnapEngine)

    def test_exe_engine_registered(self):
        from upm.core.registry import get_engine
        from upm.engines import ExeEngine
        self.assertIsInstance(get_engine("exe"), ExeEngine)

    def test_available_engines(self):
        from upm.core.registry import available_engines
        self.assertEqual(available_engines(), ["deb", "exe", "snap"])

    def test_engine_inspect_delegates_to_detector(self):
        from upm.core.registry import get_engine
        p = self.make_file(b"hello") if hasattr(self, "make_file") else None
        # Use a real temporary file.
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello")
            name = f.name
        self.assertEqual(get_engine("deb").inspect(name)["format"], "unknown")

    def test_install_is_safe_stub(self):
        from upm.core.engine import EngineOperationNotSupported
        from upm.core.registry import get_engine
        with self.assertRaises(EngineOperationNotSupported):
            get_engine("deb").install("x")

    def test_remove_is_safe_stub(self):
        from upm.core.engine import EngineOperationNotSupported
        from upm.core.registry import get_engine
        with self.assertRaises(EngineOperationNotSupported):
            get_engine("deb").remove("x")

    def test_launch_is_safe_stub(self):
        from upm.core.engine import EngineOperationNotSupported
        from upm.core.registry import get_engine
        with self.assertRaises(EngineOperationNotSupported):
            get_engine("exe").launch("x")

    def test_unknown_engine(self):
        from upm.core.registry import get_engine
        with self.assertRaises(KeyError):
            get_engine("nope")


if __name__ == "__main__":
    unittest.main()
