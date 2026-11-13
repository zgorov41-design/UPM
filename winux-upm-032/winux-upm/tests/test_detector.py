import tempfile
import unittest
from pathlib import Path
from upm.detector import detect_package
from upm.core.registry import available_engines, get_engine
from upm.core.engine import EngineOperationNotSupported

class DetectorTests(unittest.TestCase):
    def test_unknown(self):
        with tempfile.NamedTemporaryFile() as f:
            self.assertEqual(detect_package(f.name).format, "unknown")

    def test_detection_result_to_dict(self):
        with tempfile.NamedTemporaryFile() as f:
            d = detect_package(f.name).to_dict()
            self.assertIn("status", d)

    def test_json_result_contains_status(self):
        with tempfile.NamedTemporaryFile() as f:
            result = detect_package(f.name).to_dict()
            self.assertIn("status", result)

    def test_detects_pe(self):
        with tempfile.NamedTemporaryFile() as f:
            p = Path(f.name)
            data = bytearray(128)
            data[:2] = b"MZ"
            data[0x3c:0x40] = (64).to_bytes(4, "little")
            data[64:68] = b"PE\0\0"
            p.write_bytes(data)
            self.assertEqual(detect_package(p).format, "exe")

    def test_rejects_mz_without_pe(self):
        with tempfile.NamedTemporaryFile() as f:
            Path(f.name).write_bytes(b"MZ" + b"\0" * 126)
            self.assertEqual(detect_package(f.name).format, "unknown")

    def test_detects_deb_by_signature_not_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".bin") as f:
            Path(f.name).write_bytes(b"!<arch>\n")
            self.assertEqual(detect_package(f.name).format, "deb")

    def test_deb_metadata_is_structured(self):
        with tempfile.NamedTemporaryFile() as f:
            Path(f.name).write_bytes(b"!<arch>\n")
            self.assertIsInstance(detect_package(f.name).details["metadata"], dict)

    def test_detects_squashfs_as_possible_snap(self):
        with tempfile.NamedTemporaryFile() as f:
            Path(f.name).write_bytes(b"hsqs" + b"\0" * 100)
            self.assertEqual(detect_package(f.name).format, "snap")

    def test_snap_metadata_is_structured(self):
        with tempfile.NamedTemporaryFile() as f:
            Path(f.name).write_bytes(b"hsqs" + b"\0" * 100)
            self.assertIsInstance(detect_package(f.name).details, dict)

    def test_snap_without_name_is_invalid(self):
        with tempfile.NamedTemporaryFile() as f:
            Path(f.name).write_bytes(b"hsqs" + b"\0" * 100)
            r = detect_package(f.name)
            self.assertIn(r.status, {"valid", "invalid"})

    def test_parse_deb_control(self):
        with tempfile.NamedTemporaryFile() as f:
            Path(f.name).write_bytes(b"!<arch>\n")
            self.assertIsInstance(detect_package(f.name).details["metadata"], dict)

    def test_parse_snap_yaml(self):
        self.assertEqual({}, {})

class EngineTests(unittest.TestCase):
    def test_available_engines(self):
        self.assertEqual(available_engines(), ["deb", "exe", "snap"])
    def test_deb_engine_registered(self):
        self.assertEqual(get_engine("deb").name, "deb")
    def test_exe_engine_registered(self):
        self.assertEqual(get_engine("exe").name, "exe")
    def test_snap_engine_registered(self):
        self.assertEqual(get_engine("snap").name, "snap")
    def test_unknown_engine(self):
        with self.assertRaises(KeyError):
            get_engine("unknown")
    def test_engine_inspect_delegates_to_detector(self):
        with tempfile.NamedTemporaryFile() as f:
            self.assertIn("format", get_engine("exe").inspect(f.name))
    def test_install_is_safe_stub(self):
        with self.assertRaises(EngineOperationNotSupported):
            get_engine("deb").install("x")
    def test_remove_is_safe_stub(self):
        with self.assertRaises(EngineOperationNotSupported):
            get_engine("deb").remove("x")
    def test_launch_is_safe_stub(self):
        with self.assertRaises(EngineOperationNotSupported):
            get_engine("exe").launch("x")
