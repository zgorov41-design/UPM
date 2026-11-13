from dataclasses import dataclass
from pathlib import Path
import json
import struct
import subprocess
import tempfile
import os

@dataclass
class DetectionResult:
    path: str
    format: str
    confidence: str
    description: str
    details: dict
    status: str = "unknown"

    def to_dict(self):
        return {
            "path": self.path,
            "format": self.format,
            "confidence": self.confidence,
            "description": self.description,
            "details": self.details,
            "status": self.status,
        }

def _parse_deb_control(path):
    try:
        out = subprocess.run(
            ["dpkg-deb", "-f", str(path)],
            capture_output=True, text=True, timeout=5, check=True
        ).stdout
        fields = {}
        for line in out.splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                fields[k] = v
        return fields
    except Exception:
        return {}

def _parse_snap_yaml(path):
    try:
        import yaml
    except Exception:
        yaml = None
    if yaml:
        try:
            with open(path, "rb") as f:
                data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            pass
    return {}

def detect_package(path):
    p = Path(path)
    details = {}
    if not p.is_file():
        return DetectionResult(str(path), "unknown", "low", "Unknown package format", details, "unknown")

    try:
        with p.open("rb") as f:
            head = f.read(4096)
    except OSError as e:
        details["error"] = str(e)
        return DetectionResult(str(path), "unknown", "low", "Unable to read file", details, "invalid")

    if head.startswith(b"!<arch>\n"):
        details["metadata"] = _parse_deb_control(p)
        status = "valid" if details["metadata"] else "invalid"
        return DetectionResult(str(path), "deb", "high", "Debian package", details, status)

    if head[:2] == b"MZ":
        pe_off = None
        if len(head) >= 64:
            pe_off = struct.unpack_from("<I", head, 0x3C)[0]
        valid_pe = pe_off is not None and pe_off + 4 <= len(head) and head[pe_off:pe_off+4] == b"PE\0\0"
        if valid_pe:
            return DetectionResult(str(path), "exe", "high", "Windows PE executable", details, "valid")
        return DetectionResult(str(path), "unknown", "low", "Unknown package format", details, "unknown")

    if head.startswith(b"hsqs") or head.startswith(b"sqsh"):
        details["snap_candidate"] = True
        status = "valid"
        try:
            subprocess.run(["unsquashfs", "-s", str(p)], capture_output=True, timeout=5, check=True)
        except FileNotFoundError:
            pass
        except Exception:
            status = "invalid"
        return DetectionResult(str(path), "snap", "medium", "SquashFS image (possible SNAP)", details, status)

    return DetectionResult(str(path), "unknown", "low", "Unknown package format", details, "unknown")

def parse_deb_control(path):
    return _parse_deb_control(path)

def parse_snap_yaml(path):
    return _parse_snap_yaml(path)
