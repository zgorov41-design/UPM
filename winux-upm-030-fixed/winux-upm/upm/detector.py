from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile

from typing import Any


@dataclass
class DetectionResult:
    path: str
    format: str
    confidence: str
    description: str
    details: dict[str, Any]
    status: str = "candidate"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "confidence": self.confidence,
            "description": self.description,
            "details": self.details,
            "status": self.status,
        }


def _parse_deb_control(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    current = None
    for line in raw.splitlines():
        if line.startswith((" ", "\t")) and current:
            result[current] += "\n" + line.strip()
        elif ":" in line:
            key, value = line.split(":", 1)
            current = key.strip()
            result[current] = value.strip()
    return result


def _validate_deb(path: Path) -> DetectionResult:
    details: dict[str, Any] = {}
    dpkg_deb = shutil.which("dpkg-deb")
    if not dpkg_deb:
        return DetectionResult(str(path), "deb", "high", "Debian package", details, "candidate")
    try:
        proc = subprocess.run(
            [dpkg_deb, "--info", str(path)],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            return DetectionResult(str(path), "deb", "high", "Invalid Debian package",
                                   {"error": proc.stderr.strip()}, "invalid")
        raw = proc.stdout
        details["deb_control_raw"] = raw
        details["metadata"] = _parse_deb_control(raw)
        field = subprocess.run(
            [dpkg_deb, "--field", str(path)],
            capture_output=True, text=True, timeout=10,
        )
        if field.returncode == 0:
            details["metadata"] = _parse_deb_control(field.stdout)
        return DetectionResult(str(path), "deb", "high", "Debian package", details, "valid")
    except (OSError, subprocess.SubprocessError) as exc:
        details["error"] = str(exc)
        return DetectionResult(str(path), "deb", "high", "Debian package", details, "candidate")


def _parse_snap_yaml(raw: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    section = None
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and line.endswith(":"):
            section = line[:-1].strip()
            result[section] = {}
            continue
        m = re.match(r"^\s{2,}([A-Za-z0-9_.-]+):\s*(.*)$", line)
        if m and section:
            value = m.group(2).strip()
            if (value.startswith("'") and value.endswith("'")) or (value.startswith('"') and value.endswith('"')):
                value = value[1:-1]
            result[section][m.group(1)] = value
        else:
            m = re.match(r"^([A-Za-z0-9_.-]+):\s*(.*)$", line)
            if m:
                value = m.group(2).strip()
                if (value.startswith("'") and value.endswith("'")) or (value.startswith('"') and value.endswith('"')):
                    value = value[1:-1]
                result[m.group(1)] = value
    return result


def _validate_snap(path: Path) -> DetectionResult:
    details: dict[str, Any] = {}
    unsquashfs = shutil.which("unsquashfs")
    if not unsquashfs:
        return DetectionResult(str(path), "snap", "medium", "SquashFS image; possible Snap package",
                               details, "candidate")
    try:
        listing = subprocess.run(
            [unsquashfs, "-l", str(path)],
            capture_output=True, text=True, timeout=15,
        )
        if listing.returncode != 0:
            return DetectionResult(str(path), "snap", "high", "Invalid SquashFS/Snap image",
                                   {"error": listing.stderr.strip()}, "invalid")
        names = listing.stdout.splitlines()
        meta = next((n.strip() for n in names if n.strip().endswith("meta/snap.yaml")), None)
        if not meta:
            return DetectionResult(str(path), "snap", "medium", "SquashFS image without snap metadata",
                                   details, "invalid")
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.run(
                [unsquashfs, "-f", "-d", td, str(path), meta],
                capture_output=True, text=True, timeout=15,
            )
            yaml_path = Path(td) / meta
            if proc.returncode != 0 or not yaml_path.exists():
                return DetectionResult(str(path), "snap", "high", "Snap metadata could not be extracted",
                                       details, "invalid")
            raw = yaml_path.read_text(errors="replace")
            parsed = _parse_snap_yaml(raw)
            details["snap_yaml_raw"] = raw
            details["metadata"] = parsed
            if not parsed.get("name"):
                return DetectionResult(str(path), "snap", "high", "Snap metadata is missing name",
                                       details, "invalid")
            return DetectionResult(str(path), "snap", "high", "Snap package", details, "valid")
    except (OSError, subprocess.SubprocessError) as exc:
        details["error"] = str(exc)
        return DetectionResult(str(path), "snap", "medium", "SquashFS image; possible Snap package",
                               details, "candidate")


def _detect_pe(path: Path, data: bytes) -> DetectionResult:
    if len(data) < 64 or data[:2] != b"MZ":
        return DetectionResult(str(path), "unknown", "low", "Unknown package format", {}, "unknown")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset+4] != b"PE\0\0":
        return DetectionResult(str(path), "unknown", "low", "MZ file without valid PE signature", {}, "invalid")
    machine, sections = struct.unpack_from("<HH", data, pe_offset + 4)
    if not 1 <= sections <= 96:
        return DetectionResult(str(path), "unknown", "low", "Invalid PE section count", {}, "invalid")
    machines = {0x014C: "x86", 0x8664: "x86_64", 0xAA64: "ARM64", 0x01C4: "ARM"}
    details = {"machine": machines.get(machine, hex(machine)), "sections": sections}
    return DetectionResult(str(path), "exe", "high", "Windows PE executable", details, "valid")


def detect_package(path: str | Path) -> DetectionResult:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        return DetectionResult(str(p), "unknown", "low", "File could not be read", {"error": str(exc)}, "invalid")

    if data.startswith(b"!<arch>\n"):
        return _validate_deb(p)
    if data.startswith(b"hsqs") or data.startswith(b"sqsh"):
        return _validate_snap(p)
    if data.startswith(b"MZ"):
        return _detect_pe(p, data)
    return DetectionResult(str(p), "unknown", "low", "Unknown package format", {}, "unknown")
