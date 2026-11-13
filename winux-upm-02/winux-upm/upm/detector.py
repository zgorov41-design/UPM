"""Package format detection and lightweight validation.

This module only inspects files. It never installs or executes them.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import shutil
import struct
import subprocess
from typing import Optional


@dataclass
class DetectionResult:
    path: str
    format: str
    confidence: str
    description: str
    details: dict
    status: str = "candidate"

    def to_dict(self) -> dict:
        return asdict(self)


def _read_at(handle, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0:
        return b""
    handle.seek(offset)
    return handle.read(size)


def _validate_deb(path: Path) -> tuple[str, dict]:
    details: dict = {"container": "ar archive"}

    dpkg_deb = shutil.which("dpkg-deb")
    if not dpkg_deb:
        details["metadata_note"] = "dpkg-deb не установлен; полная проверка DEB невозможна."
        return "candidate", details

    completed = subprocess.run(
        [dpkg_deb, "--info", str(path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode == 0:
        field = subprocess.run(
            [dpkg_deb, "--field", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if field.returncode == 0 and field.stdout.strip():
            details["deb_control"] = field.stdout.strip()
        return "valid", details

    details["metadata_warning"] = (
        completed.stderr.strip() or "dpkg-deb не смог прочитать пакет"
    )
    return "invalid", details


def _detect_pe(handle) -> Optional[dict]:
    if _read_at(handle, 0, 2) != b"MZ":
        return None

    raw_offset = _read_at(handle, 0x3C, 4)
    if len(raw_offset) != 4:
        return None

    pe_offset = struct.unpack("<I", raw_offset)[0]
    # The PE header must fit inside a normal file and should not be absurd.
    if pe_offset < 0x40 or pe_offset > 64 * 1024 * 1024:
        return None

    signature = _read_at(handle, pe_offset, 4)
    if signature != b"PE\x00\x00":
        return None

    coff = _read_at(handle, pe_offset + 4, 20)
    if len(coff) != 20:
        return None

    machine, sections, timestamp, sym_ptr, symbols, opt_size, characteristics = struct.unpack(
        "<HHIIIHH", coff
    )
    if sections == 0 or sections > 96:
        return None

    machine_names = {
        0x014C: "x86",
        0x8664: "x86_64",
        0x01C0: "ARM",
        0x01C4: "ARMv7",
        0xAA64: "ARM64",
    }
    return {
        "container": "PE",
        "machine": machine_names.get(machine, f"unknown (0x{machine:04x})"),
        "machine_code": f"0x{machine:04x}",
        "sections": sections,
        "optional_header_size": opt_size,
        "characteristics": f"0x{characteristics:04x}",
        "pe_offset": pe_offset,
    }


def _validate_snap(path: Path, handle) -> tuple[str, dict]:
    details = {
        "container": "SquashFS",
        "note": (
            "SquashFS сам по себе не доказывает, что файл является Snap. "
            "Проверяется наличие meta/snap.yaml, если доступен unsquashfs."
        ),
    }

    unsquashfs = shutil.which("unsquashfs")
    if not unsquashfs:
        details["metadata_note"] = (
            "unsquashfs не установлен; SquashFS распознан только как кандидат Snap."
        )
        return "candidate", details

    completed = subprocess.run(
        [unsquashfs, "-l", str(path)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        details["metadata_warning"] = (
            completed.stderr.strip() or "unsquashfs не смог прочитать образ"
        )
        return "invalid", details

    listing = completed.stdout
    has_snap_yaml = any(
        line.strip().endswith("meta/snap.yaml") or line.strip() == "meta/snap.yaml"
        for line in listing.splitlines()
    )
    details["has_snap_yaml"] = has_snap_yaml

    if has_snap_yaml:
        details["note"] = "Найден meta/snap.yaml; образ соответствует структуре Snap."
        return "valid", details

    details["metadata_warning"] = "В образе не найден meta/snap.yaml."
    return "invalid", details


def detect_package(path: str | Path) -> DetectionResult:
    file_path = Path(path).expanduser()

    if not file_path.exists():
        raise FileNotFoundError(f"Файл не найден: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"Это не обычный файл: {file_path}")

    with file_path.open("rb") as handle:
        header = _read_at(handle, 0, 8)

        if header == b"!<arch>\n":
            status, details = _validate_deb(file_path)
            return DetectionResult(
                str(file_path), "DEB",
                "high" if status == "valid" else "medium",
                "Пакет Debian (ar archive)", details, status
            )

        if header[:4] == b"hsqs":
            status, details = _validate_snap(file_path, handle)
            return DetectionResult(
                str(file_path), "SNAP",
                "high" if status == "valid" else "medium",
                "Образ SquashFS (пакет Snap)" if status == "valid"
                else "Образ SquashFS (возможен пакет Snap)",
                details, status
            )

        pe_details = _detect_pe(handle)
        if pe_details:
            return DetectionResult(
                str(file_path), "EXE", "high",
                "Исполняемый файл Windows (PE)", pe_details, "valid"
            )

    return DetectionResult(
        str(file_path), "UNKNOWN", "none",
        "Неизвестный или неподдерживаемый формат",
        {"note": "Формат не распознан по поддерживаемым сигнатурам."},
        "invalid",
    )
