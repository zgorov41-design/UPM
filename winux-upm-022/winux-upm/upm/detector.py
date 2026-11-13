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


def _parse_deb_control(control: str) -> dict:
    """Parse Debian control fields without trying to interpret every field type."""
    fields: dict[str, str] = {}
    current_key: str | None = None
    for raw_line in control.splitlines():
        if not raw_line.strip():
            continue
        if raw_line[0].isspace() and current_key:
            fields[current_key] += "\n" + raw_line.strip()
            continue
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        current_key = key.strip()
        fields[current_key] = value.strip()
    return fields


def _parse_snap_yaml(yaml_text: str) -> dict:
    """Parse the small, top-level metadata subset needed by UPM.

    This deliberately avoids adding a YAML dependency to the prototype. It handles
    normal scalar fields and the common block/list forms used by snap.yaml.
    """
    fields: dict[str, object] = {}
    lines = yaml_text.splitlines()
    i = 0

    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or raw[:1].isspace():
            i += 1
            continue
        if ":" not in raw:
            i += 1
            continue

        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()

        if value in {"|", ">"}:
            block: list[str] = []
            i += 1
            while i < len(lines):
                next_line = lines[i]
                if next_line and not next_line[0].isspace():
                    break
                block.append(next_line.strip())
                i += 1
            if value == ">":
                fields[key] = " ".join(line for line in block if line)
            else:
                fields[key] = "\n".join(block).rstrip()
            continue

        if value == "":
            items: list[str] = []
            j = i + 1
            while j < len(lines):
                next_line = lines[j]
                stripped_next = next_line.strip()
                if not next_line or not next_line[0].isspace():
                    break
                if stripped_next.startswith("- "):
                    items.append(stripped_next[2:].strip().strip("'\""))
                j += 1
            if items:
                fields[key] = items
                i = j
                continue
            fields[key] = ""
            i += 1
            continue

        fields[key] = value.strip("'\"")
        i += 1

    wanted = (
        "name",
        "version",
        "summary",
        "description",
        "architectures",
    )
    return {key: fields[key] for key in wanted if key in fields}


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
            fields = _parse_deb_control(field.stdout)
            details["deb_control"] = field.stdout.strip()
            details["metadata"] = {
                key: fields[key]
                for key in (
                    "Package",
                    "Version",
                    "Architecture",
                    "Maintainer",
                    "Section",
                    "Priority",
                    "Description",
                    "Homepage",
                )
                if key in fields
            }
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

    listing = subprocess.run(
        [unsquashfs, "-l", str(path)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if listing.returncode != 0:
        details["metadata_warning"] = (
            listing.stderr.strip() or "unsquashfs не смог прочитать образ"
        )
        return "invalid", details

    has_snap_yaml = any(
        line.strip().endswith("meta/snap.yaml") or line.strip() == "meta/snap.yaml"
        for line in listing.stdout.splitlines()
    )
    details["has_snap_yaml"] = has_snap_yaml

    if not has_snap_yaml:
        details["metadata_warning"] = "В образе не найден meta/snap.yaml."
        return "invalid", details

    metadata = subprocess.run(
        [unsquashfs, "-cat", str(path), "meta/snap.yaml"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if metadata.returncode != 0:
        details["metadata_warning"] = (
            metadata.stderr.strip() or "unsquashfs не смог прочитать meta/snap.yaml"
        )
        return "invalid", details

    snap_metadata = _parse_snap_yaml(metadata.stdout)
    details["metadata"] = snap_metadata
    details["note"] = "Найден meta/snap.yaml; образ соответствует структуре Snap."

    if "name" not in snap_metadata:
        details["metadata_warning"] = "meta/snap.yaml найден, но поле name отсутствует."
        return "invalid", details

    return "valid", details


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
