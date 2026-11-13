from pathlib import Path
import gzip, io, struct, tarfile

def make_minimal_pe(path):
    data = bytearray(128)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (64).to_bytes(4, "little")
    data[64:68] = b"PE\0\0"
    Path(path).write_bytes(data)

def make_minimal_deb(path):
    # Minimal ar archive containing the required Debian members.
    control = b"Package: winux-test\nVersion: 0.1\nArchitecture: all\nDescription: Winux test package\n"
    control_tar = io.BytesIO()
    with tarfile.open(fileobj=control_tar, mode="w") as tf:
        info = tarfile.TarInfo("./control")
        info.size = len(control)
        tf.addfile(info, io.BytesIO(control))
    control_gz = gzip.compress(control_tar.getvalue())

    data_tar = io.BytesIO()
    with tarfile.open(fileobj=data_tar, mode="w"):
        pass
    data_gz = gzip.compress(data_tar.getvalue())

    members = [
        (b"debian-binary", b"2.0\n"),
        (b"control.tar.gz", control_gz),
        (b"data.tar.gz", data_gz),
    ]

    out = bytearray(b"!<arch>\n")
    for name, payload in members:
        name_field = name + b"/" * (16 - len(name))
        header = (
            name_field +
            b"0           "[:12] +
            b"0     "[:6] +
            b"0     "[:6] +
            b"100644  "[:8] +
            f"{len(payload):<10}".encode("ascii") +
            b"`\n"
        )
        out.extend(header)
        out.extend(payload)
        if len(payload) % 2:
            out.extend(b"\n")
    Path(path).write_bytes(out)

def make_squashfs_signature(path):
    # Fixture for detector-level SquashFS recognition. It is not executed.
    Path(path).write_bytes(b"hsqs" + b"\0" * 100)
