# Winux UPM 0.2.2

Safe package-format detection, validation, and metadata inspection prototype.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## CLI

```bash
python3 -m upm.cli detect file.deb
python3 -m upm.cli inspect file.deb
python3 -m upm.cli inspect file.deb --json
python3 -m upm.cli validate file.deb
```

## Supported inspection

- DEB: signature validation and structured Debian control metadata.
- SNAP: SquashFS candidate detection; when `unsquashfs` is available, `meta/snap.yaml` is read without extracting or executing the image.
- EXE: PE header validation.

The prototype only inspects files. It does not install, remove, or execute packages.
