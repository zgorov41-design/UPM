# Winux UPM 0.2.1

Safe package-format detection and inspection prototype.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## CLI

```bash
python3 -m upm.cli inspect file.deb
python3 -m upm.cli inspect file.deb --json
python3 -m upm.cli validate file.deb
```

The prototype only inspects files. It does not install, remove, or execute packages.
