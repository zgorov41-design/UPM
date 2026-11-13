# Winux UPM 0.3.2

0.3.2 adds safe package fixtures and integration-level detection tests.

Fixtures are created in temporary files and are only inspected. No fixture is
installed or executed.

Run:
    python3 -m unittest discover -s tests -v

The fixtures cover:
- minimal PE/EXE
- minimal Debian ar package
- SquashFS/SNAP signature fixture
