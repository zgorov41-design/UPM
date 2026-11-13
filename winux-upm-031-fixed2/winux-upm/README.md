# Winux UPM 0.3.1

CLI:
- `python3 -m upm.cli detect <file> --json`
- `python3 -m upm.cli inspect <file> --json`
- `python3 -m upm.cli validate <file> --json`
- `python3 -m upm.cli engines`

`inspect` is informational and returns success for recognized formats.
`validate` returns non-zero for invalid or unknown packages.

Mutating engine operations remain safe stubs.
