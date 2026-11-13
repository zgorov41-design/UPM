# Winux UPM 0.3.0

UPM 0.3.0 adds a small package-engine abstraction over the 0.2.x detector.

Supported engine identifiers: `deb`, `snap`, `exe`.

Mutating operations are deliberately safe stubs in this release:
`install()`, `remove()`, and `launch()` raise `EngineOperationNotSupported`.
No root shell, package installation, removal, or execution is performed.
