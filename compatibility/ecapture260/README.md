# eCapture 2.6.0 exporter fixture generator

This tool imports the tagged upstream module rather than reimplementing its
exporter. It runs EventProcessor, ecaptureq.Server.WriteEvent, and a loopback
WebSocket receiver, then saves the actual emitted frames.

```bash
cd compatibility/ecapture260
go run . ../../src/test/resources/ecapture260
cd ../..
./gradlew test
```

Requirements: Go 1.26.0 or its automatic toolchain download, network access
for module dependencies, and permission to bind a temporary loopback port.
There is no eBPF/root requirement. Normal extension builds use the committed
fixtures and do not need Go.

Module pin: `github.com/gojue/ecapture/v2 v2.6.0`, upstream commit
`d1d3d3c789740829d54986620ecaa81d3ea06a42`.
The Go module checksum file is included. No sandbox-local module replacement
is required.

The last fixture deliberately feeds a serialized inner LogEntry directly
to WriteEvent to test nested-envelope compatibility separately from the
actual collector-prefixed EventProcessor path.
