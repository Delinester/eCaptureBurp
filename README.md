# eCapture Burp Suite Extension 1.1.1

Compatibility repair for **eCapture 2.6.0**, verified with upstream-generated
fixtures and 44 regression tests. Fixes the timestamped direct OpenSSL
`PID/TID/Comm/FD READ/WRITE` format missed by 1.1.0, in addition to retaining
the collector-format fixes.
Read [PATCH_NOTES.md](PATCH_NOTES.md) for the diagnosed root cause, installation
steps, and limits; see [TEST_RESULTS.md](TEST_RESULTS.md) for verification scope.

Unload the previous JAR before loading `ecapture-burp-extension-1.1.1.jar`.
Requests now appear for all recognized HTTP methods, including eCapture's
decoded HTTP/2 output. Missing Host/response metadata does not hide requests.
The screenshot and Chinese README below are inherited upstream documentation.

English | [中文](README_CN.md)

A Burp Suite extension for receiving TLS/HTTP traffic data captured by [eCapture](https://github.com/gojue/ecapture).

![Screenshot](images/demo.png)

## Build

```bash
cd eCaptureBurp
./gradlew clean test jar
# Output: build/libs/ecapture-burp-extension-1.1.1.jar
```

## Usage

### 1. Start eCapture

```bash
sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/
```

### 2. Connect in Burp Suite

1. Enter WebSocket URL (default `ws://127.0.0.1:28257/`)
2. Click **Connect** button
3. Green status indicator means connected

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| WebSocket URL | `ws://127.0.0.1:28257/` | eCapture eCaptureQ service address |

## Architecture

```
┌─────────────────┐     WebSocket + Protobuf     ┌──────────────────┐
│    eCapture     │ ───────────────────────────> │  Burp Extension  │
│  (eBPF capture) │                              │                  │
└─────────────────┘                              │  ┌────────────┐  │
                                                 │  │ Event Mgr  │  │
                                                 │  │  (pairing) │  │
                                                 │  └─────┬──────┘  │
                                                 │        │         │
                                                 │  ┌─────▼──────┐  │
                                                 │  │ Site Map   │  │
                                                 │  │ + Tab UI   │  │
                                                 │  └────────────┘  │
                                                 └──────────────────┘
```

## License

Apache License 2.0

## Links

- [eCapture Project](https://github.com/gojue/ecapture)
- [eCapture Event Forward API](https://github.com/gojue/ecapture/blob/master/docs/event-forward-api.md)
- [Burp Suite Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/)
