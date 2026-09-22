# eCaptureBurp 1.1.1 compatibility verification

Build and test run: 2026-09-22. Environment: Linux amd64, JDK 17.0.20.1,
Gradle 9.2.0, Go 1.26.0 for fixture generation only.

## Outcome

```text
./gradlew clean test jar
BUILD SUCCESSFUL
tests="44" skipped="0" failures="0" errors="0"

Implementation-Title: eCapture Burp Extension
Implementation-Version: 1.1.1
```

## Regression coverage

The new direct-OpenSSL fixtures were generated using unmodified
`openssl.Event.String()`, `TextHandler.Handle()`, and `Server.WriteEvent()`
from eCapture 2.6.0. An actual loopback WebSocket recorded the frames.
The original HTTP bytes are retained separately for exact byte comparisons.

The same timestamp-prefixed POST fixture was replayed through 1.1.0's
decoder, reproducing the newly reported failure:

```text
1.1.0 DIRECT OPENSSL: request=false, method=-
```

New tests verify:

- Timestamped WRITE POSTs with process names containing spaces.
- FD=0 SOAP-shaped request and READ response both displayed, without
  inventing a connection identity to pair them.
- Full 6,220-byte synthetic POST body, without the diagnostic preview limit.
- Binary bodies containing NUL, 0xff and 0x80, byte-for-byte.
- Chunked response with UTF-8 text, preserving original chunk framing.
- LF-only messages, CRLF envelopes, and empty process names.
- Timestamp retention and exact process-name recovery.
- Nonzero FD request/response pairing across thread IDs.
- IPv4-mapped IPv6 tuple records and zero-valued tuple records counted as
  metadata rather than unparsed HTTP.
- A prefix-looking string inside a request body is never stripped.
- Direct-OpenSSL WebSocket-to-Swing replay: four requests, two standalone
  responses, two metadata records, zero unparsed events.
- Editor selection receives the exact original long POST and chunked response
  bytes, not a log preview or reconstructed text.

The following earlier collector-path coverage is also retained.

The same real 2.6.0 GET frame was also decoded using the previously delivered
1.0.0 JAR in an isolated Java process. Its result reproduced the failure:

```text
OLD JAR: isRequest=false, method=-, type=UNKNOWN
```

The 1.1.0 fixture regression instead asserts method `GET`, path
`/from-ecapture-260`, host `example.test`, process `fixture_client`, and one
visible request.

- Exact v2.6.0 collector-prefixed GET output: event recognized and request shown.
- Exact v2.6.0 PATCH export: binary body survives unchanged.
- Exact v2.6.0 multiplexed HTTP/2 export: streams 1 and 3 produce two request rows.
- Exact v2.6.0 HTTP/2 POST export: binary DATA survives unchanged.
- Exact v2.6.0 HTTP/2 gzip response: decompressed body and normalized encoding.
- Actual heartbeat export: heartbeat updates without increasing HTTP event count.
- Nested LogEntry wrapped through actual WriteEvent: DELETE request shown.
- Structured single-envelope events and unknown protobuf fields.
- GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT, PROPFIND,
  CUSTOM-METHOD, each without requiring Host or a response.
- Case-insensitive Host matching; body content is not mistaken for a Host header.
- Rapid-event unique row identifiers.
- Distinct file descriptors and process names containing underscores.
- Informational response followed by final response.
- Standalone responses when upstream connection metadata is absent.
- Malformed protobuf recovery; non-HTTP diagnostics.
- Clear removes pending connection and stream state.
- HTTP/2 stream-specific binary bodies and out-of-order responses.
- Incomplete HTTP/2 DATA retains already captured request headers.
- Collector prefix restores process and endpoint information.
- Live Java WebSocket client to real Swing table: five request rows and one
  standalone response from the recorded upstream frames.
- Row selection passes unchanged binary request bytes and normalized HTTP/2
  request bytes to the mocked Montoya editor boundary.

## Reproducibility and scope

All 44 tests execute with `./gradlew test`; no Go installation, Burp license,
root privileges, or eBPF-capable kernel is needed to replay the fixtures.
For regenerating them, use the included Go tools in
`compatibility/ecapture260` and `compatibility/openssl260`.

The fixtures exercise code pinned to upstream
[v2.6.0](https://github.com/gojue/ecapture/tree/v2.6.0), commit
`d1d3d3c789740829d54986620ecaa81d3ea06a42`. The fixture generator invokes the
actual event processor and exporter rather than copying their formatting
logic. Nested-envelope coverage is an explicit alternate-path fixture.

The Montoya host APIs are mocked because they are implemented by Burp at
runtime. No full Burp GUI session or live kernel/eBPF capture was run in
this sandbox. The compatibility limits in `PATCH_NOTES.md` remain applicable.
