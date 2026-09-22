# eCaptureBurp 1.1.1: direct OpenSSL request-display fix

Version 1.1.0 still missed the direct OpenSSL text-output path shown in the
reported logs. Its tests covered the EventProcessor collector path but not
OpenSSL's Event.String path. Version 1.1.1 adds this missing format and tests
the same request/response shapes with synthetic, non-sensitive data.

## Direct OpenSSL output fixed in 1.1.1

The direct formatter emits:

```text
[YYYY-MM-DD HH:MM:SS.mmm] PID:<pid> TID:<tid> Comm:<process> FD:<fd> WRITE (<n> bytes):
POST /path HTTP/1.1
...
```

READ events use the same prefix. This is distinct from the comma-delimited
collector prefix supported in 1.1.0 ([OpenSSL formatter](https://raw.githubusercontent.com/gojue/ecapture/v2.6.0/internal/probe/openssl/event.go)).
The text handler may append one LF after the original payload
([TextHandler](https://raw.githubusercontent.com/gojue/ecapture/v2.6.0/internal/probe/base/handlers/text_handler.go)).

- Parse the timestamped envelope, including process names containing spaces,
  trailing process padding, READ and WRITE, FD=0, and CRLF or LF.
- Preserve timestamp and process metadata. Detect HTTP from the actual payload,
  not from the wrapper or READ/WRITE direction alone.
- Remove only a proven extra terminal LF added by TextHandler, using the
  declared byte length. Do not trim binary bodies or truncate to a preview.
- Recognize `PID:..., Comm:..., TID:..., FD:..., Tuple:...` as connection
  metadata. Count it separately rather than logging it as malformed HTTP.
- Requests appear even with FD=0. Responses without a trustworthy connection
  identity appear as standalone rows; do not guess a pairing from PID/TID.
- Retain complete request/response bytes in the HTTP editor, including the
  long POST body and chunked UTF-8 response represented in the regression tests.

The actual upstream `openssl.Event.String() -> TextHandler.Handle() ->
ecaptureq.Server.WriteEvent()` path produced the new recorded fixtures via
a real loopback WebSocket. The reproducer lives in `compatibility/openssl260`.
Fixtures contain only synthetic domains, cookies, headers and bodies;
the user's credentials, cookies, phone data and application payloads are not
included in the archive.

## Earlier patch history

This release supersedes the earlier 1.0.0 protobuf-only patch. That patch
compiled, but it did not validate the event-to-request-panel path and did not
fix the reported empty request table. The earlier claims that it was
“schema-drift-proof” and that heartbeat round-trip testing had been performed
were incorrect.

## Collector path fixed in 1.1.0

The exact upstream release is `v2.6.0`, commit
`d1d3d3c789740829d54986620ecaa81d3ea06a42`.

The event processor's `CollectorWriter` interface contains the same `Write`
method as `io.Writer`. Its collector branch formats a metadata line before
the application bytes, rather than populating the structured protobuf
metadata ([interface](https://raw.githubusercontent.com/gojue/ecapture/v2.6.0/pkg/event_processor/event.go),
[Display implementation](https://raw.githubusercontent.com/gojue/ecapture/v2.6.0/pkg/event_processor/iworker.go)).

The WebSocket server puts those formatted bytes in `Event.payload`, sets
`length`, and leaves `type`, `uuid`, and the other fields at default values
([WriteEvent](https://github.com/gojue/ecapture/blob/v2.6.0/pkg/ecaptureq/server.go)).

Observed output from the unmodified 2.6.0 event processor and WebSocket server:

```text
log_type = LOG_TYPE_EVENT
event_payload.type = 0
event_payload.uuid = ""
event_payload.payload =
PID:4242, Comm:fixture_client, Src::0, Dest::0,
GET /from-ecapture-260 HTTP/1.1
Host: example.test
```

The old extension counted the event, searched for HTTP at byte zero, saw
`PID:` instead of a request line, and silently ignored it. Recompiling the
protobuf schema cannot fix that application-payload mismatch.

There is also an alternate serialization branch in the processor that
builds a complete `LogEntry`; wrapping its output in `WriteEvent` creates
a nested envelope. Version 1.1.0 handles both formats, without asserting
that this alternate branch is the active collector path.

## Changes

- **Collector payload parsing:** strip the precise 2.6.0 metadata prefix,
  recover process/address metadata where supplied, and recognize the HTTP
  payload. Retain the original payload for inspection.
- **Envelope compatibility:** accept normal structured events and guarded
  nested LogEntry envelopes. Do not attempt to unwrap real HTTP bodies.
- **All HTTP methods:** remove GET/POST-only and missing-Host rejection.
  Requests appear immediately without requiring a response.
- **HTTP/2:** parse 2.6.0's `Frame Type`, `Frame StreamID`, and HPACK-header
  text output into one request per stream. Provide a normalized HTTP/1.1
  editor view, preserve binary DATA bytes, and handle upstream merged gzip
  output. Incomplete DATA does not hide available request headers.
- **Pairing:** keep file descriptors/endpoints and HTTP/2 stream identities
  separate. Use unique row identifiers, not timestamps. Show standalone
  responses rather than silently losing them.
- **Binary-safe Burp integration:** use Montoya ByteArray APIs for editor,
  Repeater, and Site Map payloads instead of default-charset String conversion.
- **UI:** show all-method traffic, refresh selected details on updates, use
  explicit displayed-row mappings, and expose original payloads and bounded
  capture diagnostics. Label counters as Events, Requests, Pending, and
  Unparsed/control.
- **Lifecycle and build:** clear pending/stream state on Clear, stop the UI
  timer and reconnect scheduler on unload, correct the protoc include path,
  and bump Gradle metadata, JAR manifest, startup banner, and extension name
  to 1.1.1.

## Verification

`JAVA_HOME=<JDK17> ./gradlew clean test jar` passed with **44 tests, zero
failures, zero skipped**. See `TEST_RESULTS.md` and the included JUnit tests.
Generated Java classes target Java 17.

Fixtures were generated using the unmodified upstream v2.6.0
`EventProcessor` and `ecaptureq.Server.WriteEvent`, transmitted over an actual
loopback WebSocket, and saved in `src/test/resources/ecapture260`.
The Go reproducer is included in `compatibility/ecapture260`.

A second integration test runs the real Java WebSocket client, protobuf
decoder, event manager, Swing table, and selection handler. It checks five
visible requests plus a standalone response, then verifies selected binary
request bytes and an HTTP/2 request passed to the editor API. Only Burp's
host-provided Montoya factories/editors are mocked.

The integration test also runs a direct-OpenSSL scenario: four requests and
two standalone responses appear in the Swing table, two tuple events count
as metadata, and none of these events is reported as unparsed. Selecting the
long POST passes every original request byte to the editor; selecting the
chunked response passes its original chunk framing and UTF-8 bytes unchanged.

This is not a claim of a GUI smoke test inside Burp Suite, a kernel/eBPF
capture test, or complete coverage of all possible HTTP payloads.

## Remaining upstream limitations

- When the collector output omits both connection UUID and usable socket
  endpoints, reliable request/response correlation is impossible. Requests
  still appear; responses remain standalone instead of being guessed onto
  an unrelated request.
- HTTP/2 frames are a textual dump, not original wire HTTP/2. The extension
  cannot recover headers that eCapture's HPACK decoder did not produce,
  unsupported CONTINUATION frames, bytes dropped before export, or truncated
  bodies. Such events produce diagnostics with a bounded payload preview.
  See the [upstream HTTP/2 formatter](https://github.com/gojue/ecapture/blob/v2.6.0/pkg/event_processor/http2_request.go).
- Cross-event HTTP/2 DATA accumulation needs a usable connection identity
  and direction. Metadata-less DATA-only events cannot safely be assigned
  to a request. Same-event HEADERS and DATA are supported.
- This is not a general TCP/TLS reassembler or a raw HPACK decoder. HTTP/3,
  arbitrary hex-dump mode, and non-HTTP payloads are not translated into
  fabricated HTTP requests.
- Stream decoder state is bounded to 512 entries, five minutes, and 8 MiB
  of body data per stream/direction. Diagnostics keep 256 KiB of display
  text and up to a 2 KiB preview per unparsed event.
- For HTTP/2 the editor view is a reconstruction, not a byte-for-byte wire
  request. The Original event payload tab preserves the source dump for
  the selected event. Review requests before manually sending to Repeater.

## Build and load

Use a full JDK 17 or 21, not only a JRE. Dependencies and the Gradle
distribution are downloaded on the first build.

```bash
unzip eCaptureBurp-1.1.1-src.zip
cd eCaptureBurp
chmod +x gradlew
./gradlew clean test jar
```

Output: `build/libs/ecapture-burp-extension-1.1.1.jar`.
Generated Java protobuf sources are included; protoc and Go are not needed
for the normal Java build.

Unload/remove the previous extension in Burp, add the new JAR, and verify
the extension name or startup banner says **eCapture 1.1.1**. Start eCapture
with its `--ecaptureq` URL and connect the extension to the same reachable
address. Keep the endpoint bound to loopback or behind an authorized secure
tunnel because it carries decrypted application traffic.

```bash
sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/
```

When testing, watch Requests, not only Events. Select a row to inspect the
request. If an event cannot be translated, check Capture diagnostics.
