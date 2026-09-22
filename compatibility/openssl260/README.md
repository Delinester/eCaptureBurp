# Direct OpenSSL output fixtures for eCapture 2.6.0

Unlike the earlier EventProcessor fixtures, this reproducer invokes the
actual `openssl.Event.String()` through `TextHandler.Handle()` and
`ecaptureq.Server.WriteEvent()`, then records the live loopback WebSocket
frame. It also formats connection metadata with `ConnDataEvent.String()`.
All hosts, credentials, cookies, and bodies are synthetic.

Because OpenSSL is an internal Go package, the test must run within an
upstream checkout. With Go 1.26 installed, run from the extension root:

```bash
git clone --branch v2.6.0 --depth 1 https://github.com/gojue/ecapture /tmp/ecapture-burp-test
cp compatibility/openssl260/burp_fixture_test.go \
  /tmp/ecapture-burp-test/internal/probe/openssl/burp_fixture_test.go
export BURP_FIXTURE_DIR="$PWD/src/test/resources/ecapture260"
cd /tmp/ecapture-burp-test
go test ./internal/probe/openssl -run '^TestBurpDirectOutputFixtures$' -count=1 -v
```

Then return to the extension root and run `./gradlew test`.
No root privileges, live network capture, credentials, or real application
traffic are required. Fixture `.http` files are the original input bytes;
`.bin` files are actual emitted protobuf WebSocket messages.
